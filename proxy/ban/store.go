package ban

import (
	"net/netip"
	"sync"
	"time"
)

// shared is the store of every handler the process provisions: a reload's new handler finds the
// counts and the bans of the one it replaced.
var shared = newStore(time.Now)

// store holds, per address, its ban and a count per rule. One lock: a hit is a map lookup and a few
// comparisons per rule, well under a microsecond, and the server's whole traffic passes it.
//
// The store knows rules only by what a hit hands it: the handler of a reload brings its own, and a
// count belongs to the rule of its name, window and limit. A rule whose window or limit changed counts
// again from its next request; a rule no longer given loses its counts at the next sweep. A ban is the
// address's, not a rule's, and outlives any reload.
type store struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[netip.Addr]*entry
	// swept is when expired counts were last removed; a sweep runs at most once a shortest window.
	swept time.Time
	// full is set while a new address could not be tracked, so the overflow is logged once per
	// episode rather than per request.
	full bool

	// prints are the heuristics' clusters by fingerprint, swept at most once a cluster's window, and
	// printsFull is full for them.
	prints      map[string]*print
	printsSwept time.Time
	printsFull  bool
}

// print is a fingerprint's cluster in its window, and its ban.
type print struct {
	start time.Time
	count int
	// addrs are the cluster's addresses until it has minAddresses of them; nil after, when reached
	// says the rest.
	addrs   map[netip.Addr]struct{}
	reached bool
	flagged bool
	banned  time.Time
	// min is the min_addresses reached was told by: a reload with another starts the window again.
	min int
}

type entry struct {
	banned   time.Time // the ban's end; zero when not banned
	counters []counter // one per rule that counted a request of the address, in no order
}

// counter is a rule's count of an address: 40 bytes, so that 16 rules over the tracked addresses stay
// within the memory DefaultMaxTracked is measured with.
type counter struct {
	rule   string
	window time.Duration
	start  int64 // the window's start, in Unix nanoseconds
	limit  int32
	count  int32
}

func newStore(now func() time.Time) *store {
	return &store{now: now, entries: map[netip.Addr]*entry{}, prints: map[string]*print{}}
}

type outcome int

const (
	pass        outcome = iota
	banned              // banned before this request
	newlyBanned         // this request started the ban
	full                // the store is full and the address was not counted; first such request
)

type verdict struct {
	outcome outcome
	rule    rule // the rule that started the ban
	count   int
	until   time.Time
}

// hit counts one request of a toward each of rules that counts it — bit i of counts for rules[i] —
// and says what to do with it. A request no rule counts only asks whether a is banned.
func (s *store) hit(a netip.Addr, rules []rule, counts uint64, duration time.Duration, maxTracked int) verdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.Sub(s.swept) >= shortest(rules) {
		s.sweep(now, rules)
	}
	e := s.entries[a]
	if e != nil && !e.banned.IsZero() {
		if now.Before(e.banned) {
			return verdict{outcome: banned, until: e.banned}
		}
		// The ban ended: the address starts fresh windows.
		e.banned, e.counters = time.Time{}, nil
	}
	if counts == 0 {
		return verdict{outcome: pass}
	}
	if e == nil {
		if len(s.entries) >= maxTracked {
			// Swept within the window and still full: the address passes uncounted rather than the
			// table growing without bound, or an old address being forgotten mid-ban.
			if s.full {
				return verdict{outcome: pass}
			}
			s.full = true
			return verdict{outcome: full}
		}
		s.full = false
		e = &entry{}
		s.entries[a] = e
	}
	for i, r := range rules {
		if counts&(1<<i) == 0 {
			continue
		}
		c := e.counter(r)
		if now.UnixNano()-c.start >= int64(r.window) {
			c.start, c.count = now.UnixNano(), 0
		}
		c.count++
		if int(c.count) > r.limit {
			e.banned = now.Add(duration)
			return verdict{outcome: newlyBanned, rule: r, count: int(c.count), until: e.banned}
		}
	}
	return verdict{outcome: pass}
}

// counter is e's count for r, a new one when e has none of r's name, window and limit — a rule of
// that name changed since starts again.
func (e *entry) counter(r rule) *counter {
	for i := range e.counters {
		if c := &e.counters[i]; c.rule == r.name {
			if c.window != r.window || int(c.limit) != r.limit {
				*c = counter{rule: r.name, window: r.window, limit: int32(r.limit)}
			}
			return c
		}
	}
	e.counters = append(e.counters, counter{rule: r.name, window: r.window, limit: int32(r.limit)})
	return &e.counters[len(e.counters)-1]
}

// shortest is the shortest window of rules, a minute without any.
func shortest(rules []rule) time.Duration {
	d := time.Duration(0)
	for _, r := range rules {
		if d == 0 || r.window < d {
			d = r.window
		}
	}
	if d == 0 {
		d = time.Minute
	}
	return d
}

// sweep removes the counts whose window passed or whose rule rules no longer hold, and the entries
// left with no count and no ban.
func (s *store) sweep(now time.Time, rules []rule) {
	s.swept = now
	for a, e := range s.entries {
		kept := e.counters[:0]
		for _, c := range e.counters {
			if now.UnixNano()-c.start < int64(c.window) && holds(rules, c) {
				kept = append(kept, c)
			}
		}
		clear(e.counters[len(kept):])
		e.counters = kept
		if len(kept) == 0 && !now.Before(e.banned) {
			delete(s.entries, a)
		}
	}
}

// holds says whether rules still hold the rule c counts for.
func holds(rules []rule, c counter) bool {
	for _, r := range rules {
		if r.name == c.rule && r.window == c.window && r.limit == int(c.limit) {
			return true
		}
	}
	return false
}

// printVerdict is what to do with a flagged request, and what to write of it.
type printVerdict struct {
	refuse bool
	// joined: the address is new to the fingerprint's cluster in the window, a line of its own.
	joined bool
	// flagged: the request made the cluster; newlyBanned: it started the fingerprint's ban.
	flagged, newlyBanned bool
	count                int
	until                time.Time
	// full: the fingerprint could not be tracked; first such request.
	full bool
}

// forged counts a flagged request of a with fingerprint fp toward its cluster and says what to do with
// it. Mode is the handler's, asked at each request: a ban is refused only while the mode is ban, so a
// reload back to log stops refusing at once and the bans kept are not enforced.
func (s *store) forged(a netip.Addr, fp string, c cluster, mode string, duration time.Duration, maxPrints int) printVerdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.Sub(s.printsSwept) >= c.window {
		s.printsSwept = now
		for k, p := range s.prints {
			if now.Sub(p.start) >= c.window && !now.Before(p.banned) {
				delete(s.prints, k)
			}
		}
	}
	p := s.prints[fp]
	if p == nil {
		if len(s.prints) >= maxPrints {
			if s.printsFull {
				return printVerdict{}
			}
			s.printsFull = true
			return printVerdict{full: true}
		}
		s.printsFull = false
		p = &print{}
		s.prints[fp] = p
	}
	ban := mode == "ban"
	if ban && now.Before(p.banned) {
		return printVerdict{refuse: true, until: p.banned}
	}
	if now.Sub(p.start) >= c.window || p.min != c.minAddresses {
		p.start, p.count, p.addrs, p.reached, p.flagged, p.min = now, 0, nil, false, false, c.minAddresses
	}
	p.count++
	var v printVerdict
	if !p.reached {
		if _, ok := p.addrs[a]; !ok {
			if p.addrs == nil {
				p.addrs = map[netip.Addr]struct{}{}
			}
			p.addrs[a] = struct{}{}
			v.joined = true
			if len(p.addrs) >= c.minAddresses {
				p.addrs, p.reached = nil, true
			}
		}
	}
	v.count = p.count
	if p.count > c.limit && p.reached {
		v.flagged, p.flagged = !p.flagged, true
		if ban {
			p.banned = now.Add(duration)
			v.refuse, v.newlyBanned, v.until = true, true, p.banned
		}
	}
	return v
}
