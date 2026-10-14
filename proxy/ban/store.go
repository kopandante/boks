package ban

import (
	"net/netip"
	"sync"
	"time"
)

// shared is the store of every handler the process provisions: a reload's new handler finds the
// counts and the bans of the one it replaced.
var shared = newStore(time.Now)

// store holds, per address, its window's count and its ban. One lock: a hit is a map lookup and a few
// comparisons, well under a microsecond, and the server's whole traffic passes it.
type store struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[netip.Addr]*entry
	// swept is when expired entries were last removed; a sweep runs at most once a window.
	swept time.Time
	// full is set while a new address could not be tracked, so the overflow is logged once per
	// episode rather than per request.
	full bool
}

type entry struct {
	start  time.Time // the window's start
	count  int       // requests in the window
	banned time.Time // the ban's end; zero when not banned
}

func newStore(now func() time.Time) *store {
	return &store{now: now, entries: map[netip.Addr]*entry{}}
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
	count   int
	until   time.Time
}

// hit counts one request of a and says what to do with it.
func (s *store) hit(a netip.Addr, limit int, window, duration time.Duration, maxTracked int) verdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.Sub(s.swept) >= window {
		s.sweep(now, window)
	}
	e := s.entries[a]
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
		e = &entry{start: now}
		s.entries[a] = e
	}
	if !e.banned.IsZero() {
		if now.Before(e.banned) {
			return verdict{outcome: banned, until: e.banned}
		}
		*e = entry{start: now}
	}
	if now.Sub(e.start) >= window {
		e.start, e.count = now, 0
	}
	e.count++
	if e.count > limit {
		e.banned = now.Add(duration)
		return verdict{outcome: newlyBanned, count: e.count, until: e.banned}
	}
	return verdict{outcome: pass, count: e.count}
}

// sweep removes the entries whose window passed and whose ban, if any, ended.
func (s *store) sweep(now time.Time, window time.Duration) {
	s.swept = now
	for a, e := range s.entries {
		if now.Sub(e.start) >= window && !now.Before(e.banned) {
			delete(s.entries, a)
		}
	}
}
