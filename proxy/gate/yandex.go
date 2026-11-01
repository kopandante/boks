package gate

// Yandex's search robot — YandexBot, YandexMobileBot, YandexImages, YandexVideo and
// YandexRenderResourcesBot, which renders a page and fetches its /api over HTTP/1.1 without Fetch
// Metadata — passes fetch_meta and alpn as Googlebot does, and is spared page_first, static_rhythm and
// the signatures (spared). Yandex publishes no list of its robots' addresses; its own way to tell one
// (yandex.com/support/webmaster, "How to check that a robot belongs to Yandex") is a reverse lookup that
// ends in yandex.ru, yandex.net or yandex.com and a forward lookup of that name back to the same address.
// The gate asks exactly that (#162), and only of a request that names a search robot (yandexRobots) from
// an address Yandex's own AS, AS13238, announces (yandex/as13238.txt, a file in the image like Google's):
// any other request never waits on DNS. Yandex Cloud, where anyone can rent a machine, is another AS.
// Yandex's other fetchers — Translate, previews, Metrika, any other Yandex* — come from the same AS, but
// a user points them at a page, as Google's user-triggered fetchers (#155): they are checked as browsers.
//
// The bounds of the lookup (yandexStore): an address's answer is kept a day when it is Yandex's and an
// hour when it is not, for at most yandexEntries addresses; one lookup at a time per address, the rest
// wait for it; at most yandexTimeout for both lookups. A resolver that fails — an error or a timeout, not
// an answer that the name is not Yandex's — keeps the verdict the gate had before the lookup, AS13238 and
// the robot's name, for a minute, and writes gate_yandex_dns: unavailable into the request's log entry:
// the Russian sites live off Yandex's search, and a resolver that is down must not refuse its robot. A
// name that does not exist (NXDOMAIN) is an answer. A new list of prefixes is a new image.

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

//go:embed yandex/as13238.txt
var yandexFile string

var yandexRanges = sync.OnceValue(func() []netip.Prefix {
	ps, err := readYandex(yandexFile)
	if err != nil {
		// The file is the image's own; a test reads it whole (TestYandexRanges).
		panic(err)
	}
	return ps
})

// readYandex reads one CIDR prefix a line; blank lines and # comments are skipped.
func readYandex(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		p, err := netip.ParsePrefix(l)
		if err != nil || p.Bits() == 0 {
			return nil, fmt.Errorf("yandex/as13238.txt:%d: prefix %q", i+1, l)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// yandexRobots are the tokens in the User-Agent of Yandex's search robots; any other Yandex* is a
// fetcher of Yandex's other services.
var yandexRobots = []string{"YandexBot/", "YandexMobileBot/", "YandexImages/", "YandexVideo/", "YandexRenderResourcesBot/"}

// yandexDomains are what the reverse lookup of a robot's address ends in.
var yandexDomains = []string{".yandex.ru", ".yandex.net", ".yandex.com"}

const (
	yandexConfirmed = 24 * time.Hour // how long an address confirmed Yandex's is kept
	yandexRefused   = time.Hour      // how long an address refused is kept
	yandexFailed    = time.Minute    // how long a failed resolver's verdict is kept
	yandexTimeout   = 1500 * time.Millisecond
	yandexEntries   = 4096
)

// resolver is the part of net.Resolver the gate asks; the tests' is their own.
type resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// yandexRobot says whether r from a is Yandex's search robot: a robot's name from AS13238, confirmed by
// DNS, or kept by a resolver that failed.
func (h *Handler) yandexRobot(r *http.Request, a netip.Addr) bool {
	if !yandexRobotUA(r.UserAgent()) || !inRanges(yandexRanges(), a) {
		return false
	}
	switch h.yandexStore().ask(a, h.now()) {
	case yandexYes:
		return true
	case yandexUnknown:
		setField(r, zap.String("gate_yandex_dns", "unavailable"))
		return true
	}
	return false
}

// yandexRobotUA says whether ua names one of Yandex's search robots.
func yandexRobotUA(ua string) bool {
	for _, t := range yandexRobots {
		if strings.Contains(ua, t) {
			return true
		}
	}
	return false
}

func (h *Handler) yandexStore() *yandexStore {
	if h.yandex != nil {
		return h.yandex
	}
	return sharedYandex
}

// sharedYandex are the answers of every handler the process provisions.
var sharedYandex = newYandexStore(net.DefaultResolver)

type yandexVerdict int

const (
	yandexNo yandexVerdict = iota
	yandexYes
	yandexUnknown // the resolver failed
)

// ttl is how long the verdict is kept.
func (v yandexVerdict) ttl() time.Duration {
	switch v {
	case yandexYes:
		return yandexConfirmed
	case yandexNo:
		return yandexRefused
	}
	return yandexFailed
}

type yandexEntry struct {
	v     yandexVerdict
	until time.Time
}

// yandexCall is a lookup in flight; done closes when v is set.
type yandexCall struct {
	done chan struct{}
	v    yandexVerdict
}

// yandexStore is the answer of DNS for each address asked, and the lookups in flight.
type yandexStore struct {
	dns     resolver
	mu      sync.Mutex
	answers map[netip.Addr]yandexEntry
	calls   map[netip.Addr]*yandexCall
}

func newYandexStore(dns resolver) *yandexStore {
	return &yandexStore{dns: dns, answers: map[netip.Addr]yandexEntry{}, calls: map[netip.Addr]*yandexCall{}}
}

// ask is the verdict of DNS on a at now: the one kept while it lasts, else one lookup's, which a request
// asking meanwhile waits for.
func (s *yandexStore) ask(a netip.Addr, now time.Time) yandexVerdict {
	s.mu.Lock()
	if e, ok := s.answers[a]; ok && now.Before(e.until) {
		s.mu.Unlock()
		return e.v
	}
	if c, ok := s.calls[a]; ok {
		s.mu.Unlock()
		<-c.done
		return c.v
	}
	c := &yandexCall{done: make(chan struct{})}
	s.calls[a] = c
	s.mu.Unlock()

	c.v = yandexUnknown
	defer func() {
		s.mu.Lock()
		delete(s.calls, a)
		s.keep(a, yandexEntry{c.v, now.Add(c.v.ttl())}, now)
		s.mu.Unlock()
		close(c.done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), yandexTimeout)
	defer cancel()
	c.v = lookupYandex(ctx, s.dns, a)
	return c.v
}

// keep stores e for a; a full store drops the answers past their time first, then any one.
func (s *yandexStore) keep(a netip.Addr, e yandexEntry, now time.Time) {
	if _, ok := s.answers[a]; !ok && len(s.answers) >= yandexEntries {
		for k, old := range s.answers {
			if !now.Before(old.until) {
				delete(s.answers, k)
			}
		}
		for k := range s.answers {
			if len(s.answers) < yandexEntries {
				break
			}
			delete(s.answers, k)
		}
	}
	s.answers[a] = e
}

// lookupYandex asks dns whether a is Yandex's: a name of its reverse lookup in yandexDomains whose
// forward lookup holds a. A name that does not exist is a no; any other error, unless another name
// confirms a, is unknown.
func lookupYandex(ctx context.Context, dns resolver, a netip.Addr) yandexVerdict {
	names, err := dns.LookupAddr(ctx, a.String())
	if err != nil {
		return failure(err)
	}
	v := yandexNo
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !yandexName(n) {
			continue
		}
		addrs, err := dns.LookupNetIP(ctx, "ip", n)
		if err != nil {
			if failure(err) == yandexUnknown {
				v = yandexUnknown
			}
			continue
		}
		for _, b := range addrs {
			if b.Unmap() == a.Unmap() {
				return yandexYes
			}
		}
	}
	return v
}

func yandexName(n string) bool {
	for _, d := range yandexDomains {
		if strings.HasSuffix(n, d) {
			return true
		}
	}
	return false
}

// failure is the verdict an error of the resolver gives: no for a name that does not exist, unknown
// for anything else.
func failure(err error) yandexVerdict {
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return yandexNo
	}
	return yandexUnknown
}
