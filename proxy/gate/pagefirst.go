package gate

// page_first (kopandante/todo#419): the gate's look at what an address does, beside what its headers
// say. A visitor's browser asks for a page of the site — a document, or Next.js's RSC fetch of the next
// one — before the site's script calls the API, and from the same address; the scraper of cars.dbauto.kr
// asked for none in a day of 92 000 requests from 1 400 addresses. With page_first, an API request from an
// address that asked for no page of the group within window goes into the access log as gate_behavior
// no_page, and in enforce is refused, gate_reason no_page.
//
// An address let through renews its window as a page does: a visitor working one page of a catalog
// asks for none for as long as it works. The pages seen are kept by the process: a reload keeps them, a
// restart forgets them, and every visitor in the middle of a visit would then be an address without a
// page; so would every visitor of a group whose page_first a reload turns on. So for warmup after
// page_first goes on for a group in the process nothing is refused, and an address without a page is
// written and kept as if it had one: the visit goes on. Google's and Yandex's crawlers, the checks' exempt_ranges, the partner's Bearer,
// the health probe and the exemptions — servers' calls that ask for no page — are never asked; the
// token's issue, exempt as it is, is: a scraper asks for it, a browser after its page.
//
// An IPv6 address counts by its /64: a page from one address of it opens the API to all of it, as a
// browser's privacy addresses change within one, and a /64 fills the store with one entry, not 2^64.
// A full store fails open: an address it has no room for is not refused, and the overflow goes into the
// log once while it lasts.

import (
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// PageFirst is the group's rule of a page before the API: off — the default — log or enforce.
type PageFirst struct {
	Mode string `json:"mode,omitempty"`
	// Window is how long an address's page lets its API requests through, renewed by each page and by
	// each request it lets through.
	Window caddy.Duration `json:"window"`
	// Warmup is how long after page_first went on for the group in the process nothing is refused,
	// defaultWarmup when not given; not past the window.
	Warmup caddy.Duration `json:"warmup,omitempty"`
}

const (
	defaultWarmup = 30 * time.Minute
	minPageWindow = 10 * time.Minute
	maxPageWindow = 7 * 24 * time.Hour
	// maxPages bounds the addresses kept over every group: a day of cars.dbauto.kr is under 2 000
	// visitors' addresses, an entry under a hundred bytes.
	maxPages = 500_000
	// pageSweepEvery is how often at most a full store looks for entries past the window: not on every
	// new address, which would scan it all under the one lock.
	pageSweepEvery = time.Minute
)

func (pf *PageFirst) on() bool { return pf != nil && (pf.Mode == "log" || pf.Mode == "enforce") }

func (pf *PageFirst) warmup() time.Duration {
	if pf.Warmup != 0 {
		return time.Duration(pf.Warmup)
	}
	return defaultWarmup
}

// validate refuses a mode it does not know, enforce in a group that is not, and, when on, a window or a
// warmup out of bounds — the default warmup included.
func (pf *PageFirst) validate(groupMode string) error {
	w := time.Duration(pf.Window)
	switch {
	case pf.Mode != "" && pf.Mode != "off" && pf.Mode != "log" && pf.Mode != "enforce":
		return fmt.Errorf("page_first: mode %q must be off, log or enforce", pf.Mode)
	case pf.Mode == "enforce" && groupMode != "enforce":
		return fmt.Errorf("page_first: enforce goes with the group's mode enforce")
	case !pf.on():
		return nil
	case w < minPageWindow || w > maxPageWindow:
		return fmt.Errorf("page_first: window %s must be from %s to %s", w, minPageWindow, maxPageWindow)
	case pf.Warmup < 0 || pf.warmup() > w:
		return fmt.Errorf("page_first: warmup %s must not be past the window %s", pf.warmup(), w)
	}
	return nil
}

// sawPage keeps a page request of ip on the cleaned path p: the start of its window.
func (h *Handler) sawPage(r *http.Request, p, ip string) {
	if !h.PageFirst.on() || !pageRequest(r, p) {
		return
	}
	if a, err := netip.ParseAddr(ip); err == nil && h.pageStore().saw(h.Name, a, h.now()) {
		h.logFull()
	}
}

// logFull writes that the store of pages went full: an address it has no room for passes, page or not.
func (h *Handler) logFull() {
	if h.logger != nil {
		h.logger.Error("page_first: the store of pages is full, new addresses pass unchecked",
			zap.String("group", h.Name), zap.Int("max", maxPages))
	}
}

// pageless is page_first's verdict on an API request of ip, and whether it has one: refused in
// enforce, past the warmup, when the address asked for no page within the window.
func (h *Handler) pageless(r *http.Request, p, ip string) (decision, bool) {
	pf := h.PageFirst
	if !pf.on() || h.keyed(r) {
		return decision{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || h.spared(r, a) {
		return decision{}, false
	}
	ans := h.pageStore().ask(h.Name, a, h.now(), time.Duration(pf.Window), pf.warmup())
	if ans.firstFull {
		h.logFull()
	}
	if ans.seen || ans.unkept {
		return decision{}, false
	}
	setField(r, zap.String("gate_behavior", "no_page"))
	if pf.Mode != "enforce" || ans.warming {
		return decision{}, false
	}
	return deny("no_page", forbidden), true
}

func (h *Handler) pageStore() *pageStore {
	if h.pages != nil {
		return h.pages
	}
	return sharedPages
}

// sharedPages are the pages of every handler the process provisions: a reload's handler of a group
// finds the pages the one it replaced saw.
var sharedPages = newPageStore()

// pageStore is when each address last asked for a page, or was let through by one, by group; and since
// when each group has had page_first on in the process.
type pageStore struct {
	mu     sync.Mutex
	last   map[banKey]time.Time
	groups map[string]*groupSpan
	max    int
	// window is the longest window the store was asked with, for the sweep.
	window time.Duration
	// swept is when a full store last looked for entries past the window.
	swept time.Time
	// full is set while a new address found no room, so the overflow is logged once per episode, as
	// boks_ban's store does.
	full bool
}

// pageKey is a's entry in group: an IPv6 address by its /64.
func pageKey(group string, a netip.Addr) banKey {
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			a = p.Addr()
		}
	}
	return banKey{group, a}
}

// groupSpan is since when a group has had page_first on, and how many handlers provisioned have it on:
// a reload provisions the new ones before it cleans up the old, so the span goes on through it.
type groupSpan struct {
	began    time.Time
	handlers int
}

func newPageStore() *pageStore {
	return &pageStore{last: map[banKey]time.Time{}, groups: map[string]*groupSpan{}, max: maxPages}
}

// begin counts a handler of group with page_first on, provisioned at now: the first begins the span.
func (s *pageStore) begin(group string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.groups[group]
	if g == nil {
		g = &groupSpan{began: now}
		s.groups[group] = g
	}
	g.handlers++
}

// end counts a handler of group cleaned up: with the last, the span is over.
func (s *pageStore) end(group string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.groups[group]; g != nil {
		if g.handlers--; g.handlers <= 0 {
			delete(s.groups, group)
		}
	}
}

// saw keeps a page of a in group at now, and says whether the store went full on it.
func (s *pageStore) saw(group string, a netip.Addr, now time.Time) (firstFull bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, firstFull = s.put(pageKey(group, a), now)
	return firstFull
}

// answer is ask's: whether the address asked for a page within the window; whether the group warms
// up; whether the store, full, has no room for the address, which then passes; and whether that began
// the overflow.
type answer struct {
	seen, warming, unkept, firstFull bool
}

// ask says whether a asked for a page of group within window before now, and whether the group is
// still warming up — within warmup of page_first going on for it in the process. An address let
// through is kept as seen at now: a visitor's API requests renew its window as its pages do, since a
// catalog's filters change the URL with no request and the token is renewed every two minutes. Within
// the warmup an address without a page is kept too: its page may have come before the process knew
// the group's pages — a restart of the proxy, page_first turned on by a reload — and the visit goes on
// without one.
func (s *pageStore) ask(group string, a netip.Addr, now time.Time, window, warmup time.Duration) (ans answer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if window > s.window {
		s.window = window
	}
	if g := s.groups[group]; g == nil || now.Sub(g.began) < warmup {
		ans.warming = true
	}
	k := pageKey(group, a)
	t, ok := s.last[k]
	ans.seen = ok && now.Sub(t) < window
	switch {
	case ans.seen || ans.warming:
		_, ans.firstFull = s.put(k, now)
	case !ok:
		// An address the store has no room for may have had its page then: it passes.
		ans.unkept, ans.firstFull = s.noRoom(k, now)
	}
	return ans
}

// noRoom says whether the store is full for k, a new key: swept of the entries past the window at most
// once a pageSweepEvery, still full. firstFull is the first of an overflow.
func (s *pageStore) noRoom(k banKey, now time.Time) (full, firstFull bool) {
	if _, ok := s.last[k]; ok || len(s.last) < s.max {
		return false, false
	}
	if now.Sub(s.swept) >= pageSweepEvery {
		s.swept = now
		for key, t := range s.last {
			if now.Sub(t) >= s.window {
				delete(s.last, key)
			}
		}
		if len(s.last) < s.max {
			return false, false
		}
	}
	firstFull = !s.full
	s.full = true
	return true, firstFull
}

// put keeps k at now, unless the store is full for it.
func (s *pageStore) put(k banKey, now time.Time) (kept, firstFull bool) {
	_, had := s.last[k]
	if full, first := s.noRoom(k, now); full {
		return false, first
	}
	if !had {
		s.full = false
	}
	s.last[k] = now
	return true, false
}
