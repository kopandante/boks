package gate

// page_first (kopandante/todo#419): the gate's look at what an address does, beside what its headers
// say. A visitor's browser asks for a page of the site — a document, or Next.js's RSC fetch of the next
// one — before the site's script calls the API, and from the same address; the scraper of cars.dbauto.kr
// asked for none in a day of 92 000 requests from 1 400 addresses. With page_first, an API request from an
// address that asked for no page of the group within window goes into the access log as gate_behavior
// no_page, and in enforce is refused, gate_reason no_page.
//
// The pages seen are kept by the process: a reload keeps them, a restart forgets them, and every
// visitor in the middle of a visit would then be an address without a page. So a process refuses
// nothing for warmup after it began — longer than a visit's pause between a page and its API calls —
// and only writes. Google's and Yandex's crawlers, the checks' exempt_ranges, the partner's Bearer and
// the health probe are never asked.

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
	// Window is how long an address's page lets its API requests through, renewed by each page.
	Window caddy.Duration `json:"window"`
	// Warmup is how long after the process began nothing is refused, defaultWarmup when not given.
	Warmup caddy.Duration `json:"warmup,omitempty"`
}

const (
	defaultWarmup = 30 * time.Minute
	minPageWindow = 10 * time.Minute
	maxPageWindow = 7 * 24 * time.Hour
	// maxPages bounds the addresses kept over every group: a day of cars.dbauto.kr is under 2 000
	// visitors' addresses, an entry under a hundred bytes.
	maxPages = 500_000
)

func (pf *PageFirst) on() bool { return pf != nil && (pf.Mode == "log" || pf.Mode == "enforce") }

func (pf *PageFirst) warmup() time.Duration {
	if pf.Warmup != 0 {
		return time.Duration(pf.Warmup)
	}
	return defaultWarmup
}

// validate refuses a mode it does not know, enforce in a group that is not, and a window or a warmup
// out of bounds.
func (pf *PageFirst) validate(groupMode string) error {
	w := time.Duration(pf.Window)
	switch {
	case pf.Mode != "" && pf.Mode != "off" && pf.Mode != "log" && pf.Mode != "enforce":
		return fmt.Errorf("page_first: mode %q must be off, log or enforce", pf.Mode)
	case pf.Mode == "enforce" && groupMode != "enforce":
		return fmt.Errorf("page_first: enforce goes with the group's mode enforce")
	case w < minPageWindow || w > maxPageWindow:
		return fmt.Errorf("page_first: window %s must be from %s to %s", w, minPageWindow, maxPageWindow)
	case pf.Warmup != 0 && (time.Duration(pf.Warmup) < 0 || time.Duration(pf.Warmup) > w):
		return fmt.Errorf("page_first: warmup %s must be from 0 to the window", time.Duration(pf.Warmup))
	}
	return nil
}

// sawPage keeps a page request of ip on the cleaned path p: the start of its window.
func (h *Handler) sawPage(r *http.Request, p, ip string) {
	if !h.PageFirst.on() || !pageRequest(r, p) {
		return
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		h.pageStore().saw(h.Name, a, h.now())
	}
}

// pageless is page_first's verdict on an API request of ip, and whether it has one: refused in
// enforce, past the warmup, when the address asked for no page within the window.
func (h *Handler) pageless(r *http.Request, p, ip string) (decision, bool) {
	pf := h.PageFirst
	if !pf.on() || h.bearer != nil && h.bearer.admits(r, p) {
		return decision{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || h.spared(r, a) {
		return decision{}, false
	}
	now := h.now()
	ps := h.pageStore()
	if ps.seen(h.Name, a, now, time.Duration(pf.Window)) {
		return decision{}, false
	}
	setField(r, zap.String("gate_behavior", "no_page"))
	if pf.Mode != "enforce" || ps.age(now) < pf.warmup() {
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

// sharedPages are the pages of every handler the process provisions; began is when the process did.
var sharedPages = newPageStore(time.Now())

// pageStore is when each address last asked for a page, by group.
type pageStore struct {
	mu    sync.Mutex
	last  map[banKey]time.Time
	began time.Time
	max   int
	// window is the longest window a seen() asked with, for the sweep.
	window time.Duration
}

func newPageStore(began time.Time) *pageStore {
	return &pageStore{last: map[banKey]time.Time{}, began: began, max: maxPages}
}

func (s *pageStore) age(now time.Time) time.Duration { return now.Sub(s.began) }

// saw keeps a page of a in group at now. A full store sweeps the pages past the window first; still
// full, it keeps no new address, which then reads as without a page.
func (s *pageStore) saw(group string, a netip.Addr, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := banKey{group, a}
	if _, ok := s.last[k]; !ok && len(s.last) >= s.max {
		for key, t := range s.last {
			if now.Sub(t) >= s.window {
				delete(s.last, key)
			}
		}
		if len(s.last) >= s.max {
			return
		}
	}
	s.last[k] = now
}

// seen says whether a asked for a page of group within window before now.
func (s *pageStore) seen(group string, a netip.Addr, now time.Time, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if window > s.window {
		s.window = window
	}
	t, ok := s.last[banKey{group, a}]
	return ok && now.Sub(t) < window
}
