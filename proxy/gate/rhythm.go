package gate

// static_rhythm (kopandante/todo#422): how an address fetches the site's files, beside whether it asked
// for a page. A browser fetches the files a page names at once, over one connection: of 74 addresses
// with six files of /_next/ or more in a day of cars.dbauto.kr, no browser's least gap between two of
// them was over 20 ms. The scraper, which fetches a page and its files so that page_first counts the
// page, fetches them one by one, the least gap 0.59 to 0.64 s; Bingbot's is 0.12 to 0.19 s, Google's
// over 0.3 s. With static_rhythm, the first files requests of an address under prefix are timed; when
// the least gap between two in a row is over min_gap, the address is serial: for window its API
// requests go into the access log as gate_behavior serial_static, and in enforce are refused, gate_reason
// serial_static. An address whose least gap is min_gap or under is done with until window after its
// first file; then it is timed again.
//
// The API asked is page_first's: not the health probe, not the exemptions but the token's issue, not a
// partner's Bearer; Google's and Yandex's crawlers and the checks' exempt_ranges are neither timed nor
// asked. Bing is not spared, which is why min_gap is 300 ms and not 100.
//
// The times and marks are kept by the process, shared by its handlers: a reload keeps them, a restart
// forgets them. A marked address is then unmarked, and marked again by its next files requests: the
// scraper's six take it under four seconds. Nothing is refused for want of a mark, so there is no
// warmup. An IPv6 address counts by its /64, as page_first's; a full store fails open: an address it has
// no room for is not timed, so never marked, and the overflow goes into the log once while it lasts.

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// StaticRhythm is the group's rule of the files' rhythm: off — the default — log or enforce.
type StaticRhythm struct {
	Mode string `json:"mode,omitempty"`
	// Prefix is the path of the files timed, defaultRhythmPrefix when not given.
	Prefix string `json:"prefix,omitempty"`
	// Files is how many of an address's first files are timed, defaultRhythmFiles when not given.
	Files int `json:"files,omitempty"`
	// MinGap is the least gap past which the files' requests are serial, defaultMinGap when not given.
	MinGap caddy.Duration `json:"min_gap,omitempty"`
	// Window is how long a mark lasts, and how long an address found not serial is not timed again.
	Window caddy.Duration `json:"window"`
}

const (
	defaultRhythmPrefix = "/_next/"
	defaultRhythmFiles  = 6
	defaultMinGap       = 300 * time.Millisecond
	minRhythmFiles      = 3
	maxRhythmFiles      = 64
	minMinGap           = 10 * time.Millisecond
	maxMinGap           = 10 * time.Second
	minRhythmWindow     = 10 * time.Minute
	maxRhythmWindow     = 7 * 24 * time.Hour
	// maxRhythms bounds the addresses kept over every group, as maxPages does page_first's.
	maxRhythms = 500_000
)

func (sr *StaticRhythm) on() bool { return sr != nil && (sr.Mode == "log" || sr.Mode == "enforce") }

func (sr *StaticRhythm) prefix() string {
	if sr.Prefix != "" {
		return sr.Prefix
	}
	return defaultRhythmPrefix
}

func (sr *StaticRhythm) files() int {
	if sr.Files != 0 {
		return sr.Files
	}
	return defaultRhythmFiles
}

func (sr *StaticRhythm) minGap() time.Duration {
	if sr.MinGap != 0 {
		return time.Duration(sr.MinGap)
	}
	return defaultMinGap
}

// validate refuses a mode it does not know, enforce in a group that is not, and, when on, a prefix
// that is not a path outside /api/ — the API is what the rhythm is asked for, not what it times — and
// files, a gap or a window out of bounds.
func (sr *StaticRhythm) validate(groupMode string) error {
	w, g := time.Duration(sr.Window), sr.minGap()
	switch {
	case sr.Mode != "" && sr.Mode != "off" && sr.Mode != "log" && sr.Mode != "enforce":
		return fmt.Errorf("static_rhythm: mode %q must be off, log or enforce", sr.Mode)
	case sr.Mode == "enforce" && groupMode != "enforce":
		return fmt.Errorf("static_rhythm: enforce goes with the group's mode enforce")
	case !sr.on():
		return nil
	case !strings.HasPrefix(sr.prefix(), "/") || underPrefix(sr.prefix(), "/api/") || strings.HasPrefix("/api/", sr.prefix()):
		return fmt.Errorf("static_rhythm: prefix %q must be a path outside /api/", sr.prefix())
	case sr.files() < minRhythmFiles || sr.files() > maxRhythmFiles:
		return fmt.Errorf("static_rhythm: files %d must be from %d to %d", sr.files(), minRhythmFiles, maxRhythmFiles)
	case sr.MinGap < 0 || g < minMinGap || g > maxMinGap:
		return fmt.Errorf("static_rhythm: min_gap %s must be from %s to %s", g, minMinGap, maxMinGap)
	case w < minRhythmWindow || w > maxRhythmWindow:
		return fmt.Errorf("static_rhythm: window %s must be from %s to %s", w, minRhythmWindow, maxRhythmWindow)
	}
	return nil
}

// sawFile times a request of ip on the cleaned path p when it is one of the files.
func (h *Handler) sawFile(r *http.Request, p, ip string) {
	sr := h.StaticRhythm
	if !sr.on() || (r.Method != http.MethodGet && r.Method != http.MethodHead) || !strings.HasPrefix(p, sr.prefix()) {
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || h.spared(r, a) || h.noBan(a) {
		return
	}
	if h.rhythmStore().saw(h.Name, a, h.now(), sr.files(), sr.minGap(), time.Duration(sr.Window)) && h.logger != nil {
		h.logger.Error("static_rhythm: the store of addresses is full, new addresses go untimed",
			zap.String("group", h.Name), zap.Int("max", maxRhythms))
	}
}

// serial says whether the API request r of ip is from an address marked serial, and whether it is
// refused for it: in enforce.
func (h *Handler) serial(r *http.Request, ip string) (marked, refused bool) {
	sr := h.StaticRhythm
	if !sr.on() {
		return false, false
	}
	// spared covers the partner's Bearer.
	a, err := netip.ParseAddr(ip)
	if err != nil || h.spared(r, a) || h.noBan(a) || !h.rhythmStore().marked(h.Name, a, h.now()) {
		return false, false
	}
	return true, sr.Mode == "enforce"
}

func (h *Handler) rhythmStore() *rhythmStore {
	if h.rhythms != nil {
		return h.rhythms
	}
	return sharedRhythms
}

// sharedRhythms are the times and marks of every handler the process provisions: a reload's handler
// of a group finds the marks the one it replaced made.
var sharedRhythms = newRhythmStore()

// rhythm is an address's files: how many were timed, the last one's time and the least gap between two
// in a row, until when the entry stands, and whether it is a mark.
type rhythm struct {
	n      int
	last   time.Time
	least  time.Duration
	until  time.Time
	serial bool
}

// rhythmStore is the rhythms by group and address, an IPv6 address by its /64.
type rhythmStore struct {
	mu    sync.Mutex
	of    map[banKey]*rhythm
	max   int
	swept time.Time
	full  bool
}

func newRhythmStore() *rhythmStore { return &rhythmStore{of: map[banKey]*rhythm{}, max: maxRhythms} }

// saw times a file of a in group at now, and says whether the store went full on it. An entry past its
// until begins anew; one that has its files timed is left as it is.
func (s *rhythmStore) saw(group string, a netip.Addr, now time.Time, files int, minGap, window time.Duration) (firstFull bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := pageKey(group, a)
	e := s.of[k]
	if e != nil && !now.Before(e.until) {
		e = nil
	}
	if e == nil {
		if s.noRoom(k, now) {
			firstFull = !s.full
			s.full = true
			return firstFull
		}
		s.full = false
		s.of[k] = &rhythm{n: 1, last: now, until: now.Add(window)}
		return false
	}
	if e.n >= files {
		return false
	}
	// Requests timed outside the lock may come in a little out of order.
	gap := now.Sub(e.last)
	if gap < 0 {
		gap = -gap
	}
	if e.n == 1 || gap < e.least {
		e.least = gap
	}
	e.n++
	e.last = now
	if e.n == files && e.least > minGap {
		e.serial, e.until = true, now.Add(window)
	}
	return false
}

// marked says whether a is marked serial in group at now.
func (s *rhythmStore) marked(group string, a netip.Addr, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.of[pageKey(group, a)]
	return e != nil && e.serial && now.Before(e.until)
}

// noRoom says whether the store is full for k, a new key: swept of the entries past their until at
// most once a pageSweepEvery, still full.
func (s *rhythmStore) noRoom(k banKey, now time.Time) bool {
	if _, ok := s.of[k]; ok || len(s.of) < s.max {
		return false
	}
	if now.Sub(s.swept) >= pageSweepEvery {
		s.swept = now
		for key, e := range s.of {
			if !now.Before(e.until) {
				delete(s.of, key)
			}
		}
	}
	return len(s.of) >= s.max
}
