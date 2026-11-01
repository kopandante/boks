package gate

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rhythming is a group in enforce with static_rhythm in mode — /_next/, six files, 300 ms, a day — a
// store of its own, the clock at *now.
func rhythming(t *testing.T, now *time.Time, mode string) *Handler {
	t.Helper()
	h := &Handler{StaticRhythm: &StaticRhythm{Mode: mode, Prefix: "/_next/", Files: 6, MinGap: 300 * 1e6, Window: caddyDay},
		rhythms: newRhythmStore(), Checks: &Checks{ExemptRanges: []string{"139.100.226.95"}}}
	h = enforcing(t, h, *now)
	h.now = func() time.Time { return *now }
	return h
}

// files fetches n files of /_next/ from c through h, gap apart, the clock moving.
func files(t *testing.T, h *Handler, now *time.Time, c client, n int, gap time.Duration) {
	t.Helper()
	for i := range n {
		if i > 0 {
			*now = now.Add(gap)
		}
		if code := serve(t, h, c.request(h, "GET", "/_next/static/chunks/"+strconv.Itoa(i)+".js")).Code; code != 200 {
			t.Fatalf("file %d: %d", i, code)
		}
	}
}

// apiOf is h's answer to an API request of c, with the access log's fields.
func apiOf(t *testing.T, h *Handler, c client, target string) (int, map[string]any) {
	t.Helper()
	r, extra := withLog(c.request(h, "GET", target))
	return serve(t, h, r).Code, fields(extra)
}

// The scraper's six files 0.6 s apart mark its address: its API is refused for the window, and no
// longer after; a browser's, at once, is not marked.
func TestStaticRhythm(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "enforce")
	bot := browserClient(stormUA, "203.0.113.20")
	files(t, h, &now, bot, 6, 600*time.Millisecond)
	if code, f := apiOf(t, h, bot, "/api/auctions/heydealer/cars"); code != 403 || f["gate_reason"] != "serial_static" || f["gate_behavior"] != "serial_static" {
		t.Errorf("the scraper: %d %v", code, f)
	}
	if code, f := apiOf(t, h, bot, tokenPath); code != 403 || f["gate_reason"] != "serial_static" {
		t.Errorf("the scraper's token: %d %v", code, f)
	}
	now = now.Add(24*time.Hour - time.Second)
	if code, _ := apiOf(t, h, bot, "/api/x"); code != 403 {
		t.Errorf("within the window: %d", code)
	}
	now = now.Add(2 * time.Second)
	if code, f := apiOf(t, h, bot, "/api/x"); code != 200 || f["gate_behavior"] != nil {
		t.Errorf("past the window: %d %v", code, f)
	}
	browser := browserClient(chromeUA, "203.0.113.21")
	files(t, h, &now, browser, 12, 5*time.Millisecond)
	if code, f := apiOf(t, h, browser, "/api/x"); code != 200 || f["gate_behavior"] != nil {
		t.Errorf("a browser: %d %v", code, f)
	}
}

// The least gap decides: one pair of files at once among slow ones is a browser's; the gap of min_gap
// itself is not past it; five files are not six.
func TestStaticRhythmThreshold(t *testing.T) {
	cases := []struct {
		name   string
		gaps   []time.Duration
		serial bool
	}{
		{"all past min_gap", []time.Duration{301, 900, 400, 2000, 350}, true},
		{"one at min_gap", []time.Duration{900, 900, 300, 900, 900}, false},
		{"one just past", []time.Duration{900, 900, 301, 900, 900}, true},
		{"one pair at once", []time.Duration{900, 900, 900, 900, 10}, false},
		{"Bing's", []time.Duration{120, 190, 150, 170, 160}, false},
		{"five files", []time.Duration{900, 900, 900, 900}, false},
	}
	for _, c := range cases {
		now := time.Now()
		h := rhythming(t, &now, "enforce")
		cl := browserClient(stormUA, "203.0.113.30")
		files(t, h, &now, cl, 1, 0)
		for i, g := range c.gaps {
			now = now.Add(g * time.Millisecond)
			serve(t, h, cl.request(h, "GET", "/_next/static/media/"+strconv.Itoa(i)+".woff2"))
		}
		if code, _ := apiOf(t, h, cl, "/api/x"); (code == 403) != c.serial {
			t.Errorf("%s: %d", c.name, code)
		}
	}
}

// The first files are what is timed: files after them change nothing — a mark stands, a browser's
// verdict too — until the entry's window is over, when the address is timed again.
func TestStaticRhythmFirstFiles(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "enforce")
	c := browserClient(chromeUA, "203.0.113.31")
	files(t, h, &now, c, 6, 5*time.Millisecond)
	files(t, h, &now, c, 6, time.Second)
	if code, _ := apiOf(t, h, c, "/api/x"); code != 200 {
		t.Errorf("slow files after a browser's six: %d", code)
	}
	now = now.Add(24 * time.Hour)
	files(t, h, &now, c, 6, time.Second)
	if code, _ := apiOf(t, h, c, "/api/x"); code != 403 {
		t.Errorf("timed again past the window: %d", code)
	}
	files(t, h, &now, c, 6, time.Millisecond)
	if code, _ := apiOf(t, h, c, "/api/x"); code != 403 {
		t.Errorf("fast files after the mark: %d", code)
	}
}

// What is not a file: a page, an asset outside the prefix, the API, a POST under the prefix.
func TestStaticRhythmWhatIsAFile(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "enforce")
	c := browserClient(stormUA, "203.0.113.32")
	for i, target := range []string{"/", "/favicon.ico", "/api/encar/pics/1.jpg", "/en/car", "/robots.txt", "/x.png"} {
		if i > 0 {
			now = now.Add(time.Second)
		}
		serve(t, h, c.request(h, "GET", target))
	}
	for range 5 {
		now = now.Add(time.Second)
		serve(t, h, c.request(h, "POST", "/_next/static/a.js"))
	}
	if code, _ := apiOf(t, h, c, "/api/x"); code != 200 {
		t.Errorf("no files: %d", code)
	}
	if len(h.rhythms.of) != 0 {
		t.Errorf("%d timed", len(h.rhythms.of))
	}
}

// In log the mark is written, gate_behavior serial_static, and the request goes on; beside page_first
// both are written; a group whose page_first refuses keeps no_page as the reason.
func TestStaticRhythmLogAndPageFirst(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "log")
	c := browserClient(stormUA, "203.0.113.33")
	files(t, h, &now, c, 6, time.Second)
	if code, f := apiOf(t, h, c, "/api/x"); code != 200 || f["gate_behavior"] != "serial_static" || f["gate_reason"] != "token" {
		t.Errorf("log: %d %v", code, f)
	}
	h.PageFirst = &PageFirst{Mode: "log", Window: sixHours}
	h.pages = newPageStore()
	h.pages.begin(h.Name, now.Add(-time.Hour))
	if code, f := apiOf(t, h, c, "/api/x"); code != 200 || f["gate_behavior"] != "no_page,serial_static" {
		t.Errorf("both in log: %d %v", code, f)
	}
	h.PageFirst.Mode = "enforce"
	h.StaticRhythm.Mode = "enforce"
	if code, f := apiOf(t, h, browserClient(stormUA, "203.0.113.33"), "/api/x"); code != 403 || f["gate_reason"] != "no_page" || f["gate_behavior"] != "no_page,serial_static" {
		t.Errorf("both in enforce: %d %v", code, f)
	}
	// The page opens page_first's way; static_rhythm's stays shut.
	serve(t, h, c.request(h, "GET", "/en/car"))
	if code, f := apiOf(t, h, c, "/api/x"); code != 403 || f["gate_reason"] != "serial_static" || f["gate_behavior"] != "serial_static" {
		t.Errorf("after the page: %d %v", code, f)
	}
}

// Google, Yandex, the checks' exempt addresses are neither timed nor asked; nor are the partner's
// Bearer, the health probe and the exemptions but the token's issue.
func TestStaticRhythmSpared(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "enforce")
	for _, c := range []client{
		{ua: googleUA, fpHeader: true, tokenFP: true, ip: "66.249.66.1"},
		{ua: yandexBotUA, fpHeader: true, tokenFP: true, ip: "213.180.203.222"},
		browserClient(stormUA, "139.100.226.95"),
	} {
		files(t, h, &now, c, 6, time.Second)
		if code, _ := apiOf(t, h, c, "/api/x"); code != 200 {
			t.Errorf("%s from %s: %d", c.ua[:30], c.ip, code)
		}
	}
	if len(h.rhythms.of) != 0 {
		t.Errorf("the spared timed: %d", len(h.rhythms.of))
	}
	// The exemptions and the probe of a marked address.
	files(t, h, &now, browserClient(stormUA, visitor), 6, time.Second)
	for _, target := range []string{"/api/health", "/api/env-check", "/api/admin/users"} {
		if code := serve(t, h, withVars(request("GET", target, visitor), visitor, false)).Code; code != 200 {
			t.Errorf("%s of a marked address: %d", target, code)
		}
	}
	b := &Handler{StaticRhythm: &StaticRhythm{Mode: "enforce", Window: caddyDay}, rhythms: newRhythmStore(),
		Bearer: &Bearer{Paths: []string{"^/api/encar/"}, Methods: []string{"GET"}, Digests: []string{digestOf("partner-token-of-thirty-two-chars")}}}
	b = enforcing(t, b, now)
	b.now = func() time.Time { return now }
	files(t, b, &now, browserClient(stormUA, visitor), 6, time.Second)
	r := withVars(request("GET", "/api/encar/catalog", visitor), visitor, false)
	r.Header.Set("Authorization", "Bearer partner-token-of-thirty-two-chars")
	if code := serve(t, b, r).Code; code != 200 {
		t.Errorf("the partner's Bearer from a marked address: %d", code)
	}
	if code, _ := apiOf(t, b, browserClient(stormUA, visitor), "/api/encar/catalog"); code != 403 {
		t.Errorf("the same address without the Bearer: %d", code)
	}
}

// An IPv6 address counts by its /64: the files of its addresses are one entry, and the mark shuts the
// /64's API, no other's.
func TestStaticRhythmIPv6By64(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "enforce")
	for i := range 6 {
		if i > 0 {
			now = now.Add(time.Second)
		}
		c := browserClient(stormUA, "2001:db8:1:2::"+strconv.Itoa(i+1))
		serve(t, h, c.request(h, "GET", "/_next/static/"+strconv.Itoa(i)+".js"))
	}
	if len(h.rhythms.of) != 1 {
		t.Errorf("one /64 kept as %d entries", len(h.rhythms.of))
	}
	if code, _ := apiOf(t, h, browserClient(stormUA, "2001:db8:1:2:aaaa::1"), "/api/x"); code != 403 {
		t.Errorf("the /64: %d", code)
	}
	if code, _ := apiOf(t, h, browserClient(stormUA, "2001:db8:1:3::1"), "/api/x"); code != 200 {
		t.Errorf("another /64: %d", code)
	}
}

// A mark of one group shuts nothing of another's.
func TestStaticRhythmByGroup(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "enforce")
	g2 := &Handler{Name: "other", StaticRhythm: h.StaticRhythm, rhythms: h.rhythms}
	g2 = enforcing(t, g2, now)
	c := browserClient(stormUA, "203.0.113.34")
	files(t, h, &now, c, 6, time.Second)
	if code, _ := apiOf(t, g2, c, "/api/x"); code != 200 {
		t.Errorf("another group: %d", code)
	}
}

// A full store fails open: an address it has no room for is not timed, so its slow files mark nothing,
// and the overflow is written once; entries past their window are swept to make room.
func TestStaticRhythmFullFailsOpen(t *testing.T) {
	now := time.Now()
	h := rhythming(t, &now, "enforce")
	h.rhythms.max = 1
	files(t, h, &now, browserClient(chromeUA, "203.0.113.40"), 1, 0)
	c := browserClient(stormUA, "203.0.113.41")
	files(t, h, &now, c, 6, time.Second)
	if code, f := apiOf(t, h, c, "/api/x"); code != 200 || f["gate_behavior"] != nil {
		t.Errorf("no room: %d %v", code, f)
	}
	if !h.rhythms.full {
		t.Error("the overflow is not noted")
	}
	now = now.Add(24*time.Hour + time.Minute)
	files(t, h, &now, c, 6, time.Second)
	if code, _ := apiOf(t, h, c, "/api/x"); code != 403 {
		t.Errorf("room after the sweep: %d", code)
	}
	if h.rhythms.full {
		t.Error("the overflow outlives the room")
	}
}

// The overflow goes into the log once an episode, and a full store sweeps at most once a minute.
func TestRhythmStoreOverflow(t *testing.T) {
	t0 := time.Now()
	s := newRhythmStore()
	s.max = 1
	a := func(i int) netip.Addr { return netip.MustParseAddr("203.0.113." + strconv.Itoa(i)) }
	s.saw("g", a(1), t0, 6, time.Millisecond, time.Hour)
	if !s.saw("g", a(2), t0, 6, time.Millisecond, time.Hour) {
		t.Error("the overflow's first is not reported")
	}
	if s.saw("g", a(3), t0, 6, time.Millisecond, time.Hour) {
		t.Error("the overflow reported twice")
	}
	// Full, nothing past the window: the sweep finds nothing.
	s.saw("g", a(4), t0.Add(59*time.Minute+50*time.Second), 6, time.Millisecond, time.Hour)
	// Past the window now, but swept 20 seconds ago: no sweep, no room.
	s.saw("g", a(5), t0.Add(time.Hour+10*time.Second), 6, time.Millisecond, time.Hour)
	if _, ok := s.of[rhythmKey("g", a(5))]; ok || len(s.of) != 1 {
		t.Error("swept within the minute")
	}
	s.saw("g", a(6), t0.Add(time.Hour+50*time.Second), 6, time.Millisecond, time.Hour)
	if _, ok := s.of[rhythmKey("g", a(6))]; !ok || len(s.of) != 1 {
		t.Errorf("not swept past the minute: %d", len(s.of))
	}
}

// The marks outlive a reload — a new handler of the group finds them in sharedRhythms — and are lost
// with the process, which a new store stands for.
func TestStaticRhythmSurvivesReload(t *testing.T) {
	now := time.Now()
	name := "reload-" + strconv.FormatInt(now.UnixNano(), 36)
	mk := func() *Handler {
		h := &Handler{Name: name, StaticRhythm: &StaticRhythm{Mode: "enforce", Window: caddyDay}}
		h = enforcing(t, h, now)
		h.now = func() time.Time { return now }
		return h
	}
	c := browserClient(stormUA, "203.0.113.42")
	files(t, mk(), &now, c, 6, time.Second)
	if code, _ := apiOf(t, mk(), c, "/api/x"); code != 403 {
		t.Errorf("after a reload: %d", code)
	}
	restarted := mk()
	restarted.rhythms = newRhythmStore()
	if code, _ := apiOf(t, restarted, c, "/api/x"); code != 200 {
		t.Errorf("after a restart: %d", code)
	}
}

func TestStaticRhythmValidate(t *testing.T) {
	day := StaticRhythm{Mode: "log", Window: caddyDay}
	with := func(f func(*StaticRhythm)) StaticRhythm { s := day; f(&s); return s }
	for _, c := range []struct {
		name string
		sr   StaticRhythm
		mode string
		want string
	}{
		{"a bad mode", with(func(s *StaticRhythm) { s.Mode = "ban" }), "enforce", "mode"},
		{"enforce in a group in log", with(func(s *StaticRhythm) { s.Mode = "enforce" }), "log", "group's mode"},
		{"no window", with(func(s *StaticRhythm) { s.Window = 0 }), "enforce", "window"},
		{"a window of eight days", with(func(s *StaticRhythm) { s.Window = 8 * caddyDay }), "enforce", "window"},
		{"a prefix under /api/", with(func(s *StaticRhythm) { s.Prefix = "/api/encar/pics/" }), "enforce", "prefix"},
		{"the prefix /api", with(func(s *StaticRhythm) { s.Prefix = "/api" }), "enforce", "prefix"},
		{"the prefix /", with(func(s *StaticRhythm) { s.Prefix = "/" }), "enforce", "prefix"},
		{"a prefix without a slash", with(func(s *StaticRhythm) { s.Prefix = "_next/" }), "enforce", "prefix"},
		{"two files", with(func(s *StaticRhythm) { s.Files = 2 }), "enforce", "files"},
		{"a gap of a millisecond", with(func(s *StaticRhythm) { s.MinGap = 1e6 }), "enforce", "min_gap"},
		{"a gap below zero", with(func(s *StaticRhythm) { s.MinGap = -1 }), "enforce", "min_gap"},
		{"a gap of a minute", with(func(s *StaticRhythm) { s.MinGap = 60 * 1e9 }), "enforce", "min_gap"},
	} {
		h := Handler{Name: "site", Mode: c.mode, Secrets: []string{secret}, StaticRhythm: &c.sr}
		if err := h.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, sr := range []StaticRhythm{
		{Mode: "off"},
		day,
		{Mode: "enforce", Prefix: "/static/", Files: 3, MinGap: 10 * 1e6, Window: 10 * 60 * 1e9},
	} {
		h := Handler{Name: "site", Mode: "enforce", Secrets: []string{secret}, StaticRhythm: &sr}
		if err := h.Validate(); err != nil {
			t.Errorf("%+v: %v", sr, err)
		}
	}
}

// The handler takes both fields as a policy writes them: durations as strings, a signature's path.
func TestStaticSignalsJSON(t *testing.T) {
	var h Handler
	err := json.Unmarshal([]byte(`{"static_rhythm":{"mode":"log","prefix":"/_next/","files":6,"min_gap":"300ms","window":"24h"},
		"signatures":[{"name":"static-as-document","mode":"log","path":"^/_next/","headers":[{"name":"sec-fetch-dest","pattern":"^document$"}]}]}`), &h)
	if err != nil {
		t.Fatal(err)
	}
	sr := h.StaticRhythm
	if sr.Files != 6 || sr.minGap() != 300*time.Millisecond || time.Duration(sr.Window) != 24*time.Hour || sr.prefix() != "/_next/" {
		t.Errorf("static_rhythm: %+v", *sr)
	}
	if h.Signatures[0].Path != "^/_next/" {
		t.Errorf("signature: %+v", h.Signatures[0])
	}
}
