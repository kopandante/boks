package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

const sixHours = 6 * 60 * 60 * 1e9

// pageFirsting is a group in enforce with page_first in mode, a window of six hours, a store of its own,
// provisioned an hour before *now — past the warmup — the clock at *now.
func pageFirsting(t *testing.T, now *time.Time, mode string) *Handler {
	t.Helper()
	return pageFirstingAt(t, now, mode, "site", newPageStore(), now.Add(-time.Hour))
}

// pageFirstingAt is pageFirsting of group name on pages, provisioned at began.
func pageFirstingAt(t *testing.T, now *time.Time, mode, name string, pages *pageStore, began time.Time) *Handler {
	t.Helper()
	h := &Handler{Name: name, PageFirst: &PageFirst{Mode: mode, Window: sixHours}, pages: pages,
		Checks: &Checks{ExemptRanges: []string{"139.100.226.95"}}}
	h = enforcing(t, h, began)
	h.now = func() time.Time { return *now }
	return h
}

func TestPageFirst(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	ip := "203.0.113.40"
	api := func() (int, map[string]any) {
		r, extra := withLog(browserClient(chromeUA, ip).request(h, "GET", "/api/auctions/heydealer/cars"))
		return serve(t, h, r).Code, fields(extra)
	}
	if code, f := api(); code != 403 || f["gate_reason"] != "no_page" || f["gate_behavior"] != "no_page" {
		t.Fatalf("no page: %d %v", code, f)
	}
	if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/en/heydealer")).Code; code != 200 {
		t.Fatalf("the page: %d", code)
	}
	if code, f := api(); code != 200 || f["gate_behavior"] != nil {
		t.Errorf("after the page: %d %v", code, f)
	}
	// The API requests it lets through renew the window: a catalog's filters ask for no page.
	now = now.Add(6*time.Hour - time.Second)
	if code, _ := api(); code != 200 {
		t.Errorf("within the window: %d", code)
	}
	now = now.Add(6*time.Hour - time.Second)
	if code, _ := api(); code != 200 {
		t.Errorf("within the window the last API request renewed: %d", code)
	}
	now = now.Add(6*time.Hour + time.Second)
	if code, _ := api(); code != 403 {
		t.Errorf("past the window: %d", code)
	}
	// Next.js's RSC fetch of the next page is a page too: it renews the window.
	if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/en/heydealer/car/abc?_rsc=1")).Code; code != 200 {
		t.Fatalf("the RSC fetch: %d", code)
	}
	if code, _ := api(); code != 200 {
		t.Errorf("after the RSC fetch: %d", code)
	}
	if code := serve(t, h, browserClient(chromeUA, "203.0.113.41").request(h, "GET", "/api/auth/token")).Code; code != 403 {
		t.Errorf("the token's issue without a page: %d", code)
	}
}

// Not pages: an asset, Next.js's files, a POST, the API itself. None of them opens the window.
func TestPageFirstWhatIsAPage(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	for i, target := range []string{"/_next/static/chunks/a.js", "/favicon.ico", "/api/encar/pics/1.jpg"} {
		ip := "203.0.113." + string(rune('1'+i)) + "0"
		serve(t, h, browserClient(chromeUA, ip).request(h, "GET", target))
		if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")).Code; code != 403 {
			t.Errorf("after %s: %d", target, code)
		}
	}
	ip := "203.0.113.90"
	serve(t, h, browserClient(chromeUA, ip).request(h, "POST", "/en/form"))
	if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")).Code; code != 403 {
		t.Errorf("after a POST: %d", code)
	}
}

// Within warmup after page_first went on nothing is refused, only written, and an address without a
// page is kept as if it had one: a visit the process did not see begin goes on. In log never refused.
func TestPageFirstWarmupAndLog(t *testing.T) {
	now := time.Now()
	h := pageFirstingAt(t, &now, "enforce", "site", newPageStore(), now.Add(-29*time.Minute))
	r, extra := withLog(browserClient(chromeUA, "203.0.113.50").request(h, "GET", "/api/x"))
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_behavior"] != "no_page" {
		t.Errorf("warmup: %d %v", w.Code, fields(extra))
	}
	now = now.Add(2 * time.Minute)
	if code := serve(t, h, browserClient(chromeUA, "203.0.114.52").request(h, "GET", "/api/x")).Code; code != 403 {
		t.Errorf("a new address past warmup: %d", code)
	}
	r, extra = withLog(browserClient(chromeUA, "203.0.113.50").request(h, "GET", "/api/x"))
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_behavior"] != nil {
		t.Errorf("the visit warmup kept, past it: %d %v", w.Code, fields(extra))
	}
	h = pageFirsting(t, &now, "log")
	r, extra = withLog(browserClient(chromeUA, "203.0.113.51").request(h, "GET", "/api/x"))
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_behavior"] != "no_page" || fields(extra)["gate_reason"] != "token" {
		t.Errorf("log: %d %v", w.Code, fields(extra))
	}
}

func TestPageFirstSpared(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	for _, c := range []client{
		{ua: googleUA, fpHeader: true, tokenFP: true, ip: "66.249.66.1"},
		{ua: yandexBotUA, fpHeader: true, tokenFP: true, ip: "213.180.203.222"},
		browserClient(chromeUA, "139.100.226.95"),
	} {
		if code := serve(t, h, c.request(h, "GET", "/api/x")).Code; code != 200 {
			t.Errorf("%s from %s: %d", c.ua[:30], c.ip, code)
		}
	}
	if code := serve(t, h, withVars(request("GET", "/api/health", visitor), visitor, false)).Code; code != 200 {
		t.Errorf("health: %d", code)
	}
	b := &Handler{PageFirst: &PageFirst{Mode: "enforce", Window: sixHours}, pages: newPageStore(),
		Bearer: &Bearer{Paths: []string{"^/api/encar/"}, Methods: []string{"GET"}, Digests: []string{digestOf("partner-token-of-thirty-two-chars")}}}
	b = enforcing(t, b, now.Add(-time.Hour))
	b.now = func() time.Time { return now }
	r := withVars(request("GET", "/api/encar/catalog", visitor), visitor, false)
	r.Header.Set("Authorization", "Bearer partner-token-of-thirty-two-chars")
	if code := serve(t, b, r).Code; code != 200 {
		t.Errorf("the partner's Bearer: %d", code)
	}
}

// A page of one group opens nothing of another's.
func TestPageFirstByGroup(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	g2 := pageFirstingAt(t, &now, "enforce", "other", h.pages, now.Add(-time.Hour))
	ip := "203.0.113.60"
	serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/"))
	if code := serve(t, g2, browserClient(chromeUA, ip).request(g2, "GET", "/api/x")).Code; code != 403 {
		t.Errorf("another group: %d", code)
	}
}

func TestPageFirstValidate(t *testing.T) {
	cases := []struct {
		name string
		pf   PageFirst
		mode string
		want string
	}{
		{"a bad mode", PageFirst{Mode: "ban", Window: sixHours}, "enforce", "mode"},
		{"enforce in a group in log", PageFirst{Mode: "enforce", Window: sixHours}, "log", "group's mode"},
		{"no window", PageFirst{Mode: "log"}, "enforce", "window"},
		{"a window of a minute", PageFirst{Mode: "log", Window: 60 * 1e9}, "enforce", "window"},
		{"a warmup past the window", PageFirst{Mode: "log", Window: sixHours, Warmup: 2 * sixHours}, "enforce", "warmup"},
		{"the default warmup past the window", PageFirst{Mode: "log", Window: 20 * 60 * 1e9}, "enforce", "warmup"},
		{"a warmup below zero", PageFirst{Mode: "log", Window: sixHours, Warmup: -1}, "enforce", "warmup"},
	}
	for _, c := range cases {
		pf := c.pf
		h := Handler{Name: "site", Mode: c.mode, Secrets: []string{secret}, PageFirst: &pf}
		if err := h.Provision(ctxForTest(t)); err != nil {
			t.Fatal(err)
		}
		if err := h.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// Turned off by its mode alone, the rule asks nothing else.
	h := Handler{Name: "site", Mode: "enforce", Secrets: []string{secret}, PageFirst: &PageFirst{Mode: "off"}}
	if err := h.Provision(ctxForTest(t)); err != nil {
		t.Fatal(err)
	}
	if err := h.Validate(); err != nil {
		t.Errorf("off without a window: %v", err)
	}
}

// A full store fails open: an address it has no room for passes, and the overflow is told once while it
// lasts; a page past the window is swept for a new address.
func TestPageStoreFull(t *testing.T) {
	now := time.Now()
	s := newPageStore()
	s.begin("g", now.Add(-time.Hour))
	s.max = 1
	a, b, c := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.114.2"), netip.MustParseAddr("203.0.115.3")
	if s.saw("g", a, now) {
		t.Error("full with room")
	}
	if ans := s.ask("g", a, now, time.Hour, time.Minute); !ans.seen || ans.unkept {
		t.Errorf("a: %+v", ans)
	}
	if !s.saw("g", b, now) {
		t.Error("the overflow's first page not told")
	}
	if ans := s.ask("g", b, now, time.Hour, time.Minute); !ans.unkept || ans.seen || ans.firstFull {
		t.Errorf("b, no room: %+v", ans)
	}
	if ans := s.ask("g", c, now, time.Hour, time.Minute); !ans.unkept || ans.firstFull {
		t.Errorf("c, no room, told once: %+v", ans)
	}
	if len(s.last) != 1 {
		t.Errorf("kept %d past the bound", len(s.last))
	}
	later := now.Add(2 * time.Hour)
	if s.saw("g", b, later) {
		t.Error("swept and kept, yet told full")
	}
	if ans := s.ask("g", b, later, time.Hour, time.Minute); !ans.seen {
		t.Errorf("a page past the window was not swept for a new one: %+v", ans)
	}
	// Kept again, the next overflow is told anew.
	if !s.saw("g", c, later) {
		t.Error("a new overflow not told")
	}
}

// In enforce, an address the full store has no room for passes its API: the store full is no refusal.
func TestPageFirstFullFailsOpen(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	h.pages.max = 1
	serve(t, h, browserClient(chromeUA, "203.0.113.80").request(h, "GET", "/"))
	r, extra := withLog(browserClient(chromeUA, "203.0.114.81").request(h, "GET", "/api/x"))
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_behavior"] != nil {
		t.Errorf("no room, no page: %d %v", w.Code, fields(extra))
	}
	// With room, the address without a page is refused again.
	h.pages.max = 2
	if code := serve(t, h, browserClient(chromeUA, "203.0.114.81").request(h, "GET", "/api/x")).Code; code != 403 {
		t.Errorf("room, no page: %d", code)
	}
}

// A full store looks for entries past the window at most once a minute, not on every new address.
func TestPageStoreSweepsOnceAMinute(t *testing.T) {
	t0 := time.Now()
	s := newPageStore()
	s.begin("g", t0.Add(-time.Hour))
	s.max = 2
	s.ask("g", netip.MustParseAddr("203.0.109.9"), t0, time.Hour, time.Minute)
	s.saw("g", netip.MustParseAddr("203.0.101.1"), t0)
	s.saw("g", netip.MustParseAddr("203.0.102.1"), t0)
	// Full, nothing past the window: the sweep finds nothing.
	s.saw("g", netip.MustParseAddr("203.0.103.1"), t0.Add(59*time.Minute+50*time.Second))
	// Both past the window now, but swept 20 seconds ago: no sweep, no room.
	d := netip.MustParseAddr("203.0.104.1")
	s.saw("g", d, t0.Add(time.Hour+10*time.Second))
	if _, ok := s.last[pageKey("g", d)]; ok || len(s.last) != 2 {
		t.Errorf("swept within the minute: %d kept", len(s.last))
	}
	// A minute after the last sweep: swept, kept.
	e := netip.MustParseAddr("203.0.105.1")
	s.saw("g", e, t0.Add(time.Hour+50*time.Second))
	if _, ok := s.last[pageKey("g", e)]; !ok || len(s.last) != 1 {
		t.Errorf("not swept past the minute: %d kept", len(s.last))
	}
}

// An IPv6 address counts by its /64: a page from one address opens the API to the /64 and to no other,
// and the /64's addresses are one entry.
func TestPageFirstIPv6By64(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	serve(t, h, browserClient(chromeUA, "2001:db8:1:2::1").request(h, "GET", "/"))
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2:aaaa:bbbb:cccc:dddd"} {
		if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")).Code; code != 200 {
			t.Errorf("%s, the /64's page: %d", ip, code)
		}
	}
	if code := serve(t, h, browserClient(chromeUA, "2001:db8:1:3::1").request(h, "GET", "/api/x")).Code; code != 403 {
		t.Errorf("another /64: %d", code)
	}
	for i := range 50 {
		ip := "2001:db8:1:2::" + strconv.Itoa(i+10)
		serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/"))
	}
	if len(h.pages.last) != 1 {
		t.Errorf("one /64 kept as %d entries", len(h.pages.last))
	}
}

// The exemptions — servers' calls, which ask for no page — are not asked; the token's issue is.
func TestPageFirstExemptions(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	h.Exempt = []Exempt{{Exact: "/api/china/sync", Methods: []string{"POST"}}}
	h = enforcing(t, h, now.Add(-time.Hour))
	h.now = func() time.Time { return now }
	for _, c := range []struct{ method, target string }{
		{"GET", "/api/env-check"}, {"GET", "/api/admin/users"}, {"POST", "/api/china/sync"},
	} {
		r, extra := withLog(request(c.method, c.target, "203.0.113.90"))
		r = withVars(r, "203.0.113.90", false)
		if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_reason"] != "exempt" || fields(extra)["gate_behavior"] != nil {
			t.Errorf("%s %s without a page: %d %v", c.method, c.target, w.Code, fields(extra))
		}
	}
	r, extra := withLog(browserClient(chromeUA, "203.0.113.91").request(h, "POST", tokenPath))
	if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "no_page" {
		t.Errorf("the token's issue without a page: %d %v", w.Code, fields(extra))
	}
}

// The pages and the warmup outlive a reload: the handler of the same group provisioned anew, before the
// old one is cleaned up, finds the pages in sharedPages and the group past its warmup.
func TestPageFirstSurvivesReload(t *testing.T) {
	now := time.Now()
	name := "reload-" + t.Name()
	mk := func() *Handler {
		h := &Handler{Name: name, PageFirst: &PageFirst{Mode: "enforce", Window: sixHours}}
		h = enforcing(t, h, now)
		h.now = func() time.Time { return now }
		return h
	}
	h := mk()
	t.Cleanup(func() { sharedPages.end(name); sharedPages.end(name) })
	now = now.Add(time.Hour)
	serve(t, h, browserClient(chromeUA, "198.51.100.80").request(h, "GET", "/"))
	h2 := mk()
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if code := serve(t, h2, browserClient(chromeUA, "198.51.100.80").request(h2, "GET", "/api/x")).Code; code != 200 {
		t.Errorf("the page after the reload: %d", code)
	}
	if code := serve(t, h2, browserClient(chromeUA, "198.51.101.81").request(h2, "GET", "/api/x")).Code; code != 403 {
		t.Errorf("no page after the reload, past the warmup: %d", code)
	}
}

// A reload that turns page_first on for a group — none of its handlers had it — begins the warmup: the
// visits going on had their pages before anything kept them.
func TestPageFirstTurnedOnByReload(t *testing.T) {
	now := time.Now()
	pages := newPageStore()
	old := pageFirstingAt(t, &now, "off", "site", pages, now.Add(-24*time.Hour))
	now = now.Add(time.Minute)
	h := pageFirstingAt(t, &now, "enforce", "site", pages, now)
	if err := old.Cleanup(); err != nil {
		t.Fatal(err)
	}
	ip := "203.0.113.70"
	if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")).Code; code != 200 {
		t.Errorf("a visit going on, right after the reload: %d", code)
	}
	now = now.Add(time.Hour)
	if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")).Code; code != 200 {
		t.Errorf("the same visit past the warmup: %d", code)
	}
	// Off and on again: the span ends with the last handler that had it on and begins anew.
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	h = pageFirstingAt(t, &now, "enforce", "site", pages, now)
	if code := serve(t, h, browserClient(chromeUA, "203.0.113.71").request(h, "GET", "/api/x")).Code; code != 200 {
		t.Errorf("on again, within the warmup: %d", code)
	}
}

func digestOf(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
