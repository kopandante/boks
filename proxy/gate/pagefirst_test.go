package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const sixHours = 6 * 60 * 60 * 1e9

// pageFirsting is a group in enforce with page_first in mode, a window of six hours, a store of its own
// begun an hour before *now, the clock at *now.
func pageFirsting(t *testing.T, now *time.Time, mode string) *Handler {
	t.Helper()
	h := &Handler{PageFirst: &PageFirst{Mode: mode, Window: sixHours}, pages: newPageStore(now.Add(-time.Hour)),
		Checks: &Checks{ExemptRanges: []string{"139.100.226.95"}}}
	h = enforcing(t, h, *now)
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
	now = now.Add(6*time.Hour - time.Second)
	if code, _ := api(); code != 200 {
		t.Errorf("within the window: %d", code)
	}
	now = now.Add(2 * time.Second)
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

// Within warmup after the process began nothing is refused, only written; in log never.
func TestPageFirstWarmupAndLog(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	h.pages = newPageStore(now.Add(-29 * time.Minute))
	r, extra := withLog(browserClient(chromeUA, "203.0.113.50").request(h, "GET", "/api/x"))
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_behavior"] != "no_page" {
		t.Errorf("warmup: %d %v", w.Code, fields(extra))
	}
	now = now.Add(2 * time.Minute)
	if code := serve(t, h, browserClient(chromeUA, "203.0.113.50").request(h, "GET", "/api/x")).Code; code != 403 {
		t.Errorf("past warmup: %d", code)
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
	b := &Handler{PageFirst: &PageFirst{Mode: "enforce", Window: sixHours}, pages: newPageStore(now.Add(-time.Hour)),
		Bearer: &Bearer{Paths: []string{"^/api/encar/"}, Methods: []string{"GET"}, Digests: []string{digestOf("partner-token-of-thirty-two-chars")}}}
	b = enforcing(t, b, now)
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
	g2 := pageFirsting(t, &now, "enforce")
	g2.Name, g2.pages = "other", h.pages
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
}

func TestPageStoreFull(t *testing.T) {
	now := time.Now()
	s := newPageStore(now)
	s.max = 1
	a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	s.saw("g", a, now)
	s.seen("g", a, now, time.Hour)
	s.saw("g", b, now)
	if s.seen("g", b, now, time.Hour) {
		t.Error("kept past the bound")
	}
	s.saw("g", b, now.Add(2*time.Hour))
	if !s.seen("g", b, now.Add(2*time.Hour), time.Hour) {
		t.Error("a page past the window was not swept for a new one")
	}
}

func digestOf(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
