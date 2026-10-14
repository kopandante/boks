package ban

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// clock is a time the test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// len is the number of addresses tracked.
func (s *store) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// counters are the rules a has a count for, with the count: name → count.
func (s *store) counters(a string) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	if e := s.entries[netip.MustParseAddr(a)]; e != nil {
		for _, c := range e.counters {
			out[c.rule] = int(c.count)
		}
	}
	return out
}

// fixture swaps the shared store for one on a hand-moved clock, as the process's would be.
func fixture(t *testing.T) *clock {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 14, 1, 47, 0, 0, time.UTC)}
	prev := shared
	shared = newStore(c.now)
	t.Cleanup(func() { shared = prev })
	return c
}

// provisioned is a handler from its JSON, as Caddy loads it, with its log lines kept.
func provisioned(t *testing.T, config string) (*Handler, *observer.ObservedLogs) {
	t.Helper()
	var h Handler
	if err := json.Unmarshal([]byte(config), &h); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.InfoLevel)
	h.logger = zap.New(core)
	return &h, logs
}

const policy = `{"limit": 300, "window": "1m", "duration": "24h",
	"exempt_paths": ["^/api/[a-z]+/pics", "^/api/auctions/[^/]+/(image|video)"], "exempt_ranges": ["203.0.113.0/24"]}`

var upstream = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

// request is a request from ip as Caddy hands it to a handler: with its client_ip variable set.
func request(ip, path string, header ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://cars.dbauto.kr"+path, nil)
	r.RemoteAddr = "172.18.0.1:40000" // the connection: Caddy decided the client past it
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: ip}))
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	return r
}

func serve(t *testing.T, h *Handler, r *http.Request) int {
	t.Helper()
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, upstream); err != nil {
		t.Fatal(err)
	}
	return w.Code
}

// 300 requests a minute pass; the 301st is refused and starts the ban, logged once with what the
// metric is made of; every request after it is refused without reaching the app or the log.
func TestTheRequestPastTheLimitBans(t *testing.T) {
	c := fixture(t)
	h, logs := provisioned(t, policy)
	for i := 1; i <= 300; i++ {
		if code := serve(t, h, request("217.81.103.213", fmt.Sprintf("/en/encar/%d", i))); code != 200 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code := serve(t, h, request("217.81.103.213", "/api/encar/info/301")); code != 403 {
		t.Fatalf("request 301: want 403, got %d", code)
	}
	c.add(time.Hour)
	for range 5 {
		if code := serve(t, h, request("217.81.103.213", "/")); code != 403 {
			t.Fatalf("want the ban held within its day: %d", code)
		}
	}
	if code := serve(t, h, request("217.81.103.214", "/")); code != 200 {
		t.Errorf("another address: %d", code)
	}
	if logs.Len() != 1 {
		t.Fatalf("want one log line for the ban, got %d: %v", logs.Len(), logs.All())
	}
	e := logs.All()[0]
	f := e.ContextMap()
	if e.Level != zap.WarnLevel || f["ip"] != "217.81.103.213" || f["host"] != "cars.dbauto.kr" || f["rule"] != "default" ||
		f["count"] != int64(301) || f["window"] != "1m0s" || f["until"] != "2026-10-15T01:47:00Z" {
		t.Errorf("log line: %s %v", e.Level, f)
	}
}

// The window is fixed from an address's first request: 300 in it and 300 in the next pass.
func TestTheWindowStartsAgain(t *testing.T) {
	c := fixture(t)
	h, _ := provisioned(t, policy)
	for range 2 {
		for i := range 300 {
			if code := serve(t, h, request("198.51.100.7", "/")); code != 200 {
				t.Fatalf("request %d: %d", i, code)
			}
		}
		c.add(time.Minute)
	}
}

// A ban ends after its duration, and the address starts a fresh window.
func TestTheBanEnds(t *testing.T) {
	c := fixture(t)
	h, _ := provisioned(t, `{"limit": 2, "window": "1m", "duration": "24h"}`)
	for range 3 {
		serve(t, h, request("198.51.100.7", "/"))
	}
	c.add(24*time.Hour - time.Second)
	if code := serve(t, h, request("198.51.100.7", "/")); code != 403 {
		t.Fatalf("a second before the end: %d", code)
	}
	c.add(time.Second)
	for i := range 2 {
		if code := serve(t, h, request("198.51.100.7", "/")); code != 200 {
			t.Fatalf("after the ban, request %d: %d", i, code)
		}
	}
	if code := serve(t, h, request("198.51.100.7", "/")); code != 403 {
		t.Errorf("want a fresh window that bans again: %d", code)
	}
}

// What is never counted: the private networks, loopback and the exempt ranges; Next.js's files, a
// page's subresources and the exempt paths. None of it bans, and none of it adds to
// a count that would.
func TestExemptRequestsAreNotCounted(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, `{"limit": 1, "window": "1m", "duration": "24h",
		"exempt_paths": ["^/api/[a-z]+/pics", "^/api/auctions/[^/]+/(image|video)"], "exempt_ranges": ["203.0.113.0/24"]}`)
	for _, ip := range []string{"10.240.1.1", "172.17.0.1", "192.168.1.5", "100.64.0.9", "127.0.0.1", "::1", "fd00::5", "203.0.113.50", "::ffff:10.0.0.1"} {
		for range 3 {
			if code := serve(t, h, request(ip, "/en/encar/1")); code != 200 {
				t.Errorf("%s: %d", ip, code)
			}
		}
	}
	const ip = "198.51.100.7"
	for _, r := range []*http.Request{
		request(ip, "/_next/static/chunks/main.js"),
		request(ip, "/_next/image?url=x"),
		request(ip, "/en/encar/1", "Sec-Fetch-Dest", "image"),
		request(ip, "/x.woff2", "Sec-Fetch-Dest", "font"),
		request(ip, "/x.css", "Sec-Fetch-Dest", "style"),
		request(ip, "/x.js", "Sec-Fetch-Dest", "Script"),
		request(ip, "/v.mp4", "Sec-Fetch-Dest", "video"),
		request(ip, "/a.mp3", "Sec-Fetch-Dest", "audio"),
		request(ip, "/api/encar/pics/123/1.jpg"),
		request(ip, "/api/auctions/lotte/image/9"),
	} {
		for range 3 {
			if code := serve(t, h, r); code != 200 {
				t.Errorf("%s %v: %d", r.URL.Path, r.Header, code)
			}
		}
	}
	// A path is judged cleaned: dot segments do not make a page a file of Next.js or an exempt path.
	other, _ := provisioned(t, `{"limit": 1, "window": "1m", "duration": "24h", "exempt_paths": ["^/api/[a-z]+/pics"]}`)
	for _, p := range []string{"/_next/../en/encar/1", "/api/encar/pics/../../encar/info/1"} {
		r := request("198.51.100.9", p)
		r.URL.Path = p // httptest cleans nothing, but say it: the request target as the client sent it
		serve(t, other, r)
	}
	if code := serve(t, other, request("198.51.100.9", "/_next/image?url=x")); code != 403 {
		t.Errorf("dot segments past an exemption: want them counted to a ban, got %d", code)
	}
	// A page — even fetched as a document — counts: the first passes, the second bans.
	if serve(t, h, request(ip, "/en/encar/1", "Sec-Fetch-Dest", "document")) != 200 || serve(t, h, request(ip, "/api/encar/info/1")) != 403 {
		t.Error("want pages counted from the first")
	}

}

// A banned address gets 403 for what it would not be counted for too — Next.js's files and image
// optimizer, subresources, exempt paths — and reaches no app; an exempt range still passes, lifting
// the ban it is added for.
func TestABanRefusesUncountedRequests(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, `{"limit": 1, "window": "1m", "duration": "24h", "exempt_paths": ["^/api/[a-z]+/pics"]}`)
	const ip = "198.51.100.7"
	if serve(t, h, request(ip, "/en/encar/1")) != 200 || serve(t, h, request(ip, "/en/encar/2")) != 403 {
		t.Fatal("want the second page to ban")
	}
	for _, r := range []*http.Request{
		request(ip, "/_next/image?url=x"),
		request(ip, "/_next/static/chunks/main.js"),
		request(ip, "/api/encar/info/1", "Sec-Fetch-Dest", "image"),
		request(ip, "/api/encar/pics/123/1.jpg"),
	} {
		if code := serve(t, h, r); code != 403 {
			t.Errorf("%s %v: want 403 to a banned address, got %d", r.URL.Path, r.Header, code)
		}
	}
	if code := serve(t, h, request("198.51.100.8", "/_next/image?url=x")); code != 200 {
		t.Errorf("an address not banned: %d", code)
	}
	exempted, _ := provisioned(t, `{"limit": 1, "window": "1m", "duration": "24h", "exempt_ranges": ["198.51.100.0/24"]}`)
	if code := serve(t, exempted, request(ip, "/en/encar/3")); code != 200 {
		t.Errorf("an exempt range added after the ban: want it lifted, got %d", code)
	}
}

// The address is the one Caddy decided past the trusted proxies, not the connection's; without one
// set, the connection's.
func TestTheClientAddressIsCaddys(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, `{"limit": 1, "window": "1m", "duration": "1h"}`)
	serve(t, h, request("198.51.100.7", "/"))
	if code := serve(t, h, request("198.51.100.7", "/")); code != 403 {
		t.Errorf("want the client_ip variable counted: %d", code)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.8:5555"
	serve(t, h, r)
	if code := serve(t, h, r); code != 403 {
		t.Errorf("want the connection's address without the variable: %d", code)
	}
}

// A reload provisions a new handler, and it holds the bans and counts of the one before it.
func TestABanOutlivesAReload(t *testing.T) {
	fixture(t)
	before, _ := provisioned(t, `{"limit": 3, "window": "1m", "duration": "24h"}`)
	for range 4 {
		serve(t, before, request("198.51.100.7", "/"))
	}
	for range 3 {
		serve(t, before, request("198.51.100.8", "/"))
	}
	after, _ := provisioned(t, `{"limit": 3, "window": "1m", "duration": "24h"}`)
	if code := serve(t, after, request("198.51.100.7", "/")); code != 403 {
		t.Errorf("want the ban kept across the reload: %d", code)
	}
	if code := serve(t, after, request("198.51.100.8", "/")); code != 403 {
		t.Errorf("want the count kept across the reload: %d", code)
	}
}

// A full table lets new addresses pass uncounted, logged once, while the ones it holds stay banned;
// expired entries make room again.
func TestAFullTableFailsOpen(t *testing.T) {
	c := fixture(t)
	h, logs := provisioned(t, `{"limit": 1, "window": "1m", "duration": "1h", "max_tracked": 3}`)
	serve(t, h, request("198.51.100.1", "/"))
	serve(t, h, request("198.51.100.1", "/")) // banned
	serve(t, h, request("198.51.100.2", "/"))
	serve(t, h, request("198.51.100.3", "/"))
	for range 5 {
		if code := serve(t, h, request("198.51.100.4", "/")); code != 200 {
			t.Fatalf("want an address past the bound passed: %d", code)
		}
	}
	if shared.len() != 3 {
		t.Errorf("want the table held at its bound, got %d", shared.len())
	}
	if code := serve(t, h, request("198.51.100.1", "/")); code != 403 {
		t.Errorf("want the ban kept while full: %d", code)
	}
	if n := logs.FilterLevelExact(zap.ErrorLevel).Len(); n != 1 {
		t.Errorf("want the overflow logged once, got %d", n)
	}
	// A window later 2 and 3 expire; 1 is still banned.
	c.add(time.Minute)
	serve(t, h, request("198.51.100.4", "/"))
	if code := serve(t, h, request("198.51.100.4", "/")); code != 403 {
		t.Errorf("want room again after the sweep: %d", code)
	}
	if shared.len() != 2 {
		t.Errorf("want 2 and 3 swept and 1 kept, got %d", shared.len())
	}
	c.add(time.Hour)
	serve(t, h, request("198.51.100.5", "/"))
	if shared.len() != 1 {
		t.Errorf("want the ended bans swept, got %d", shared.len())
	}
}

// Requests from many goroutines at once count exactly: run with -race.
func TestConcurrentRequestsCountExactly(t *testing.T) {
	fixture(t)
	h, logs := provisioned(t, `{"limit": 1000, "window": "1m", "duration": "1h"}`)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for g := range 20 {
		wg.Go(func() {
			for i := range 100 {
				ip := "198.51.100.7"
				if i%2 == 1 {
					ip = fmt.Sprintf("192.0.2.%d", g)
				}
				w := httptest.NewRecorder()
				if err := h.ServeHTTP(w, request(ip, "/"), upstream); err != nil {
					t.Error(err)
				}
				if ip == "198.51.100.7" {
					mu.Lock()
					codes[w.Code]++
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	// 1000 from one address pass; the rest of the other's are under any limit.
	if codes[200] != 1000 || codes[403] != 0 || logs.Len() != 0 {
		t.Errorf("codes %v, logs %d", codes, logs.Len())
	}
	if code := serve(t, h, request("198.51.100.7", "/")); code != 403 {
		t.Errorf("want the 1001st banned: %d", code)
	}
}

// A handler that would ban everyone or no one is refused when the config loads.
func TestValidateRefuses(t *testing.T) {
	for _, c := range []string{
		`{"limit": 0, "window": "1m", "duration": "1h"}`,
		`{"limit": 1, "duration": "1h"}`,
		`{"limit": 1, "window": "1m"}`,
		`{"rules": [], "duration": "1h"}`,
		`{"limit": 1, "window": "1m", "rules": [{"name": "a", "limit": 1, "window": "1m"}], "duration": "1h"}`,
		`{"rules": [{"limit": 1, "window": "1m"}], "duration": "1h"}`,
		`{"rules": [{"name": "a", "limit": 1, "window": "1m"}, {"name": "a", "limit": 2, "window": "1m"}], "duration": "1h"}`,
		`{"rules": [{"name": "a", "limit": 0, "window": "1m"}], "duration": "1h"}`,
		`{"rules": [{"name": "a", "limit": 1}], "duration": "1h"}`,
		`{"rules": [{"name": "a", "limit": 1, "window": "1m", "class": "pages"}], "duration": "1h"}`,
		`{"limit": 1, "window": "1m", "duration": "1h", "heuristics": {"mode": "block"}}`,
		`{"limit": 1, "window": "1m", "duration": "1h", "heuristics": {"mode": "log", "cluster": {"window": "1m", "min_addresses": 2}}}`,
		`{"limit": 1, "window": "1m", "duration": "1h", "heuristics": {"mode": "ban", "cluster": {"limit": 1, "min_addresses": 2}}}`,
		`{"limit": 1, "window": "1m", "duration": "1h", "heuristics": {"mode": "ban", "cluster": {"limit": 1, "window": "1m", "min_addresses": 101}}}`,
	} {
		var h Handler
		if err := json.Unmarshal([]byte(c), &h); err != nil {
			t.Fatal(err)
		}
		h.MaxTracked, h.MaxFingerprints = 1, 1
		if err := h.Validate(); err == nil {
			t.Errorf("%s: want refused", c)
		}
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	for _, c := range []Handler{{ExemptPaths: []string{"("}}, {ExemptRanges: []string{"10.0.0.1"}},
		{Rules: []Rule{{Name: "a", Limit: 1, Window: caddy.Duration(time.Minute), Paths: []string{"("}}}}} {
		if err := c.Provision(ctx); err == nil {
			t.Errorf("%+v: want refused", c)
		}
	}
}

// The private ranges hold the addresses the server's own traffic comes from.
func TestPrivateRanges(t *testing.T) {
	h := Handler{ranges: private}
	for _, s := range []string{"10.240.1.1", "172.31.255.255", "fc00::1", "fe80::1"} {
		if !h.exemptAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s: want exempt", s)
		}
	}
	for _, s := range []string{"172.32.0.1", "8.8.8.8", "2001:db8::1"} {
		if h.exemptAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s: want counted", s)
		}
	}
}

// rules is the ban the plan sets for hb-sites, small enough to count by hand: two windows over
// everything, one over pages, one over the API, and one over a path whatever its Sec-Fetch-Dest.
const rules = `{"duration": "24h", "rules": [
	{"name": "all-1m", "limit": 5, "window": "1m"},
	{"name": "all-10m", "limit": 8, "window": "10m", "class": "all"},
	{"name": "pages", "limit": 3, "window": "1m", "class": "page"},
	{"name": "api", "limit": 4, "window": "1m", "class": "api"},
	{"name": "pics", "limit": 2, "window": "1m", "paths": ["^/pics/"]}]}`

// Each rule counts and bans on its own: four a minute pass the minute's rule, and the ninth in ten
// minutes is past the ten minutes', which outlives the minute's sweeps; the journal names the rule.
func TestEachRuleBansOnItsOwn(t *testing.T) {
	c := fixture(t)
	h, logs := provisioned(t, rules)
	const ip = "198.51.100.7"
	for minute := range 2 {
		for i := range 4 {
			if code := serve(t, h, request(ip, fmt.Sprintf("/api/encar/%d", i))); code != 200 {
				t.Fatalf("minute %d, request %d: %d", minute, i, code)
			}
		}
		c.add(time.Minute)
		serve(t, h, request("192.0.2.1", "/")) // another address's request runs the minute's sweep
	}
	if got := shared.counters(ip); !maps.Equal(got, map[string]int{"all-10m": 8}) {
		t.Fatalf("want the ten minutes' count kept past the sweeps, the minute's swept: %v", got)
	}
	if code := serve(t, h, request(ip, "/api/encar/9")); code != 403 {
		t.Fatalf("the ninth in ten minutes: want 403, got %d", code)
	}
	if logs.Len() != 1 || logs.All()[0].ContextMap()["rule"] != "all-10m" || logs.All()[0].ContextMap()["count"] != int64(9) ||
		logs.All()[0].ContextMap()["window"] != "10m0s" {
		t.Errorf("want the ban logged with its rule: %v", logs.All())
	}
	// The ban is the address's on every host, whatever rule started it.
	r := request(ip, "/")
	r.Host = "autogroup.kr"
	if code := serve(t, h, r); code != 403 {
		t.Errorf("another host: want the ban held, got %d", code)
	}
	// One minute's rule alone bans too: the sixth request of a minute.
	for i := range 5 {
		if code := serve(t, h, request("198.51.100.8", fmt.Sprintf("/api/encar/%d", i))); code != 200 && i < 4 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if f := logs.All()[logs.Len()-1].ContextMap(); f["ip"] != "198.51.100.8" || f["rule"] != "api" {
		t.Errorf("want the fifth api request a minute banned by api: %v", f)
	}
}

// What each class counts: page is a GET outside /api/ that is no prefetch; api is under /api/,
// whatever Sec-Fetch-Dest it claims; all and page leave a page's subresources out, a rule on paths
// counts its paths whatever they claim.
func TestClassesCountTheirOwn(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, rules)
	post := func(ip, p string) *http.Request {
		r := request(ip, p)
		r.Method = http.MethodPost
		return r
	}
	for _, c := range []struct {
		r    *http.Request
		want map[string]int
	}{
		{request("198.51.100.1", "/en/encar/1"), map[string]int{"all-1m": 1, "all-10m": 1, "pages": 1}},
		{request("198.51.100.2", "/en/encar/1", "Next-Router-Prefetch", "1", "RSC", "1"), map[string]int{"all-1m": 1, "all-10m": 1}},
		{request("198.51.100.3", "/en/encar/1", "RSC", "1"), map[string]int{"all-1m": 1, "all-10m": 1, "pages": 1}},
		{post("198.51.100.4", "/en/encar/1"), map[string]int{"all-1m": 1, "all-10m": 1}},
		{request("198.51.100.5", "/api/encar/info/1"), map[string]int{"all-1m": 1, "all-10m": 1, "api": 1}},
		{request("198.51.100.6", "/api"), map[string]int{"all-1m": 1, "all-10m": 1, "api": 1}},
		{request("198.51.100.7", "/apis/x"), map[string]int{"all-1m": 1, "all-10m": 1, "pages": 1}},
		{request("198.51.100.8", "/api/encar/info/1", "Sec-Fetch-Dest", "image"), map[string]int{"api": 1}},
		{request("198.51.100.9", "/pics/1.jpg", "Sec-Fetch-Dest", "image"), map[string]int{"pics": 1}},
		{request("198.51.100.10", "/pics/1.jpg"), map[string]int{"all-1m": 1, "all-10m": 1, "pages": 1, "pics": 1}},
		{request("198.51.100.11", "/en/x.css", "Sec-Fetch-Dest", "style"), map[string]int{}},
		{request("198.51.100.12", "/_next/static/a.js"), map[string]int{}},
		// Cleaned: dot segments do not take a page under /api/ or out of it.
		{request("198.51.100.13", "/api/../en/encar/1"), map[string]int{"all-1m": 1, "all-10m": 1, "pages": 1}},
	} {
		if code := serve(t, h, c.r); code != 200 {
			t.Fatalf("%s: %d", c.r.URL.Path, code)
		}
		ip, _ := clientAddr(c.r)
		if got := shared.counters(ip.String()); !maps.Equal(got, c.want) {
			t.Errorf("%s %s %v: want %v, got %v", c.r.Method, c.r.URL.Path, c.r.Header, c.want, got)
		}
	}
}

// A reload with other rules: a rule kept as it was keeps its count, and so does one whose limit or
// window changed — judged by the new ones, as v1's one count was; one removed is dropped at the next
// sweep. A ban outlives any of it, rules
// gone included, and provisioning changes nothing of the shared state.
func TestAReloadWithOtherRules(t *testing.T) {
	c := fixture(t)
	before, _ := provisioned(t, `{"duration": "24h", "rules": [
		{"name": "kept", "limit": 10, "window": "10m"}, {"name": "changed", "limit": 10, "window": "10m"},
		{"name": "relimited", "limit": 10, "window": "10m"}, {"name": "gone", "limit": 10, "window": "10m"}]}`)
	for range 3 {
		serve(t, before, request("198.51.100.7", "/"))
	}
	banner, _ := provisioned(t, `{"duration": "24h", "rules": [{"name": "strict", "limit": 1, "window": "1m"}]}`)
	serve(t, banner, request("198.51.100.9", "/"))
	serve(t, banner, request("198.51.100.9", "/"))

	store, entries := shared, shared.len()
	after, _ := provisioned(t, `{"duration": "24h", "rules": [
		{"name": "kept", "limit": 10, "window": "10m"}, {"name": "changed", "limit": 10, "window": "5m"},
		{"name": "relimited", "limit": 20, "window": "10m"}, {"name": "new", "limit": 10, "window": "1m"}]}`)
	if shared != store || shared.len() != entries || shared.counters("198.51.100.7")["gone"] != 3 {
		t.Fatal("want provisioning to leave the shared state as it was")
	}
	serve(t, after, request("198.51.100.7", "/"))
	if got := shared.counters("198.51.100.7"); got["kept"] != 4 || got["changed"] != 4 || got["relimited"] != 4 || got["new"] != 1 || got["gone"] != 3 {
		t.Errorf("after the reload: %v", got)
	}
	c.add(time.Minute)
	serve(t, after, request("192.0.2.1", "/")) // the sweep
	if got := shared.counters("198.51.100.7"); got["gone"] != 0 || got["kept"] != 4 || len(got) != 3 {
		t.Errorf("want the removed rule's count swept, the rest kept: %v", got)
	}
	if code := serve(t, after, request("198.51.100.9", "/")); code != 403 {
		t.Errorf("want the ban kept though its rule is gone: %d", code)
	}
}

// A lowered limit holds the count an address already has to it at once, as v1 did across a reload:
// 200 requests under 300 a minute, then 100 a minute, and the next request bans.
func TestALoweredLimitBansOnTheCountAlreadyMade(t *testing.T) {
	fixture(t)
	before, _ := provisioned(t, `{"duration": "24h", "rules": [{"name": "default", "limit": 300, "window": "1m"}]}`)
	for range 200 {
		serve(t, before, request("198.51.100.7", "/"))
	}
	after, _ := provisioned(t, `{"duration": "24h", "rules": [{"name": "default", "limit": 100, "window": "1m"}]}`)
	if code := serve(t, after, request("198.51.100.7", "/")); code != 403 {
		t.Errorf("want the lowered limit to ban on the count already made, got %d", code)
	}
}

// A widened window keeps the count and the start an address already has, as v1 did across a reload:
// 300 in 30 s under 300 a minute, then 2 minutes, and the next request bans.
func TestAWidenedWindowKeepsTheCount(t *testing.T) {
	c := fixture(t)
	before, _ := provisioned(t, `{"duration": "24h", "rules": [{"name": "default", "limit": 300, "window": "1m"}]}`)
	for range 300 {
		serve(t, before, request("198.51.100.7", "/"))
	}
	c.add(30 * time.Second)
	after, _ := provisioned(t, `{"duration": "24h", "rules": [{"name": "default", "limit": 300, "window": "2m"}]}`)
	if code := serve(t, after, request("198.51.100.7", "/")); code != 403 {
		t.Errorf("want the widened window to ban on the count already made, got %d", code)
	}
}

// A sweep between a reload that widened a window and the address's next request judges the count by
// the new window: 300 at 30 s under 1m, widened to 2m at 50 s, a sweep at 2m from another address,
// and the 301st request of the first, 90 s into its window, bans.
func TestASweepAfterAWidenedWindowKeepsTheCount(t *testing.T) {
	c := fixture(t)
	before, _ := provisioned(t, `{"duration": "24h", "rules": [{"name": "default", "limit": 300, "window": "1m"}]}`)
	serve(t, before, request("192.0.2.1", "/")) // sweeps at 0
	c.add(30 * time.Second)
	for range 300 {
		serve(t, before, request("198.51.100.7", "/"))
	}
	c.add(20 * time.Second)
	after, _ := provisioned(t, `{"duration": "24h", "rules": [{"name": "default", "limit": 300, "window": "2m"}]}`)
	c.add(70 * time.Second)
	serve(t, after, request("192.0.2.2", "/")) // the sweep, at 2m
	if code := serve(t, after, request("198.51.100.7", "/")); code != 403 {
		t.Errorf("want the count kept through the sweep under the widened window, got %d", code)
	}
}

func TestAPolicyOfFormat6RunsAsTheRuleDefault(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, `{"limit": 2, "window": "1m", "duration": "1h"}`)
	serve(t, h, request("198.51.100.7", "/api/x", "Sec-Fetch-Dest", "image")) // left out, as by class all
	serve(t, h, request("198.51.100.7", "/api/x"))
	if got := shared.counters("198.51.100.7"); !maps.Equal(got, map[string]int{"default": 1}) {
		t.Errorf("want one rule, default, of class all: %v", got)
	}
}

// A rule's window starts again when it passed, whether or not a sweep came between: an address's
// window ends between two sweeps another address's requests ran.
func TestTheWindowStartsAgainBetweenSweeps(t *testing.T) {
	c := fixture(t)
	h, _ := provisioned(t, policy)
	serve(t, h, request("198.51.100.1", "/")) // sweeps at 0
	c.add(30 * time.Second)
	for range 300 {
		serve(t, h, request("198.51.100.2", "/"))
	}
	c.add(30 * time.Second)
	serve(t, h, request("198.51.100.1", "/")) // sweeps at 1m: the second's window, from 30s, holds
	c.add(45 * time.Second)                   // 1m45s: the second's window passed, no sweep due until 2m
	if code := serve(t, h, request("198.51.100.2", "/")); code != 200 {
		t.Fatalf("want the window started again, got %d", code)
	}
	if got := shared.counters("198.51.100.2")["default"]; got != 1 {
		t.Errorf("want the count started again at 1, got %d", got)
	}
}

// A rule of a class and paths counts what both select: its paths within its class, the path judged
// cleaned, a subresource of its paths too.
func TestARuleOfAClassAndPaths(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, `{"duration": "24h", "rules": [
		{"name": "page-pics", "limit": 100, "window": "1m", "class": "page", "paths": ["^/pics/"]},
		{"name": "api-pics", "limit": 100, "window": "1m", "class": "api", "paths": ["^/api/pics/"]}]}`)
	post := request("198.51.100.2", "/pics/a")
	post.Method = http.MethodPost
	for _, c := range []struct {
		r    *http.Request
		want map[string]int
	}{
		{request("198.51.100.1", "/pics/a", "Sec-Fetch-Dest", "image"), map[string]int{"page-pics": 1}},
		{post, map[string]int{}},
		{request("198.51.100.3", "/else/../pics/a"), map[string]int{"page-pics": 1}},
		{request("198.51.100.4", "/else/a"), map[string]int{}},
		{request("198.51.100.5", "/api/pics/a", "Sec-Fetch-Dest", "image"), map[string]int{"api-pics": 1}},
		{request("198.51.100.6", "/api/other"), map[string]int{}},
		{request("198.51.100.7", "/pics/a", "Next-Router-Prefetch", "1"), map[string]int{}},
	} {
		serve(t, h, c.r)
		ip, _ := clientAddr(c.r)
		if got := shared.counters(ip.String()); !maps.Equal(got, c.want) {
			t.Errorf("%s %s %v: want %v, got %v", c.r.Method, c.r.URL.Path, c.r.Header, c.want, got)
		}
	}
}
