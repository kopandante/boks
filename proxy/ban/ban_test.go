package ban

import (
	"context"
	"encoding/json"
	"fmt"
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
	if e.Level != zap.WarnLevel || f["ip"] != "217.81.103.213" || f["host"] != "cars.dbauto.kr" || f["count"] != int64(301) ||
		f["until"] != "2026-10-15T01:47:00Z" {
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
// page's subresources, ACME's challenge and the exempt paths. None of it bans, and none of it adds to
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
		request(ip, "/.well-known/acme-challenge/token"),
		request(ip, "/api/encar/pics/123/1.jpg"),
		request(ip, "/api/auctions/lotte/image/9"),
	} {
		for range 3 {
			if code := serve(t, h, r); code != 200 {
				t.Errorf("%s %v: %d", r.URL.Path, r.Header, code)
			}
		}
	}
	// A page — even fetched as a document — counts: the first passes, the second bans.
	if serve(t, h, request(ip, "/en/encar/1", "Sec-Fetch-Dest", "document")) != 200 || serve(t, h, request(ip, "/api/encar/info/1")) != 403 {
		t.Error("want pages counted from the first")
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
	} {
		var h Handler
		if err := json.Unmarshal([]byte(c), &h); err != nil {
			t.Fatal(err)
		}
		h.MaxTracked = 1
		if err := h.Validate(); err == nil {
			t.Errorf("%s: want refused", c)
		}
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	for _, c := range []Handler{{ExemptPaths: []string{"("}}, {ExemptRanges: []string{"10.0.0.1"}}} {
		if err := c.Provision(ctx); err == nil {
			t.Errorf("%+v: want refused", c)
		}
	}
}

// The private ranges hold the addresses the server's own traffic comes from.
func TestPrivateRanges(t *testing.T) {
	h := Handler{ranges: private}
	for _, s := range []string{"10.240.1.1", "172.31.255.255", "fc00::1", "fe80::1"} {
		if !h.exempt(netip.MustParseAddr(s), request(s, "/")) {
			t.Errorf("%s: want exempt", s)
		}
	}
	for _, s := range []string{"172.32.0.1", "8.8.8.8", "2001:db8::1"} {
		if h.exempt(netip.MustParseAddr(s), request(s, "/")) {
			t.Errorf("%s: want counted", s)
		}
	}
}
