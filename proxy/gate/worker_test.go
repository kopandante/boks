package gate

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// Cloudflare's client address of a Worker's request from another zone, 2a06:98c0:3600::103, is cut out
// of its trusted ranges by boks (internal/config, TrustedPrefixes writes testdata/worker/trusted.json):
// through Caddy, with the request headers boks writes on every route, the app gets the Worker's address
// as the client — never the one the Worker wrote before it. An address of Cloudflare's beside it stays
// trusted and is read past as before.
func TestWorkerIsTheClientThroughCaddy(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Forwarded-For"))
		mu.Unlock()
	}))
	defer upstream.Close()
	trusted, err := os.ReadFile("testdata/worker/trusted.json")
	if err != nil {
		t.Fatal(err)
	}
	headers, err := os.ReadFile("testdata/xff/request-headers.json")
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	cfg := fmt.Sprintf(`{"admin":{"disabled":true},
"apps":{"http":{"servers":{"s":{"listen":["127.0.0.1:%d"],
 "trusted_proxies":{"source":"static","ranges":%s},"client_ip_headers":["X-Forwarded-For"],"trusted_proxies_strict":1,
 "routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":%q}],"headers":{"request":%s}}]}]}}}}}`,
		port, trusted, strings.TrimPrefix(upstream.URL, "http://"), headers)
	if err := caddy.Load([]byte(cfg), true); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	}()
	for _, c := range []struct{ xff, want string }{
		{"1.2.3.4, 2a06:98c0:3600::103", "2a06:98c0:3600::103"},
		{"1.2.3.4, 2a06:98c0:3600::104", "1.2.3.4"},
	} {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
		req.Header.Set("X-Forwarded-For", c.xff)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		mu.Lock()
		got := seen[len(seen)-1]
		mu.Unlock()
		if resp.StatusCode != http.StatusOK || got != c.want {
			t.Errorf("%s: %d, the app got %q, want %q", c.xff, resp.StatusCode, got, c.want)
		}
	}
}
