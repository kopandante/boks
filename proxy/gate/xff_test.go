package gate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// The address the app gets, through Caddy with the request headers boks writes on every route
// (internal/proxy, xff_test.go checks testdata/xff/request-headers.json) and a proxy in front trusted
// at 127.0.0.1 (#136). Behind the proxy the app gets X-Forwarded-For as one address, the client Caddy
// read from the right — never the entries the visitor wrote before it, which an app taking the first
// entry would believe. A visitor from elsewhere — ::1 — gets its own address, whatever it writes.
func TestForwardedForIsTheClientThroughCaddy(t *testing.T) {
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback to connect a visitor from elsewhere: %v", err)
	} else {
		ln.Close()
	}
	var mu sync.Mutex
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, strings.Join(r.Header.Values("X-Forwarded-For"), " | "))
		mu.Unlock()
	}))
	defer upstream.Close()
	headers, err := os.ReadFile("testdata/xff/request-headers.json")
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	cfg := fmt.Sprintf(`{"admin":{"disabled":true},
"apps":{"http":{"servers":{"s":{"listen":["127.0.0.1:%d","[::1]:%d"],
 "trusted_proxies":{"source":"static","ranges":["127.0.0.1/32"]},"client_ip_headers":["X-Forwarded-For"],"trusted_proxies_strict":1,
 "routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":%q}],"headers":{"request":%s}}]}]}}}}}`,
		port, port, strings.TrimPrefix(upstream.URL, "http://"), headers)
	if err := caddy.Load([]byte(cfg), true); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	}()
	for _, c := range []struct {
		name, host string
		xff        []string
		want       string
	}{
		{"behind the proxy, a forged entry before the real one", "127.0.0.1", []string{"1.2.3.4, 198.51.100.7"}, "198.51.100.7"},
		{"behind the proxy, the forged entry in a header of its own", "127.0.0.1", []string{"1.2.3.4", "198.51.100.7"}, "198.51.100.7"},
		{"behind the proxy, IPv6 client", "127.0.0.1", []string{"1.2.3.4, 2001:db8::7"}, "2001:db8::7"},
		{"behind the proxy, no header", "127.0.0.1", nil, "127.0.0.1"},
		{"a visitor from elsewhere", "::1", []string{"1.2.3.4"}, "::1"},
	} {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/", net.JoinHostPort(c.host, fmt.Sprint(port))), nil)
		for _, v := range c.xff {
			req.Header.Add("X-Forwarded-For", v)
		}
		mu.Lock()
		before := len(seen)
		mu.Unlock()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		mu.Lock()
		n := len(seen) - before
		reached := n == 1
		var got string
		if reached {
			got = seen[before]
		}
		mu.Unlock()
		// A request Caddy answered itself never reached the app: the last value seen is the case before.
		if resp.StatusCode != http.StatusOK || !reached {
			t.Errorf("%s: %d, the app saw %d requests, want 200 and one", c.name, resp.StatusCode, n)
			continue
		}
		if got != c.want {
			t.Errorf("%s: the app got X-Forwarded-For %q, want %q", c.name, got, c.want)
		}
	}
}
