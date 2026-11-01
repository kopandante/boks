package gate

import (
	"crypto/tls"
	"crypto/x509"
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

// The origin pull through Caddy, with the connection policies boks writes for a proxy in front at
// 127.0.0.1 whose client certificate chains to the test CA (internal/proxy, origin_test.go writes and
// checks testdata/originpull/policies.json). The proxy with its certificate has the visitor it names
// reach the app; without one, or with another CA's, its connection is refused; a visitor connecting
// from elsewhere — ::1 here — is asked for no certificate and has its own address as before, whatever
// it writes into X-Forwarded-For.
func TestOriginPullThroughCaddy(t *testing.T) {
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback to connect a visitor from elsewhere: %v", err)
	} else {
		ln.Close()
	}
	var mu sync.Mutex
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Forwarded-For"))
		mu.Unlock()
	}))
	defer upstream.Close()
	policies, err := os.ReadFile("testdata/originpull/policies.json")
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	cfg := fmt.Sprintf(`{"admin":{"disabled":true},
"apps":{"tls":{"certificates":{"load_files":[{"certificate":"testdata/originpull/server.pem","key":"testdata/originpull/server.key"}]}},
"http":{"servers":{"https":{"listen":["127.0.0.1:%d","[::1]:%d"],"protocols":["h1","h2"],
 "automatic_https":{"disable":true},
 "trusted_proxies":{"source":"static","ranges":["127.0.0.1/32"]},"client_ip_headers":["X-Forwarded-For"],"trusted_proxies_strict":1,
 "tls_connection_policies":%s,"strict_sni_host":false,
 "routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":%q}]}]}]}}}}}`,
		port, port, policies, strings.TrimPrefix(upstream.URL, "http://"))
	if err := caddy.Load([]byte(cfg), true); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	}()
	roots := x509.NewCertPool()
	serverCA, err := os.ReadFile("testdata/originpull/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots.AppendCertsFromPEM(serverCA)
	get := func(host, cert string) (string, error) {
		conf := &tls.Config{RootCAs: roots, ServerName: "localhost"}
		if cert != "" {
			pair, err := tls.LoadX509KeyPair("testdata/originpull/"+cert+".pem", "testdata/originpull/"+cert+".key")
			if err != nil {
				t.Fatal(err)
			}
			conf.Certificates = []tls.Certificate{pair}
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true}}
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/", net.JoinHostPort(host, fmt.Sprint(port))), nil)
		req.Host = "a.example.com"
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		resp, err := c.Do(req)
		if err != nil {
			return "", err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		mu.Lock()
		defer mu.Unlock()
		if len(seen) == n {
			return "", fmt.Errorf("status %d, the app saw no request", resp.StatusCode)
		}
		return strings.TrimSpace(strings.Split(seen[len(seen)-1], ",")[0]), nil
	}
	if first, err := get("127.0.0.1", "client"); err != nil || first != "198.51.100.7" {
		t.Errorf("the proxy with its certificate: first X-Forwarded-For %q, %v; want the visitor it names", first, err)
	}
	for _, cert := range []string{"", "other-client"} {
		if first, err := get("127.0.0.1", cert); err == nil {
			t.Errorf("the proxy's address with certificate %q: want the connection refused, the app saw %q", cert, first)
		}
	}
	if first, err := get("::1", ""); err != nil || first != "::1" {
		t.Errorf("a visitor from elsewhere: first X-Forwarded-For %q, %v; want its own address, as before", first, err)
	}
}
