package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// blockSparingBearer is the route boks writes (internal/proxy, botRoutes and bearerAllows) for a block of
// HTTP libraries on a group with a bearer: the block leaves out the group's hosts, its bearer's methods
// and paths, and the Bearer scheme with a token. TestConfigSparesTheGatesPartners holds boks to it.
const blockSparingBearer = `{"match":[{"header_regexp":{"User-Agent":{"pattern":"(?i)(axios|python-requests)"}},"not":[` +
	`{"path":["/.well-known/acme-challenge/*"]},` +
	`{"header_regexp":{"Authorization":{"pattern":"(?i)^bearer\\s+\\S"}},"host":["shop.example.com"],` +
	`"method":["GET","HEAD"],"path_regexp":{"pattern":"(?:^/api/encar(/|$))"}}]}],` +
	`"handle":[{"handler":"static_response","status_code":403}],"terminal":true}`

// Through Caddy, a partner's library gets past the block by its Bearer to the gate, which lets its key
// in; a key that does not pass gets past the block to the gate's 401 — the header alone opens nothing —
// and the library without the header, or outside the bearer's methods, paths and hosts, gets the
// block's 403 (todo#419).
func TestThroughCaddyTheBlockSparesTheBearer(t *testing.T) {
	partner := strings.Repeat("p", 40)
	sum := sha256.Sum256([]byte(partner))
	port := freePort(t)
	cfg := fmt.Sprintf(`{"admin":{"disabled":true},"apps":{"http":{"servers":{"s":{"listen":["127.0.0.1:%d"],"automatic_https":{"disable":true},"routes":[
  %s,
  {"match":[{"host":["shop.example.com"]}],"handle":[{"handler":"boks_gate","name":"shop","mode":"enforce","secrets":[%q],
    "bearer":{"paths":["^/api/encar(/|$)"],"digests":[%q]}}]},
  {"handle":[{"handler":"static_response","status_code":200}],"terminal":true}]}}}}}`,
		port, blockSparingBearer, secret, hex.EncodeToString(sum[:]))
	if err := caddy.Load([]byte(cfg), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	cases := []struct {
		name, host, method, path, auth string
		want                           int
	}{
		{"the partner", "shop.example.com", "GET", "/api/encar/catalog", "Bearer " + partner, 200},
		{"the partner's HEAD", "shop.example.com", "HEAD", "/api/encar", "bearer " + partner, 200},
		{"another key: past the block to the gate", "shop.example.com", "GET", "/api/encar/catalog", "Bearer " + strings.Repeat("q", 40), 401},
		{"no key", "shop.example.com", "GET", "/api/encar/catalog", "", 403},
		{"the scheme without a token", "shop.example.com", "GET", "/api/encar/catalog", "Bearer  ", 403},
		{"a write", "shop.example.com", "POST", "/api/encar/catalog", "Bearer " + partner, 403},
		{"outside its paths", "shop.example.com", "GET", "/api/rates", "Bearer " + partner, 403},
		{"another host", "blog.example.com", "GET", "/api/encar/catalog", "Bearer " + partner, 403},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, fmt.Sprintf("http://127.0.0.1:%d%s", port, c.path), nil)
		req.Host = c.host
		req.Header.Set("User-Agent", "axios/1.7.9")
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d, want %d", c.name, resp.StatusCode, c.want)
		}
	}
}
