package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// xffGolden is the request headers of a route as boks writes them, which the live test of the
// forwarded address loads into Caddy (proxy/gate, TestForwardedForIsTheClientThroughCaddy).
const xffGolden = "../../proxy/gate/testdata/xff/request-headers.json"

// Every route hands the app X-Forwarded-For as the one client Caddy decided, whether proxies are
// trusted or not, and deletes Forwarded (#136); the live test runs these very ops.
func TestRoutesSetForwardedForToTheClient(t *testing.T) {
	for _, p := range []Policy{{}, {TrustedProxies: []string{"127.0.0.1/32"}}} {
		b, err := Config(p, []Fragment{{App: "a", Routes: []Route{{Host: "a.example.com", Dial: "a:1", TLS: true}, {Host: "p.example.com", Dial: "a:2"}}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, srv := range []string{"http", "https"} {
			routes, _ := dig(decoded(t, b), "apps", "http", "servers", srv, "routes").([]any)
			h := dig(routes[0], "handle").([]any)[0]
			got, _ := json.MarshalIndent(dig(h, "headers", "request"), "", "  ")
			got = append(got, '\n')
			if os.Getenv("BOKS_UPDATE") == "1" {
				if err := os.WriteFile(xffGolden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(xffGolden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("trusted %v, %s: request headers\n%s\nwant (%s, BOKS_UPDATE=1 to rewrite)\n%s", p.TrustedProxies, srv, got, xffGolden, want)
			}
		}
	}
}
