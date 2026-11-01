package gate

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// jpSig is the scraper's signature on Japan's addresses alone (#140, owner 01.11: Japan and the other
// factors together ban).
var jpSig = Signature{Name: "node-chrome-jp", Mode: "enforce", Ranges: "jp", Headers: scraperSig.Headers}

// A signature with ranges matches only a client in its set: the scraper's headers from Japan are
// refused and banned, the same headers from elsewhere pass to the rest of the gate, and a browser from
// Japan is no signature's at all. IPv6 the same way.
func TestSignatureRanges(t *testing.T) {
	cases := []struct {
		name, ua, ae, ip string
		want             int
		reason           string
	}{
		{"the scraper from Japan", stormUA, scraperAE, "126.10.20.30", 403, "signature"},
		{"the scraper from Japan over IPv6", stormUA, scraperAE, "2400:4050:1::7", 403, "signature"},
		{"the scraper's headers from elsewhere", stormUA, scraperAE, "", 200, "token"},
		{"the scraper's headers next to the set", stormUA, scraperAE, "127.0.0.9", 200, "token"},
		{"Chrome from Japan", chromeUA, "gzip, deflate, br, zstd", "126.10.20.31", 200, "token"},
	}
	for _, c := range cases {
		now := time.Now()
		h := &Handler{Signatures: []Signature{jpSig}, SignatureBan: caddyDay, bans: newBanStore(),
			RangeSets: map[string][]string{"jp": {"126.0.0.0/8", "2400:4050::/32", "1.0.16.0/20"}}}
		h = enforcing(t, h, now)
		r, extra := withLog(browserClient(c.ua, c.ip).request(h, "GET", "/api/auctions/heydealer/cars"))
		r.Header.Set("Accept-Encoding", c.ae)
		w := serve(t, h, r)
		if w.Code != c.want || fields(extra)["gate_reason"] != c.reason {
			t.Errorf("%s: %d %v, want %d %s", c.name, w.Code, fields(extra), c.want, c.reason)
		}
	}
}

// A signature naming a set the group has not, an empty set, and a set's entry that is no address or
// holds every one are refused at the provision: Caddy keeps the config it runs.
func TestSignatureRangesRefused(t *testing.T) {
	for _, c := range []struct {
		sets map[string][]string
		want string
	}{
		{nil, `the group has no range set "jp"`},
		{map[string][]string{"kr": {"1.0.0.0/8"}}, `the group has no range set "jp"`},
		{map[string][]string{"jp": {}}, `the group has no range set "jp"`},
		{map[string][]string{"jp": {"japan"}}, `range_sets.jp: "japan" is neither an address nor a CIDR range`},
		{map[string][]string{"jp": {"0.0.0.0/0"}}, `range_sets.jp: "0.0.0.0/0" holds every address`},
	} {
		h := &Handler{Name: "site", Mode: "enforce", Secrets: []string{secret}, Signatures: []Signature{jpSig}, RangeSets: c.sets}
		if err := h.Provision(ctxForTest(t)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: want %q, got %v", c.sets, c.want, err)
		}
	}
}

// Through Caddy, the group as boks writes it (internal/config, withRangeSets): Caddy's strict decoder
// takes range_sets and ranges, and the signature refuses the scraper's headers from an address in the
// set only. An image without the fields refuses the same config at the reload, by the same decoder.
func TestSignatureRangesThroughCaddy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	for _, c := range []struct {
		set  string
		want int
	}{{"127.0.0.0/8", 403}, {"126.0.0.0/8", 200}} {
		port := freePort(t)
		cfg := fmt.Sprintf(`{"admin":{"disabled":true},"apps":{"http":{"servers":{"s":{"listen":["127.0.0.1:%d"],"routes":[
 {"handle":[{"handler":"boks_gate","name":"site","mode":"enforce","secrets":[%q],"range_sets":{"jp":[%q]},
   "signatures":[{"name":"node-chrome-jp","mode":"enforce","ranges":"jp","headers":[{"name":"accept-encoding","pattern":"^br, gzip, deflate$"}]}]}]},
 {"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":%q}]}]}]}}}}}`,
			port, secret, c.set, strings.TrimPrefix(upstream.URL, "http://"))
		if err := caddy.Load([]byte(cfg), true); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
		req.Header.Set("Accept-Encoding", "br, gzip, deflate")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("set %s: %d, want %d", c.set, resp.StatusCode, c.want)
		}
	}
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
}
