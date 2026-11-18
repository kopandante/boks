package gate

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
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
		// Banned: the same address as a browser next is refused by the ban, not let by.
		if c.want == 403 {
			r, extra := withLog(browserClient(chromeUA, c.ip).request(h, "GET", "/api/auctions/heydealer/cars"))
			r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
			if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "signature_ban" {
				t.Errorf("%s, then as a browser: %d %v, want 403 signature_ban", c.name, w.Code, fields(extra))
			}
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

// A token issued to an address of a token pool passes from every other address of the same pool: Meta's in-app
// browser takes the page's token at 57.141.20.34 and calls the API from 57.141.20.42 (todo#419). Every ordered
// pair of the addresses below is asked, the token's and the request's each also written IPv4-mapped: a token
// passes from the address it was issued to, as written, or from any address of its pool — never across pools,
// never between a pool and an address of none. The verdict comes from the lists of addresses, not the ranges.
func TestTokenPool(t *testing.T) {
	pools := map[string]struct{ ranges, addrs []string }{
		"meta": {
			[]string{"57.141.16.0/21", "157.240.0.0/16", "2a03:2880::/32"},
			[]string{"57.141.20.34", "57.141.20.42", "157.240.9.9", "2a03:2880:10ff:1::1", "2a03:2880:20ff:2::7"},
		},
		"other": {[]string{"192.0.2.0/24"}, []string{"192.0.2.7", "192.0.2.9"}},
	}
	// Of no pool: a visitor, Meta's next address past its range, another network, an IPv6 one.
	none := []string{visitor, "57.141.24.1", "198.51.100.1", "2001:db8::1"}
	h := &Handler{RangeSets: map[string][]string{}}
	poolOf := map[string]string{}
	addrs := slices.Clone(none)
	for name, p := range pools {
		h.RangeSets[name] = p.ranges
		h.TokenPools = append(h.TokenPools, name)
		for _, a := range p.addrs {
			poolOf[a] = name
		}
		addrs = append(addrs, p.addrs...)
	}
	h = enforcing(t, h, time.Now())
	forms := func(a string) []string {
		if netip.MustParseAddr(a).Is4() {
			return []string{a, "::ffff:" + a}
		}
		return []string{a}
	}
	for _, signed := range addrs {
		for _, from := range addrs {
			pooled := poolOf[signed] != "" && poolOf[signed] == poolOf[from]
			for _, s := range forms(signed) {
				for _, f := range forms(from) {
					// The request's address is as Caddy decided it, unmapped (clientIP).
					want, reason := 403, "ip_mismatch"
					if s == from || pooled {
						want, reason = 200, "token"
					}
					r, extra := withLog(request(http.MethodGet, "/api/encar/catalog", f))
					r.AddCookie(&http.Cookie{Name: cookieName, Value: h.sign(fp, s)})
					if w := serve(t, h, r); w.Code != want || fields(extra)["gate_reason"] != reason {
						t.Errorf("token of %s from %s: %d %v, want %d %s", s, f, w.Code, fields(extra), want, reason)
					}
				}
			}
		}
	}
}

// Without token_pools two addresses of Meta's are two visitors, as before the pool — though a set holds both.
func TestNoTokenPoolKeepsAddressBinding(t *testing.T) {
	h := enforcing(t, &Handler{RangeSets: map[string][]string{"meta": {"57.141.16.0/21"}}}, time.Now())
	r, extra := withLog(request(http.MethodGet, "/api/encar/catalog", "57.141.20.42"))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: h.sign(fp, "57.141.20.34")})
	if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "ip_mismatch" {
		t.Errorf("%d %v", w.Code, fields(extra))
	}
}

// A token pool naming no set, or an empty one, is refused at Provision, not left to pool no one.
func TestTokenPoolNeedsASet(t *testing.T) {
	for name, h := range map[string]*Handler{
		"no set":    {TokenPools: []string{"meta"}},
		"wrong set": {RangeSets: map[string][]string{"other": {"203.0.113.0/24"}}, TokenPools: []string{"meta"}},
		"empty set": {RangeSets: map[string][]string{"meta": {}}, TokenPools: []string{"meta"}},
	} {
		h.Name, h.Mode, h.Secrets = "site", "enforce", []string{secret}
		if err := h.Provision(ctxForTest(t)); err == nil || !strings.Contains(err.Error(), "token_pools") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
