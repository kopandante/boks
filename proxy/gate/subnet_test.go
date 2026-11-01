package gate

import (
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// sameNet is one /24 of IPv4, one /64 of IPv6, a v4-mapped address as its IPv4 one, never across the
// families, never of what is no address (#173).
func TestSameNet(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"203.0.113.7", "203.0.113.7", true},
		{"203.0.113.7", "203.0.113.250", true},
		{"203.0.113.7", "203.0.112.7", false},
		{"203.0.113.7", "203.1.113.7", false},
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:eeee:dddd:cccc", true},
		{"2001:db8:1:2::1", "2001:db8:1:3::1", false},
		{"2001:DB8:1:2::1", "2001:db8:1:2::9", true},
		{"::ffff:203.0.113.7", "203.0.113.9", true},
		{"::ffff:203.0.113.7", "203.0.114.7", false},
		{"203.0.113.7", "::ffff:203.0.113.9", true},
		{"203.0.113.7", "2001:db8::7", false},
		// An IPv6 address whose /64 holds the IPv4 one's bytes is still another family.
		{"203.0.113.7", "cb00:7100::1", false},
		{"::cb00:7107", "203.0.113.7", false},
		{"fe80::1%eth0", "fe80::2", true},
		{"unknown", "unknown", false},
		{"", "203.0.113.7", false},
		{"203.0.113.7", "", false},
	}
	for _, c := range cases {
		if got := sameNet(c.a, c.b); got != c.want {
			t.Errorf("sameNet(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A token passes from another address of its network — a mobile operator moves its visitor within a
// /24 — and is refused from another network; gate_token_ip tells the exact, the network's and
// Googlebot's passes apart, and is written on a refusal after the token was read too (#173).
func TestTokenByNetwork(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	cases := []struct {
		name, signedFor, from string
		status                int
		reason, match         string
	}{
		{"its own address", visitor, visitor, 200, "token", "exact"},
		{"its own address v4-mapped", "::ffff:" + visitor, visitor, 200, "token", "exact"},
		{"the /24's next address", visitor, "203.0.113.8", 200, "token", "net"},
		{"the /24's last address", visitor, "203.0.113.255", 200, "token", "net"},
		{"v4-mapped, the /24's next", "::ffff:" + visitor, "203.0.113.99", 200, "token", "net"},
		{"another /24", visitor, "203.0.112.7", 403, "ip_mismatch", "no"},
		{"the next /24", visitor, "203.0.114.1", 403, "ip_mismatch", "no"},
		{"v4-mapped, another /24", "::ffff:" + visitor, "203.0.112.7", 403, "ip_mismatch", "no"},
		{"the /64's other address", "2001:db8:1:2::1", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", 200, "token", "net"},
		{"another /64", "2001:db8:1:2::1", "2001:db8:1:3::1", 403, "ip_mismatch", "no"},
		{"an IPv4 token from IPv6", visitor, "2001:db8::7", 403, "ip_mismatch", "no"},
		{"an IPv6 token from IPv4", "2001:db8::7", visitor, 403, "ip_mismatch", "no"},
		{"Googlebot from another /64 of Googlebot", "2001:4860:4801:10::1", "2001:4860:4801:11::7", 200, "token", "google"},
	}
	for _, c := range cases {
		r, extra := withLog(request(http.MethodGet, "/api/encar/catalog", c.from))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: h.sign(fp, c.signedFor)})
		w := serve(t, h, r)
		f := fields(extra)
		if w.Code != c.status || f["gate_reason"] != c.reason || f["gate_token_ip"] != c.match {
			t.Errorf("%s: %d %v, want %d %s %s", c.name, w.Code, f, c.status, c.reason, c.match)
		}
	}
	// A refusal past reading the token, before the address: the field is there.
	r, extra := withLog(request(http.MethodPost, "/api/encar/catalog", "203.0.113.8"))
	r.Header.Set(fpHeader, "b")
	r.AddCookie(&http.Cookie{Name: cookieName, Value: h.sign(fp, visitor)})
	if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "fp_mismatch" || fields(extra)["gate_token_ip"] != "net" {
		t.Errorf("fp_mismatch: %d %v", w.Code, fields(extra))
	}
	// No token, or one that fails its signature: no field.
	for _, tok := range []string{"", h.sign(fp, visitor) + "x"} {
		r, extra := withLog(request(http.MethodGet, "/api/encar/catalog", visitor))
		if tok != "" {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		}
		serve(t, h, r)
		if v, ok := fields(extra)["gate_token_ip"]; ok {
			t.Errorf("token %q: gate_token_ip %v", tok, v)
		}
	}
}

// page_first keeps an IPv4 address by its /24: a page from one address opens the API to the /24's
// others and to no other /24, and the /24's addresses are one entry (#173).
func TestPageFirstIPv4By24(t *testing.T) {
	now := time.Now()
	h := pageFirsting(t, &now, "enforce")
	serve(t, h, browserClient(chromeUA, "198.51.100.10").request(h, "GET", "/"))
	for _, ip := range []string{"198.51.100.10", "198.51.100.11", "198.51.100.254", "198.51.100.0"} {
		if code := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")).Code; code != 200 {
			t.Errorf("%s, the /24's page: %d", ip, code)
		}
	}
	for _, ip := range []string{"198.51.101.10", "198.51.99.10"} {
		r, extra := withLog(browserClient(chromeUA, ip).request(h, "GET", "/api/x"))
		if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "no_page" {
			t.Errorf("%s, another /24: %d %v", ip, w.Code, fields(extra))
		}
	}
	for i := range 50 {
		serve(t, h, browserClient(chromeUA, "198.51.100."+strconv.Itoa(i+20)).request(h, "GET", "/"))
	}
	if len(h.pages.last) != 1 {
		t.Errorf("one /24 kept as %d entries", len(h.pages.last))
	}
	// A v4-mapped address is its IPv4 one's entry.
	if pageKey("g", netip.MustParseAddr("::ffff:198.51.100.7")) != pageKey("g", netip.MustParseAddr("198.51.100.200")) {
		t.Error("v4-mapped: another entry")
	}
	if pageKey("g", netip.MustParseAddr("198.51.100.7")) == pageKey("g", netip.MustParseAddr("198.51.101.7")) {
		t.Error("two /24s: one entry")
	}
}

// static_rhythm keeps counting an IPv4 address by itself, not by pageKey's /24: two addresses of a /24
// are two entries (#173).
func TestStaticRhythmIPv4ByAddress(t *testing.T) {
	a, b := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")
	if rhythmKey("g", a) == rhythmKey("g", b) {
		t.Error("two addresses of a /24: one rhythm")
	}
	if rhythmKey("g", netip.MustParseAddr("2001:db8::1")) != rhythmKey("g", netip.MustParseAddr("2001:db8::2")) {
		t.Error("one /64: two rhythms")
	}
}
