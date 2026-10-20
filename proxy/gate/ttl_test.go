package gate

import (
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// ownTTL is a group whose site checks no token and sends no fingerprint (encarexport): enforce,
// site_gate off, skip_fp on the API, tokens for twelve hours.
func ownTTL(t *testing.T, now time.Time) *Handler {
	t.Helper()
	return enforcing(t, &Handler{SiteGate: "off", SkipFP: []string{"/api/"}, TokenTTL: caddy.Duration(12 * time.Hour)}, now)
}

// issuedAgo is a token of the group h, fingerprint fp and address ip, issued d before now.
func issuedAgo(h *Handler, now time.Time, d time.Duration, fp, ip string) string {
	return (&Handler{Secrets: h.Secrets, now: func() time.Time { return now.Add(-d) }}).sign(fp, ip)
}

// token_ttl is the lifetime of a site that checks nothing itself: only with site_gate off, from three
// minutes to a day.
func TestTokenTTLValidate(t *testing.T) {
	cases := []struct {
		name string
		h    Handler
		ok   bool
	}{
		{"12h, site_gate off", Handler{Mode: "enforce", SiteGate: "off", TokenTTL: caddy.Duration(12 * time.Hour)}, true},
		{"3m, site_gate off", Handler{Mode: "enforce", SiteGate: "off", TokenTTL: caddy.Duration(3 * time.Minute)}, true},
		{"24h, site_gate off", Handler{Mode: "enforce", SiteGate: "off", TokenTTL: caddy.Duration(24 * time.Hour)}, true},
		{"site_gate on", Handler{Mode: "enforce", SiteGate: "on", TokenTTL: caddy.Duration(time.Hour)}, false},
		{"site_gate unset", Handler{Mode: "log", TokenTTL: caddy.Duration(time.Hour)}, false},
		{"below 3m", Handler{Mode: "enforce", SiteGate: "off", TokenTTL: caddy.Duration(time.Minute)}, false},
		{"above a day", Handler{Mode: "enforce", SiteGate: "off", TokenTTL: caddy.Duration(25 * time.Hour)}, false},
	}
	for _, c := range cases {
		c.h.Name, c.h.Secrets = "a", []string{secret}
		if err := c.h.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// A group's own lifetime is the one its tokens pass by; without it, three minutes as before.
func TestTokenTTLVerify(t *testing.T) {
	now := time.Now()
	own := ownTTL(t, now)
	if _, reason := own.verify(issuedAgo(own, now, 11*time.Hour, fp, visitor), now); reason != "" {
		t.Errorf("11h old under 12h: %q", reason)
	}
	if _, reason := own.verify(issuedAgo(own, now, 13*time.Hour, fp, visitor), now); reason != "expired" {
		t.Errorf("13h old under 12h: %q, want expired", reason)
	}
	plain := enforcing(t, &Handler{}, now)
	if _, reason := plain.verify(issuedAgo(plain, now, 4*time.Minute, fp, visitor), now); reason != "expired" {
		t.Errorf("4m old without token_ttl: %q, want expired", reason)
	}
}

// The proxy's own cookie lives as long as the group's token.
func TestTokenTTLCookie(t *testing.T) {
	now := time.Now()
	h := ownTTL(t, now)
	w := through(t, h, request("GET", "/cars", visitor), site(200))
	cs := w.Result().Cookies()
	if len(cs) != 1 || cs[0].MaxAge != int((12*time.Hour)/time.Second) {
		t.Fatalf("%v", tokenCookies(w))
	}
	if pl, reason := h.verify(cs[0].Value, now); reason != "" || pl.ip != visitor {
		t.Errorf("%+v %q", pl, reason)
	}
}

// With its own lifetime, a token past half of it is renewed on the response of the request that brings
// it — the API's as well as a page's — keeping its fingerprint; a fresher one is left alone, a refused
// request gets none, and a group without token_ttl never renews on the API (its site does).
func TestTokenTTLRenewal(t *testing.T) {
	now := time.Now()
	own := ownTTL(t, now)
	plain := enforcing(t, &Handler{}, now)
	cases := []struct {
		name   string
		h      *Handler
		method string
		path   string
		token  string
		status int
		renew  bool
	}{
		{"api, 7h of 12h", own, "GET", "/api/encar/catalog", issuedAgo(own, now, 7*time.Hour, fp, visitor), 200, true},
		{"api POST, 7h of 12h", own, "POST", "/api/contact", issuedAgo(own, now, 7*time.Hour, fp, visitor), 200, true},
		{"api picture, 7h of 12h", own, "GET", "/api/encar/pics/1.jpg", issuedAgo(own, now, 7*time.Hour, "", visitor), 200, true},
		{"api, 1h of 12h", own, "GET", "/api/encar/catalog", issuedAgo(own, now, time.Hour, fp, visitor), 200, false},
		{"api, token of another address", own, "GET", "/api/encar/catalog", issuedAgo(own, now, 7*time.Hour, fp, "198.51.100.9"), 403, false},
		{"api, expired", own, "GET", "/api/encar/catalog", issuedAgo(own, now, 13*time.Hour, fp, visitor), 401, false},
		{"page, 7h of 12h", own, "GET", "/cars", issuedAgo(own, now, 7*time.Hour, fp, visitor), 200, true},
		{"page, 1h of 12h", own, "GET", "/cars", issuedAgo(own, now, time.Hour, fp, visitor), 200, false},
		{"no token_ttl, api, 2m of 3m", plain, "GET", "/api/encar/catalog", issuedAgo(plain, now, 2*time.Minute, fp, visitor), 200, false},
		{"no token_ttl, page, 2m of 3m", plain, "GET", "/cars", issuedAgo(plain, now, 2*time.Minute, fp, visitor), 200, false},
	}
	for _, c := range cases {
		r := request(c.method, c.path, visitor)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: c.token})
		w := through(t, c.h, r, site(200))
		if w.Code != c.status {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.status)
			continue
		}
		got := tokenCookies(w)
		if (len(got) == 1) != c.renew || len(got) > 1 {
			t.Errorf("%s: %v, want renewal=%v", c.name, got, c.renew)
			continue
		}
		if !c.renew {
			continue
		}
		old, _ := c.h.verify(c.token, now)
		pl, reason := c.h.verify(valueOf(got[0]), now)
		if reason != "" || pl.ip != visitor || pl.fp != old.fp || pl.iat != float64(now.UnixMilli()) {
			t.Errorf("%s: %+v %q, want ip %s fp %q issued now", c.name, pl, reason, visitor, old.fp)
		}
	}
}
