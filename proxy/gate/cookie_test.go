package gate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// site is the app behind the gate answering with the Set-Cookie lines given.
func site(status int, setCookies ...string) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		for _, c := range setCookies {
			w.Header().Add("Set-Cookie", c)
		}
		w.WriteHeader(status)
		return nil
	})
}

func through(t *testing.T, h *Handler, r *http.Request, app caddyhttp.Handler) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, app); err != nil {
		t.Fatal(err)
	}
	return w
}

// tokenCookies are the x-api-token lines of a response.
func tokenCookies(w *httptest.ResponseRecorder) []string {
	var out []string
	for _, l := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(l, cookieName+"=") {
			out = append(out, l)
		}
	}
	return out
}

func valueOf(line string) string {
	v, _, _ := strings.Cut(strings.TrimPrefix(line, cookieName+"="), ";")
	return v
}

// The token a page sets — without the address, or with the fingerprint of the token it replaces (pakim)
// — leaves the proxy with the address Caddy decided; the fingerprint stays only when the site signed
// it, the cookie's attributes as the site wrote them (R1, S4).
func TestSiteCookieReplaced(t *testing.T) {
	now := time.Now()
	h := enforcing(t, &Handler{}, now)
	stranger := &Handler{Secrets: []string{strings.Repeat("x", 32)}, now: h.now}
	cases := []struct {
		name, siteToken, wantFP string
	}{
		{"page token without fp and ip", h.sign("", ""), ""},
		{"page token with fp of the old one (pakim)", h.sign(fp, "198.51.100.9"), fp},
		{"a token the group's secret did not sign", stranger.sign(fp, ""), ""},
	}
	for _, c := range cases {
		attrs := "; Path=/; Expires=Mon, 19 Oct 2026 00:03:00 GMT; Max-Age=180; Secure; SameSite=strict"
		w := through(t, h, request("GET", "/catalog", visitor), site(200, cookieName+"="+c.siteToken+attrs, "NEXT_LOCALE=ru; Path=/"))
		got := tokenCookies(w)
		if len(got) != 1 {
			t.Fatalf("%s: %v", c.name, got)
		}
		if !strings.HasSuffix(got[0], attrs) || valueOf(got[0]) == c.siteToken {
			t.Errorf("%s: %s", c.name, got[0])
		}
		pl, reason := h.verify(valueOf(got[0]), now)
		if reason != "" || pl.ip != visitor || pl.fp != c.wantFP {
			t.Errorf("%s: %+v %q, want ip %s fp %q", c.name, pl, reason, visitor, c.wantFP)
		}
		if l := w.Header().Values("Set-Cookie"); len(l) != 2 || l[1] != "NEXT_LOCALE=ru; Path=/" {
			t.Errorf("%s: the site's other cookies stay: %v", c.name, l)
		}
	}
	// Two lines of the token from the site leave as one.
	w := through(t, h, request("GET", "/catalog", visitor), site(200, cookieName+"=a.b; Path=/", cookieName+"=c.d; Path=/x"))
	if got := tokenCookies(w); len(got) != 1 {
		t.Errorf("two from the site: %v", got)
	}
}

// Where the site set no cookie, the proxy sets its own on the requests the sites set it on today: a
// GET of a page — an RSC request and a 304 alike — without a valid token of this address; never on
// /api/, Next.js's files, the metadata and the public assets, nor beside a valid token (S3, T1).
func TestOwnCookie(t *testing.T) {
	now := time.Now()
	h := enforcing(t, &Handler{}, now)
	signedElsewhere := h.sign(fp, "198.51.100.9")
	stranger := (&Handler{Secrets: []string{strings.Repeat("x", 32)}, now: h.now}).sign(fp, visitor)
	cases := []struct {
		name, method, path string
		status             int
		header             map[string]string
		token              string
		set                bool
		wantFP             string
	}{
		{name: "page", method: "GET", path: "/catalog", status: 200, set: true},
		{name: "RSC navigation", method: "GET", path: "/catalog/1", status: 200, header: map[string]string{"RSC": "1"}, set: true},
		{name: "304", method: "GET", path: "/catalog", status: 304, set: true},
		{name: "page with a valid token of this address", method: "GET", path: "/catalog", status: 200, token: h.sign("", visitor)},
		{name: "page with a token of another address", method: "GET", path: "/catalog", status: 200, token: signedElsewhere, set: true, wantFP: fp},
		{name: "page with a token another secret signed", method: "GET", path: "/catalog", status: 200, token: stranger, set: true},
		{name: "page with an expired token", method: "GET", path: "/catalog", status: 200, token: (&Handler{Secrets: h.Secrets, now: func() time.Time { return now.Add(-time.Hour) }}).sign(fp, visitor), set: true},
		{name: "api", method: "GET", path: "/api/health", status: 200},
		{name: "next static", method: "GET", path: "/_next/static/chunks/a.js", status: 200},
		{name: "next image", method: "GET", path: "/_next/image", status: 200},
		{name: "favicon", method: "GET", path: "/favicon.ico", status: 200},
		{name: "icon", method: "GET", path: "/icon", status: 200},
		{name: "manifest", method: "GET", path: "/manifest.webmanifest", status: 200},
		{name: "public asset", method: "GET", path: "/logo.svg", status: 200},
		{name: "POST to a page", method: "POST", path: "/catalog", status: 200},
		{name: "HEAD", method: "HEAD", path: "/catalog", status: 200},
	}
	for _, c := range cases {
		r := request(c.method, c.path, visitor)
		for k, v := range c.header {
			r.Header.Set(k, v)
		}
		if c.token != "" {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: c.token})
		}
		w := through(t, h, r, site(c.status))
		got := tokenCookies(w)
		if (len(got) == 1) != c.set || len(got) > 1 {
			t.Errorf("%s: %v, want set=%v", c.name, got, c.set)
			continue
		}
		if !c.set {
			continue
		}
		pl, reason := h.verify(valueOf(got[0]), now)
		if reason != "" || pl.ip != visitor || pl.fp != c.wantFP {
			t.Errorf("%s: %+v %q, want fp %q", c.name, pl, reason, c.wantFP)
		}
		ck := w.Result().Cookies()[0]
		if ck.Path != "/" || ck.MaxAge != 180 || ck.SameSite != http.SameSiteStrictMode || ck.HttpOnly {
			t.Errorf("%s: %s", c.name, got[0])
		}
	}
}

// In log the proxy changes nothing of the response: the site's cookie leaves as the site set it, and
// none is added (R1, д2).
func TestLogLeavesResponse(t *testing.T) {
	now := time.Now()
	h := enforcing(t, &Handler{}, now)
	h.Mode = "log"
	line := cookieName + "=" + h.sign("", "") + "; Path=/"
	w := through(t, h, request("GET", "/catalog", visitor), site(200, line))
	if got := w.Header().Values("Set-Cookie"); len(got) != 1 || got[0] != line {
		t.Errorf("site cookie: %v", got)
	}
	if got := tokenCookies(through(t, h, request("GET", "/catalog", visitor), site(200))); len(got) != 0 {
		t.Errorf("own cookie in log: %v", got)
	}
	if w := through(t, h, request("GET", "/api/encar/catalog", visitor), site(200)); w.Code != 200 {
		t.Errorf("a refused request passes in log: %d", w.Code)
	}
	if w := through(t, h, issueRequest(`{"fingerprint":"`+fp+`"}`, "application/json"), site(200)); w.Code != 200 || len(tokenCookies(w)) != 0 {
		t.Errorf("the issue goes to the site in log: %d %v", w.Code, tokenCookies(w))
	}
}

// A streamed response — Next.js's RSC — is flushed as it comes, the cookie fixed before the headers
// leave, whichever comes first: the status, the body or a flush.
func TestStreamedResponse(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	for name, app := range map[string]caddyhttp.HandlerFunc{
		"status, body, flush": func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("chunk"))
			return http.NewResponseController(w).Flush()
		},
		"flush first": func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			return http.NewResponseController(w).Flush()
		},
		"early hints, then the response": func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Link", "</_next/static/a.css>; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			w.WriteHeader(200)
			return nil
		},
		"body first": func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			_, err := w.Write([]byte("chunk"))
			return err
		},
	} {
		w := through(t, h, request("GET", "/catalog", visitor), app)
		got := tokenCookies(w)
		if len(got) != 1 || valueOf(got[0]) == "a.b" {
			t.Errorf("%s: %v", name, got)
		}
		if strings.HasPrefix(name, "status") || strings.HasPrefix(name, "flush") {
			if !w.Flushed {
				t.Errorf("%s: not flushed", name)
			}
		}
	}
	// The wrapper hands the writer below it to Caddy's ResponseController (Hijack, deadlines).
	app := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok || u.Unwrap() == nil {
			t.Error("no Unwrap")
		}
		return nil
	})
	through(t, h, request("GET", "/catalog", visitor), app)
}
