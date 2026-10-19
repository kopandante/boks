package gate

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
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
		{"an expired one the group signed", (&Handler{Secrets: h.Secrets, now: func() time.Time { return now.Add(-time.Hour) }}).sign(fp, ""), fp},
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
	// The site issues a page token without fp when the old one expired: the fp the old one carried,
	// signed, stays with the visitor.
	expired := (&Handler{Secrets: h.Secrets, now: func() time.Time { return now.Add(-time.Hour) }}).sign(fp, visitor)
	r := request("GET", "/catalog", visitor)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: expired})
	got := tokenCookies(through(t, h, r, site(200, cookieName+"="+h.sign("", "")+"; Path=/")))
	if pl, reason := h.verify(valueOf(got[0]), now); len(got) != 1 || reason != "" || pl.fp != fp || pl.ip != visitor {
		t.Errorf("renewed over an expired token: %v %+v %q", got, pl, reason)
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
		{name: "page with an expired token", method: "GET", path: "/catalog", status: 200, token: (&Handler{Secrets: h.Secrets, now: func() time.Time { return now.Add(-time.Hour) }}).sign(fp, visitor), set: true, wantFP: fp},
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
// leave, whichever comes first: the status, the body or a flush; an early hint goes ahead without it.
// Checked on the wire, through a real server: the headers the client receives, and the stream reaching
// it while the app still holds the response open.
func TestStreamedResponse(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	type streamApp func(w http.ResponseWriter, release <-chan struct{})
	// The app holds the response open until the client has read the chunk: a stream that only arrives
	// once the app lets go fails here rather than arriving late.
	hold := func(release <-chan struct{}) {
		select {
		case <-release:
		case <-time.After(3 * time.Second):
			t.Error("the client did not get the chunk while the app held the response open")
		}
	}
	for _, c := range []struct {
		name   string
		app    streamApp
		stream bool // the client reads a chunk before the app lets go
		hint   bool
	}{
		{"status, body, flush", func(w http.ResponseWriter, release <-chan struct{}) {
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("chunk"))
			_ = http.NewResponseController(w).Flush()
			hold(release)
		}, true, false},
		{"flush first", func(w http.ResponseWriter, release <-chan struct{}) {
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			_ = http.NewResponseController(w).Flush()
			_, _ = w.Write([]byte("chunk"))
			_ = http.NewResponseController(w).Flush()
			hold(release)
		}, true, false},
		{"early hints, then the response", func(w http.ResponseWriter, release <-chan struct{}) {
			w.Header().Set("Link", "</_next/static/a.css>; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			w.WriteHeader(200)
		}, false, true},
		{"body first", func(w http.ResponseWriter, release <-chan struct{}) {
			w.Header().Add("Set-Cookie", cookieName+"=a.b; Path=/")
			_, _ = w.Write([]byte("chunk"))
		}, false, false},
	} {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				c.app(w, release)
				return nil
			}))
		}))
		hints := 0
		req, _ := http.NewRequest("GET", srv.URL+"/catalog", nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			Got1xxResponse: func(code int, hdr textproto.MIMEHeader) error {
				if code == http.StatusEarlyHints {
					hints++
					if len(hdr.Values("Set-Cookie")) != 0 {
						t.Errorf("%s: a cookie on the early hint", c.name)
					}
				}
				return nil
			}}))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, l := range resp.Header.Values("Set-Cookie") {
			if strings.HasPrefix(l, cookieName+"=") {
				got = append(got, l)
			}
		}
		if len(got) != 1 || valueOf(got[0]) == "a.b" {
			t.Errorf("%s: cookies on the wire %v", c.name, got)
		}
		if c.stream {
			buf := make([]byte, 5)
			if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "chunk" {
				t.Errorf("%s: the chunk did not stream: %q %v", c.name, buf, err)
			}
		}
		if c.hint && hints != 1 {
			t.Errorf("%s: %d early hints reached the client", c.name, hints)
		}
		close(release)
		resp.Body.Close()
		srv.Close()
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

// The race T9 names: a page response of pakim that left before the client's token issue arrives after
// it and overwrites the fp token with one without fp (pakim copies fp only from the request's token,
// and that request had none). Through the proxy a GET still passes — the 1.7.0 relaxation — and a
// write gets 403 with "mismatch", on which the client refreshes once; the refreshed token passes.
func TestDelayedPageResponseCostsOneRefresh(t *testing.T) {
	now := time.Now()
	h := enforcing(t, &Handler{}, now)
	issue := func() *http.Cookie {
		w := serve(t, h, issueRequest(`{"fingerprint":"`+fp+`"}`, "application/json"))
		if w.Code != 200 {
			t.Fatalf("issue: %d", w.Code)
		}
		return w.Result().Cookies()[0]
	}
	jar := issue()
	// The delayed page response: its request carried no token, pakim set one without fp.
	page := through(t, h, request("GET", "/catalog", visitor), site(200, cookieName+"="+h.sign("", "")+"; Path=/"))
	jar = page.Result().Cookies()[0]
	if pl, _ := h.verify(jar.Value, now); pl.fp != "" || pl.ip != visitor {
		t.Fatalf("the page's cookie: %+v", pl)
	}
	api := func(method string, c *http.Cookie) *httptest.ResponseRecorder {
		r := request(method, "/api/encar/catalog", visitor)
		r.AddCookie(c)
		r.Header.Set(fpHeader, fp)
		return serve(t, h, r)
	}
	if w := api("GET", jar); w.Code != 200 {
		t.Errorf("GET after the overwrite: %d %s", w.Code, w.Body.String())
	}
	refreshes := 0
	w := api("POST", jar)
	for w.Code == 401 || (w.Code == 403 && strings.Contains(w.Body.String(), "mismatch")) {
		if refreshes++; refreshes > 1 {
			t.Fatalf("more than one refresh: %d %s", w.Code, w.Body.String())
		}
		jar = issue()
		w = api("POST", jar)
	}
	if refreshes != 1 || w.Code != 200 {
		t.Errorf("want one refresh, then 200: %d refreshes, %d %s", refreshes, w.Code, w.Body.String())
	}
}
