package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	secret  = strings.Repeat("s", 32)
	fp      = strings.Repeat("a", 64)
	visitor = "203.0.113.7"
)

// enforcing is a group in enforce with the test secret, the clock at now.
func enforcing(t *testing.T, h *Handler, now time.Time) *Handler {
	t.Helper()
	h.Mode, h.Secrets = "enforce", []string{secret}
	if h.Name == "" {
		h.Name = "site"
	}
	h.now = func() time.Time { return now }
	return provisioned(t, h)
}

// serve is a request through h, the app behind it answering 200.
func serve(t *testing.T, h *Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, pass); err != nil {
		t.Fatal(err)
	}
	return w
}

// Every refusal is the code and body of request-gate's, as application/json (AC2, the table (г)).
func TestRefusals(t *testing.T) {
	now := time.Now()
	h := enforcing(t, &Handler{}, now)
	valid := h.sign(fp, visitor)
	withToken := func(method, tok string, hdr map[string]string) *http.Request {
		r := request(method, "/api/encar/catalog", visitor)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	tokenIssue := request(http.MethodPost, tokenPath, visitor)
	tokenIssue.Host = "cars.example.com"
	tokenIssue.Header.Set("Origin", "https://evil.example")
	cases := []struct {
		name   string
		r      *http.Request
		status int
		body   string
	}{
		{"no token", request(http.MethodGet, "/api/encar/catalog", visitor), 401, `{"error":"Access denied"}`},
		{"bad signature", withToken("GET", valid[:len(valid)-2]+"xx", nil), 401, `{"error":"Access denied"}`},
		{"no ip", withToken("GET", h.sign(fp, ""), nil), 401, `{"error":"Access denied"}`},
		{"another fp", withToken("GET", valid, map[string]string{fpHeader: strings.Repeat("b", 64)}), 403, `{"error":"Fingerprint mismatch"}`},
		{"POST with a token without fp", withToken("POST", h.sign("", visitor), map[string]string{fpHeader: fp}), 403, `{"error":"Fingerprint mismatch"}`},
		{"POST without X-Fingerprint", withToken("POST", valid, nil), 403, `{"error":"Forbidden"}`},
		{"another address", withToken("GET", h.sign(fp, "198.51.100.9"), nil), 403, `{"error":"Token address mismatch"}`},
		{"token issue from another origin", tokenIssue, 403, `{"error":"Access denied"}`},
	}
	for _, c := range cases {
		w := serve(t, h, c.r)
		if w.Code != c.status || w.Body.String() != c.body || w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q %q, want %d %q application/json", c.name, w.Code, w.Body.String(), w.Header().Get("Content-Type"), c.status, c.body)
		}
	}
	if w := serve(t, h, withToken("GET", valid, map[string]string{fpHeader: fp})); w.Code != 200 {
		t.Errorf("a valid token: %d %s", w.Code, w.Body.String())
	}
}

// The exemptions of every site under the gate, from its src/proxy.ts: each path goes without a token
// (200) or is checked (401 without one), as request-gate decides it today (AC3, (е)).
func TestExemptions(t *testing.T) {
	pics := []string{"/api/encar/pics"}
	sites := map[string]Handler{
		"template":  {SkipFP: pics}, // dbauto, glavdoroga, koreaautotrade, myencar, onestar, wegugin, dkauto
		"82auto":    {Exempt: []Exempt{{Prefix: "/api/encar/"}}},
		"autogroup": {Gated: []string{"/api/admin/"}, SkipFP: []string{"/api/encar/pics", "/api/admin/"}},
		"autohubkorea": {SkipFP: pics, Exempt: []Exempt{{Exact: "/api/encar/pics"}, {Exact: "/api/encar/pics_i"},
			{Regex: `^/api/auctions/[^/]+/(image|video|registration-cert)`}, {Regex: `^/api/auctions/image-proxy`}}},
		"kiramax": {Exempt: []Exempt{{Exact: "/api/rates"}, {Exact: "/api/settings"}}, Gated: []string{"/api/admin/"},
			SkipFP: []string{"/api/encar/pics", "/api/admin/"}},
		"pakim-frontend": {Exempt: []Exempt{{Exact: "/api/china/sync"}}},
	}
	cases := []struct {
		site, method, path string
		exempt             bool
	}{
		// Every site's: the token's issue, the env check, the routes with their own authorization, the probe.
		{"template", "GET", "/api/auth/token", true}, // POST is issued by the proxy (TestIssue)
		{"template", "GET", "/api/env-check", true},
		{"template", "POST", "/api/admin/login", true},
		{"template", "GET", "/api/admin", true},
		{"template", "GET", "/api/auth/session", true},
		{"template", "GET", "/api/health", true},
		{"template", "HEAD", "/api/health", true},
		{"template", "POST", "/api/health", false},
		{"template", "GET", "/api/encar/catalog", false},
		{"template", "GET", "/api/encar/pics/1.jpg", false},
		{"template", "GET", "/api/adminx", false},
		{"82auto", "GET", "/api/encar/catalog", true},
		{"82auto", "GET", "/api/encar", true},
		{"82auto", "GET", "/api/encar/", true},
		{"82auto", "GET", "/api/encarx", false},
		{"82auto", "GET", "/api/rates", false},
		{"autogroup", "POST", "/api/admin/revalidate", false},
		{"autogroup", "GET", "/api/admin", false},
		{"autogroup", "GET", "/api/health", true},
		{"autogroup", "GET", "/api/auth/session", true},
		{"autohubkorea", "GET", "/api/encar/pics", true},
		{"autohubkorea", "GET", "/api/encar/pics_i", true},
		{"autohubkorea", "GET", "/api/encar/pics/1.jpg", false},
		{"autohubkorea", "GET", "/api/auctions/lot-1/image", true},
		{"autohubkorea", "GET", "/api/auctions/lot-1/video/2", true},
		{"autohubkorea", "GET", "/api/auctions/lot-1/registration-cert", true},
		{"autohubkorea", "GET", "/api/auctions/image-proxy", true},
		{"autohubkorea", "GET", "/api/auctions/lot-1/data", false},
		{"kiramax", "POST", "/api/rates", true},
		{"kiramax", "GET", "/api/settings", true},
		{"kiramax", "GET", "/api/rates/today", false},
		{"kiramax", "POST", "/api/admin/revalidate", false},
		{"pakim-frontend", "POST", "/api/china/sync", true},
		{"pakim-frontend", "POST", "/api/china/sync/now", false},
		{"pakim-frontend", "GET", "/api/encar/catalog", false},
	}
	now := time.Now()
	for _, c := range cases {
		cfg := sites[c.site]
		h := enforcing(t, &cfg, now)
		r := request(c.method, c.path, visitor)
		r.Host = "cars.example.com"
		r.Header.Set("Origin", "https://cars.example.com")
		w := serve(t, h, r)
		if got := w.Code == http.StatusOK; got != c.exempt {
			t.Errorf("%s %s %s: %d, want exempt=%v", c.site, c.method, c.path, w.Code, c.exempt)
		}
	}
}

// An exemption with methods covers those alone, as an exemptPaths entry {path, methods} does.
func TestExemptMethods(t *testing.T) {
	h := enforcing(t, &Handler{Exempt: []Exempt{{Exact: "/api/hook", Methods: []string{"POST"}}}}, time.Now())
	if w := serve(t, h, request("POST", "/api/hook", visitor)); w.Code != 200 {
		t.Errorf("POST: %d", w.Code)
	}
	if w := serve(t, h, request("GET", "/api/hook", visitor)); w.Code != 401 {
		t.Errorf("GET: %d", w.Code)
	}
}

// The token's issue needs the request's own host in Origin, or in Referer without one (request-gate's sameOrigin).
func TestTokenIssueOrigin(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	cases := []struct {
		origin, referer string
		ok              bool
	}{
		{"https://cars.example.com", "", true},
		{"https://CARS.example.com:443", "", true},
		{"", "https://cars.example.com/catalog?x=1", true},
		{"https://evil.example", "https://cars.example.com/", false},
		{"null", "", false},
		{"", "", false},
		{"https://cars.example.com:8443", "", false},
	}
	for _, c := range cases {
		r := request(http.MethodGet, tokenPath, visitor)
		r.Host = "cars.example.com"
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.referer != "" {
			r.Header.Set("Referer", c.referer)
		}
		if w := serve(t, h, r); (w.Code == 200) != c.ok {
			t.Errorf("origin %q referer %q: %d, want ok=%v", c.origin, c.referer, w.Code, c.ok)
		}
	}
}

// A partner's Bearer reads /api/encar/ of glavdoroga without the browser's token; a Bearer that does
// not match, or a write, goes to the token check like any request (AC11, R3).
func TestBearer(t *testing.T) {
	partner := strings.Repeat("p", 40)
	sum := sha256.Sum256([]byte(partner))
	h := enforcing(t, &Handler{SkipFP: []string{"/api/encar/pics"}, Bearer: &Bearer{
		Paths: []string{`^/api/encar(/|$)`}, Methods: []string{"GET", "HEAD"}, Digests: []string{hex.EncodeToString(sum[:]), strings.Repeat("0", 64)}}}, time.Now())
	cases := []struct {
		name, method, path, auth string
		status                   int
	}{
		{"valid GET", "GET", "/api/encar/catalog", "Bearer " + partner, 200},
		{"valid HEAD", "HEAD", "/api/encar/catalog", "Bearer " + partner, 200},
		{"scheme in any case, spaces", "GET", "/api/encar", "bearer   " + partner + " ", 200},
		{"another token", "GET", "/api/encar/catalog", "Bearer " + strings.Repeat("q", 40), 401},
		{"empty token", "GET", "/api/encar/catalog", "Bearer ", 401},
		{"no scheme", "GET", "/api/encar/catalog", partner, 401},
		{"no Authorization", "GET", "/api/encar/catalog", "", 401},
		{"POST with a valid one", "POST", "/api/encar/catalog", "Bearer " + partner, 401},
		{"outside its paths", "GET", "/api/rates", "Bearer " + partner, 401},
		{"a prefix that only looks like it", "GET", "/api/encarx", "Bearer " + partner, 401},
	}
	for _, c := range cases {
		r := request(c.method, c.path, visitor)
		if c.auth != "" {
			r.Header.Set("Authorization", c.auth)
		}
		if w := serve(t, h, r); w.Code != c.status {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.status)
		}
	}
	// A Bearer that does not let a request in leaves it to the token: the Bearer only adds a way in.
	for method, bearer := range map[string]string{"POST": partner, "GET": strings.Repeat("q", 40)} {
		r := request(method, "/api/encar/catalog", visitor)
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set(fpHeader, fp)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: h.sign(fp, visitor)})
		if w := serve(t, h, r); w.Code != 200 {
			t.Errorf("%s with a Bearer that does not pass and a token: %d", method, w.Code)
		}
	}
}

// No path that Go and Next.js resolve to different routes reaches the app without a token: the
// exempt /api/admin/ cannot be a way into the catalog (AC12, R7).
func TestUncleanPaths(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	cases := []struct {
		target string
		status int
	}{
		{"/api/admin/../encar/catalog", 401},
		{"/api/admin/%2e%2e/encar/catalog", 400},
		{"/api/admin/%2E%2E/encar/catalog", 400},
		{"/api/admin/..%2fencar/catalog", 400},
		{"/api/admin/..%2Fencar/catalog", 400},
		{"/api/admin/..%5cencar/catalog", 400},
		{`/api/admin/..\encar/catalog`, 400},
		{"/api/encar//../admin/x", 400},
		// An empty segment under /api/ is refused as well: Next.js keeps it, Go drops it.
		{"//api/encar/catalog", 400},
		{"/api//encar/catalog", 400},
		// An escaped slash with `..` moves the route anywhere, from a page's path too.
		{"/p%2fq/../api/encar/catalog", 400},
		{"/api/x/%2f/../../encar/catalog", 400},
		{"/p%5cq/../api/encar/catalog", 400},
		{`/api\encar\catalog`, 400},
		{"/api/admin/x", 200},
		// Next.js's data URLs, which it unwraps into any route, an API route included: refused whole.
		{"/_next/data/b1d/api/encar/catalog.json", 400},
		{"/_next/data/b1d/index/api/encar/catalog.json", 400},
		{"/_next/data/b1d/_next/data/b1d/api/encar/catalog.json.json", 400},
		{"/_next/data/b1d/catalog.json", 400},
		{"/_next/data", 400},
		{"/_next/static/chunks/a.js", 200},
		{"/_next/database", 200},
		// A page with the same characters is the app's business, not the gate's.
		{"/catalog/a%2fb", 200},
		{`/catalog/a\b`, 200},
		{"/catalog/../catalog/a", 200},
		// An escaped slash under /api/ is refused without a dot segment too.
		{"/api/auth%2Ftoken", 400},
		{"/api%2fencar/catalog", 400},
		// An escaped letter under /api/: Go matches the exempt /api/admin/, Next.js a dynamic sibling.
		{"/api/%61dmin/x", 400},
		{"/api/adm%69n/x", 400},
		{"/%61bout", 200},
	}
	for _, c := range cases {
		// Parsed as the server parses a request's target: no reference resolution, no host in "//".
		r := request("GET", "/", visitor)
		var err error
		if r.URL, err = url.ParseRequestURI(c.target); err != nil {
			t.Fatal(err)
		}
		if w := serve(t, h, r); w.Code != c.status {
			t.Errorf("%s: %d, want %d", c.target, w.Code, c.status)
		}
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]*Handler{
		"no name":       {Mode: "enforce", Secrets: []string{secret}},
		"bad mode":      {Name: "a", Mode: "ban", Secrets: []string{secret}},
		"no secret":     {Name: "a", Mode: "enforce"},
		"short secret":  {Name: "a", Mode: "enforce", Secrets: []string{"short"}},
		"three secrets": {Name: "a", Mode: "enforce", Secrets: []string{secret, secret, secret}},
	}
	for name, h := range cases {
		if err := h.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := map[string]*Handler{
		"two kinds":       {Exempt: []Exempt{{Exact: "/api/a", Prefix: "/api/"}}},
		"none":            {Exempt: []Exempt{{Methods: []string{"GET"}}}},
		"outside /api/":   {Exempt: []Exempt{{Prefix: "/"}}},
		"bad regex":       {Exempt: []Exempt{{Regex: "("}}},
		"bearer no paths": {Bearer: &Bearer{Digests: []string{strings.Repeat("0", 64)}}},
		"bearer digest":   {Bearer: &Bearer{Paths: []string{"^/api/"}, Digests: []string{"abc"}}},
		"bearer none":     {Bearer: &Bearer{Paths: []string{"^/api/"}}},
	}
	for name, h := range bad {
		h.now = time.Now
		if err := h.Provision(ctxForTest(t)); err == nil {
			t.Errorf("%s: provisioned", name)
		}
	}
}

// A write through a Next.js data URL is refused like a read.
func TestNextDataURLWrite(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	for _, target := range []string{"/_next/data/b1d/api/delivery/suggest.json", "/_next/data/b1d/index/api/delivery/suggest.json"} {
		if w := serve(t, h, request("POST", target, visitor)); w.Code != 400 {
			t.Errorf("POST %s: %d", target, w.Code)
		}
	}
}
