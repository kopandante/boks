package gate

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func issueRequest(body, contentType string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, tokenPath, strings.NewReader(body))
	r.RemoteAddr = visitor + ":40000"
	r.Host = "cars.example.com"
	r.Header.Set("Origin", "https://cars.example.com")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

// In enforce the proxy answers the token's issue itself, as route.ts does: 200 {"ok":true} and the
// cookie, now with the address Caddy decided; the token passes the API from there and from nowhere else.
func TestIssue(t *testing.T) {
	now := time.Now()
	h := enforcing(t, &Handler{}, now)
	r := issueRequest(`{"fingerprint":"`+fp+`"}`, "application/json; charset=utf-8")
	r.TLS = &tls.ConnectionState{}
	w := serve(t, h, r)
	if w.Code != 200 || w.Body.String() != `{"ok":true}` || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies %v", w.Header().Values("Set-Cookie"))
	}
	c := cookies[0]
	if c.Name != cookieName || c.Path != "/" || c.MaxAge != 180 || c.SameSite != http.SameSiteStrictMode || !c.Secure || c.HttpOnly {
		t.Errorf("cookie %s", w.Header().Get("Set-Cookie"))
	}
	if c.Expires.Sub(now.Add(180*time.Second)).Abs() > time.Second {
		t.Errorf("expires %v, want now+180s as Next writes it", c.Expires)
	}
	pl, reason := h.verify(c.Value, now)
	if reason != "" || pl.fp != fp || pl.ip != visitor {
		t.Errorf("token %+v %q", pl, reason)
	}
	api := func(ip string) int {
		r := request(http.MethodPost, "/api/encar/quote", ip)
		r.AddCookie(c)
		r.Header.Set(fpHeader, fp)
		return serve(t, h, r).Code
	}
	if got := api(visitor); got != 200 {
		t.Errorf("from its address: %d", got)
	}
	if got := api("198.51.100.9"); got != 403 {
		t.Errorf("from another: %d", got)
	}
	// Without TLS, Secure only where a trusted proxy in front says the visitor came by HTTPS.
	if w := serve(t, h, issueRequest(`{"fingerprint":"`+fp+`"}`, "application/json")); strings.Contains(w.Header().Get("Set-Cookie"), "Secure") {
		t.Errorf("plain HTTP: %s", w.Header().Get("Set-Cookie"))
	}
	plain := issueRequest(`{"fingerprint":"`+fp+`"}`, "application/json")
	plain.Header.Set("X-Forwarded-Proto", "https")
	if w := serve(t, h, plain); strings.Contains(w.Header().Get("Set-Cookie"), "Secure") {
		t.Errorf("X-Forwarded-Proto from an untrusted peer: %s", w.Header().Get("Set-Cookie"))
	}
	trusted := withVars(issueRequest(`{"fingerprint":"`+fp+`"}`, "application/json"), visitor, true)
	trusted.Header.Set("X-Forwarded-Proto", "https")
	if w := serve(t, h, trusted); !strings.Contains(w.Header().Get("Set-Cookie"), "Secure") {
		t.Errorf("X-Forwarded-Proto from a trusted proxy: %s", w.Header().Get("Set-Cookie"))
	}
}

// What route.ts refuses, the proxy refuses alike: 403 {"error":"Forbidden"}.
func TestIssueRefuses(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	cases := map[string]*http.Request{
		"no content type":             issueRequest(`{"fingerprint":"`+fp+`"}`, ""),
		"form":                        issueRequest(`fingerprint=`+fp, "application/x-www-form-urlencoded"),
		"not json":                    issueRequest(`{`, "application/json"),
		"null":                        issueRequest(`null`, "application/json"),
		"array":                       issueRequest(`[1]`, "application/json"),
		"no fingerprint":              issueRequest(`{}`, "application/json"),
		"a number":                    issueRequest(`{"fingerprint":1}`, "application/json"),
		"short":                       issueRequest(`{"fingerprint":"`+fp[1:]+`"}`, "application/json"),
		"upper case":                  issueRequest(`{"fingerprint":"`+strings.ToUpper(fp)+`"}`, "application/json"),
		"trailing garbage":            issueRequest(`{"fingerprint":"`+fp+`"} x`, "application/json"),
		"a valid prefix, cut at 4 KB": issueRequest(padded(`{"fingerprint":"`+fp+`"}`, maxIssueBody+1)+"x", "application/json"),
		"larger than 4 KB":            issueRequest(`{"fingerprint":"`+fp+`","pad":"`+strings.Repeat("x", 4096)+`"}`, "application/json"),
	}
	for name, r := range cases {
		w := serve(t, h, r)
		if w.Code != 403 || w.Body.String() != `{"error":"Forbidden"}` || w.Header().Get("Set-Cookie") != "" {
			t.Errorf("%s: %d %q %q", name, w.Code, w.Body.String(), w.Header().Get("Set-Cookie"))
		}
	}
}

// padded is body with spaces after it up to n bytes: valid JSON as long as body is.
func padded(body string, n int) string { return body + strings.Repeat(" ", n-len(body)) }

// A body of exactly the bound is read whole.
func TestIssueBodyAtTheBound(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	if w := serve(t, h, issueRequest(padded(`{"fingerprint":"`+fp+`"}`, maxIssueBody), "application/json")); w.Code != 200 {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
}
