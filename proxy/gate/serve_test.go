package gate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/logging"
)

// withLog is r with the access log's extra fields, as Caddy's server gives every request.
func withLog(r *http.Request) (*http.Request, *caddyhttp.ExtraLogFields) {
	extra := new(caddyhttp.ExtraLogFields)
	return r.WithContext(context.WithValue(r.Context(), caddyhttp.ExtraLogFieldsCtxKey, extra)), extra
}

// fields are the string fields the handler added to the access log. ExtraLogFields has no reader, and
// its list is unexported: read by reflection, which reads a string without exporting it.
func fields(extra *caddyhttp.ExtraLogFields) map[string]any {
	out := map[string]any{}
	list := reflect.ValueOf(extra).Elem().FieldByName("fields")
	for i := range list.Len() {
		f := list.Index(i)
		out[f.FieldByName("Key").String()] = f.FieldByName("String").String()
	}
	return out
}

// The verdict goes into the access log, in log and enforce alike; the response carries none of it (R11).
func TestVerdictInAccessLog(t *testing.T) {
	for _, mode := range []string{"log", "enforce"} {
		h := enforcing(t, &Handler{Name: "koreaautotrade", App: "koreaautotrade"}, time.Now())
		h.Mode = mode
		r, extra := withLog(request("GET", "/api/encar/catalog", visitor))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: h.sign("", "")})
		w := serve(t, h, r)
		got := fields(extra)
		want := map[string]any{"gate_group": "koreaautotrade", "gate_mode": mode, "gate_verdict": "deny", "gate_reason": "no_ip"}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: %s = %v, want %v (%v)", mode, k, got[k], v, got)
			}
		}
		for k := range w.Header() {
			if strings.Contains(strings.ToLower(k), "gate") {
				t.Errorf("%s: the response names the gate: %s", mode, k)
			}
		}
	}
	// A page is nothing for the journal to record.
	h := enforcing(t, &Handler{}, time.Now())
	r, extra := withLog(request("GET", "/catalog", visitor))
	serve(t, h, r)
	if got := fields(extra); len(got) != 0 {
		t.Errorf("page: %v", got)
	}
}

// The handler failing is a pass while the sites still check (site_gate on), and 503 once the proxy is
// the only gate (off) — owner's decision 2. Either way the journal says so.
func TestFailure(t *testing.T) {
	for _, c := range []struct {
		siteGate string
		status   int
	}{{"", 200}, {"on", 200}, {"off", 503}} {
		h := enforcing(t, &Handler{SiteGate: c.siteGate}, time.Now())
		h.fault = func() { panic("boom") }
		r, extra := withLog(request("GET", "/api/encar/catalog", visitor))
		w := serve(t, h, r)
		if w.Code != c.status {
			t.Errorf("site_gate %q: %d, want %d", c.siteGate, w.Code, c.status)
		}
		if c.status == 503 && w.Body.String() != `{"error":"Service unavailable"}` {
			t.Errorf("503 body %q", w.Body.String())
		}
		if got := fields(extra); got["gate_verdict"] != "error" {
			t.Errorf("site_gate %q: journal %v", c.siteGate, got)
		}
	}
	if err := (&Handler{Name: "a", Mode: "log", SiteGate: "off", Secrets: []string{secret}}).Validate(); err == nil {
		t.Error("site_gate off outside enforce: accepted")
	}
	if err := (&Handler{Name: "a", Mode: "enforce", SiteGate: "maybe", Secrets: []string{secret}}).Validate(); err == nil {
		t.Error("site_gate maybe: accepted")
	}
}

// A failure while the response's cookie is fixed leaves the response as the site wrote it.
func TestCookieFailureLeavesResponse(t *testing.T) {
	h := enforcing(t, &Handler{}, time.Now())
	h.cookieFault = func() { panic("boom") }
	w := through(t, h, request("GET", "/catalog", visitor), site(200, cookieName+"=a.b; Path=/"))
	if w.Code != 200 || w.Header().Get("Set-Cookie") != cookieName+"=a.b; Path=/" {
		t.Errorf("%d %v", w.Code, w.Header().Values("Set-Cookie"))
	}
}

// The app gets X-Forwarded-For with the address Caddy decided first, in log and in enforce; off
// leaves the header as Caddy's reverse_proxy makes it (S13, T3).
func TestForwardedFor(t *testing.T) {
	for _, mode := range []string{"off", "log", "enforce"} {
		h := enforcing(t, &Handler{}, time.Now())
		h.Mode = mode
		var got string
		app := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			got = r.Header.Get("X-Forwarded-For")
			return nil
		})
		r := withVars(request("GET", "/catalog", "10.88.0.11"), visitor, true)
		r.Header.Set("X-Forwarded-For", "1.2.3.4, "+visitor)
		through(t, h, r, app)
		want := visitor
		if mode == "off" {
			want = "1.2.3.4, " + visitor
		}
		if got != want {
			t.Errorf("%s: %q, want %q", mode, got, want)
		}
	}
}

// Through Caddy itself — its trusted proxies, the gate, reverse_proxy — the first address of
// X-Forwarded-For at the app is the client Caddy decided, whatever the visitor wrote on its left: on a
// connection from an untrusted peer and from a trusted one (AC15). The access log carries the verdict.
func TestThroughCaddy(t *testing.T) {
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Forwarded-For"))
	}))
	defer upstream.Close()
	logFile := filepath.Join(t.TempDir(), "access.log")
	for _, c := range []struct {
		name, trusted, xff, wantFirst string
	}{
		{"untrusted peer", "10.88.0.11/32", "1.2.3.4", "127.0.0.1"},
		{"trusted peer", "127.0.0.1/32", "1.2.3.4, 198.51.100.7", "198.51.100.7"},
	} {
		port := freePort(t)
		cfg := fmt.Sprintf(`{"admin":{"disabled":true},
"logging":{"logs":{"default":{"writer":{"output":"file","filename":%q},"encoder":{"format":"json"}}}},
"apps":{"http":{"servers":{"s":{"listen":["127.0.0.1:%d"],"logs":{},
 "trusted_proxies":{"source":"static","ranges":[%q]},"client_ip_headers":["X-Forwarded-For"],"trusted_proxies_strict":1,
 "routes":[
  {"handle":[{"handler":"boks_gate","name":"site","mode":"log","secrets":[%q]}]},
  {"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":%q}]}]}]}}}}}`,
			logFile, port, c.trusted, secret, strings.TrimPrefix(upstream.URL, "http://"))
		if err := caddy.Load([]byte(cfg), true); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/encar/catalog", port), nil)
		req.Header.Set("X-Forwarded-For", c.xff)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		first := strings.TrimSpace(strings.Split(seen[len(seen)-1], ",")[0])
		if first != c.wantFirst {
			t.Errorf("%s: X-Forwarded-For at the app %q, first %q, want %q", c.name, seen[len(seen)-1], first, c.wantFirst)
		}
	}
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	verdicts := 0
	for sc := bufio.NewScanner(f); sc.Scan(); {
		var entry map[string]any
		if json.Unmarshal(sc.Bytes(), &entry) == nil && entry["gate_verdict"] == "deny" && entry["gate_reason"] == "no_token" && entry["status"] == float64(200) {
			verdicts++
		}
	}
	if verdicts != 2 {
		t.Errorf("access log: %d entries with the verdict beside the site's status, want 2", verdicts)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
