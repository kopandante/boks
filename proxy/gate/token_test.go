package gate

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// vectors are testdata/vectors.json, written by scripts/gen-token-vectors.ts from the sites' own code:
// tokens createApiToken issued, and the verdict request-gate 1.7.0 gave each request carrying one.
type vectors struct {
	KeyCurrent  string   `json:"key_current"`
	KeyPrevious string   `json:"key_previous"`
	NowMS       int64    `json:"now_ms"`
	SkipFP      []string `json:"skip_fp"`
	Vectors     []struct {
		Name        string  `json:"name"`
		Class       string  `json:"class"`
		Token       string  `json:"token"`
		Via         string  `json:"via"`
		HeaderToken string  `json:"header_token"`
		Method      string  `json:"method"`
		Path        string  `json:"path"`
		Fingerprint string  `json:"fingerprint"`
		ClientIP    string  `json:"client_ip"`
		Site        verdict `json:"site"`
		Proxy       verdict `json:"proxy"`
	} `json:"vectors"`
}

type verdict struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// pass is the app behind the gate: 200 and no body, as NextResponse.next() reads in the vectors.
var pass = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

// request is a request from ip, through Caddy: its client_ip is the one the server decided.
func request(method, target, ip string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = net.JoinHostPort(ip, "40000")
	return r
}

// The proxy's verdict on every vector is its second column, and it differs from the site's only in
// the classes the plan lets it be stricter in: a token without the address, and base64url only Node's
// lenient decoder reads (AC1).
func TestVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Vectors) < 50 {
		t.Fatalf("%d vectors, want at least 50", len(v.Vectors))
	}
	h := provisioned(t, &Handler{Name: "site", Mode: "enforce", Secrets: []string{v.KeyCurrent, v.KeyPrevious}, SkipFP: v.SkipFP})
	h.now = func() time.Time { return time.UnixMilli(v.NowMS) }
	classes := map[string]int{}
	for _, c := range v.Vectors {
		classes[c.Class]++
		r := request(c.Method, c.Path, c.ClientIP)
		if c.Fingerprint != "" {
			r.Header.Set("X-Fingerprint", c.Fingerprint)
		}
		switch c.Via {
		case "header":
			r.Header.Set("X-Api-Token", c.Token)
		case "cookie-empty":
			r.Header.Set("Cookie", "x-api-token=")
			r.Header.Set("X-Api-Token", c.Token)
		default:
			if c.Token != "" {
				r.AddCookie(&http.Cookie{Name: "x-api-token", Value: c.Token})
			}
			if c.HeaderToken != "" {
				r.Header.Set("X-Api-Token", c.HeaderToken)
			}
		}
		w := httptest.NewRecorder()
		if err := h.ServeHTTP(w, r, pass); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got := verdict{w.Code, strings.TrimSuffix(w.Body.String(), "\n")}
		if got != c.Proxy {
			t.Errorf("%s [%s]: got %d %q, want %d %q", c.Name, c.Class, got.Status, got.Body, c.Proxy.Status, c.Proxy.Body)
		}
		if got.Status != http.StatusOK && w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: a refusal is application/json, got %q", c.Name, w.Header().Get("Content-Type"))
		}
		stricter := c.Class == "no_ip" || c.Class == "stricter"
		if (c.Site != c.Proxy) != stricter {
			t.Errorf("%s [%s]: site %v and proxy %v columns must differ exactly in no_ip and stricter", c.Name, c.Class, c.Site, c.Proxy)
		}
	}
	for _, want := range []string{"valid", "previous", "ttl", "signature", "ip", "no_ip", "stricter", "garbage"} {
		if classes[want] == 0 {
			t.Errorf("no vector of class %s", want)
		}
	}
}

// A token the proxy issues is one the sites' code takes: the format of api-token.ts, field by field.
func TestIssuedTokenFormat(t *testing.T) {
	h := provisioned(t, &Handler{Name: "site", Mode: "enforce", Secrets: []string{strings.Repeat("k", 32)}})
	now := time.UnixMilli(1_792_400_000_000)
	h.now = func() time.Time { return now }
	tok := h.sign("ab", "203.0.113.7")
	enc, _, _ := strings.Cut(tok, ".")
	raw, err := decodePayload(enc)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p["iat"] != float64(now.UnixMilli()) || p["fp"] != "ab" || p["ip"] != "203.0.113.7" || len(p["nonce"].(string)) != 16 {
		t.Errorf("payload %s", raw)
	}
	if !strings.HasPrefix(string(raw), `{"iat":`) {
		t.Errorf("iat first, as createApiToken writes it: %s", raw)
	}
	got, reason := h.verify(tok, now.Add(tokenTTL))
	if reason != "" || got.fp != "ab" || got.ip != "203.0.113.7" {
		t.Errorf("verify %+v %q", got, reason)
	}
	if _, reason := h.verify(tok, now.Add(tokenTTL+time.Millisecond)); reason != "expired" {
		t.Errorf("past the ttl: %q", reason)
	}
}

// Of two x-api-token cookies the last is the token, as Next.js parses the header; an empty last one
// leaves it to X-Api-Token, as request-gate's `|| header` does.
func TestDuplicateCookieLastCounts(t *testing.T) {
	h := provisioned(t, &Handler{Name: "site", Mode: "enforce", Secrets: []string{strings.Repeat("k", 32)}})
	valid := h.sign("", "203.0.113.7")
	stale := h.sign("", "198.51.100.9")
	for _, c := range []struct {
		cookie, header string
		want           int
	}{
		{"x-api-token=; x-api-token=" + valid, "", http.StatusOK},
		{"x-api-token=" + stale + "; x-api-token=" + valid, "", http.StatusOK},
		{"x-api-token=" + valid + "; x-api-token=" + stale, "", http.StatusForbidden},
		{"x-api-token=" + valid + "; x-api-token=", "", http.StatusUnauthorized},
		{"x-api-token=" + stale + "; x-api-token=", valid, http.StatusOK},
	} {
		r := request(http.MethodGet, "/api/encar/catalog", "203.0.113.7")
		r.Header.Set("Cookie", c.cookie)
		if c.header != "" {
			r.Header.Set("X-Api-Token", c.header)
		}
		w := httptest.NewRecorder()
		if err := h.ServeHTTP(w, r, pass); err != nil {
			t.Fatal(err)
		}
		if w.Code != c.want {
			t.Errorf("Cookie: %s, header %t: got %d, want %d", c.cookie, c.header != "", w.Code, c.want)
		}
	}
}

// The issue reads body.fingerprint by its exact name, as route.ts does; the last of two keys counts.
func TestIssueFingerprintKey(t *testing.T) {
	h := provisioned(t, &Handler{Name: "site", Mode: "enforce", Secrets: []string{strings.Repeat("k", 32)}})
	fp := strings.Repeat("a", 64)
	for body, want := range map[string]int{
		`{"fingerprint":"` + fp + `"}`:                    http.StatusOK,
		`{"Fingerprint":"` + fp + `"}`:                    http.StatusForbidden,
		`{"fingerprint":"` + fp + `","Fingerprint":null}`: http.StatusOK,
		`{"fingerprint":null,"fingerprint":"` + fp + `"}`: http.StatusOK,
		`{"fingerprint":"` + fp + `","fingerprint":null}`: http.StatusForbidden,
		`{"fingerprint":1}`:                               http.StatusForbidden,
	} {
		r := request(http.MethodPost, "/api/auth/token", "203.0.113.7")
		r.Body = io.NopCloser(strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		if err := h.issue(w, r, "203.0.113.7"); err != nil {
			t.Fatal(err)
		}
		if w.Code != want {
			t.Errorf("%s: got %d, want %d", body, w.Code, want)
		}
	}
}
