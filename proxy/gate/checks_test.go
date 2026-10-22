package gate

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	chromeUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"
	safariUA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
	webviewUA = "Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.7390.122 Mobile Safari/537.36 Telegram-Android/12.1.1"
	googleUA  = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.122 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	stormUA   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)

// client is how a request of a kind of client looks to the gate: its headers, its protocol, its address.
type client struct {
	ua        string
	fetchMeta bool // Sec-Fetch-Site same-origin, -Mode cors, -Dest empty
	fpHeader  bool
	tokenFP   bool // the token carries the fingerprint
	h2        bool
	ip        string
	trusted   bool // the connection is a trusted proxy's in front of the server
}

func (c client) request(h *Handler, method, target string) *http.Request {
	ip := c.ip
	if ip == "" {
		ip = visitor
	}
	r := withVars(request(method, target, ip), ip, c.trusted)
	r.TLS = &tls.ConnectionState{}
	if c.h2 {
		r.ProtoMajor, r.ProtoMinor, r.Proto = 2, 0, "HTTP/2.0"
		r.TLS.NegotiatedProtocol = "h2"
	}
	if c.ua != "" {
		r.Header.Set("User-Agent", c.ua)
	}
	if c.fetchMeta {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		r.Header.Set("Sec-Fetch-Dest", "empty")
	}
	if c.fpHeader {
		r.Header.Set(fpHeader, fp)
	}
	tfp := ""
	if c.tokenFP {
		tfp = fp
	}
	r.AddCookie(&http.Cookie{Name: cookieName, Value: h.sign(tfp, ip)})
	return r
}

var allLog = &Checks{FP: "log", FetchMeta: "log", ALPN: "log"}

// Which checks each kind of client fails — the classes of the plan's measurement (section 1.1): the
// browsers, the in-app ones and Google fail none; the storm fails alpn alone; a script with a page's
// cookie fails all three; an exempt address none.
func TestShadowByClient(t *testing.T) {
	browser := client{fetchMeta: true, fpHeader: true, tokenFP: true, h2: true}
	with := func(c client, f func(*client)) client { f(&c); return c }
	cases := []struct {
		name string
		c    client
		want string
	}{
		{"Chrome on h2", with(browser, func(c *client) { c.ua = chromeUA }), ""},
		{"Firefox on h2", with(browser, func(c *client) { c.ua = firefoxUA }), ""},
		{"Safari on h2", with(browser, func(c *client) { c.ua = safariUA }), ""},
		{"Telegram WebView on h2", with(browser, func(c *client) { c.ua = webviewUA }), ""},
		{"the storm: everything but h2", with(browser, func(c *client) { c.ua, c.h2 = stormUA, false }), "alpn"},
		{"Firefox on h1", with(browser, func(c *client) { c.ua, c.h2 = firefoxUA, false }), "alpn"},
		{"Chrome on h1 past a trusted proxy", with(browser, func(c *client) { c.ua, c.h2, c.trusted = chromeUA, false, true }), ""},
		{"a page's cookie, no fingerprint, no Fetch Metadata, h1", client{ua: chromeUA}, "fp,fetch_meta,alpn"},
		{"the header but a page's token", with(browser, func(c *client) { c.ua, c.tokenFP = chromeUA, false }), "fp"},
		{"Chrome/129 with no Fetch Metadata on h2", client{ua: chromeUA, h2: true, fpHeader: true, tokenFP: true}, "fetch_meta"},
		{"axios: not a browser, so no alpn", client{ua: "axios/1.20.0"}, "fp,fetch_meta"},
		{"n8n", client{ua: "n8n"}, "fp,fetch_meta"},
		{"Googlebot from Google", client{ua: googleUA, fpHeader: true, tokenFP: true, ip: "66.249.66.1"}, ""},
		{"Read Aloud from Google", client{ua: chromeUA, fpHeader: true, tokenFP: true, ip: "142.250.32.5"}, ""},
		{"Googlebot from Google without the fingerprint", client{ua: googleUA, ip: "66.249.66.1"}, "fp"},
		{"Googlebot's name from elsewhere", client{ua: googleUA, fpHeader: true, tokenFP: true}, "fetch_meta,alpn"},
		{"an exempt address", client{ua: chromeUA, ip: "139.100.226.95"}, ""},
		{"the exempt address's neighbour", client{ua: chromeUA, ip: "139.100.226.96"}, "fp,fetch_meta,alpn"},
		{"an exempt range", client{ua: chromeUA, ip: "86.57.245.110"}, ""},
	}
	for _, c := range cases {
		h := enforcing(t, &Handler{Checks: &Checks{FP: "log", FetchMeta: "log", ALPN: "log",
			ExemptRanges: []string{"139.100.226.95", "86.57.245.0/24"}}}, time.Now())
		h.Mode = "log"
		r, extra := withLog(c.c.request(h, "GET", "/api/encar/catalog"))
		w := serve(t, h, r)
		got, _ := fields(extra)["gate_shadow"].(string)
		if got != c.want || w.Code != 200 {
			t.Errorf("%s: gate_shadow %q (%d), want %q", c.name, got, w.Code, c.want)
		}
	}
}

// In log the checks change nothing: the verdict is the token's, gate_shadow beside it.
func TestShadowInLog(t *testing.T) {
	for _, mode := range []string{"log", "enforce"} {
		h := enforcing(t, &Handler{Checks: allLog}, time.Now())
		h.Mode = mode
		r, extra := withLog(client{ua: stormUA, fetchMeta: true, fpHeader: true, tokenFP: true}.request(h, "GET", "/api/encar/catalog"))
		w := serve(t, h, r)
		got := fields(extra)
		if w.Code != 200 || got["gate_verdict"] != "allow" || got["gate_reason"] != "token" || got["gate_shadow"] != "alpn" {
			t.Errorf("%s: %d %v", mode, w.Code, got)
		}
	}
	// A check off is not asked.
	h := enforcing(t, &Handler{Checks: &Checks{FP: "off", FetchMeta: "log"}}, time.Now())
	r, extra := withLog(client{ua: chromeUA}.request(h, "GET", "/api/encar/catalog"))
	serve(t, h, r)
	if got := fields(extra)["gate_shadow"]; got != "fetch_meta" {
		t.Errorf("fp off: gate_shadow %v", got)
	}
}

// In enforce a failed check refuses what the token lets through: fp as the client refreshes its token
// on, the others as request-gate's Forbidden; a refusal of the token itself stands as it was.
func TestChecksEnforced(t *testing.T) {
	cases := []struct {
		name   string
		checks *Checks
		c      client
		status int
		body   string
		reason string
		shadow string
	}{
		{"fp", &Checks{FP: "enforce"}, client{ua: chromeUA, fetchMeta: true, h2: true}, 403, `{"error":"Fingerprint mismatch"}`, "check_fp", "fp"},
		{"fetch_meta", &Checks{FetchMeta: "enforce"}, client{ua: chromeUA, h2: true}, 403, `{"error":"Forbidden"}`, "check_fetch_meta", "fetch_meta"},
		{"alpn", &Checks{ALPN: "enforce"}, client{ua: stormUA, fetchMeta: true, fpHeader: true, tokenFP: true}, 403, `{"error":"Forbidden"}`, "check_alpn", "alpn"},
		{"the first enforced of two", &Checks{FP: "log", FetchMeta: "enforce", ALPN: "enforce"}, client{ua: chromeUA}, 403, `{"error":"Forbidden"}`, "check_fetch_meta", "fp,fetch_meta,alpn"},
		{"log beside enforce", &Checks{FP: "log", ALPN: "enforce"}, client{ua: chromeUA, h2: true}, 200, "", "token", "fp"},
		{"a browser passes", &Checks{FP: "enforce", FetchMeta: "enforce", ALPN: "enforce"}, client{ua: chromeUA, fetchMeta: true, fpHeader: true, tokenFP: true, h2: true}, 200, "", "token", ""},
	}
	for _, c := range cases {
		h := enforcing(t, &Handler{Checks: c.checks}, time.Now())
		r, extra := withLog(c.c.request(h, "GET", "/api/encar/catalog"))
		w := serve(t, h, r)
		got := fields(extra)
		if w.Code != c.status || (c.body != "" && w.Body.String() != c.body) || got["gate_reason"] != c.reason || got["gate_shadow"] != map[bool]any{true: nil, false: c.shadow}[c.shadow == ""] {
			t.Errorf("%s: %d %q %v", c.name, w.Code, w.Body.String(), got)
		}
	}
	// The token's own refusal is answered as before, the checks it fails beside it.
	h := enforcing(t, &Handler{Checks: &Checks{FP: "enforce", ALPN: "enforce"}}, time.Now())
	r, extra := withLog(request("GET", "/api/encar/catalog", visitor))
	r.Header.Set("User-Agent", chromeUA)
	r.TLS = &tls.ConnectionState{}
	w := serve(t, h, r)
	if got := fields(extra); w.Code != 401 || got["gate_reason"] != "no_token" || got["gate_shadow"] != "fp,alpn" {
		t.Errorf("no token: %d %v", w.Code, got)
	}
}

// On a skip_fp path the fingerprint is not asked, and Fetch Metadata only for same-origin: an <img>
// sends no-cors and image. The exemptions and the partner's Bearer are asked nothing.
func TestChecksPaths(t *testing.T) {
	partner := strings.Repeat("p", 40)
	sum := sha256.Sum256([]byte(partner))
	h := enforcing(t, &Handler{SkipFP: []string{"/api/encar/pics"}, Exempt: []Exempt{{Prefix: "/api/rates"}},
		Bearer: &Bearer{Paths: []string{"^/api/encar/"}, Methods: []string{"GET"}, Digests: []string{hex.EncodeToString(sum[:])}},
		Checks: &Checks{FP: "enforce", FetchMeta: "enforce", ALPN: "log"}}, time.Now())
	img := client{ua: chromeUA, h2: true}.request(h, "GET", "/api/encar/pics/1.jpg")
	img.Header.Set("Sec-Fetch-Site", "same-origin")
	img.Header.Set("Sec-Fetch-Mode", "no-cors")
	img.Header.Set("Sec-Fetch-Dest", "image")
	if w := serve(t, h, img); w.Code != 200 {
		t.Errorf("an <img> of the site: %d", w.Code)
	}
	img.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := serve(t, h, img); w.Code != 403 {
		t.Errorf("an <img> of another site: %d", w.Code)
	}
	for _, target := range []string{"/api/rates", "/api/health"} {
		r, extra := withLog(client{ua: chromeUA}.request(h, "GET", target))
		if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_shadow"] != nil {
			t.Errorf("%s: %d %v", target, w.Code, fields(extra))
		}
	}
	r := request("GET", "/api/encar/catalog", visitor)
	r.Header.Set("Authorization", "Bearer "+partner)
	r, extra := withLog(r)
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_shadow"] != nil {
		t.Errorf("bearer: %d %v", w.Code, fields(extra))
	}
}

func TestChecksValidate(t *testing.T) {
	for _, c := range []struct {
		mode   string
		checks Checks
		err    string
	}{
		{"enforce", Checks{FP: "log", FetchMeta: "enforce", ALPN: "off"}, ""},
		{"log", Checks{FP: "log", ALPN: "log", ExemptRanges: []string{"139.100.226.95", "86.57.245.0/24", "2001:db8::/32"}}, ""},
		{"log", Checks{ALPN: "enforce"}, "checks.alpn enforce goes with the group's mode enforce"},
		{"enforce", Checks{FP: "ban"}, `checks.fp "ban" must be off, log or enforce`},
		{"enforce", Checks{ExemptRanges: []string{"example.com"}}, "neither an address nor a CIDR range"},
		{"enforce", Checks{ExemptRanges: []string{"0.0.0.0/0"}}, "holds every address"},
		{"enforce", Checks{ExemptRanges: []string{"::ffff:1.2.3.4"}}, "an IPv4 address goes as IPv4"},
	} {
		h := &Handler{Name: "site", Mode: c.mode, Secrets: []string{secret}, Checks: &c.checks}
		err := h.Provision(ctxForTest(t))
		if err == nil {
			err = h.Validate()
		}
		if (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%+v in %s: %v, want %q", c.checks, c.mode, err, c.err)
		}
	}
}

// The image's Google files read whole, and hold the addresses Googlebot and Read Aloud came from in
// the measurement; an address beside them is not Google's.
func TestGoogleRanges(t *testing.T) {
	ps, err := readGoogle()
	if err != nil || len(ps) < 100 {
		t.Fatalf("%d ranges, %v", len(ps), err)
	}
	for _, ip := range []string{"66.249.66.1", "192.178.6.3", "142.250.32.5", "2001:4860:4801:10::1"} {
		if !isGoogle(netip.MustParseAddr(ip)) {
			t.Errorf("%s is not Google's", ip)
		}
	}
	for _, ip := range []string{visitor, "8.8.8.8", "142.250.31.255"} {
		if isGoogle(netip.MustParseAddr(ip)) {
			t.Errorf("%s is Google's", ip)
		}
	}
}

// alpn asks only a TLS connection: a browser on a plain-HTTP gated host passes it. fp of a request
// without a valid token is the header alone: the token's refusal speaks for the token. Off skip_fp
// paths Fetch Metadata asks all three headers: same-origin with a navigation's mode or dest fails.
func TestChecksEdges(t *testing.T) {
	h := enforcing(t, &Handler{Checks: &Checks{FP: "enforce", ALPN: "enforce"}}, time.Now())
	r, extra := withLog(client{ua: chromeUA, fpHeader: true, tokenFP: true}.request(h, "GET", "/api/encar/catalog"))
	r.TLS = nil
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_shadow"] != nil {
		t.Errorf("Chrome on plain HTTP: %d %v", w.Code, fields(extra))
	}
	r, extra = withLog(request("GET", "/api/encar/catalog", visitor))
	r.Header.Set(fpHeader, fp)
	w := serve(t, h, r)
	if got := fields(extra); w.Code != 401 || got["gate_reason"] != "no_token" || got["gate_shadow"] != nil {
		t.Errorf("the header without a token: %d %v", w.Code, got)
	}
	fm := enforcing(t, &Handler{Checks: &Checks{FetchMeta: "enforce"}}, time.Now())
	for hdr, v := range map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"} {
		r, extra := withLog(client{ua: chromeUA, fetchMeta: true, h2: true}.request(fm, "GET", "/api/encar/catalog"))
		r.Header.Set(hdr, v)
		if w := serve(t, fm, r); w.Code != 403 || fields(extra)["gate_reason"] != "check_fetch_meta" {
			t.Errorf("%s %s: %d %v", hdr, v, w.Code, fields(extra))
		}
	}
}
