package gate

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// scraperAE is the Accept-Encoding the scraper of cars.dbauto.kr sends under Chrome's name (todo#419);
// Chrome sends "gzip, deflate, br, zstd".
const scraperAE = "br, gzip, deflate"

var scraperSig = Signature{Name: "node-chrome", Mode: "enforce", Headers: []HeaderPattern{
	{Name: "accept-encoding", Pattern: `^br, gzip, deflate$`},
	{Name: "user-agent", Pattern: `^Mozilla/`},
}}

// signing is a group in enforce with sigs and a ban of a day, a store of its own, the clock at *now.
func signing(t *testing.T, now *time.Time, sigs ...Signature) *Handler {
	t.Helper()
	h := &Handler{Signatures: sigs, SignatureBan: caddyDay, bans: newBanStore(),
		Checks: &Checks{ExemptRanges: []string{"139.100.226.95"}}}
	h = enforcing(t, h, *now)
	h.now = func() time.Time { return *now }
	return h
}

const caddyDay = 24 * 60 * 60 * 1e9

// browserClient is a browser of the measurement: h2, Fetch Metadata, the fingerprint.
func browserClient(ua, ip string) client {
	return client{ua: ua, fetchMeta: true, fpHeader: true, tokenFP: true, h2: true, ip: ip}
}

func TestSignatureByClient(t *testing.T) {
	cases := []struct {
		name, ua, ae, ip string
		want             int
		reason           string
	}{
		{"the scraper", stormUA, scraperAE, "", 403, "signature"},
		{"Chrome", chromeUA, "gzip, deflate, br, zstd", "", 200, "token"},
		{"Chrome without zstd", chromeUA, "gzip, deflate, br", "", 200, "token"},
		{"Safari", safariUA, "gzip, deflate, br", "", 200, "token"},
		{"Firefox", firefoxUA, "gzip, deflate, br, zstd", "", 200, "token"},
		{"a server's Node fetch: not a browser's name", "node", scraperAE, "", 200, "token"},
		{"the scraper's headers from Google", stormUA, scraperAE, "66.249.66.1", 200, "token"},
		{"the scraper's headers as YandexBot from Yandex", yandexBotUA, scraperAE, "213.180.203.222", 200, "token"},
		{"the scraper's headers as YandexBot from elsewhere", yandexBotUA, scraperAE, "", 403, "signature"},
		{"the scraper from the checks' exempt address", stormUA, scraperAE, "139.100.226.95", 200, "token"},
		{"an encoding around the scraper's", stormUA, "br, gzip, deflate, zstd", "", 200, "token"},
	}
	for _, c := range cases {
		now := time.Now()
		h := signing(t, &now, scraperSig)
		r, extra := withLog(browserClient(c.ua, c.ip).request(h, "GET", "/api/auctions/heydealer/cars"))
		r.Header.Set("Accept-Encoding", c.ae)
		w := serve(t, h, r)
		if w.Code != c.want || fields(extra)["gate_reason"] != c.reason {
			t.Errorf("%s: %d %v, want %d %s", c.name, w.Code, fields(extra), c.want, c.reason)
		}
	}
}

// A matched address is refused on every request of the group for signature_ban, whatever it sends —
// a page and the token's issue too — and no longer after; another group does not know of it.
func TestSignatureBan(t *testing.T) {
	now := time.Now()
	h := signing(t, &now, scraperSig)
	ip := "203.0.113.9"
	r := browserClient(stormUA, ip).request(h, "GET", "/api/auctions/heydealer/cars")
	r.Header.Set("Accept-Encoding", scraperAE)
	if w := serve(t, h, r); w.Code != 403 || !strings.Contains(w.Body.String(), "Forbidden") {
		t.Fatalf("the match: %d %s", w.Code, w.Body)
	}
	for _, target := range []string{"/api/auctions/heydealer/cars", "/en/heydealer", "/api/auth/token"} {
		r, extra := withLog(browserClient(chromeUA, ip).request(h, "GET", target))
		if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "signature_ban" {
			t.Errorf("banned, %s: %d %v", target, w.Code, fields(extra))
		}
	}
	other := browserClient(chromeUA, "203.0.113.10").request(h, "GET", "/api/auctions/heydealer/cars")
	if w := serve(t, h, other); w.Code != 200 {
		t.Errorf("the next address: %d", w.Code)
	}
	g2 := &Handler{Name: "other", bans: h.bans, Signatures: []Signature{scraperSig}, SignatureBan: caddyDay}
	g2 = enforcing(t, g2, now)
	if w := serve(t, g2, browserClient(chromeUA, ip).request(g2, "GET", "/api/x")); w.Code != 200 {
		t.Errorf("another group: %d", w.Code)
	}
	now = now.Add(24*time.Hour - time.Second)
	if w := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")); w.Code != 403 {
		t.Errorf("a second before the ban's end: %d", w.Code)
	}
	now = now.Add(2 * time.Second)
	if w := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")); w.Code != 200 {
		t.Errorf("after the ban: %d", w.Code)
	}
}

// The ban outlives a reload: the handler of the same group provisioned anew finds it in sharedBans.
func TestSignatureBanSurvivesReload(t *testing.T) {
	now := time.Now()
	mk := func() *Handler {
		h := &Handler{Name: "reload-" + t.Name(), Signatures: []Signature{scraperSig}, SignatureBan: caddyDay}
		return enforcing(t, h, now)
	}
	ip := "198.51.100.77"
	r := browserClient(stormUA, ip).request(mk(), "GET", "/api/x")
	r.Header.Set("Accept-Encoding", scraperAE)
	h := mk()
	serve(t, h, r)
	t.Cleanup(func() { sharedBans.sweep(now.Add(48 * time.Hour)) })
	h2 := mk()
	if w := serve(t, h2, browserClient(chromeUA, ip).request(h2, "GET", "/api/x")); w.Code != 403 {
		t.Errorf("after the reload: %d", w.Code)
	}
}

// Without signature_ban the match alone is refused; in log nothing changes but gate_signature.
func TestSignatureModes(t *testing.T) {
	now := time.Now()
	h := signing(t, &now, scraperSig)
	h.SignatureBan = 0
	ip := "203.0.113.20"
	r := browserClient(stormUA, ip).request(h, "GET", "/api/x")
	r.Header.Set("Accept-Encoding", scraperAE)
	if w := serve(t, h, r); w.Code != 403 {
		t.Errorf("enforce without a ban: %d", w.Code)
	}
	if w := serve(t, h, browserClient(chromeUA, ip).request(h, "GET", "/api/x")); w.Code != 200 {
		t.Errorf("enforce without a ban, next request: %d", w.Code)
	}
	logSig := scraperSig
	logSig.Mode = "log"
	h = signing(t, &now, logSig)
	r, extra := withLog(browserClient(stormUA, ip).request(h, "GET", "/api/x"))
	r.Header.Set("Accept-Encoding", scraperAE)
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_signature"] != "node-chrome" || fields(extra)["gate_reason"] != "token" {
		t.Errorf("log: %d %v", w.Code, fields(extra))
	}
	if h.bans.banned(h.Name, netip.MustParseAddr(ip), now) {
		t.Error("log banned the address")
	}
	for _, mode := range []string{"", "off"} {
		off := scraperSig
		off.Mode = mode
		h = signing(t, &now, off)
		r, extra = withLog(browserClient(stormUA, ip).request(h, "GET", "/api/x"))
		r.Header.Set("Accept-Encoding", scraperAE)
		if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_signature"] != nil {
			t.Errorf("off %q: %d %v", mode, w.Code, fields(extra))
		}
	}
}

// A signature in log listed first never shadows an enforced one that matches the same request.
func TestSignatureLogBeforeEnforce(t *testing.T) {
	now := time.Now()
	broad := Signature{Name: "any-mozilla", Mode: "log", Headers: []HeaderPattern{{Name: "user-agent", Pattern: `^Mozilla/`}}}
	h := signing(t, &now, broad, scraperSig)
	ip := "203.0.113.40"
	r, extra := withLog(browserClient(stormUA, ip).request(h, "GET", "/api/x"))
	r.Header.Set("Accept-Encoding", scraperAE)
	if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_signature"] != "node-chrome" || fields(extra)["gate_reason"] != "signature" {
		t.Errorf("the scraper: %d %v", w.Code, fields(extra))
	}
	r, extra = withLog(browserClient(chromeUA, "203.0.113.41").request(h, "GET", "/api/x"))
	if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_signature"] != "any-mozilla" {
		t.Errorf("Chrome under the log one: %d %v", w.Code, fields(extra))
	}
}

// Moving the signatures to log lifts their bans; back in enforce, the bans not yet over return.
func TestSignatureBanLiftedByLog(t *testing.T) {
	now := time.Now()
	h := signing(t, &now, scraperSig)
	ip := "203.0.113.50"
	r := browserClient(stormUA, ip).request(h, "GET", "/api/x")
	r.Header.Set("Accept-Encoding", scraperAE)
	serve(t, h, r)
	logSig := scraperSig
	logSig.Mode = "log"
	lifted := &Handler{Signatures: []Signature{logSig}, SignatureBan: caddyDay, bans: h.bans}
	lifted = enforcing(t, lifted, now)
	if w := serve(t, lifted, browserClient(chromeUA, ip).request(lifted, "GET", "/en/heydealer")); w.Code != 200 {
		t.Errorf("signatures in log, the banned address: %d", w.Code)
	}
	noBan := &Handler{Signatures: []Signature{scraperSig}, bans: h.bans}
	noBan = enforcing(t, noBan, now)
	if w := serve(t, noBan, browserClient(chromeUA, ip).request(noBan, "GET", "/en/heydealer")); w.Code != 200 {
		t.Errorf("signature_ban dropped, the banned address: %d", w.Code)
	}
	back := &Handler{Signatures: []Signature{scraperSig}, SignatureBan: caddyDay, bans: h.bans}
	back = enforcing(t, back, now)
	if w := serve(t, back, browserClient(chromeUA, ip).request(back, "GET", "/en/heydealer")); w.Code != 403 {
		t.Errorf("back in enforce: %d", w.Code)
	}
}

// A header sent twice is matched by its first value.
func TestSignatureFirstValue(t *testing.T) {
	now := time.Now()
	h := signing(t, &now, scraperSig)
	r := browserClient(stormUA, "203.0.113.60").request(h, "GET", "/api/x")
	r.Header.Set("Accept-Encoding", scraperAE)
	r.Header.Add("Accept-Encoding", "zstd")
	if w := serve(t, h, r); w.Code != 403 {
		t.Errorf("the scraper's value first: %d", w.Code)
	}
}

// An absent header is "": a signature names what browsers send and the client leaves out.
func TestSignatureAbsentHeader(t *testing.T) {
	now := time.Now()
	h := signing(t, &now, Signature{Name: "no-priority", Mode: "enforce", Headers: []HeaderPattern{
		{Name: "priority", Pattern: `^$`}, {Name: "user-agent", Pattern: `Chrome/149`}}})
	r := browserClient(stormUA, "203.0.113.30").request(h, "GET", "/api/x")
	if w := serve(t, h, r); w.Code != 403 {
		t.Errorf("without Priority: %d", w.Code)
	}
	r = browserClient(stormUA, "203.0.113.31").request(h, "GET", "/api/x")
	r.Header.Set("Priority", "u=1, i")
	if w := serve(t, h, r); w.Code != 200 {
		t.Errorf("with Priority: %d", w.Code)
	}
}

func TestSignatureValidate(t *testing.T) {
	sig := func(f func(*Signature)) Signature {
		s := scraperSig
		s.Headers = append([]HeaderPattern(nil), s.Headers...)
		f(&s)
		return s
	}
	cases := []struct {
		name string
		h    Handler
		want string
	}{
		{"no name", Handler{Signatures: []Signature{sig(func(s *Signature) { s.Name = "" })}}, "name"},
		{"a name with a capital and a space", Handler{Signatures: []Signature{sig(func(s *Signature) { s.Name = "Node Chrome" })}}, "must match"},
		{"33 signatures", Handler{Signatures: thirtyThree()}, "more than 32"},
		{"a bad mode", Handler{Signatures: []Signature{sig(func(s *Signature) { s.Mode = "ban" })}}, "mode"},
		{"enforce in a group in log", Handler{Mode: "log", Signatures: []Signature{scraperSig}}, "group's mode enforce"},
		{"no headers", Handler{Signatures: []Signature{sig(func(s *Signature) { s.Headers = nil })}}, "at least one"},
		{"a header without a name", Handler{Signatures: []Signature{sig(func(s *Signature) { s.Headers[0].Name = "" })}}, "without a name"},
		{"every pattern takes an absent header", Handler{Signatures: []Signature{sig(func(s *Signature) {
			s.Headers = []HeaderPattern{{Name: "priority", Pattern: `^$`}, {Name: "x", Pattern: `.*`}}
		})}}, "every pattern"},
		{"a name twice", Handler{Signatures: []Signature{scraperSig, scraperSig}}, "twice"},
		{"a ban of a second", Handler{Signatures: []Signature{scraperSig}, SignatureBan: 1e9}, "signature_ban"},
		{"a ban of a month", Handler{Signatures: []Signature{scraperSig}, SignatureBan: 30 * caddyDay}, "signature_ban"},
		{"a ban without signatures", Handler{SignatureBan: caddyDay}, "goes with signatures"},
	}
	for _, c := range cases {
		h := c.h
		h.Name, h.Secrets = "site", []string{secret}
		if h.Mode == "" {
			h.Mode = "enforce"
		}
		if err := h.Provision(ctxForTest(t)); err != nil {
			t.Fatalf("%s: provision: %v", c.name, err)
		}
		if err := h.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	bad := Handler{Name: "site", Mode: "enforce", Secrets: []string{secret}, Signatures: []Signature{sig(func(s *Signature) { s.Headers[0].Pattern = "(" })}}
	if err := bad.Provision(ctxForTest(t)); err == nil {
		t.Error("a pattern that does not compile was provisioned")
	}
}

// thirtyThree is one signature more than a group takes, each named apart.
func thirtyThree() []Signature {
	sigs := make([]Signature, 33)
	for i := range sigs {
		sigs[i] = scraperSig
		sigs[i].Name = "s" + strconv.Itoa(i)
	}
	return sigs
}

// "off" written out is a valid mode.
func TestSignatureOffValidates(t *testing.T) {
	off := scraperSig
	off.Mode = "off"
	h := Handler{Name: "site", Mode: "enforce", Secrets: []string{secret}, Signatures: []Signature{off}, SignatureBan: caddyDay}
	if err := h.Provision(ctxForTest(t)); err != nil {
		t.Fatal(err)
	}
	if err := h.Validate(); err != nil {
		t.Error(err)
	}
}

// A full store refuses the match without keeping its address, and keeps one once bans are over.
func TestBanStoreFull(t *testing.T) {
	now := time.Now()
	s := newBanStore()
	s.max = 1
	a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
	if !s.ban("g", a, now.Add(time.Hour), now) || s.ban("g", b, now.Add(time.Hour), now) {
		t.Fatal("the store's bound")
	}
	if !s.ban("g", b, now.Add(3*time.Hour), now.Add(2*time.Hour)) || !s.banned("g", b, now.Add(2*time.Hour)) {
		t.Error("an ended ban was not swept for a new one")
	}
}
