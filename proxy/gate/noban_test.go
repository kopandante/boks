package gate

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const office = "203.0.113.7" // in no_ban_ranges

// officeGroup is a group in enforce with every rule on — the scraper's signature with a day's ban, alpn
// and fetch_meta, page_first and static_rhythm — the checks' exempt address and an office in
// no_ban_ranges, the clock at *now.
func officeGroup(t *testing.T, now *time.Time) *Handler {
	t.Helper()
	h := &Handler{Signatures: []Signature{scraperSig}, SignatureBan: caddyDay, bans: newBanStore(),
		Checks: &Checks{ALPN: "enforce", FetchMeta: "enforce",
			ExemptRanges: []string{"139.100.226.95"}, NoBanRanges: []string{"203.0.113.0/24"}},
		PageFirst: &PageFirst{Mode: "enforce", Window: sixHours}, pages: newPageStore(),
		StaticRhythm: &StaticRhythm{Mode: "enforce", Prefix: "/_next/", Files: 6, MinGap: 300 * 1e6, Window: caddyDay},
		rhythms:      newRhythmStore()}
	h = enforcing(t, h, now.Add(-time.Hour))
	h.now = func() time.Time { return *now }
	return h
}

// An office in no_ban_ranges is refused when the scraper's signature matches, and the refusal is
// written, gate_signature and all; nothing bans it, so its browsers go on — Chrome behind its proxy
// without h2 or Fetch Metadata, and no page before the API — as an exempt address's do (#160).
func TestNoBanRefusesWithoutBan(t *testing.T) {
	now := time.Now()
	h := officeGroup(t, &now)
	officeChrome := client{ua: chromeUA, fpHeader: true, tokenFP: true, ip: office}

	r, extra := withLog(client{ua: stormUA, fpHeader: true, tokenFP: true, ip: office}.request(h, "GET", "/api/auctions/heydealer/cars"))
	r.Header.Set("Accept-Encoding", scraperAE)
	w := serve(t, h, r)
	if f := fields(extra); w.Code != 403 || !strings.Contains(w.Body.String(), "Forbidden") || f["gate_reason"] != "signature" || f["gate_signature"] != scraperSig.Name {
		t.Fatalf("the office's scraper: %d %v", w.Code, f)
	}
	// The token's issue is asked its own origin rule, apart from the checks; the API and a page tell a ban.
	for _, target := range []string{"/api/auctions/heydealer/cars", "/en/heydealer"} {
		r, extra := withLog(officeChrome.request(h, "GET", target))
		if w := serve(t, h, r); w.Code != 200 || fields(extra)["gate_reason"] == "signature_ban" {
			t.Errorf("the office's Chrome after the match, %s: %d %v", target, w.Code, fields(extra))
		}
	}
	if h.banStore().banned(h.Name, netip.MustParseAddr(office), now) {
		t.Error("the office is banned")
	}
	// The rhythm neither marks it nor refuses it.
	files(t, h, &now, officeChrome, 6, time.Second)
	if code, _ := apiOf(t, h, officeChrome, "/api/x"); code != 200 {
		t.Errorf("the office's API after serial files: %d", code)
	}
}

// The checks' exempt address is asked nothing, signatures neither, and writes none; any other address
// the signature matches is refused and banned — as before.
func TestNoBanLeavesExemptAndOthersAsTheyWere(t *testing.T) {
	now := time.Now()
	h := officeGroup(t, &now)
	for ip, want := range map[string][2]any{"139.100.226.95": {200, nil}, "198.51.100.9": {403, scraperSig.Name}} {
		r, extra := withLog(browserClient(stormUA, ip).request(h, "GET", "/api/auctions/heydealer/cars"))
		r.Header.Set("Accept-Encoding", scraperAE)
		w := serve(t, h, r)
		if f := fields(extra); w.Code != want[0] || f["gate_signature"] != want[1] {
			t.Errorf("the scraper from %s: %d %v", ip, w.Code, f)
		}
	}
	r, extra := withLog(browserClient(chromeUA, "198.51.100.9").request(h, "GET", "/api/x"))
	if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "signature_ban" {
		t.Errorf("another address after its match: %d %v", w.Code, fields(extra))
	}
}

// An address in both exempt_ranges and no_ban_ranges says two opposite things, and the group is refused.
func TestNoBanAndExemptOverlapRefused(t *testing.T) {
	for _, nb := range []string{"139.100.226.95", "139.100.226.0/24"} {
		c := &Checks{ExemptRanges: []string{"139.100.226.95"}, NoBanRanges: []string{nb}}
		if err := c.validate("enforce"); err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Errorf("%s: %v", nb, err)
		}
	}
	if err := (&Checks{NoBanRanges: []string{"0.0.0.0/0"}}).validate("enforce"); err == nil || !strings.Contains(err.Error(), "no_ban_ranges") {
		t.Errorf("every address: %v", err)
	}
}

// The field as boks writes it, read by the strict decoder Caddy reads a module's config with.
func TestNoBanRangesDecode(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"name":"site","mode":"enforce","checks":{"exempt_ranges":["139.100.226.95"],"no_ban_ranges":["203.0.113.0/24"]}}`))
	dec.DisallowUnknownFields()
	var h Handler
	if err := dec.Decode(&h); err != nil || h.Checks == nil || len(h.Checks.NoBanRanges) != 1 {
		t.Fatalf("%v %+v", err, h.Checks)
	}
}

// An office banned before it went into no_ban_ranges — the ban outlives the reload that adds it — is not
// asked the ban: its Chrome passes, and its scraper is refused by the signature, not the ban (#160).
func TestNoBanSkipsAnEarlierBan(t *testing.T) {
	now := time.Now()
	h := officeGroup(t, &now)
	a := netip.MustParseAddr(office)
	if !h.banStore().ban(h.Name, a, now.Add(time.Hour), now) {
		t.Fatal("the ban was not kept")
	}
	officeChrome := client{ua: chromeUA, fpHeader: true, tokenFP: true, ip: office}
	if code, f := apiOf(t, h, officeChrome, "/api/x"); code != 200 {
		t.Errorf("the office's Chrome under an earlier ban: %d %v", code, f)
	}
	r, extra := withLog(client{ua: stormUA, fpHeader: true, tokenFP: true, ip: office}.request(h, "GET", "/api/auctions/heydealer/cars"))
	r.Header.Set("Accept-Encoding", scraperAE)
	if w := serve(t, h, r); w.Code != 403 || fields(extra)["gate_reason"] != "signature" {
		t.Errorf("the office's scraper under an earlier ban: %d %v", w.Code, fields(extra))
	}
}
