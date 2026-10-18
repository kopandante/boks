package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

var habsida = Policy{Revision: 1, Floor: 1,
	Allow: []BotAllow{
		{Host: "img.dev.habsidev.com", Paths: []string{"/pics", "/pics_i"}, UserAgent: "(?i)telegrambot"},
		{UserAgent: "(?i)googlebot"},
	},
	Block: []BotBlock{
		{Name: "infra", Domains: []string{"habsidev.com"}, UserAgent: "(?i)(bot|crawler)"},
		{Name: "crawlers", UserAgent: "(?i)(bingbot|gptbot)"},
	}}

// The blocks go first on both servers — before the app's routes, the redirect and the 404 — answer
// 403, and carry ACME's challenge and every allow in `not`, so an allow wins over every block.
func TestConfigPutsTheBotFilterFirst(t *testing.T) {
	b, err := Config(habsida, []Fragment{{App: "a", Routes: []Route{
		{Host: "a.example.com", Dial: "a:1", TLS: true}, {Host: "p.example.com", Dial: "a:2"}}}})
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	for _, name := range []string{"http", "https"} {
		routes := dig(m, "apps", "http", "servers", name, "routes").([]any)
		for i, want := range []string{"infra", "crawlers"} {
			r := routes[i].(map[string]any)
			h := r["handle"].([]any)[0].(map[string]any)
			if h["handler"] != "static_response" || h["status_code"] != float64(403) {
				t.Errorf("%s route %d: want 403 for %s, got %v", name, i, want, h)
			}
			set := r["match"].([]any)[0].(map[string]any)
			// No host matcher at the top: Caddy would set out to obtain a certificate for its names.
			if set["host"] != nil {
				t.Errorf("%s route %d: a host matcher on a block: %v", name, i, set)
			}
			not, _ := json.Marshal(set["not"])
			if want := `[{"path":["/.well-known/acme-challenge/*"]},{"header_regexp":{"User-Agent":{"pattern":"(?i)telegrambot"}},"host":["img.dev.habsidev.com"],"path":["/pics","/pics/*","/pics_i","/pics_i/*"]},{"header_regexp":{"User-Agent":{"pattern":"(?i)googlebot"}}}]`; string(not) != want {
				t.Errorf("%s route %d: want ACME and every allow exempt:\n got %s\nwant %s", name, i, not, want)
			}
		}
		if h := routes[2].(map[string]any)["handle"].([]any)[0].(map[string]any); h["status_code"] == float64(403) {
			t.Errorf("%s: want the app's route after the two blocks", name)
		}
	}
	for _, name := range []string{"http", "https"} {
		routes := dig(m, "apps", "http", "servers", name, "routes").([]any)
		for i, want := range []string{
			`{"Host":{"pattern":"(?i)^([^.:/]+\\.)*(habsidev\\.com)\\.?(:[0-9]+)?$"},"User-Agent":{"pattern":"(?i)(bot|crawler)"}}`,
			`{"User-Agent":{"pattern":"(?i)(bingbot|gptbot)"}}`, // no Host: every host
		} {
			got, _ := json.Marshal(routes[i].(map[string]any)["match"].([]any)[0].(map[string]any)["header_regexp"])
			if string(got) != want {
				t.Errorf("%s block %d: want the rule's own patterns:\n got %s\nwant %s", name, i, got, want)
			}
		}
	}
	// No policy, no filter: the config is what C1–C4 assembled.
	plain, _ := Config(Policy{}, []Fragment{{App: "a", Routes: web}})
	if strings.Contains(string(plain), "403") {
		t.Errorf("want no block without a policy: %s", plain)
	}
}

// A block with paths refuses its User-Agent on those prefixes only, and an allow of ranges exempts the
// client's address — as Caddy tells it past trusted_proxies — from every block and from the ban.
func TestConfigBlockPathsAndAllowRanges(t *testing.T) {
	p := Policy{Revision: 1,
		Allow: []BotAllow{{Ranges: []string{"203.0.113.7/32"}}},
		Block: []BotBlock{{Name: "api-clients", Paths: []string{"/api"}, UserAgent: "(?i)axios/"}},
		Ban:   &Ban{Duration: "24h", Rules: []BanRule{{Name: "all-1m", Limit: 1500, Window: "1m", Class: "all"}}}}
	b, err := Config(p, []Fragment{{App: "a", Routes: web}})
	if err != nil {
		t.Fatal(err)
	}
	routes := dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)
	ban, _ := json.Marshal(routes[0].(map[string]any)["match"])
	block, _ := json.Marshal(routes[1].(map[string]any)["match"])
	exempt := `{"path":["/.well-known/acme-challenge/*"]},{"client_ip":{"ranges":["203.0.113.7/32"]}}`
	if want := `[{"header_regexp":{"User-Agent":{"pattern":"(?i)axios/"}},"not":[` + exempt + `],"path":["/api","/api/*"]}]`; string(block) != want {
		t.Errorf("block:\n got %s\nwant %s", block, want)
	}
	if want := `[{"not":[` + exempt + `]}]`; string(ban) != want {
		t.Errorf("ban:\n got %s\nwant %s", ban, want)
	}
}

// A domain covers itself and every host under it at any depth — Caddy's `*.` covers one label — with
// or without a port, and nothing that merely ends in the same letters. Go's regexp is Caddy's.
func TestDomainsPatternCoversEveryDepth(t *testing.T) {
	re := regexp.MustCompile(domainsPattern([]string{"habsidev.com", "x.org"}))
	for host, want := range map[string]bool{
		"habsidev.com": true, "a.habsidev.com": true, "backends-encar.v1.backend.dev.habsidev.com": true,
		"A.HabsiDev.com:443": true, "x.org": true, "habsidev.com.": true,
		"evilhabsidev.com": false, "habsidev.com.evil.org": false, "habsidevXcom": false, "a.habsidev.co": false,
	} {
		if re.MatchString(host) != want {
			t.Errorf("%s: want %v", host, want)
		}
	}
}

// served is a server with demo's routes and pol applied and running; the config each policy makes
// is what the tests compare Caddy's against.
func served(t *testing.T, pol Policy) *disk {
	t.Helper()
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, pol); err != nil {
		t.Fatal(err)
	}
	return d
}

func configOf(p Policy) string {
	b, _ := Config(p, []Fragment{{App: "demo", Routes: web}})
	return string(b)
}

// revision2 drops the crawlers block of habsida: a policy Caddy runs differently.
func revision2() Policy {
	p := habsida
	p.Revision, p.Floor, p.Block = 2, 2, habsida.Block[:1]
	return p
}

// Caddy runs the policy — assembled from the policy recorded before the reload — the history keeps it
// without the floor, and a later deploy assembles from the record and keeps the filter.
func TestSetPolicyRecordsThenReloads(t *testing.T) {
	d := served(t, habsida)
	if d.caddy != configOf(habsida) || d.files[Dir+"/caddy.json"] != d.caddy {
		t.Errorf("want Caddy on the filtered config, recorded as applied")
	}
	if h := d.files[ServerDir+"/history/1.json"]; !strings.Contains(h, `"floor": 0`) {
		t.Errorf("want the history without the server's floor: %s", h)
	}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", []Route{{Host: "o.example.com", Dial: "o:1"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.caddy, `"status_code": 403`) {
		t.Errorf("a deploy dropped the filter")
	}
}

// A run that fails once its policy may be in place — the answer to its write or to its reload lost —
// puts the previous policy back, Caddy on it and recorded, and no history claims the revision.
func TestSetPolicyPutsThePreviousBack(t *testing.T) {
	for _, lost := range []string{"upload " + ServerDir + "/policy.json", reloadNext} {
		d := served(t, habsida)
		before := d.files[ServerDir+"/policy.json"]
		d.lost[lost] = errors.New("connection reset")
		if err := SetPolicy(context.Background(), d, io.Discard, revision2()); err == nil || !strings.Contains(err.Error(), "previous one is back") {
			t.Fatalf("%s: want the failure reported, got %v", lost, err)
		}
		if d.files[ServerDir+"/policy.json"] != before || d.caddy != configOf(habsida) || d.files[Dir+"/caddy.json"] != d.caddy {
			t.Errorf("%s: want the previous policy back, run and recorded", lost)
		}
		if _, ok := d.files[ServerDir+"/history/2.json"]; ok {
			t.Errorf("%s: want no history for a revision that was not applied", lost)
		}
	}
}

// A first policy that fails — refused, or taken with the answer lost — leaves no policy behind and
// Caddy on the config without one.
func TestSetPolicyRemovesAFirstPolicyThatFailed(t *testing.T) {
	for _, lost := range []bool{false, true} {
		d := newDisk()
		if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
			t.Fatal(err)
		}
		if lost {
			d.lost[reloadNext] = errors.New("connection reset")
		} else {
			d.fail[reloadNext] = errors.New("refused")
		}
		if err := SetPolicy(context.Background(), d, io.Discard, habsida); err == nil {
			t.Fatal("want an error")
		}
		if _, ok := d.files[ServerDir+"/policy.json"]; ok {
			t.Errorf("lost %v: want no policy left", lost)
		}
		if d.caddy != configOf(Policy{}) || d.files[Dir+"/caddy.json"] != d.caddy {
			t.Errorf("lost %v: want Caddy on the config without a policy, recorded", lost)
		}
		if _, ok := d.files[ServerDir+"/history/1.json"]; ok {
			t.Errorf("lost %v: want no history", lost)
		}
	}
}

// A proxy that is not running gets the files it loads when it starts, and no reload.
func TestSetPolicyWritesTheFilesForAProxyThatIsNotRunning(t *testing.T) {
	d := newDisk()
	d.ps = "exited\tcaddy"
	if err := SetPolicy(context.Background(), d, io.Discard, habsida); err != nil {
		t.Fatal(err)
	}
	if d.ran("docker exec") || d.files[ServerDir+"/policy.json"] == "" || d.files[Dir+"/caddy.json"] == "" {
		t.Errorf("want files only: %v", d.calls)
	}
}

// A stop-first deploy asks Caddy about the config it will load, policy included: asked without it,
// the check would pass a config the reload then assembles differently.
func TestValidateAsksWithThePolicy(t *testing.T) {
	d := newDisk()
	d.files[ServerDir+"/policy.json"] = string(marshal(habsida))
	d.fail["rm -f "+Dir+"/caddy.check.json"] = errors.New("kept for the test")
	if err := Validate(context.Background(), d, "demo", web); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.files[Dir+"/caddy.check.json"], `"status_code": 403`) {
		t.Errorf("want the policy in the config Caddy is asked about: %s", d.files[Dir+"/caddy.check.json"])
	}
}

// A server with a policy refuses a boks that does not know policies: the marker among the fragments
// holds a format newer than format 2, which such a boks stops at, while this one reads past it.
func TestSetPolicyMarksTheRoutesForOlderBoks(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, habsida); err != nil {
		t.Fatal(err)
	}
	marker := d.files[Dir+"/routes/_server.json"]
	// 8: a boks of format 7 knows neither a block's paths nor an allow's ranges, and would assemble a
	// block meant for an API on every path and an allow of ranges alone that matches every request.
	if marker != "8\n" || FragmentFormat <= 7 {
		t.Errorf("want the marker to hold format %d, above the 7 of a boks without block paths: %q", FragmentFormat, marker)
	}
	if pol, mark := index(d.calls, "upload "+ServerDir+"/policy.json"), index(d.calls, "upload "+Dir+"/routes/_server.json"); mark < 0 || pol < mark {
		t.Errorf("want the marker before the policy: %v", d.calls)
	}
	fs, err := Fragments(context.Background(), d)
	if err != nil || len(fs) != 1 || fs[0].App != "demo" {
		t.Errorf("want this boks to read past the marker: %+v %v", fs, err)
	}
}

// A run cut after recording the policy and before the reload leaves the proxy behind it: Lags says so,
// so the next run of any app catches the filter up, and says no more once it is applied.
func TestLagsCountsThePolicy(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	fs, _ := Fragments(context.Background(), d)
	d.files[ServerDir+"/policy.json"] = string(marshal(habsida))
	if lag, err := Lags(context.Background(), d, fs); err != nil || !lag {
		t.Errorf("want a policy recorded but not applied to lag: %v %v", lag, err)
	}
	if _, err := converge(context.Background(), d, io.Discard, fs, false, "test"); err != nil {
		t.Fatal(err)
	}
	if lag, err := Lags(context.Background(), d, fs); err != nil || lag {
		t.Errorf("want no lag once the filter is applied: %v %v", lag, err)
	}
}

// A revision whose history write failed after Caddy took it is kept before it is replaced: otherwise it
// could never be rolled back to. Kept before anything changes: if that write fails too, the policy and
// Caddy stay as they were.
func TestSetPolicyKeepsTheReplacedRevisionInTheHistory(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	d.lost["upload "+ServerDir+"/history/1.json"] = errors.New("connection reset")
	if err := SetPolicy(context.Background(), d, io.Discard, habsida); err == nil {
		t.Fatal("want the failed history write reported")
	}
	delete(d.files, ServerDir+"/history/1.json") // the write did not happen
	before := d.files[ServerDir+"/policy.json"]
	failHistory := "upload sh -c umask 077 && mkdir -p '" + ServerDir + "/history' && cat > '" + ServerDir + "/history/1.json"
	d.fail[failHistory] = errors.New("connection reset")
	if err := SetPolicy(context.Background(), d, io.Discard, revision2()); err == nil {
		t.Fatal("want the failed history write reported")
	}
	if d.files[ServerDir+"/policy.json"] != before || d.caddy != configOf(habsida) {
		t.Errorf("want nothing changed while the replaced revision is not kept")
	}
	delete(d.fail, failHistory)
	if err := SetPolicy(context.Background(), d, io.Discard, revision2()); err != nil {
		t.Fatal(err)
	}
	if h := d.files[ServerDir+"/history/1.json"]; !strings.Contains(h, `"floor": 0`) || !strings.Contains(h, "crawlers") {
		t.Errorf("want revision 1 kept in the history: %q", h)
	}
}

// A run cut once Caddy took its policy, before caddy.json recorded it, leaves the record behind Caddy;
// a rollback to the policy before matches that record and must still take Caddy back, and so must a
// repeat.
func TestSetPolicyTakesCaddyBackAfterACutRun(t *testing.T) {
	d := served(t, habsida)
	cut := revision2()
	d.files[ServerDir+"/policy.json"] = string(marshal(cut))
	d.files[Dir+"/caddy.next.json"] = configOf(cut)
	if _, err := d.Run(context.Background(), strings.Fields(reloadNext)...); err != nil || d.caddy != configOf(cut) {
		t.Fatalf("setting up the cut run: %v", err)
	}
	back := habsida
	back.Floor = 2
	if err := SetPolicy(context.Background(), d, io.Discard, back); err != nil {
		t.Fatal(err)
	}
	if d.caddy != configOf(habsida) {
		t.Errorf("want Caddy back on revision 1, not on the cut run's policy")
	}
	// The retry of a rollback cut after it recorded its policy: the record and caddy.json both say
	// revision 1, Caddy runs the first cut run's policy.
	d.files[Dir+"/caddy.next.json"] = configOf(cut)
	if _, err := d.Run(context.Background(), strings.Fields(reloadNext)...); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, back); err != nil || d.caddy != configOf(habsida) {
		t.Errorf("want a repeat to take Caddy to the recorded policy: %v", err)
	}
}

// A policy that cannot be read stops a deploy before any reload: read as none, the reload would drop
// the filter.
func TestAnUnreadablePolicyStopsTheReload(t *testing.T) {
	d := served(t, habsida)
	d.fail["sh -c if [ -f '"+ServerDir+"/policy.json'"] = errors.New("connection reset")
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", []Route{{Host: "o.example.com", Dial: "o:1"}}); err == nil {
		t.Fatal("want the failed read reported")
	}
	if d.caddy != configOf(habsida) {
		t.Errorf("want Caddy left on the filtered config")
	}
}

// dbautoBan is a ban as a boks of format 6 recorded it, one limit: a revision of the history a
// rollback puts back.
var dbautoBan = &Ban{Limit: 300, Window: "1m", Duration: "24h",
	ExemptPaths: []string{"^/api/[a-z]+/pics", "^/api/auctions/[^/]+/(image|video)"}, ExemptRanges: []string{"198.51.100.0/24"}}

// The ban goes first on the servers on 80 and 443 — before the blocks, the apps' routes, the redirect
// and the 404, so it holds on every host, one no app routes included — and passes on what it does not
// refuse. The allows and ACME's challenge are exempt from it as from the blocks. The egress server has
// no ban: its clients are the services the policy lets in.
func TestConfigPutsTheBanFirst(t *testing.T) {
	p := habsida
	p.Ban, p.Egress = dbautoBan, encar
	b, err := Config(p, []Fragment{{App: "a", Routes: []Route{
		{Host: "a.example.com", Dial: "a:1", TLS: true}, {Host: "p.example.com", Dial: "a:2"}}}})
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	for _, name := range []string{"http", "https"} {
		routes := dig(m, "apps", "http", "servers", name, "routes").([]any)
		r := routes[0].(map[string]any)
		h, _ := json.Marshal(r["handle"])
		if want := `[{"duration":"24h","exempt_paths":["^/api/[a-z]+/pics","^/api/auctions/[^/]+/(image|video)"],"exempt_ranges":["198.51.100.0/24"],"handler":"boks_ban","limit":300,"window":"1m"}]`; string(h) != want {
			t.Errorf("%s route 0:\n got %s\nwant %s", name, h, want)
		}
		if r["terminal"] != false {
			t.Errorf("%s: want the ban to pass on what it does not refuse: %v", name, r["terminal"])
		}
		match, _ := json.Marshal(r["match"])
		if want := `[{"not":[{"path":["/.well-known/acme-challenge/*"]},{"header_regexp":{"User-Agent":{"pattern":"(?i)telegrambot"}},"host":["img.dev.habsidev.com"],"path":["/pics","/pics/*","/pics_i","/pics_i/*"]},{"header_regexp":{"User-Agent":{"pattern":"(?i)googlebot"}}}]}]`; string(match) != want {
			t.Errorf("%s: want only ACME and the allows exempt, on every host:\n got %s\nwant %s", name, match, want)
		}
		for i := 1; i <= 2; i++ {
			if h := dig(routes[i], "handle").([]any)[0].(map[string]any); h["status_code"] != float64(403) {
				t.Errorf("%s route %d: want the blocks right after the ban: %v", name, i, h)
			}
		}
		if last := dig(routes[len(routes)-1], "handle").([]any)[0].(map[string]any); last["status_code"] != float64(404) {
			t.Errorf("%s: want the 404 last, behind the ban: %v", name, last)
		}
	}
	if strings.Contains(string(mustJSON(t, dig(m, "apps", "http", "servers", "egress"))), "boks_ban") {
		t.Error("want no ban on the egress server")
	}
	plain, _ := Config(habsida, []Fragment{{App: "a", Routes: web}})
	if strings.Contains(string(plain), "boks_ban") {
		t.Errorf("want no ban without one in the policy: %s", plain)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Two policies with other bans filter otherwise.
func TestSamePolicySeesTheBan(t *testing.T) {
	a, b := habsida, habsida
	b.Ban = dbautoBan
	if SamePolicy(a, b) {
		t.Error("want a ban to make another policy")
	}
	c := *dbautoBan
	c.Limit = 301
	a.Ban = &c
	if SamePolicy(a, b) {
		t.Error("want another limit to make another policy")
	}
	// The same server.yml validated today: its limit as the rule default.
	d := *dbautoBan
	d.Limit, d.Window, d.Rules = 0, "", []BanRule{{Name: "default", Limit: 300, Window: "1m", Class: "all"}}
	a.Ban = &d
	if !SamePolicy(a, b) || !SamePolicy(b, a) {
		t.Error("want a ban of format 6 to be the same policy as its rule default")
	}
	d.Rules = []BanRule{{Name: "default", Limit: 300, Window: "10m", Class: "all"}}
	if SamePolicy(a, b) {
		t.Error("want another window of the rule default to make another policy")
	}
	a.Ban, b.Ban = hbSitesBan(), hbSitesBan()
	if !SamePolicy(a, b) {
		t.Error("want the same rules to make the same policy")
	}
	b.Ban.Rules[2].Class = "api"
	if SamePolicy(a, b) {
		t.Error("want another class to make another policy")
	}
	b.Ban = hbSitesBan()
	b.Ban.Heuristics.Mode = "ban"
	if SamePolicy(a, b) {
		t.Error("want another mode to make another policy")
	}
}

// hbSitesBan is the ban the plan sets for hb-sites, with a rule on paths beside.
func hbSitesBan() *Ban {
	return &Ban{Duration: "24h", Rules: []BanRule{
		{Name: "all-1m", Limit: 1500, Window: "1m", Class: "all"},
		{Name: "all-10m", Limit: 2500, Window: "10m", Class: "all"},
		{Name: "pages", Limit: 120, Window: "1m", Class: "page"},
		{Name: "report", Limit: 30, Window: "1m", Class: "api", Paths: []string{"^/api/[a-z]+/report$"}},
	}, Heuristics: &BanHeuristics{Mode: "log", Cluster: BanCluster{Limit: 300, Window: "10m", MinAddresses: 10}},
		ExemptPaths: []string{"^/api/[a-z]+/pics"}}
}

// The handler gets the rules and the heuristics as the policy holds them, typed, in a stable order.
func TestConfigCarriesTheBansRules(t *testing.T) {
	p := habsida
	p.Ban = hbSitesBan()
	b, err := Config(p, []Fragment{{App: "a", Routes: web}})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := json.Marshal(dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)[0].(map[string]any)["handle"])
	want := `[{"duration":"24h","exempt_paths":["^/api/[a-z]+/pics"],"handler":"boks_ban",` +
		`"heuristics":{"cluster":{"limit":300,"min_addresses":10,"window":"10m"},"mode":"log"},"rules":[` +
		`{"class":"all","limit":1500,"name":"all-1m","window":"1m"},{"class":"all","limit":2500,"name":"all-10m","window":"10m"},` +
		`{"class":"page","limit":120,"name":"pages","window":"1m"},` +
		`{"class":"api","limit":30,"name":"report","paths":["^/api/[a-z]+/report$"],"window":"1m"}]}]`
	if string(h) != want {
		t.Errorf("handler:\n got %s\nwant %s", h, want)
	}
	again, _ := Config(p, []Fragment{{App: "a", Routes: web}})
	if !bytes.Equal(b, again) {
		t.Error("want the same policy to make the same bytes")
	}
}

// The ban reads as its rules, and a ban of format 6 as its one rule.
func TestBanString(t *testing.T) {
	if got, want := hbSitesBan().String(), "ban: an address past a rule is refused for 24h — all-1m: 1500 in 1m; all-10m: 2500 in 10m; "+
		"pages: 120 page requests in 1m; report: 30 api requests on 1 path in 1m; heuristics log, cluster of 300 in 10m from 10 addresses"; got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	if got, want := dbautoBan.String(), "ban: an address past a rule is refused for 24h — default: 300 in 1m"; got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

// A revision a boks of format 6 recorded — the policy on hb-sites, and the history a rollback puts
// back — goes to the handler in its own form, the bytes that boks assembled: the ban3 a server runs
// until its proxy is upgraded refuses rules, and a config that changed under an unchanged policy would
// make every deploy reload it, and the upgrade reload it into the old proxy before the swap.
func TestConfigKeepsABanOfFormat6(t *testing.T) {
	var p Policy
	if err := json.Unmarshal([]byte(`{"revision":7,"ban":{"limit":1500,"window":"1m","duration":"24h","exempt_paths":["^/x"]}}`), &p); err != nil {
		t.Fatal(err)
	}
	b, err := Config(p, []Fragment{{App: "a", Routes: web}})
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, b); err != nil {
		t.Fatal(err)
	}
	if want := `{"handler":"boks_ban","limit":1500,"window":"1m","duration":"24h","exempt_paths":["^/x"]}`; !strings.Contains(compact.String(), want) ||
		strings.Contains(compact.String(), `"rules"`) {
		t.Errorf("want the ban of format 6 as that boks wrote it, %s:\n%s", want, compact.String())
	}
}
