package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

var habsida = Policy{Revision: 1, Floor: 1,
	Allow: []BotAllow{{Host: "img.dev.habsidev.com", Paths: []string{"/pics", "/pics_i"}, UserAgent: "(?i)telegrambot"}},
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
			if want := `[{"path":["/.well-known/acme-challenge/*"]},{"header_regexp":{"User-Agent":{"pattern":"(?i)telegrambot"}},"host":["img.dev.habsidev.com"],"path":["/pics","/pics/*","/pics_i","/pics_i/*"]}]`; string(not) != want {
				t.Errorf("%s route %d: want ACME and the allow exempt:\n got %s\nwant %s", name, i, not, want)
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

// A first policy that fails leaves no policy behind.
func TestSetPolicyRemovesAFirstPolicyThatFailed(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	d.fail[reloadNext] = errors.New("refused")
	if err := SetPolicy(context.Background(), d, io.Discard, habsida); err == nil {
		t.Fatal("want an error")
	}
	if _, ok := d.files[ServerDir+"/policy.json"]; ok {
		t.Errorf("want no policy left")
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
	if marker != "3\n" || FragmentFormat <= 2 {
		t.Errorf("want the marker to hold format %d, above the 2 of a boks without policies: %q", FragmentFormat, marker)
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
// a rollback to the policy before matches that record and must still take Caddy back. A repeat of
// the policy Caddy runs reloads nothing.
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
	d.calls = nil
	if err := SetPolicy(context.Background(), d, io.Discard, back); err != nil || d.ran(reloadNext) {
		t.Errorf("want a repeat of the policy Caddy runs to reload nothing: %v %v", err, d.calls)
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
