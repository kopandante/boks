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

// The policy is recorded before the reload, the history only after Caddy took it.
func TestSetPolicyRecordsThenReloads(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	if err := SetPolicy(context.Background(), d, io.Discard, habsida); err != nil {
		t.Fatal(err)
	}
	pol, reload, hist := index(d.calls, "upload "+ServerDir+"/policy.json"), index(d.calls, reloadNext), index(d.calls, "upload "+ServerDir+"/history/1.json")
	if pol < 0 || reload < pol || hist < reload {
		t.Errorf("want policy, reload, history in that order: %v", d.calls)
	}
	want, _ := Config(habsida, []Fragment{{App: "demo", Routes: web}})
	if d.files[Dir+"/caddy.json"] != string(want) {
		t.Errorf("want the filtered config applied")
	}
	if h := d.files[ServerDir+"/history/1.json"]; !strings.Contains(h, `"floor": 0`) {
		t.Errorf("want the history without the server's floor: %s", h)
	}
	// Any later reload keeps the filter: a deploy assembles from the recorded policy.
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", []Route{{Host: "o.example.com", Dial: "o:1"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.files[Dir+"/caddy.json"], `"status_code": 403`) {
		t.Errorf("a deploy dropped the filter")
	}
}

// A reload whose answer is lost after Caddy took the new config puts the previous policy back and
// reloads it by force, and the previous config is what is recorded as applied. No history claims the
// revision.
func TestSetPolicyPutsThePreviousBackWhenTheReloadFails(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, habsida); err != nil {
		t.Fatal(err)
	}
	before, applied := d.files[ServerDir+"/policy.json"], d.files[Dir+"/caddy.json"]
	next := habsida
	next.Revision, next.Floor = 2, 2
	next.Block = next.Block[:1]
	d.lost[reloadNext] = errors.New("connection reset")
	d.calls = nil
	if err := SetPolicy(context.Background(), d, io.Discard, next); err == nil || !strings.Contains(err.Error(), "previous one is back") {
		t.Fatalf("want the failure reported, got %v", err)
	}
	if d.files[ServerDir+"/policy.json"] != before {
		t.Errorf("want the previous policy back:\n%s", d.files[ServerDir+"/policy.json"])
	}
	if !d.ran(reloadNext+" --force") || d.files[Dir+"/caddy.json"] != applied {
		t.Errorf("want the previous config reloaded by force and recorded: %v", d.calls)
	}
	if _, ok := d.files[ServerDir+"/history/2.json"]; ok {
		t.Errorf("want no history for a revision that was not applied")
	}
}

// A write of the policy whose answer is lost after the file was replaced is put back too: left there,
// the next deploy of any app would load the policy this run reported failed.
func TestSetPolicyPutsThePreviousBackWhenTheWriteIsLost(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, habsida); err != nil {
		t.Fatal(err)
	}
	before, applied := d.files[ServerDir+"/policy.json"], d.files[Dir+"/caddy.json"]
	next := habsida
	next.Revision, next.Floor, next.Block = 2, 2, nil
	d.lost["upload "+ServerDir+"/policy.json"] = errors.New("connection reset")
	if err := SetPolicy(context.Background(), d, io.Discard, next); err == nil || !strings.Contains(err.Error(), "previous one is back") {
		t.Fatalf("want the failure reported, got %v", err)
	}
	if d.files[ServerDir+"/policy.json"] != before || d.files[Dir+"/caddy.json"] != applied {
		t.Errorf("want the previous policy back and applied:\n%s", d.files[ServerDir+"/policy.json"])
	}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", []Route{{Host: "o.example.com", Dial: "o:1"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.files[Dir+"/caddy.json"], `"status_code": 403`) {
		t.Errorf("a later deploy dropped the filter the failed run did not apply")
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
