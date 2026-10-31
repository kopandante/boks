package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// spared is the gated policy with its partners spared, as the apply of this boks records it, and shop's
// gate in enforce: the gate refuses a request whose key does not pass, so the blocks may leave it out.
func spared() Policy {
	p := gated()
	p.SpareBearer = true
	p.Gate = json.RawMessage(strings.Replace(string(p.Gate), `"mode":"log"`, `"mode":"enforce"`, 1))
	return p
}

// bearerAllowOn is the matcher the blocks leave out for shop's partner on a server of hosts: the group's
// own hosts, its bearer's methods and paths, and the Bearer scheme with a token — its keys in order, as
// a config decoded and written again has them.
func bearerAllowOn(hosts string) string {
	return `{"header_regexp":{"Authorization":{"pattern":"(?i)^bearer\\s+\\S"}},"host":` + hosts +
		`,"method":["GET","HEAD"],"path_regexp":{"pattern":"(?:^/api/encar(/|$))"}}`
}

// matchOf is a route's first matcher set as JSON.
func matchOf(t *testing.T, route any) map[string]any {
	t.Helper()
	return route.(map[string]any)["match"].([]any)[0].(map[string]any)
}

// With spare_bearer a group's partner gets past the blocks on the group's hosts — its methods, its
// paths, a Bearer with a token — on each server its own; the ban gets the key with every host of the
// app, and its route leaves out none of the partner's requests: the handler checks the key.
func TestConfigSparesTheGatesPartners(t *testing.T) {
	b, err := Config(spared(), shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	for name, hosts := range map[string]string{"https": `["shop.example.com","www.shop.example.com"]`, "http": `["plain.shop.example.com"]`} {
		routes := dig(m, "apps", "http", "servers", name, "routes").([]any)
		not, _ := json.Marshal(matchOf(t, routes[1])["not"])
		if want := `[{"path":["/.well-known/acme-challenge/*"]},` + bearerAllowOn(hosts) + `]`; string(not) != want {
			t.Errorf("%s: the block's exceptions\n got %s\nwant %s", name, not, want)
		}
		ban := handlerOf(t, routes[0])
		keys, _ := json.Marshal(ban["bearer"])
		if want := `[{"digests":["` + digest + `"],"hosts":["plain.shop.example.com","shop.example.com","www.shop.example.com"],"paths":["^/api/encar(/|$)"]}]`; string(keys) != want {
			t.Errorf("%s: the ban's keys\n got %s\nwant %s", name, keys, want)
		}
		if banNot, _ := json.Marshal(matchOf(t, routes[0])["not"]); strings.Contains(string(banNot), "Authorization") {
			t.Errorf("%s: the ban's route leaves out a header alone: %s", name, banNot)
		}
	}
}

// A group in log passes every request on, so a header alone would take a refused bot past the blocks
// to its API: the blocks leave out no partner of it, and the ban, which checks the key, still spares it.
func TestAGroupInLogSparesItsPartnerFromTheBanAlone(t *testing.T) {
	p := gated()
	p.SpareBearer = true
	b, err := Config(p, shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	routes := dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)
	if not, _ := json.Marshal(matchOf(t, routes[1])["not"]); strings.Contains(string(not), "Authorization") {
		t.Errorf("the block leaves out a Bearer of a group in log: %s", not)
	}
	if keys, _ := json.Marshal(handlerOf(t, routes[0])["bearer"]); !strings.Contains(string(keys), digest) {
		t.Errorf("want the ban to know the key of a group in log, got %s", keys)
	}
}

// A policy without spare_bearer — one an older boks applied — is assembled as that boks assembled it:
// no key in the ban, whose handler of that time would refuse the field, and no partner past the blocks.
func TestConfigWithoutSpareBearerIsAsBefore(t *testing.T) {
	b, err := Config(gated(), shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, `"bearer":[`) || strings.Contains(s, "Authorization") || strings.Contains(s, "path_regexp") {
		t.Errorf("want neither the ban's keys nor the blocks' exception:\n%s", s)
	}
}

// A group that is off has no gate to check the key, so its partner is spared by nothing; a group
// without a bearer has no partner.
func TestOnlyAGroupThatChecksTheKeySparesIt(t *testing.T) {
	p := spared()
	p.Gate = json.RawMessage(`{"groups":[{"name":"shop","app":"shop","mode":"off","secret_env":"SHOP_SECRET",` +
		`"bearer":{"paths":["^/api/encar(/|$)"],"digests_env":"SHOP_DIGESTS"}},` +
		`{"name":"blog","app":"blog","mode":"log","secret_env":"BLOG_SECRET"}]}`)
	b, err := Config(p, shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, `"bearer":[`) || strings.Contains(s, "Authorization") {
		t.Errorf("want no key spared:\n%s", s)
	}
}

// An allow by a header spares the blocks on the hosts it names — a header with any value but blanks —
// and never the ban, whose route still counts and refuses those requests.
func TestAnAllowByAHeaderSparesTheBlocksAlone(t *testing.T) {
	p := habsida
	p.Ban = hbSitesBan()
	p.Allow = append(p.Allow,
		BotAllow{Domains: []string{"v1.backend.dev.habsidev.com"}, Header: "x-cars-key"},
		BotAllow{Host: "translate.habsidev.com", Paths: []string{"/api"}, Header: "X-Cars-Key"})
	b, err := Config(p, []Fragment{{App: "a", Routes: []Route{{Host: "translate.habsidev.com", Dial: "a:1", TLS: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	routes := dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)
	block, _ := json.Marshal(matchOf(t, routes[1])["not"])
	for _, want := range []string{
		`{"header_regexp":{"Host":{"pattern":"(?i)^([^.:/]+\\.)*(v1\\.backend\\.dev\\.habsidev\\.com)\\.?(:[0-9]+)?$"},"X-Cars-Key":{"pattern":"\\S"}}}`,
		`{"header_regexp":{"X-Cars-Key":{"pattern":"\\S"}},"host":["translate.habsidev.com"],"path":["/api","/api/*"]}`,
	} {
		if !strings.Contains(string(block), want) {
			t.Errorf("want the block to leave out %s\n got %s", want, block)
		}
	}
	if ban, _ := json.Marshal(matchOf(t, routes[0])["not"]); strings.Contains(string(ban), "X-Cars-Key") {
		t.Errorf("the ban leaves out a request by the header alone: %s", ban)
	}
}

// A key — an allow by a header, spare_bearer — needs format 10: a boks of format 9 would read the allow
// without its header, an allow of the whole host from the blocks and the ban, and assemble the config
// without the partners. Without one the marker stays as it was, so a server stays open to older boks.
func TestAKeyMarksFormat10(t *testing.T) {
	byHeader := habsida
	byHeader.Allow = []BotAllow{{Host: "translate.habsidev.com", Header: "X-Cars-Key"}}
	// A boks of format 9 drops domains and reads the allow as one of every host: it must be refused.
	byDomains := habsida
	byDomains.Allow = []BotAllow{{Domains: []string{"habsidev.com"}, Paths: []string{"/pics"}}}
	for _, c := range []struct {
		name string
		p    Policy
		want int
	}{
		{"plain", habsida, FragmentFormat}, {"gated", gated(), GateFormat}, {"denied", denied(), DenyFormat},
		{"spared", spared(), KeyFormat}, {"an allow by a header", byHeader, KeyFormat},
		{"an allow by domains", byDomains, KeyFormat},
	} {
		if got := policyFormat(c.p); got != c.want {
			t.Errorf("%s: want format %d, got %d", c.name, c.want, got)
		}
	}
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, byHeader); err != nil {
		t.Fatal(err)
	}
	if marker := d.files[Dir+"/routes/_server.json"]; marker != "10\n" {
		t.Errorf("want the marker at 10: %q", marker)
	}
}

// The ban is checked by the proxy's image with the partners' keys only with spare_bearer: an image
// whose ban knows no keys still takes a policy without.
func TestCheckBanAsksForTheKeysOnlyWithSpareBearer(t *testing.T) {
	for _, c := range []struct {
		p        Policy
		refuse   error
		withKeys bool
		want     string
	}{
		{gated(), nil, false, ""},
		{spared(), nil, true, ""},
		{spared(), errors.New(`unknown field "bearer"`), true, "refuses a ban with rules and heuristics and the gate's partner keys"},
	} {
		d := newDisk()
		d.ps = "running\tcaddy"
		r := &probe{disk: d, refuse: c.refuse}
		err := CheckBan(context.Background(), r, c.p)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("refused %v: got %v", c.refuse, err)
		}
		if got := strings.Contains(r.stdin, `"bearer":[{"hosts"`); got != c.withKeys {
			t.Errorf("want the keys in the probe %v: %s", c.withKeys, r.stdin)
		}
		if !json.Valid([]byte(r.stdin)) {
			t.Errorf("the probe is not JSON: %s", r.stdin)
		}
	}
}
