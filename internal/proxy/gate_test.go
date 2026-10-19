package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

var (
	siteSecret = strings.Repeat("s", 32)
	digest     = strings.Repeat("d", 64)
)

// gated is a policy with the ban, a block and a gate of two groups: shop in log with a partner's
// Bearer, and blog off.
func gated() Policy {
	return Policy{Revision: 16, Floor: 16,
		Ban:   &Ban{Duration: "24h", Rules: []BanRule{{Name: "all", Limit: 1500, Window: "1m", Class: "all"}}},
		Block: []BotBlock{{Name: "crawlers", UserAgent: "(?i)gptbot"}},
		Gate: json.RawMessage(`{"groups":[` +
			`{"name":"shop","app":"shop","mode":"log","site_gate":"on","secret_env":"SHOP_SECRET","skip_fp":["/api/encar/pics"],` +
			`"bearer":{"paths":["^/api/encar(/|$)"],"digests_env":"SHOP_DIGESTS"}},` +
			`{"name":"blog","app":"blog","mode":"off","secret_env":"BLOG_SECRET"}]}`),
		GateSecrets: map[string][]string{"SHOP_SECRET": {siteSecret}, "SHOP_DIGESTS": {digest}, "BLOG_SECRET": {siteSecret}}}
}

var shopAndBlog = []Fragment{
	{App: "blog", Routes: []Route{{Host: "blog.example.com", Dial: "blog:1", TLS: true}}},
	{App: "shop", Routes: []Route{{Host: "shop.example.com", Dial: "shop:1", TLS: true}, {Host: "www.shop.example.com", Dial: "shop:1", TLS: true},
		{Host: "plain.shop.example.com", Dial: "shop:1"}}},
}

func handlerOf(t *testing.T, route any) map[string]any {
	t.Helper()
	return route.(map[string]any)["handle"].([]any)[0].(map[string]any)
}

// The gate goes after the ban and the blocks and before every app's route, on the hosts of its app on
// each server: the TLS hosts on 443, the others on 80, not terminal. Its handler is the group as
// written with the secrets the server keeps in place of the variables' names; a group that is off has
// no route (plan §5 boks 5, R10).
func TestConfigPutsTheGateBeforeTheApps(t *testing.T) {
	b, err := Config(gated(), shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	for name, hosts := range map[string]string{"https": `["shop.example.com","www.shop.example.com"]`, "http": `["plain.shop.example.com"]`} {
		routes := dig(m, "apps", "http", "servers", name, "routes").([]any)
		if h := handlerOf(t, routes[0]); h["handler"] != "boks_ban" {
			t.Errorf("%s: want the ban first, got %v", name, h["handler"])
		}
		if h := handlerOf(t, routes[1]); h["status_code"] != float64(403) {
			t.Errorf("%s: want the block second, got %v", name, h)
		}
		gate := routes[2].(map[string]any)
		h := handlerOf(t, gate)
		got, _ := json.Marshal(gate["match"].([]any)[0].(map[string]any)["host"])
		if h["handler"] != "boks_gate" || string(got) != hosts || gate["terminal"] != false {
			t.Errorf("%s: want the gate third on %s, got %s %v", name, hosts, got, gate)
		}
		if h["name"] != "shop" || h["mode"] != "log" || h["secret_env"] != nil || h["secrets"].([]any)[0] != siteSecret {
			t.Errorf("%s: handler %v", name, h)
		}
		bearer := h["bearer"].(map[string]any)
		if bearer["digests_env"] != nil || bearer["digests"].([]any)[0] != digest || bearer["paths"].([]any)[0] != "^/api/encar(/|$)" {
			t.Errorf("%s: bearer %v", name, bearer)
		}
		if h := handlerOf(t, routes[3]); h["handler"] == "boks_gate" {
			t.Errorf("%s: the group that is off has a route", name)
		}
	}
}

// A host the app adds to its routes is under the gate with its next deploy, server.yml unchanged.
func TestANewHostOfTheAppIsGated(t *testing.T) {
	fs := []Fragment{{App: "shop", Routes: append(shopAndBlog[1].Routes, Route{Host: "new-shop.example.org", Dial: "shop:1", TLS: true})}}
	b, err := Config(gated(), fs)
	if err != nil {
		t.Fatal(err)
	}
	gate := dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)[2].(map[string]any)
	got, _ := json.Marshal(gate["match"].([]any)[0].(map[string]any)["host"])
	if handlerOf(t, gate)["handler"] != "boks_gate" || !strings.Contains(string(got), `"new-shop.example.org"`) {
		t.Errorf("want the new host in the gate's matcher: %s", got)
	}
}

// A host of the group's app that another app routes too would be judged by the group's rules: refused.
// A wildcard of the group's app leaves out the exact hosts of other apps it covers.
func TestGateHostsAreTheAppsAlone(t *testing.T) {
	shared := append(shopAndBlog, Fragment{App: "img", Routes: []Route{{Host: "shop.example.com", Path: "/img", Dial: "img:1", TLS: true}}})
	if _, err := Config(gated(), shared); err == nil || !strings.Contains(err.Error(), "routed by img too") {
		t.Errorf("want a shared host refused, got %v", err)
	}
	wild := []Fragment{
		{App: "shop", Routes: []Route{{Host: "*.shop.example.com", Dial: "shop:1", TLS: true}}},
		{App: "api", Routes: []Route{{Host: "api.shop.example.com", Dial: "api:1", TLS: true}}},
	}
	b, err := Config(gated(), wild)
	if err != nil {
		t.Fatal(err)
	}
	gate := dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)[2].(map[string]any)
	got, _ := json.Marshal(gate["match"])
	if string(got) != `[{"host":["*.shop.example.com"],"not":[{"host":["api.shop.example.com"]}]}]` {
		t.Errorf("want the other app's host left out of the wildcard: %s", got)
	}
	// A path another app routes on a covered host: that path is the other app's, the host's other paths
	// fall through to the wildcard's app and stay under the gate. A host of the other server is left out
	// whole, as the wildcard's own route leaves it.
	wild[1].Routes = []Route{{Host: "api.shop.example.com", Path: "/assets", Dial: "api:1", TLS: true}, {Host: "plain.shop.example.com", Dial: "api:1"}}
	if b, err = Config(gated(), wild); err != nil {
		t.Fatal(err)
	}
	gate = dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)[2].(map[string]any)
	got, _ = json.Marshal(gate["match"])
	if string(got) != `[{"host":["*.shop.example.com"],"not":[{"host":["api.shop.example.com"],"path":["/assets","/assets/*"]},{"host":["plain.shop.example.com"]}]}]` {
		t.Errorf("want only the other app's path left out: %s", got)
	}
	// Hosts compare as Caddy matches them, in any case: a shared host spelled otherwise is still shared,
	// and another app's exact host spelled otherwise is still left out of the wildcard.
	upper := append(shopAndBlog, Fragment{App: "img", Routes: []Route{{Host: "SHOP.example.com", Path: "/img", Dial: "img:1", TLS: true}}})
	if _, err := Config(gated(), upper); err == nil || !strings.Contains(err.Error(), "routed by img too") {
		t.Errorf("want a shared host in capitals refused, got %v", err)
	}
	// The app's own exact host beside its wildcard stays under the gate.
	wild = []Fragment{
		{App: "shop", Routes: []Route{{Host: "*.shop.example.com", Dial: "shop:1", TLS: true}, {Host: "foo.shop.example.com", Dial: "shop:1", TLS: true}}},
		{App: "api", Routes: []Route{{Host: "api.SHOP.example.com", Dial: "api:1", TLS: true}}},
	}
	if b, err = Config(gated(), wild); err != nil {
		t.Fatal(err)
	}
	gate = dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)[2].(map[string]any)
	got, _ = json.Marshal(gate["match"])
	if string(got) != `[{"host":["*.shop.example.com","foo.shop.example.com"],"not":[{"host":["api.SHOP.example.com"]}]}]` {
		t.Errorf("want the app's own host gated and the other's left out: %s", got)
	}
	// A route of the gated app by path: the gate would judge the visitor's path, not the app's.
	byPath := []Fragment{{App: "shop", Routes: []Route{{Host: "cars.example.com", Path: "/shop", StripPath: true, Dial: "shop:1", TLS: true}}}}
	if _, err := Config(gated(), byPath); err == nil || !strings.Contains(err.Error(), "by path") {
		t.Errorf("want a gated app's path route refused, got %v", err)
	}
}

// probe answers CheckGate's run of the proxy's image: it records the command and the config on stdin,
// and refuses when told to.
type probe struct {
	*disk
	args   []string
	stdin  string
	refuse error
}

func (p *probe) Run(ctx context.Context, args ...string) (string, error) {
	if strings.Contains(strings.Join(args, " "), "docker inspect -f '{{.Config.Image}}' boks-proxy") {
		return "ghcr.io/kopandante/boks-caddy:old\n", nil
	}
	return p.disk.Run(ctx, args...)
}

func (p *probe) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	if len(args) > 1 && args[0] == "docker" && args[1] == "run" {
		p.args, p.stdin = args, string(content)
		return "", p.refuse
	}
	return p.disk.Pipe(ctx, content, args...)
}

// The gate is checked by the proxy's own image, offline, with the handlers as the config will hold
// them; a Caddy that refuses them stops the apply, naming the image to upgrade (T6).
func TestCheckGateAsksTheProxysImage(t *testing.T) {
	for _, c := range []struct {
		ps     string
		refuse error
		want   string
	}{{"running\tcaddy", nil, ""}, {"running\tcaddy", errors.New("unknown module boks_gate"), "runs ghcr.io/kopandante/boks-caddy:old"},
		{"exited\tcaddy", errors.New("unknown module boks_gate"), "is a stopped container of ghcr.io/kopandante/boks-caddy:old"}} {
		d := newDisk()
		if _, err := SetRoutes(context.Background(), d, io.Discard, "shop", shopAndBlog[1].Routes); err != nil {
			t.Fatal(err)
		}
		d.ps = c.ps
		r := &probe{disk: d, refuse: c.refuse}
		err := CheckGate(context.Background(), r, gated())
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "boks proxy upgrade")) {
			t.Errorf("%s, refused %v: got %v", c.ps, c.refuse, err)
		}
		if got := strings.Join(r.args, " "); got != "docker run --rm -i --network none --entrypoint caddy ghcr.io/kopandante/boks-caddy:old validate --config /dev/stdin" {
			t.Errorf("probe: %s", got)
		}
		if !strings.Contains(r.stdin, `"handler":"boks_gate"`) || !strings.Contains(r.stdin, siteSecret) {
			t.Errorf("the probe's config lacks the gate as the server would run it: %s", r.stdin)
		}
	}
}

// A group whose secret the server does not keep cannot be assembled: the handler would refuse every token.
func TestGateNeedsItsSecrets(t *testing.T) {
	p := gated()
	delete(p.GateSecrets, "SHOP_DIGESTS")
	if _, err := Config(p, shopAndBlog); err == nil || !strings.Contains(err.Error(), "SHOP_DIGESTS") {
		t.Errorf("want the missing digests named, got %v", err)
	}
	p = gated()
	p.GateSecrets = nil
	if _, err := Config(p, shopAndBlog); err == nil || !strings.Contains(err.Error(), "SHOP_SECRET") {
		t.Errorf("want the missing secret named, got %v", err)
	}
}

// The secrets go to a file of their own, never to the policy or its history; the marker holds 8 while
// the policy has a gate and 7 once it has none, so a boks of format 7 deploys again after a rollback
// without each app deploying anew. A rollback to the gate's revision takes the secrets the server keeps
// (R4, R5, S12).
func TestSetPolicyKeepsTheGatesSecretsApart(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "shop", shopAndBlog[1].Routes); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, gated()); err != nil {
		t.Fatal(err)
	}
	if got := d.files[Dir+"/routes/_server.json"]; got != "8\n" {
		t.Errorf("marker with a gate: %q", got)
	}
	for _, f := range []string{ServerDir + "/policy.json", ServerDir + "/history/16.json"} {
		if strings.Contains(d.files[f], siteSecret) || strings.Contains(d.files[f], digest) {
			t.Errorf("%s holds a secret", f)
		}
		if !strings.Contains(d.files[f], "SHOP_SECRET") {
			t.Errorf("%s lost the gate: %s", f, d.files[f])
		}
	}
	if s := d.files[ServerDir+"/gate.secret"]; !strings.Contains(s, siteSecret) || !strings.Contains(s, digest) {
		t.Errorf("gate.secret: %q", s)
	}
	if !strings.Contains(d.caddy, siteSecret) {
		t.Errorf("Caddy runs the gate without its secret")
	}

	plain := gated()
	plain.Revision, plain.Floor, plain.Gate, plain.GateSecrets = 17, 17, nil, nil
	if err := SetPolicy(context.Background(), d, io.Discard, plain); err != nil {
		t.Fatal(err)
	}
	if got := d.files[Dir+"/routes/_server.json"]; got != "7\n" {
		t.Errorf("marker without a gate: %q", got)
	}
	if strings.Contains(d.caddy, "boks_gate") || !strings.Contains(d.files[ServerDir+"/gate.secret"], siteSecret) {
		t.Errorf("want no gate in Caddy and the secrets kept for a rollback")
	}

	back, _, err := History(context.Background(), d, 16)
	if err != nil {
		t.Fatal(err)
	}
	back.Floor = 17
	if err := SetPolicy(context.Background(), d, io.Discard, back); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.caddy, siteSecret) || d.files[Dir+"/routes/_server.json"] != "8\n" {
		t.Errorf("a rollback to the gate's revision runs it with the secrets the server keeps")
	}
	// A later deploy of any app assembles the gate from the file too.
	if _, err := SetRoutes(context.Background(), d, io.Discard, "blog", shopAndBlog[0].Routes); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.caddy, siteSecret) {
		t.Errorf("a deploy dropped the gate's secret")
	}
}

// A gate whose secret neither the apply nor the server has is refused before anything changes.
func TestSetPolicyRefusesAGateWithoutItsSecret(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "shop", shopAndBlog[1].Routes); err != nil {
		t.Fatal(err)
	}
	p := gated()
	p.GateSecrets = map[string][]string{"SHOP_SECRET": {siteSecret}}
	before := len(d.calls)
	if err := SetPolicy(context.Background(), d, io.Discard, p); err == nil || !strings.Contains(err.Error(), "SHOP_DIGESTS") {
		t.Fatalf("want the missing digests named, got %v", err)
	}
	for _, c := range d.calls[before:] {
		if strings.HasPrefix(c, "upload ") || strings.HasPrefix(c, "docker exec boks-proxy caddy reload") {
			t.Errorf("changed something: %s", c)
		}
	}
}

// A failed apply puts the previous secrets back with the previous policy.
func TestSetPolicyPutsTheGatesSecretsBack(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "shop", shopAndBlog[1].Routes); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, gated()); err != nil {
		t.Fatal(err)
	}
	before := d.files[ServerDir+"/gate.secret"]
	next := gated()
	next.Revision, next.Floor = 17, 17
	next.GateSecrets = map[string][]string{"SHOP_SECRET": {strings.Repeat("n", 32)}}
	d.lost[reloadNext] = errors.New("connection reset")
	d.fail[reloadNext] = errors.New("refused")
	if err := SetPolicy(context.Background(), d, io.Discard, next); err == nil {
		t.Fatal("want the apply to fail")
	}
	if got := d.files[ServerDir+"/gate.secret"]; got != before {
		t.Errorf("want the previous secrets back:\n got %q\nwant %q", got, before)
	}
}

// A secret the apply brings replaces the one the server keeps: a rotation reaches Caddy and the file.
func TestSetPolicyRotatesAGateSecret(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "shop", shopAndBlog[1].Routes); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, gated()); err != nil {
		t.Fatal(err)
	}
	rotated := strings.Repeat("r", 32)
	next := gated()
	next.Revision, next.Floor = 17, 17
	next.GateSecrets = map[string][]string{"SHOP_SECRET": {rotated, siteSecret}}
	if err := SetPolicy(context.Background(), d, io.Discard, next); err != nil {
		t.Fatal(err)
	}
	var kept map[string][]string
	if err := json.Unmarshal([]byte(d.files[ServerDir+"/gate.secret"]), &kept); err != nil {
		t.Fatal(err)
	}
	if got := kept["SHOP_SECRET"]; len(got) != 2 || got[0] != rotated || len(kept["SHOP_DIGESTS"]) != 1 {
		t.Errorf("want the rotated secret first and the digests kept: %v", kept)
	}
	if !strings.Contains(d.caddy, rotated) {
		t.Errorf("Caddy runs the gate without the rotated secret")
	}
}

// Two policies with the same gate are one policy, whatever secrets each carries: the secrets are not
// the policy.
func TestSamePolicySeesTheGate(t *testing.T) {
	a, b := gated(), gated()
	b.GateSecrets = nil
	if !SamePolicy(a, b) {
		t.Error("want the same gate to be the same policy")
	}
	b.Gate = json.RawMessage(strings.Replace(string(b.Gate), `"mode":"log"`, `"mode":"enforce"`, 1))
	if SamePolicy(a, b) {
		t.Error("want another mode to be another policy")
	}
}

// The check of a rollback to a revision with a gate assembles the config with every secret the server
// keeps — the egress login's password among them, which no revision of the history records (R5).
func TestCheckGateTakesEverySecretFromTheServer(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "shop", shopAndBlog[1].Routes); err != nil {
		t.Fatal(err)
	}
	p := gated()
	p.Egress = encar
	if err := SetPolicy(context.Background(), d, io.Discard, p); err != nil {
		t.Fatal(err)
	}
	back, _, err := History(context.Background(), d, 16)
	if err != nil {
		t.Fatal(err)
	}
	if back.Egress.Password != "" || back.GateSecrets != nil {
		t.Fatalf("the history holds a secret: %+v", back)
	}
	if err := CheckGate(context.Background(), d, back); err != nil {
		t.Errorf("want the rollback's gate checked with the secrets the server keeps: %v", err)
	}
}

// A new container for the policy is validated with the gate's secrets the server keeps, as the policy
// itself is: a rollback without env, or an apply leaving a variable to the server, would otherwise
// fail under the lock whenever the egress port changes.
func TestReshapeTakesTheGatesSecretsFromTheServer(t *testing.T) {
	s := reshapeServer()
	s.out["sh -c if [ -f '"+ServerDir+"/gate.secret' ]"] = "present\n" + string(gateSecretFile(gated().GateSecrets))
	next := openEgress
	next.Gate = gated().Gate
	if err := Reshape(context.Background(), s, io.Discard, next); err != nil {
		t.Errorf("want the secrets taken from the server: %v", err)
	}
}

// A failed apply puts the marker back with the policy: the gate's 8 beside a policy without it would
// turn away every boks of format 7 for nothing, a 7 beside the gate would let one drop it.
func TestSetPolicyPutsTheMarkerBack(t *testing.T) {
	plain := gated()
	plain.Gate, plain.GateSecrets = nil, nil
	for _, c := range []struct {
		name       string
		from, to   Policy
		wantMarker string
	}{{"gate to none", gated(), plain, "8\n"}, {"none to gate", plain, gated(), "7\n"}} {
		d := newDisk()
		if _, err := SetRoutes(context.Background(), d, io.Discard, "shop", shopAndBlog[1].Routes); err != nil {
			t.Fatal(err)
		}
		if err := SetPolicy(context.Background(), d, io.Discard, c.from); err != nil {
			t.Fatal(err)
		}
		c.to.Revision, c.to.Floor = 17, 17
		// A refused reload, and a write of the secrets that fails before the policy is written.
		for _, fail := range []string{reloadNext, "upload " + ServerDir + "/gate.secret"} {
			if fail != reloadNext && len(c.to.Gate) == 0 {
				continue
			}
			to := c.to
			if len(to.Gate) > 0 {
				to.GateSecrets = map[string][]string{"SHOP_SECRET": {strings.Repeat("n", 32)}, "SHOP_DIGESTS": {digest}, "BLOG_SECRET": {siteSecret}}
			}
			if fail == reloadNext {
				d.fail[fail] = errors.New("refused")
			} else {
				d.lost[fail] = errors.New("connection reset") // written, the answer lost
			}
			if err := SetPolicy(context.Background(), d, io.Discard, to); err == nil {
				t.Fatalf("%s, %s: want the apply to fail", c.name, fail)
			}
			delete(d.fail, fail)
			delete(d.lost, fail)
			if got := d.files[Dir+"/routes/_server.json"]; got != c.wantMarker {
				t.Errorf("%s, %s: marker %q, want %q back", c.name, fail, got, c.wantMarker)
			}
		}
	}
}

// A deploy that would route a host of a gated app beside another app is refused before anything of
// the app changes, not when the config is reloaded.
func TestCheckHostsSeesTheGate(t *testing.T) {
	p := gated()
	p.GateSecrets = nil // a deploy checks without the secrets
	if err := CheckHosts(p, shopAndBlog, "img", []Route{{Host: "shop.example.com", Path: "/img", Dial: "img:1", TLS: true}}); err == nil ||
		!strings.Contains(err.Error(), "routed by img too") {
		t.Errorf("want the shared host refused: %v", err)
	}
	if err := CheckHosts(p, shopAndBlog, "img", []Route{{Host: "img.example.com", Dial: "img:1", TLS: true}}); err != nil {
		t.Errorf("a host of its own: %v", err)
	}
}
