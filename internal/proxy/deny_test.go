package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// denied is the gated policy with an address the ban refuses whatever it sends.
func denied() Policy {
	p := gated()
	b := *p.Ban
	b.DenyRanges = []string{"89.167.100.21/32"}
	p.Ban = &b
	p.Allow = []BotAllow{{UserAgent: "(?i)n8n"}}
	return p
}

// A denied address reaches the ban's handler past the policy's allows: the route's second matcher set
// takes it by client_ip, where the first leaves out what the allows let through. The ban's route goes
// first, so the deny answers before the blocks and the gate are asked; the handler gets the ranges.
func TestConfigDeniesBeforeTheAllowsAndTheGate(t *testing.T) {
	b, err := Config(denied(), shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	routes := dig(m, "apps", "http", "servers", "https", "routes").([]any)
	h := handlerOf(t, routes[0])
	if h["handler"] != "boks_ban" || fmt.Sprint(h["deny_ranges"]) != "[89.167.100.21/32]" {
		t.Errorf("want the ban first, with the deny: %v", h)
	}
	match, _ := json.Marshal(routes[0].(map[string]any)["match"])
	if want := `[{"not":[{"path":["/.well-known/acme-challenge/*"]},{"header_regexp":{"User-Agent":{"pattern":"(?i)n8n"}}}]},` +
		`{"client_ip":{"ranges":["89.167.100.21/32"]}}]`; string(match) != want {
		t.Errorf("want the denied ranges matched past the allows:\n got %s\nwant %s", match, want)
	}
	gate := -1
	for i, r := range routes {
		if handlerOf(t, r)["handler"] == "boks_gate" {
			gate = i
			break
		}
	}
	if gate < 1 {
		t.Errorf("want the gate after the ban, at %d", gate)
	}
	// Without a deny, the route is the one a boks before it assembled.
	plain, err := Config(gated(), shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "client_ip") || strings.Contains(string(plain), "deny_ranges") {
		t.Errorf("want no deny in a policy without one")
	}
}

// A policy with a deny needs format 9 — a boks of format 8 would read the policy without it and
// assemble the config with no deny — and only it: without a deny the marker stays 8 with a gate and 7
// without one, so a server stays open to the boks its apps pin.
func TestADenyMarksFormat9(t *testing.T) {
	plain := habsida
	plain.Ban = hbSitesBan()
	deny := plain
	b := *plain.Ban
	b.DenyRanges = []string{"89.167.100.21/32"}
	deny.Ban = &b
	for _, c := range []struct {
		p    Policy
		want int
	}{{plain, FragmentFormat}, {gated(), GateFormat}, {deny, DenyFormat}, {denied(), DenyFormat}} {
		if got := policyFormat(c.p); got != c.want {
			t.Errorf("%s: want format %d, got %d", c.p.Ban, c.want, got)
		}
	}
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, deny); err != nil {
		t.Fatal(err)
	}
	if marker := d.files[Dir+"/routes/_server.json"]; marker != "9\n" {
		t.Errorf("want the marker at 9: %q", marker)
	}
	if fs, err := Fragments(context.Background(), d); err != nil || len(fs) != 1 {
		t.Errorf("want this boks to read past format 9: %+v %v", fs, err)
	}
	d.files[Dir+"/routes/new.json"] = fmt.Sprintf("%d\n{\"app\": \"new\", \"routes\": []}\n", KeyFormat+1)
	if _, err := Fragments(context.Background(), d); err == nil || !strings.Contains(err.Error(), "newer than this boks") {
		t.Errorf("want format %d refused, got %v", KeyFormat+1, err)
	}
}

// The ban is checked by the proxy's own image with the fields the policy holds: a deny_ranges only
// when it has one, so a proxy whose handler predates the deny still takes a policy without it.
func TestCheckBanAsksForTheDenyOnlyWithOne(t *testing.T) {
	for _, c := range []struct {
		p        Policy
		refuse   error
		withDeny bool
		want     string
	}{
		{gated(), nil, false, ""},
		{denied(), nil, true, ""},
		{denied(), errors.New(`unknown field "deny_ranges"`), true, "refuses a ban with rules, heuristics and deny_ranges"},
	} {
		d := newDisk()
		d.ps = "running\tcaddy"
		r := &probe{disk: d, refuse: c.refuse}
		err := CheckBan(context.Background(), r, c.p)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "boks proxy upgrade")) {
			t.Errorf("refused %v: got %v", c.refuse, err)
		}
		if got := strings.Contains(r.stdin, `"deny_ranges"`); got != c.withDeny || !strings.Contains(r.stdin, `"handler":"boks_ban"`) {
			t.Errorf("want deny_ranges in the probe %v: %s", c.withDeny, r.stdin)
		}
	}
}

// The deny reads in the ban's line.
func TestBanStringNamesTheDeny(t *testing.T) {
	b := dbautoBan
	withDeny := *b
	withDeny.DenyRanges = []string{"89.167.100.21/32", "198.51.100.0/24"}
	if got, want := withDeny.String(), "ban: an address past a rule is refused for 24h — default: 300 in 1m; denied: 89.167.100.21/32, 198.51.100.0/24"; got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}
