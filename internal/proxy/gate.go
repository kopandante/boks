package proxy

// The server's gate: the sites' API token checked by the proxy (proxy/gate, http.handlers.boks_gate)
// on the hosts of the apps its groups name. The policy keeps the gate as written in server.yml, as
// JSON boks does not interpret beyond the fields it acts on itself (GateGroup); the handler's schema is
// Caddy's, which refuses a field it does not know at the reload and keeps the config it runs. The
// secrets — each group's HMAC secret, the partners' Bearer digests — are never recorded in the policy
// or its history: they sit in a file of their own (gateSecretPath), as the egress password does, and
// are put into the handlers when the config is assembled.

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/kopandante/boks/internal/hostname"
	"github.com/kopandante/boks/internal/remote"
)

// GateGroup is what boks reads of a group of the gate.
type GateGroup struct {
	Name      string `json:"name"`
	App       string `json:"app"`
	Mode      string `json:"mode"`
	SiteGate  string `json:"site_gate"`
	SecretEnv string `json:"secret_env"`
	Bearer    *struct {
		DigestsEnv string `json:"digests_env"`
	} `json:"bearer"`
}

// SiteGateOff says whether the site no longer checks the token itself: the proxy's gate is the only one.
func (g GateGroup) SiteGateOff() bool { return g.SiteGate == "off" }

// gateGroup is a group as written, with what boks reads of it.
type gateGroup struct {
	GateGroup
	raw map[string]json.RawMessage
}

func gateSecretPath() string { return path.Join(ServerDir, "gate.secret") }

// GateGroups are the groups of a policy's gate; none without one.
func GateGroups(p Policy) ([]GateGroup, error) {
	gs, err := groupsOf(p.Gate)
	out := make([]GateGroup, len(gs))
	for i, g := range gs {
		out[i] = g.GateGroup
	}
	return out, err
}

func groupsOf(gate json.RawMessage) ([]gateGroup, error) {
	if len(gate) == 0 {
		return nil, nil
	}
	var top struct {
		Groups []json.RawMessage `json:"groups"`
	}
	if err := json.Unmarshal(gate, &top); err != nil {
		return nil, fmt.Errorf("reading the gate: %w", err)
	}
	var out []gateGroup
	for _, b := range top.Groups {
		var g gateGroup
		if err := json.Unmarshal(b, &g.GateGroup); err != nil {
			return nil, fmt.Errorf("reading the gate: %w", err)
		}
		if err := json.Unmarshal(b, &g.raw); err != nil {
			return nil, fmt.Errorf("reading the gate: %w", err)
		}
		out = append(out, g)
	}
	return out, nil
}

// secretNames are the variables p's gate takes its secrets from.
func secretNames(p Policy) ([]string, error) {
	gs, err := groupsOf(p.Gate)
	var names []string
	for _, g := range gs {
		names = append(names, g.SecretEnv)
		if g.Bearer != nil {
			names = append(names, g.Bearer.DigestsEnv)
		}
	}
	return names, err
}

// gateHandler is one group's handler with the secrets in place, the app whose hosts it covers, and its
// partner's key when it has one.
type gateHandler struct {
	app, group string
	raw        json.RawMessage
	bearer     *banBearer
	// enforce says the group's gate refuses: a request whose key does not pass needs the site's token there.
	enforce bool
}

// banBearer is a group's partner key as the ban's handler takes it (proxy/ban, bearer.go): the paths and
// methods of the group's bearer, its digests, and the hosts of its app on the server.
type banBearer struct {
	Hosts   []string `json:"hosts"`
	Paths   []string `json:"paths"`
	Methods []string `json:"methods,omitempty"`
	Digests []string `json:"digests"`
}

// gateHandlers are the handlers of p's groups that are not off: the group as written, its secret_env
// and its Bearer's digests_env replaced by the values the server keeps.
func gateHandlers(p Policy) ([]gateHandler, error) {
	gs, err := groupsOf(p.Gate)
	if err != nil {
		return nil, err
	}
	var out []gateHandler
	for _, g := range gs {
		if g.Mode == "off" {
			continue
		}
		h := map[string]any{}
		for k, v := range g.raw {
			h[k] = v
		}
		delete(h, "secret_env")
		secrets := p.GateSecrets[g.SecretEnv]
		if len(secrets) == 0 {
			return nil, fmt.Errorf("gate group %s: the server keeps no secret %s; apply the policy again with it set", g.Name, g.SecretEnv)
		}
		h["secrets"] = secrets
		var key *banBearer
		if g.Bearer != nil {
			var b map[string]json.RawMessage
			if err := json.Unmarshal(g.raw["bearer"], &b); err != nil {
				return nil, fmt.Errorf("gate group %s: bearer: %w", g.Name, err)
			}
			key = &banBearer{}
			if err := json.Unmarshal(g.raw["bearer"], key); err != nil {
				return nil, fmt.Errorf("gate group %s: bearer: %w", g.Name, err)
			}
			digests := p.GateSecrets[g.Bearer.DigestsEnv]
			if len(digests) == 0 {
				return nil, fmt.Errorf("gate group %s: the server keeps no digests %s; apply the policy again with it set", g.Name, g.Bearer.DigestsEnv)
			}
			bearer := map[string]any{}
			for k, v := range b {
				bearer[k] = v
			}
			delete(bearer, "digests_env")
			bearer["digests"] = digests
			h["bearer"] = bearer
			key.Hosts, key.Digests = nil, digests
		}
		h["handler"] = "boks_gate"
		raw, err := json.Marshal(h)
		if err != nil {
			return nil, err
		}
		out = append(out, gateHandler{app: g.App, group: g.Name, raw: raw, bearer: key, enforce: g.Mode == "enforce"})
	}
	return out, nil
}

// gateRoutes are the gate's routes of one server — the TLS hosts' on 443 or the others' on 80 — to go
// after the ban and the bot filter and before every app's route: a group's handler on the hosts its
// app routes on that server, whichever they are now. Not terminal: the handler passes what it does not
// answer on to the app. A host of the group's app that another app routes too is refused: the handler
// would judge the other app's requests by this site's rules. So is a route of the group's app by path:
// the gate judges the path the visitor sent, the app sees the path under its prefix, or stripped of
// it, where /shop/api/x is a page to the gate and the API to the app. A wildcard of the group's app
// leaves out exactly the requests another app's routes take before it — on this server, a route's host
// and path; of the other server's exact hosts, the whole host, as the app's own route does — so a path
// another app routes on a covered host is left to that app, and the host's other paths, which fall
// through to the wildcard, are gated.
func gateRoutes(hs []gateHandler, fragments []Fragment, tls bool) ([]caddyRoute, error) {
	gm, err := gateMatches(hs, fragments, tls)
	var out []caddyRoute
	for _, g := range gm {
		out = append(out, caddyRoute{Match: []match{g.m}, Handle: []handler{{raw: g.raw}}})
	}
	return out, err
}

// gatedMatch is a group's handler with the matcher of the requests it judges on one server.
type gatedMatch struct {
	gateHandler
	m match
}

// gateMatches are gateRoutes' matchers, one a group with hosts on the server.
func gateMatches(hs []gateHandler, fragments []Fragment, tls bool) ([]gatedMatch, error) {
	apps := map[string][]string{} // canonical host -> the apps that route it
	for _, f := range fragments {
		for _, r := range f.Routes {
			h := hostname.Canonical(r.Host)
			if !slices.Contains(apps[h], f.App) {
				apps[h] = append(apps[h], f.App)
			}
		}
	}
	var out []gatedMatch
	for _, g := range hs {
		var hosts []string
		for _, r := range Of(fragments, g.app) {
			if others := slices.DeleteFunc(slices.Clone(apps[hostname.Canonical(r.Host)]), func(a string) bool { return a == g.app }); len(others) > 0 {
				return nil, fmt.Errorf("gate group %s: host %s of %s is routed by %s too, whose requests the gate would judge by %s's rules",
					g.group, r.Host, g.app, strings.Join(others, ", "), g.app)
			}
			if r.Path != "" {
				return nil, fmt.Errorf("gate group %s: %s routes %s%s by path; the gate judges the path the visitor sent, not the one %s sees, so a gated app routes whole hosts",
					g.group, g.app, r.Host, r.Path, g.app)
			}
			if r.TLS == tls {
				hosts = addHost(hosts, r.Host)
			}
		}
		if len(hosts) == 0 {
			continue
		}
		slices.SortFunc(hosts, func(a, b string) int { return strings.Compare(hostname.Canonical(a), hostname.Canonical(b)) })
		m := match{Host: hosts}
		var except []match
		var elsewhere []string
		for _, h := range hosts {
			suffix, ok := strings.CutPrefix(hostname.Canonical(h), "*")
			if !ok {
				continue
			}
			for _, f := range fragments {
				for _, r := range f.Routes {
					other := hostname.Canonical(r.Host)
					// Caddy's wildcard stands for one label.
					if label, ok := strings.CutSuffix(other, suffix); !ok || label == "" || strings.Contains(label, ".") || strings.HasPrefix(other, "*") {
						continue
					}
					switch {
					case r.TLS != tls:
						// An exact host of the other server, the app's own included: its wildcard route leaves it out.
						elsewhere = addHost(elsewhere, r.Host)
					case f.App != g.app:
						except = append(except, routeMatch(r))
					}
				}
			}
		}
		if len(elsewhere) > 0 {
			slices.Sort(elsewhere)
			except = append(except, match{Host: elsewhere})
		}
		if len(except) > 0 {
			m.Not = except
		}
		out = append(out, gatedMatch{g, m})
	}
	return out, nil
}

// bearerAllows are the matchers of the requests no block refuses for their User-Agent on one server: a
// group's own requests, as its gate route matches them, on its bearer's methods and paths, with
// `Authorization: Bearer` and a token. A partner's server reading by the key is most often an HTTP
// library — axios, python-requests — whose name is what a block refuses. The header alone is enough
// here, unlike in the ban, which checks the key: the request goes on to the group's gate, which checks
// the token's digest, and a request whose key does not pass is judged as any other there — without the
// site's token it gets 401 — so a scraper writing the header gets past the block to the gate's checks
// still, and is counted by the ban. That holds on the paths the gate checks: a bearer path under the
// group's exempt, or outside /api/, would be open to the header alone, so the bearer's paths are kept
// under /api/ and off the exempt (docs/architecture.md, «API по ключу мимо блоков»). Only a
// group in enforce refuses so: one in log passes every request on, and its site may check no token at
// all (encarexport's does not), so a header alone would let a refused bot past the block to the API.
// The partner of a group in log is spared by the ban and the gate's signatures, which check the key,
// and by the blocks once its group is in enforce.
func bearerAllows(hs []gateHandler, fragments []Fragment, tls bool) ([]match, error) {
	gm, err := gateMatches(hs, fragments, tls)
	var out []match
	for _, g := range gm {
		if g.bearer == nil || !g.enforce {
			continue
		}
		m := g.m
		m.Method = g.bearer.methods()
		m.PathRegexp = &regexpMatch{Pattern: anyOf(g.bearer.Paths)}
		m.HeaderRegexp = map[string]regexpMatch{"Authorization": {Pattern: `(?i)^bearer\s+\S`}}
		out = append(out, m)
	}
	return out, err
}

// banBearers are the groups' partner keys with the hosts of their apps on the server, both 80's and
// 443's — the ban judges every request of the server in one route — canonical, as the request's Host
// arrives. A host under a group's wildcard that another app routes is the group's to the ban: the key
// is the group's partner's still, and the other app's gate, if it has one, asks it nothing.
func banBearers(hs []gateHandler, fragments []Fragment) []banBearer {
	var out []banBearer
	for _, g := range hs {
		if g.bearer == nil {
			continue
		}
		b := *g.bearer
		for _, r := range Of(fragments, g.app) {
			if h := hostname.Canonical(r.Host); !slices.Contains(b.Hosts, h) {
				b.Hosts = append(b.Hosts, h)
			}
		}
		if len(b.Hosts) == 0 {
			continue
		}
		slices.Sort(b.Hosts)
		out = append(out, b)
	}
	return out
}

// methods are the key's methods, GET and HEAD unless given, as the gate's handler takes them.
func (b *banBearer) methods() []string {
	if len(b.Methods) > 0 {
		return b.Methods
	}
	return []string{"GET", "HEAD"}
}

// anyOf is one RE2 pattern matching what any of patterns matches.
func anyOf(patterns []string) string {
	q := make([]string, len(patterns))
	for i, p := range patterns {
		q[i] = "(?:" + p + ")"
	}
	return strings.Join(q, "|")
}

// checkGateHosts refuses routes that would put a host of a gated app beside another app's, without the
// secrets the handlers need: what a deploy asks before anything of its app changes.
func checkGateHosts(p Policy, fragments []Fragment) error {
	gs, err := groupsOf(p.Gate)
	if err != nil {
		return err
	}
	var hs []gateHandler
	for _, g := range gs {
		if g.Mode != "off" {
			hs = append(hs, gateHandler{app: g.App, group: g.Name})
		}
	}
	_, err = gateRoutes(hs, fragments, true)
	return err
}

// loadGateSecrets gives p the gate's secrets: those it brings — from the environment of an apply —
// and, for the rest, those the server keeps from an earlier apply: a rollback, or an apply without a
// variable set. A secret neither has is an error: the config assembled without it would refuse every
// token of the group's site.
func loadGateSecrets(ctx context.Context, r remote.Runner, p *Policy) error {
	names, err := secretNames(*p)
	if err != nil || len(names) == 0 {
		return err
	}
	kept, err := keptGateSecrets(ctx, r)
	if err != nil {
		return err
	}
	// A copy: the caller's policy must not come back holding secrets it did not bring.
	merged := map[string][]string{}
	for k, v := range kept {
		merged[k] = v
	}
	for k, v := range p.GateSecrets {
		merged[k] = v
	}
	for _, n := range names {
		if len(merged[n]) == 0 {
			return fmt.Errorf("the server keeps no gate secret %s; apply the policy again with it set in the environment", n)
		}
	}
	p.GateSecrets = merged
	return nil
}

// keptGateSecrets are the gate's secrets the server keeps, by variable name; none when it keeps none.
func keptGateSecrets(ctx context.Context, r remote.Runner) (map[string][]string, error) {
	body, present, err := readFile(ctx, r, gateSecretPath())
	if err != nil || !present {
		return nil, err
	}
	var kept map[string][]string
	if err := json.Unmarshal([]byte(body), &kept); err != nil {
		return nil, fmt.Errorf("reading %s: %w", gateSecretPath(), err)
	}
	return kept, nil
}

// gateSecretFile is the file of secrets: every one the server was given, kept beyond the revision that
// named it, so a rollback to an older revision finds its secrets.
func gateSecretFile(secrets map[string][]string) []byte {
	b, _ := json.Marshal(secrets)
	return append(b, '\n')
}

// GateString is a policy's gate in one line for apply and status; "" without one.
func GateString(p Policy) string {
	gs, err := GateGroups(p)
	if err != nil {
		return "gate: " + err.Error()
	}
	if len(gs) == 0 {
		return ""
	}
	var parts []string
	for _, g := range gs {
		s := fmt.Sprintf("%s %s", g.App, g.Mode)
		if g.SiteGateOff() {
			s += " (the site no longer checks)"
		}
		parts = append(parts, s)
	}
	return "gate: " + strings.Join(parts, "; ")
}

// CheckGate refuses, before anything changes, a gate the server cannot run: a group's app with no
// routes here — a typo, or a group for another server — a secret neither the apply brings nor the
// server keeps, a host the group's app shares with another app, and a proxy whose Caddy refuses the
// handlers: an image without boks_gate (ban8 and older), or older than a field the policy writes, as
// the gate's fields go to the handler unread. The image — the running proxy's, or a stopped one's,
// which the boot after the apply starts as it is — validates the handlers in a container of its own,
// the secrets on its input, never on a command line.
func CheckGate(ctx context.Context, r remote.Runner, p Policy) error {
	if len(p.Gate) == 0 {
		return nil
	}
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	gs, err := groupsOf(p.Gate)
	if err != nil {
		return err
	}
	for _, g := range gs {
		if g.Mode != "off" && len(Of(fs, g.App)) == 0 {
			return fmt.Errorf("gate group %s: %s has no routes on this server; nothing was changed", g.Name, g.App)
		}
	}
	if err := loadSecrets(ctx, r, &p); err != nil {
		return err
	}
	if _, err := Config(p, fs); err != nil {
		return err
	}
	hs, err := gateHandlers(p)
	if err != nil || len(hs) == 0 {
		return err
	}
	state, kind, err := State(ctx, r)
	if err != nil || state == "" || kind != Kind {
		return err
	}
	image, err := Image(ctx, r)
	if err != nil {
		return err
	}
	routes := make([]caddyRoute, len(hs))
	for i, h := range hs {
		routes[i] = caddyRoute{Handle: []handler{{raw: h.raw}}}
	}
	probe, _ := json.Marshal(map[string]any{"admin": map[string]any{"disabled": true}, "apps": map[string]any{"http": map[string]any{
		"servers": map[string]any{"probe": map[string]any{"listen": []string{":80"}, "routes": routes}}}}})
	if _, err := r.Pipe(ctx, probe, "docker", "run", "--rm", "-i", "--network", "none", "--entrypoint", "caddy", image, "validate", "--config", "/dev/stdin"); err != nil {
		verb := "runs"
		if state != "running" {
			verb = "is a stopped container of"
		}
		return fmt.Errorf("the proxy %s %s, whose Caddy refuses the gate (%w); `boks proxy upgrade` with boks's own image first, then apply again", verb, image, err)
	}
	return nil
}
