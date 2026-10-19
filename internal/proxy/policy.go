package proxy

// The server's policy: what the proxy applies to every app's traffic rather than to one app's routes —
// the bot filter and the ban by request rate. Applied by `boks server apply`, read by every run that assembles the config.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/kopandante/boks/internal/remote"
)

// ServerDir holds the server's own state: the applied policy, its history and the journal of the runs
// that changed it. An underscore for the reason Dir has one: `server` could be an app's name.
const ServerDir = ".boks/_server"

// acmeChallenge is the path HTTP-01 validation asks for. Caddy answers it before any route, so a rule
// would not reach it anyway; the exception keeps that so if Caddy ever moved it into the routes.
const acmeChallenge = "/.well-known/acme-challenge/*"

// Policy is the server's policy as applied. Revision is the one the policy came with; Floor is the
// highest revision the server ever applied, which a rollback does not lower: the next edit is Floor+1.
type Policy struct {
	Revision int        `json:"revision"`
	Floor    int        `json:"floor"`
	Allow    []BotAllow `json:"allow,omitempty"`
	Block    []BotBlock `json:"block,omitempty"`
	Egress   *Egress    `json:"egress,omitempty"`
	// TrustedProxies are the CIDR ranges of the proxies in front of boks whose X-Forwarded-For the
	// servers on 80 and 443 keep; none trusts no one.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	Ban            *Ban     `json:"ban,omitempty"`
	// Gate is the gate as server.yml writes it, the proxy's check of the sites' API token (gate.go).
	Gate json.RawMessage `json:"gate,omitempty"`
	// GateSecrets are the gate's secrets by the variable they came from, never recorded in the policy:
	// they sit in gateSecretPath, read when the config is assembled.
	GateSecrets map[string][]string `json:"-"`
}

// Ban refuses, on every host the proxy serves, an address that went past one of its Rules: for
// Duration it gets 403 and reaches no app. boks's own Caddy handler (proxy/ban) counts and keeps the
// bans in the proxy's memory: a reload keeps them, a restart of the proxy loses them. Windows and
// Duration are written as Go durations without zero units (1m, 24h, 1h30m).
type Ban struct {
	Rules []BanRule `json:"rules,omitempty"`
	// Limit and Window are a ban as a boks of format 6 recorded it, one limit over every request: a
	// revision of the history a rollback puts back. It runs as the rule default of class all.
	Limit    int    `json:"limit,omitempty"`
	Window   string `json:"window,omitempty"`
	Duration string `json:"duration"`
	// Heuristics are nil when off.
	Heuristics *BanHeuristics `json:"heuristics,omitempty"`
	// ExemptPaths are patterns on the cleaned path never counted, beside the handler's own: /_next/ and,
	// for the rules of class all and page, a page's subresources by Sec-Fetch-Dest. ACME's challenge
	// the ban route leaves out by its matcher.
	ExemptPaths []string `json:"exempt_paths,omitempty"`
	// ExemptRanges are CIDR ranges never counted, beside loopback and the private networks.
	ExemptRanges []string `json:"exempt_ranges,omitempty"`
}

// BanRule counts an address's requests of Class — all, page or api — on a path one of Paths matches,
// when there are any; more than Limit within Window bans the address.
type BanRule struct {
	Name   string   `json:"name"`
	Limit  int      `json:"limit"`
	Window string   `json:"window"`
	Class  string   `json:"class"`
	Paths  []string `json:"paths,omitempty"`
}

// BanHeuristics flag a request whose Fetch Metadata no browser sends, and in Mode ban refuse the
// fingerprint a cluster of addresses sends them with.
type BanHeuristics struct {
	Mode    string     `json:"mode"`
	Cluster BanCluster `json:"cluster"`
}

// BanCluster is more than Limit flagged requests of one fingerprint within Window, from at least
// MinAddresses addresses.
type BanCluster struct {
	Limit        int    `json:"limit"`
	Window       string `json:"window"`
	MinAddresses int    `json:"min_addresses"`
}

// rules are the ban's rules, a ban of format 6 its one limit as the rule default.
func (b *Ban) rules() []BanRule {
	if len(b.Rules) > 0 || b.Limit == 0 {
		return b.Rules
	}
	return []BanRule{{Name: "default", Limit: b.Limit, Window: b.Window, Class: "all"}}
}

func (b *Ban) String() string {
	var rs []string
	for _, r := range b.rules() {
		what := map[string]string{"page": " page requests", "api": " api requests"}[r.Class]
		switch n := len(r.Paths); {
		case n == 1:
			what += " on 1 path"
		case n > 1:
			what += fmt.Sprintf(" on %d paths", n)
		}
		rs = append(rs, fmt.Sprintf("%s: %d%s in %s", r.Name, r.Limit, what, r.Window))
	}
	s := fmt.Sprintf("ban: an address past a rule is refused for %s — %s", b.Duration, strings.Join(rs, "; "))
	if h := b.Heuristics; h != nil {
		s += fmt.Sprintf("; heuristics %s, cluster of %d in %s from %d addresses", h.Mode, h.Cluster.Limit, h.Cluster.Window, h.Cluster.MinAddresses)
	}
	return s
}

// Egress is the forward proxy Caddy runs beside the apps' servers, on a port of its own, for the
// outgoing requests of services that leave from this server's address. Password is never recorded
// in the policy or its history: it sits in a file of its own (egressSecretPath), read when the config
// is assembled.
type Egress struct {
	Port      int      `json:"port"`
	Allow     []string `json:"allow"`
	User      string   `json:"user,omitempty"`
	Ports     []int    `json:"ports"`
	HostsFile string   `json:"hosts_file,omitempty"`
	Password  string   `json:"-"`
}

// BotBlock answers 403 to a User-Agent matching UserAgent on Domains — each and every host under it —
// or on every host when there are none, unless an allow matches the request.
type BotBlock struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains,omitempty"`
	UserAgent string   `json:"user_agent"`
}

// BotAllow is a request no block refuses: every field given must match.
type BotAllow struct {
	Host      string   `json:"host,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	UserAgent string   `json:"user_agent,omitempty"`
}

// policyFormat is the format a policy needs boks to know: the gate's with a gate, the fragments' without.
func policyFormat(p Policy) int {
	if len(p.Gate) > 0 {
		return GateFormat
	}
	return FragmentFormat
}

// policyMarker sits among the fragments and holds the policy's format alone: an older boks reading the
// fragments stops at it rather than reload the proxy without the policy. No app's name starts with an
// underscore.
func policyMarker() string { return path.Join(Dir, "routes", "_server.json") }

func policyPath() string         { return path.Join(ServerDir, "policy.json") }
func egressSecretPath() string   { return path.Join(ServerDir, "egress.secret") }
func historyPath(rev int) string { return path.Join(ServerDir, "history", strconv.Itoa(rev)+".json") }

// SamePolicy says whether two policies filter alike, whatever their revisions.
// A ban of format 6 is compared as its one rule: the same server.yml validates to that rule today.
func SamePolicy(a, b Policy) bool {
	a.Revision, a.Floor, b.Revision, b.Floor = 0, 0, 0, 0
	return bytes.Equal(marshal(asRules(a)), marshal(asRules(b)))
}

// asRules is p with a ban of format 6 written as its rule default.
func asRules(p Policy) Policy {
	if b := p.Ban; b != nil && len(b.Rules) == 0 && b.Limit != 0 {
		r := *b
		r.Rules, r.Limit, r.Window = r.rules(), 0, ""
		p.Ban = &r
	}
	return p
}

func marshal(p Policy) []byte {
	b, _ := json.MarshalIndent(p, "", "  ")
	return append(b, '\n')
}

// ReadPolicy is the policy the server applies; a server that never had one applies none, which is an
// answer; a failed read is an error, not an empty policy — that would drop the filter on the next reload.
func ReadPolicy(ctx context.Context, r remote.Runner) (Policy, error) {
	return readPolicy(ctx, r, policyPath())
}

// appliedPolicy is the server's policy as the config is assembled from it: with the egress login's
// password and the gate's secrets, which the policy never records.
func appliedPolicy(ctx context.Context, r remote.Runner) (Policy, error) {
	p, err := ReadPolicy(ctx, r)
	if err != nil {
		return p, err
	}
	return p, loadSecrets(ctx, r, &p)
}

// loadSecrets gives p every secret the policy never records: the egress login's password and the
// gate's secrets — those p brings, and for the rest those the server keeps. Every path that assembles
// the config from a policy goes through it: one that skipped a secret would assemble a proxy that
// refuses its clients, or fail where the server has all it needs.
func loadSecrets(ctx context.Context, r remote.Runner, p *Policy) error {
	if err := loadSecret(ctx, r, p); err != nil {
		return err
	}
	return loadGateSecrets(ctx, r, p)
}

// loadSecret gives p's egress login the password the server keeps for it. A server whose secret is
// missing or belongs to another user is an error: the config assembled without it would refuse every
// client of the proxy.
func loadSecret(ctx context.Context, r remote.Runner, p *Policy) error {
	e := p.Egress
	if e == nil || e.User == "" || e.Password != "" {
		return nil
	}
	body, present, err := readFile(ctx, r, egressSecretPath())
	if err != nil {
		return err
	}
	user, pass, ok := strings.Cut(strings.TrimSuffix(body, "\n"), ":")
	if !present || !ok || user != e.User || pass == "" {
		return fmt.Errorf("the server keeps no password for the egress login %s; apply the policy again with its password_env set", e.User)
	}
	// A copy: the caller's policy shares the pointer, and must not come back holding the password.
	withPass := *e
	withPass.Password = pass
	p.Egress = &withPass
	return nil
}

// History is the policy a revision applied, and whether the server has it.
func History(ctx context.Context, r remote.Runner, rev int) (Policy, bool, error) {
	_, present, err := readFile(ctx, r, historyPath(rev))
	if err != nil || !present {
		return Policy{}, false, err
	}
	p, err := readPolicy(ctx, r, historyPath(rev))
	return p, true, err
}

func readPolicy(ctx context.Context, r remote.Runner, p string) (Policy, error) {
	body, present, err := readFile(ctx, r, p)
	if err != nil || !present {
		return Policy{}, err
	}
	var pol Policy
	if err := json.Unmarshal([]byte(body), &pol); err != nil {
		return Policy{}, fmt.Errorf("reading %s: %w", p, err)
	}
	return pol, nil
}

// botRoutes are the policy's blocks as Caddy routes, to go before every app's: a route that matched
// first would serve the bot. The domains are matched by a pattern on Host rather than by Caddy's host
// matcher: that one covers a single label under `*.`, and every host it names on 443 is a name Caddy
// sets out to obtain a certificate for. The allows sit in `not`, which Caddy's certificate discovery
// does not look into, so their host matcher stays a matcher.
func botRoutes(p Policy) []caddyRoute {
	exempt := allowed(p)
	var rs []caddyRoute
	for _, b := range p.Block {
		h := map[string]regexpMatch{"User-Agent": {Pattern: b.UserAgent}}
		if len(b.Domains) > 0 {
			h["Host"] = regexpMatch{Pattern: domainsPattern(b.Domains)}
		}
		rs = append(rs, caddyRoute{Match: []match{{HeaderRegexp: h, Not: exempt}},
			Handle: []handler{{Handler: "static_response", StatusCode: 403}}, Terminal: true})
	}
	return rs
}

// allowed are the matcher sets of what no filter of the policy refuses: ACME's challenge and the
// policy's allows — search engines and monitoring, which neither a block nor the ban may touch.
func allowed(p Policy) []match {
	exempt := []match{{Path: []string{acmeChallenge}}}
	for _, a := range p.Allow {
		var m match
		if a.Host != "" {
			m.Host = []string{a.Host}
		}
		for _, p := range a.Paths {
			m.Path = append(m.Path, p, p+"/*")
		}
		if a.UserAgent != "" {
			m.HeaderRegexp = map[string]regexpMatch{"User-Agent": {Pattern: a.UserAgent}}
		}
		exempt = append(exempt, m)
	}
	return exempt
}

// banRoute is the policy's ban as a Caddy route, to go first on the servers on 80 and 443: on every
// host, a host no app routes included, before a block or an app's route can answer. Not terminal —
// the handler passes what it does not refuse on to the routes after it. The policy's allows sit in
// `not`, as they do for the blocks, so the ban counts and refuses none of what they let through; the
// handler leaves out the rest (private networks, /_next/, subresources, the exempt paths).
func banRoute(b Ban, p Policy) caddyRoute {
	// A ban of format 6 goes to the handler in its own form, which ban3 and every later handler take:
	// as rules, it would be refused by the ban3 a server runs until its proxy is upgraded — every
	// deploy's reload, and the upgrade's own.
	return caddyRoute{Match: []match{{Not: allowed(p)}}, Handle: []handler{{Handler: "boks_ban", Limit: b.Limit, Window: b.Window,
		Rules: b.Rules, Heuristics: b.Heuristics, Duration: b.Duration, ExemptPaths: b.ExemptPaths, ExemptRanges: b.ExemptRanges}}}
}

// domainsPattern matches a Host that is one of domains or under one at any depth, with or without a
// port and the root's trailing dot.
func domainsPattern(domains []string) string {
	q := make([]string, len(domains))
	for i, d := range domains {
		q[i] = regexp.QuoteMeta(d)
	}
	return `(?i)^([^.:/]+\.)*(` + strings.Join(q, "|") + `)\.?(:[0-9]+)?$`
}

// SetPolicy makes p the server's policy and has the proxy run it. Like a fragment, the policy is
// recorded before the reload: a run cut after Caddy took the config would otherwise leave the old
// policy on disk, and the next run of any app would assemble from it and drop the filter without a
// word. Recorded first, a cut run leaves the policy the proxy is moving to, and the next converge of
// any run takes it there. The reload is forced. A failed write or reload puts the previous policy
// back and reloads it by force too — the answer may have been lost after the file was replaced or
// Caddy took the new config. The history is written last: it holds only revisions that were applied,
// and the replaced one, kept before anything changes. The caller holds the server's admission lock.
func SetPolicy(ctx context.Context, r remote.Runner, log io.Writer, p Policy) error {
	prevBody, prevPresent, err := readFile(ctx, r, policyPath())
	if err != nil {
		return err
	}
	// The policy being replaced goes into the history first if it is not there: a run whose history
	// write failed after Caddy took its policy left none, and once replaced, that revision could not
	// be rolled back to, nor applied again past the floor.
	var prev Policy
	if prevPresent {
		if err := json.Unmarshal([]byte(prevBody), &prev); err != nil {
			return fmt.Errorf("reading %s: %w", policyPath(), err)
		}
		if _, kept, err := readFile(ctx, r, historyPath(prev.Revision)); err != nil {
			return err
		} else if !kept {
			if err := recordHistory(ctx, r, prev); err != nil {
				return err
			}
		}
	}
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	// The login's password: the one p brings, or — a rollback, a policy applied again without it — the
	// one the server keeps, if it is that user's.
	if err := loadSecrets(ctx, r, &p); err != nil {
		return err
	}
	if _, err := Config(p, fs); err != nil {
		return err
	}
	// The marker first: alone, it only stops an older boks. Then the secrets, before the policy that
	// needs them; until the policy is applied, a failure puts the previous marker and secrets back — or
	// removes those written — with the previous policy: a secret left changed under the old policy
	// would be taken by the next deploy's reload, and clients on the old password refused; a marker
	// left at the new format would turn away every boks of format 7 for nothing (a gate added), or let
	// one drop the gate (a gate removed). Everything to put back is read before anything is written.
	prevMarker, markerPresent, err := readFile(ctx, r, policyMarker())
	if err != nil {
		return err
	}
	prevSecret, secretPresent, err := readFile(ctx, r, egressSecretPath())
	if err != nil {
		return err
	}
	prevGate, gatePresent, err := readFile(ctx, r, gateSecretPath())
	if err != nil {
		return err
	}
	putBack := func(back context.Context, path, prev string, present bool) error {
		if present {
			return remote.UploadAtomic(back, r, []byte(prev), path)
		}
		_, err := r.Run(back, "rm", "-f", path)
		return err
	}
	restoreSecret := func(back context.Context) error {
		return errors.Join(putBack(back, policyMarker(), prevMarker, markerPresent),
			putBack(back, egressSecretPath(), prevSecret, secretPresent),
			putBack(back, gateSecretPath(), prevGate, gatePresent))
	}
	if err := remote.UploadAtomic(ctx, r, fmt.Appendf(nil, "%d\n", policyFormat(p)), policyMarker()); err != nil {
		// Its answer may be lost after the file was replaced.
		return fmt.Errorf("marking the server's routes for this boks: %w", errors.Join(err, restoreSecret(context.WithoutCancel(ctx))))
	}
	if e := p.Egress; e != nil && e.User != "" && prevSecret != e.User+":"+e.Password+"\n" {
		if err := remote.UploadAtomic(ctx, r, []byte(e.User+":"+e.Password+"\n"), egressSecretPath()); err != nil {
			// Its answer may be lost after the file was replaced.
			return fmt.Errorf("recording the egress login: %w", errors.Join(err, restoreSecret(context.WithoutCancel(ctx))))
		}
	}
	// The gate's secrets: every one the server was given, those p brings replacing theirs.
	if len(p.GateSecrets) > 0 {
		if file := gateSecretFile(p.GateSecrets); string(file) != prevGate {
			if err := remote.UploadAtomic(ctx, r, file, gateSecretPath()); err != nil {
				return fmt.Errorf("recording the gate's secrets: %w", errors.Join(err, restoreSecret(context.WithoutCancel(ctx))))
			}
		}
	}
	// A failed write is put back as a failed reload is: its answer can be lost after the file was
	// replaced, and left there the next run of any app would load the policy this run reported failed.
	err = remote.UploadAtomic(ctx, r, marshal(p), policyPath())
	if err != nil {
		err = fmt.Errorf("recording the server's policy: %w", err)
	} else {
		// By force, every time: caddy.json records what Caddy runs only until a run is cut after a reload,
		// and a policy that matches the record — a rollback, a repeat, the retry of either — would
		// otherwise leave Caddy on whatever the cut run gave it. A server's policy changes rarely, and
		// a reload loses nothing.
		_, err = converge(ctx, r, log, fs, true, fmt.Sprintf("the server's policy, revision %d", p.Revision))
	}
	if err != nil {
		back := context.WithoutCancel(ctx)
		var undo error
		if prevPresent {
			undo = remote.UploadAtomic(back, r, []byte(prevBody), policyPath())
		} else {
			_, undo = r.Run(back, "rm", "-f", policyPath())
		}
		err = errors.Join(err, undo)
		// The secret follows the policy on disk, never ahead of it: beside a new policy left in place,
		// the previous secret — or none — would refuse its clients, or every deploy. A failed undo
		// says nothing of which one is there — the new policy may never have got there, or the undo's
		// answer was lost after it acted — so the file decides.
		restore := undo == nil
		if !restore {
			body, present, readErr := readFile(back, r, policyPath())
			err = errors.Join(err, readErr)
			restore = readErr == nil && present == prevPresent && body == prevBody
		}
		if restore {
			err = errors.Join(err, restoreSecret(back))
		}
		_, backErr := converge(back, r, log, fs, true, "the previous policy")
		return fmt.Errorf("the policy was not applied; the previous one is back: %w", errors.Join(err, backErr))
	}
	return recordHistory(ctx, r, p)
}

// recordHistory keeps the policy of p's revision, without the server's floor: it is what a rollback puts back.
func recordHistory(ctx context.Context, r remote.Runner, p Policy) error {
	p.Floor = 0
	if err := remote.UploadAtomic(ctx, r, marshal(p), historyPath(p.Revision)); err != nil {
		return fmt.Errorf("recording revision %d in the history: %w", p.Revision, err)
	}
	return nil
}
