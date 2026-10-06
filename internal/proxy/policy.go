package proxy

// The server's policy: what the proxy applies to every app's traffic rather than to one app's routes —
// the bot filter. Applied by `boks server apply`, read by every run that assembles the config.

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

// policyMarker sits among the fragments and holds FragmentFormat alone: an older boks reading the
// fragments stops at it rather than reload the proxy without the policy. No app's name starts with an
// underscore.
func policyMarker() string { return path.Join(Dir, "routes", "_server.json") }

func policyPath() string         { return path.Join(ServerDir, "policy.json") }
func historyPath(rev int) string { return path.Join(ServerDir, "history", strconv.Itoa(rev)+".json") }

// SamePolicy says whether two policies filter alike, whatever their revisions.
func SamePolicy(a, b Policy) bool {
	a.Revision, a.Floor, b.Revision, b.Floor = 0, 0, 0, 0
	return bytes.Equal(marshal(a), marshal(b))
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
// any run takes it there. A failed write or reload puts the previous policy back and reloads it by
// force — the answer may have been lost after the file was replaced or Caddy took the new config. The history is written last: it holds only
// revisions that were applied. The caller holds the server's admission lock.
func SetPolicy(ctx context.Context, r remote.Runner, log io.Writer, p Policy) error {
	prevBody, prevPresent, err := readFile(ctx, r, policyPath())
	if err != nil {
		return err
	}
	// The policy being replaced goes into the history first if it is not there: a run whose history
	// write failed after Caddy took its policy left none, and once replaced, that revision could not
	// be rolled back to, nor applied again past the floor.
	if prevPresent {
		var prev Policy
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
	if _, err := Config(p, fs); err != nil {
		return err
	}
	if err := remote.UploadAtomic(ctx, r, fmt.Appendf(nil, "%d\n", FragmentFormat), policyMarker()); err != nil {
		return fmt.Errorf("marking the server's routes for this boks: %w", err)
	}
	// A failed write is put back as a failed reload is: its answer can be lost after the file was
	// replaced, and left there the next run of any app would load the policy this run reported failed.
	err = remote.UploadAtomic(ctx, r, marshal(p), policyPath())
	if err != nil {
		err = fmt.Errorf("recording the server's policy: %w", err)
	} else {
		_, err = converge(ctx, r, log, fs, false, fmt.Sprintf("the server's policy, revision %d", p.Revision))
	}
	if err != nil {
		back := context.WithoutCancel(ctx)
		if prevPresent {
			err = errors.Join(err, remote.UploadAtomic(back, r, []byte(prevBody), policyPath()))
		} else if _, rmErr := r.Run(back, "rm", "-f", policyPath()); rmErr != nil {
			err = errors.Join(err, rmErr)
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
