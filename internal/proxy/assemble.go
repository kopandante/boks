package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/kopandante/boks/internal/remote"
)

// ServerBoks is the server's own boks (#154), relative to the home: the link `boks server install`
// and `apply` keep naming the build of the commit server.yml writes.
const ServerBoks = ".boks/bin/boks"

// AssembleCommand is the command the server's boks assembles the proxy's config with (ServerConfig).
const AssembleCommand = "proxy-config"

// CheckArg follows AssembleCommand to ask the server's boks for the config of a policy not applied
// yet (CandidateConfig), changing nothing.
const CheckArg = "check"

// ownBoks says whether the server has a boks of its own. One that is there and does not run — a link
// to a build that is gone — is an error, not "none": assembling here then would be what a server
// with its own boks never does.
func ownBoks(ctx context.Context, r remote.Runner) (bool, error) {
	out, err := r.Run(ctx, "sh", "-c", "if [ -x "+ServerBoks+" ]; then echo yes; elif [ -e "+ServerBoks+" ] || [ -L "+ServerBoks+" ]; then echo broken; fi; true")
	if err != nil {
		return false, err
	}
	if out == "broken" {
		return false, fmt.Errorf("the server's boks %s is there but does not run; `boks server apply` installs it again", ServerBoks)
	}
	return out == "yes", nil
}

// candidate is what `boks proxy-config check` reads: a policy not applied yet, as SetPolicy writes it,
// with the secrets a policy never records, and the routes to assemble with it.
type candidate struct {
	Policy         json.RawMessage     `json:"policy"`
	Fragments      []Fragment          `json:"fragments,omitempty"`
	EgressPassword string              `json:"egress_password,omitempty"`
	GateSecrets    map[string][]string `json:"gate_secrets,omitempty"`
}

// assembleOf is the config p — its secrets loaded — and fs make as this server's proxy would be given
// it: by the server's own boks if it has one. What a check before any change validates is then the
// config the reload will load, not one this boks would assemble instead.
func assembleOf(ctx context.Context, r remote.Runner, p Policy, fs []Fragment) ([]byte, error) {
	own, err := ownBoks(ctx, r)
	if err != nil {
		return nil, err
	}
	if !own {
		return Config(p, fs)
	}
	c := candidate{Policy: marshal(p), Fragments: fs, GateSecrets: p.GateSecrets}
	if p.Egress != nil {
		c.EgressPassword = p.Egress.Password
	}
	in, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	out, err := r.Pipe(ctx, in, ServerBoks, AssembleCommand, CheckArg)
	if err == nil && out == "" {
		err = fmt.Errorf("it answered with no config")
	}
	if err != nil {
		return nil, fmt.Errorf("the server's boks did not assemble the config of this policy: %w (if it is a build older than this "+
			"boks, `boks server apply` with a newer boks: commit replaces it)", err)
	}
	return []byte(out + "\n"), nil
}

// assemble is the config the proxy is to run with the fragments fs and the server's applied policy.
// On a server with its own boks, that boks assembles it: the policy and the code that turns it into
// Caddy's config are then of one version — the one server.yml names — whichever boks runs the deploy
// or the apply, so a boks older than the policy cannot drop a filter it does not know. Its refusal is
// a refusal: assembling here instead would be exactly that. A server without one assembles here, as
// before.
func assemble(ctx context.Context, r remote.Runner, fs []Fragment) ([]byte, error) {
	own, err := ownBoks(ctx, r)
	if err != nil {
		return nil, err
	}
	if !own {
		pol, err := appliedPolicy(ctx, r)
		if err != nil {
			return nil, err
		}
		return Config(pol, fs)
	}
	in, err := json.Marshal(fs)
	if err != nil {
		return nil, err
	}
	out, err := r.Pipe(ctx, in, ServerBoks, AssembleCommand)
	if err != nil {
		return nil, fmt.Errorf("the server's boks did not assemble the proxy's config: %w (if it is a build older than %s, "+
			"`boks server apply` with a newer boks: commit replaces it)", err, AssembleCommand)
	}
	// The runner trims what a command prints; Config ends in one newline.
	return []byte(out + "\n"), nil
}

// CheckServerBoks refuses, before anything changes, a policy the server's own boks would not read:
// SetPolicy writes p and has that boks assemble the config from it, and a field it does not know
// would otherwise be refused only then — after `server apply` had created the proxy again in p's
// shape (Reshape), which the policy put back would not listen on. The bytes asked about are the ones
// SetPolicy writes. A server without its own boks has nothing to ask.
func CheckServerBoks(ctx context.Context, r remote.Runner, p Policy) error {
	own, err := ownBoks(ctx, r)
	if err != nil || !own {
		return err
	}
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	if err := loadSecrets(ctx, r, &p); err != nil {
		return err
	}
	if _, err := assembleOf(ctx, r, p, fs); err != nil {
		return fmt.Errorf("%w; the policy and the proxy were not changed", err)
	}
	return nil
}

// ServerConfig is what the server's boks prints for `boks proxy-config`: the config of the fragments
// in, and of the policy and secrets on the server r reaches — its own disk. Both are read strictly: a
// field this boks does not know is a policy or route of a newer boks, and assembled without it the
// proxy would quietly drop what it asks for. The answer then is to install a newer boks.
func ServerConfig(ctx context.Context, r remote.Runner, in []byte) ([]byte, error) {
	var fs []Fragment
	if err := strict(in, &fs); err != nil {
		return nil, fmt.Errorf("reading the routes: %w; this boks is older than the one that wrote them", err)
	}
	body, present, err := readFile(ctx, r, policyPath())
	if err != nil {
		return nil, err
	}
	var p Policy
	if present {
		if p, err = strictPolicy([]byte(body), policyPath()); err != nil {
			return nil, err
		}
	}
	if err := loadSecrets(ctx, r, &p); err != nil {
		return nil, err
	}
	return Config(p, fs)
}

// CandidateConfig is what the server's boks answers `boks proxy-config check` with: the config of the
// candidate in — read as strictly as ServerConfig reads its disk — with the secrets it brings, and for
// the rest those the server keeps.
func CandidateConfig(ctx context.Context, r remote.Runner, in []byte) ([]byte, error) {
	var c candidate
	if err := strict(in, &c); err != nil {
		return nil, fmt.Errorf("reading the policy to check: %w; this boks is older than the one that asks", err)
	}
	p, err := strictPolicy(c.Policy, "the policy")
	if err != nil {
		return nil, err
	}
	if p.Egress != nil && c.EgressPassword != "" {
		e := *p.Egress
		e.Password = c.EgressPassword
		p.Egress = &e
	}
	p.GateSecrets = c.GateSecrets
	if err := loadSecrets(ctx, r, &p); err != nil {
		return nil, err
	}
	return Config(p, c.Fragments)
}

func strictPolicy(b []byte, what string) (Policy, error) {
	var p Policy
	if err := strict(b, &p); err != nil {
		return p, fmt.Errorf("reading %s: %w; this boks is older than the policy, so `boks server apply` "+
			"needs a newer boks: commit", what, err)
	}
	return p, nil
}

// strict decodes JSON refusing fields v does not have.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
