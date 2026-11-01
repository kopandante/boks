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

// CheckArg follows AssembleCommand to ask the server's boks whether it reads the policy on stdin
// (CheckPolicy), changing nothing.
const CheckArg = "check"

// ownBoks says whether the server has a boks of its own.
func ownBoks(ctx context.Context, r remote.Runner) (bool, error) {
	out, err := r.Run(ctx, "sh", "-c", "[ -x "+ServerBoks+" ] && echo yes; true")
	return out == "yes", err
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
		return nil, fmt.Errorf("the server's boks did not assemble the proxy's config (a build older than %s needs `boks server apply` "+
			"with a newer boks: commit): %w", AssembleCommand, err)
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
	if _, err := r.Pipe(ctx, marshal(p), ServerBoks, AssembleCommand, CheckArg); err != nil {
		return fmt.Errorf("the server's boks does not read this policy (`boks server apply` needs a boks: commit "+
			"as new as this boks): %w; the policy and the proxy were not changed", err)
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

// CheckPolicy is what the server's boks answers `boks proxy-config check` with: whether it reads the
// policy in as ServerConfig reads the one on its disk.
func CheckPolicy(in []byte) error {
	_, err := strictPolicy(in, "the policy")
	return err
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
