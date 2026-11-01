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

// assemble is the config the proxy is to run with the fragments fs and the server's applied policy.
// On a server with its own boks, that boks assembles it: the policy and the code that turns it into
// Caddy's config are then of one version — the one server.yml names — whichever boks runs the deploy
// or the apply, so a boks older than the policy cannot drop a filter it does not know. Its refusal is
// a refusal: assembling here instead would be exactly that. A server without one assembles here, as
// before.
func assemble(ctx context.Context, r remote.Runner, fs []Fragment) ([]byte, error) {
	own, err := r.Run(ctx, "sh", "-c", "[ -x "+ServerBoks+" ] && echo yes; true")
	if err != nil {
		return nil, err
	}
	if own != "yes" {
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
		if err := strict([]byte(body), &p); err != nil {
			return nil, fmt.Errorf("reading %s: %w; this boks is older than the policy, so `boks server apply` "+
				"needs a newer boks: commit", policyPath(), err)
		}
	}
	if err := loadSecrets(ctx, r, &p); err != nil {
		return nil, err
	}
	return Config(p, fs)
}

// strict decodes JSON refusing fields v does not have.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
