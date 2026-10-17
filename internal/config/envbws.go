package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// env_bws: <app> takes the app's secrets from Bitwarden Secrets Manager at deploy time instead of an
// env file next to boks.yml. A secret named `<app>__NAME` in BWS reaches the container as NAME.
//
// Why: the same secret used to live in three places — the local .env, the Depot CI secret BOKS_ENV
// that rewrote it in CI, and sometimes an HB_ENV_* blob in BWS — so changing a key meant three edits,
// and agents printed the local .env. With env_bws the secret has one home and the next deploy picks
// it up. The prefix is a naming convention, not access control: the BWS plan allows three projects.

// bwsSep separates the app from the variable name in a BWS secret key.
const bwsSep = "__"

// bwsNameRe is the variable name a BWS key may carry after the prefix. Anything else — a space, an
// empty name — docker would read as another name or refuse on the server, after the duplicate check.
var bwsNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// bwsSecret is one entry of `bws secret list --output json`.
type bwsSecret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// bwsTimeout bounds each outside call: a stalled BWS API or a keychain prompt nobody sees (a deploy
// over SSH) would otherwise hold the deploy with no output. Nothing on a server has changed yet.
var bwsTimeout = 2 * time.Minute

// bwsList fetches every secret the access token can read. A variable, so tests run without BWS.
var bwsList = func() ([]bwsSecret, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bwsTimeout)
	defer cancel()
	token := os.Getenv("BWS_ACCESS_TOKEN")
	if token == "" && runtime.GOOS == "darwin" {
		// On the owner's Mac the token lives in the login keychain, not in the shell.
		out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", "bws-claude-token", "-w").Output()
		if err == nil {
			token = strings.TrimSpace(string(out))
		}
	}
	if token == "" {
		return nil, fmt.Errorf("env_bws: BWS_ACCESS_TOKEN is not set")
	}
	cmd := exec.CommandContext(ctx, "bws", "--output", "json", "secret", "list")
	cmd.Env = append(os.Environ(), "BWS_ACCESS_TOKEN="+token)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// The reason is the server's line, not the backtrace hint bws prints last. Never the token.
		reason := strings.TrimSpace(stderr.String())
		for _, l := range strings.Split(reason, "\n") {
			if strings.Contains(l, "error message") {
				reason = strings.TrimSpace(l)
				break
			}
		}
		if ctx.Err() != nil {
			reason = fmt.Sprintf("no answer in %s", bwsTimeout)
		}
		reason = strings.ReplaceAll(reason, token, "<token>")
		return nil, fmt.Errorf("env_bws: bws secret list: %v: %s", err, reason)
	}
	var list []bwsSecret
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("env_bws: bws secret list: %w", err)
	}
	return list, nil
}

// One snapshot per boks process: every env_bws lookup of a run shares one request, because BWS
// rate-limits (429 «Slow down») a burst of calls. Separate boks processes each make their own.
var (
	bwsOnce     sync.Once
	bwsSnapshot []bwsSecret
	bwsErr      error
)

// bwsEnv returns the app's secrets, with the prefix cut off.
func bwsEnv(app string) (map[string]string, error) {
	bwsOnce.Do(func() { bwsSnapshot, bwsErr = bwsList() })
	if bwsErr != nil {
		return nil, bwsErr
	}
	prefix := app + bwsSep
	env := map[string]string{}
	for _, s := range bwsSnapshot {
		name, ok := strings.CutPrefix(s.Key, prefix)
		if !ok {
			continue
		}
		if !bwsNameRe.MatchString(name) {
			return nil, fmt.Errorf("env_bws: %q is not a variable name; rename the BWS secret %s<NAME>", name, prefix)
		}
		if _, dup := env[name]; dup {
			return nil, fmt.Errorf("env_bws: %s%s is in BWS twice; keep one", prefix, name)
		}
		// An env file carries one line per variable; a multi-line value would be cut, silently.
		if strings.ContainsAny(s.Value, "\n\r") {
			return nil, fmt.Errorf("env_bws: %s%s spans several lines; an env file cannot carry it", prefix, name)
		}
		env[name] = s.Value
	}
	if len(env) == 0 {
		// An empty set is a misspelled app or a token without access, never an app with no secrets.
		return nil, fmt.Errorf("env_bws: no secrets named %s* in BWS", prefix)
	}
	return env, nil
}

// envFileKeys lists the variable names an env file sets, to refuse a name set twice. It reads names
// the way `docker run --env-file` does (docker/cli pkg/kvfile): a UTF-8 BOM before the first line is
// dropped, and a bare `NAME` line sets NAME from the server's environment, so it counts too.
func envFileKeys(data []byte) map[string]bool {
	keys := map[string]bool{}
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, _, _ := strings.Cut(line, "=")
		keys[strings.TrimSpace(k)] = true
	}
	return keys
}
