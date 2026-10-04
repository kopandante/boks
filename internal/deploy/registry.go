package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// Login is what a pull from a private registry logs in with (E2). The token came from the
// environment boks runs in; it reaches the server only on the stdin of `docker login`, never in a
// command line, which anyone on the server can read in `ps`.
type Login struct {
	*config.Registry
	Token string
}

// NewLogin reads the token of the config's registry from the environment through lookup, or is nil
// for an app whose image is public. A token the config declares and the environment lacks is a
// refusal, and the command makes it before it connects to any server (E6).
func NewLogin(cfg *config.Config, lookup func(string) (string, bool)) (*Login, error) {
	if cfg.Registry == nil {
		return nil, nil
	}
	token, err := cfg.Registry.Token(lookup)
	if err != nil {
		return nil, fmt.Errorf("%w\nnothing was changed on the servers", err)
	}
	return &Login{Registry: cfg.Registry, Token: token}, nil
}

// registryLock serializes logins on a server. The credentials live in the docker config of the
// server's user, which every app deployed there as that user shares: without it, one deploy's logout
// could land between another's login and its pull. So it lives where that config does — one lock per
// docker config, the scope of what it guards — rather than in /tmp, shared by every user. It is an
// flock, so a run that dies lets go of it with its process and nothing has to clear it by hand.
const registryLock = "boks.registry.lock"

// registryWait is how long a pull waits for another one to finish with the registry login.
const registryWait = 10 * time.Minute

// loginPull is the shell script that pulls ref with a login to l, run on the server as one
// transaction: the logout is armed before the login and runs however the script ends — the pull
// failing, the login refused, a signal, the connection to boks dropping. One script rather than
// three commands from here, because a run of boks cut short could otherwise leave the login behind
// it, and its own logout would race the login it never saw finish.
//
// The pull runs in the background, watched. A pull can sit silent for minutes (a stalled registry,
// a busy daemon), and a silent process never learns that boks went away: nothing makes it write to
// the closed connection. So a watcher writes a dot to the connection every two seconds and stops
// the pull once that write fails — the connection is gone, the run was cancelled. The script waits
// on the pull with the wait builtin, which a trapped signal interrupts at once, where a foreground
// pull would hold the trap until the pull ended.
func loginPull(l *Login, ref string) string {
	host := remote.Quote(l.Host)
	return "conf=${DOCKER_CONFIG:-$HOME/.docker}\n" +
		"(umask 077 && mkdir -p \"$conf\") && exec 9>>\"$conf/" + registryLock + "\" || exit 1\n" +
		"flock -w " + strconv.Itoa(int(registryWait.Seconds())) + " 9 || { echo " +
		remote.Quote("boks: another pull has held the registry login ("+registryLock+" in the docker config) for over "+
			registryWait.String()+"; nothing was logged in") + " >&2; exit 1; }\n" +
		// The lock may have taken minutes, and boks may have gone in the meantime: a run nobody waits
		// for any more does not log in, nor log out what it never logged in. The same write the
		// watcher makes, once, before the logout is armed and the token used.
		"printf . 2>/dev/null || exit 1\n" +
		"pull= watch=\n" +
		// A logout that fails leaves the token on the server, which is a failure of the pull even when
		// the image came: the status says so, unless the pull had already failed and says it first.
		// docker logout exits 0 even when it could not write the config back (a disk the pull filled),
		// so the config is asked too: the host must be gone from it.
		"logout() { st=$?; [ -z \"$pull\" ] || kill \"$pull\" 2>/dev/null; [ -z \"$watch\" ] || kill \"$watch\" 2>/dev/null\n" +
		"  docker logout " + host + " >/dev/null 2>&1 && ! grep -qF " + remote.Quote(`"`+l.Host+`":`) +
		" \"$conf/config.json\" 2>/dev/null && return; echo " +
		remote.Quote("boks: docker logout "+l.Host+" failed, so the token may be left in the docker config of this "+
			"server; run `docker logout "+l.Host+"` there") + " >&2; [ \"$st\" -ne 0 ] || exit 1; }\n" +
		"trap logout EXIT\n" +
		"trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 141' PIPE; trap 'exit 143' TERM\n" +
		// What docker login says goes out only when it fails: on success it is a warning that the
		// credentials are stored unencrypted, true for the length of the pull and noise after it.
		"said=$(docker login " + host + " -u " + remote.Quote(l.User) + " --password-stdin 2>&1 >/dev/null) || " +
		"{ echo \"$said\" >&2; echo " + remote.Quote(loginRefused) + " >&2; exit 1; }\n" +
		"docker pull " + remote.Quote(ref) + " </dev/null >/dev/null & pull=$!\n" +
		// A subshell takes SIGPIPE back to its default, which would end the watcher and leave the pull;
		// ignored, the failed write is an error the watcher acts on.
		// Its sleep holds neither the connection nor the lock, so stopping the watcher releases both at
		// once rather than two seconds later.
		"{ trap '' PIPE; while kill -0 \"$pull\" 2>/dev/null; do sleep 2 >/dev/null 2>&1; printf . 2>/dev/null || " +
		"{ kill \"$pull\" 2>/dev/null; exit; }; done; } 9>&- & watch=$!\n" +
		"wait \"$pull\""
}

// loginRefused marks, in what the script says, that the login failed rather than the pull.
const loginRefused = "boks: docker login was refused"

// pullWithLogin pulls ref on a server logged in to l for the length of the pull and no longer.
func pullWithLogin(ctx context.Context, r remote.Runner, l *Login, ref string) error {
	if err := checkSecure(ctx, r, l.Host); err != nil {
		return err
	}
	if _, err := r.Pipe(ctx, []byte(l.Token), "sh", "-c", loginPull(l, ref)); err != nil {
		if strings.Contains(err.Error(), loginRefused) {
			// A login fails for the network or the disk too; only docker's own words of refusal name the token.
			if refusedToken(err) {
				return fmt.Errorf("%s refused the login as %s with the token in %s: %w\nnothing was changed on this server",
					l.Host, l.User, l.TokenEnv, err)
			}
			return fmt.Errorf("docker login to %s on this server failed: %w\nnothing was changed on this server", l.Host, err)
		}
		// Depot takes any token at the login and refuses it only when the image is asked for, so a
		// wrong token is mostly seen here.
		if refusedToken(err) {
			return fmt.Errorf("%s refused the pull of %s with the token in %s (user %s): the token is wrong, expired, "+
				"or has no access to this repository: %w\nnothing was changed on this server", l.Host, ref, l.TokenEnv, l.User, err)
		}
		return fmt.Errorf("pull %s from %s: %w", ref, l.Host, err)
	}
	return nil
}

// refusedToken reports a pull the registry turned down for its credentials, as docker words it. A
// bare "permission denied" is not one: that is the docker socket or the disk.
func refusedToken(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"401 unauthorized", "unauthorized:", "pull access denied", "denied: requested access", "authentication required"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// registryConfig is the part of `docker info` that says which registries the daemon would reach
// over plain HTTP: those named in insecure-registries, and every address in the insecure ranges
// (loopback by default).
type registryConfig struct {
	InsecureRegistryCIDRs []string
	IndexConfigs          map[string]struct{ Secure bool }
}

// checkSecure refuses a registry the server's docker would reach over plain HTTP, before the token
// is sent anywhere (E2): the config rules out http:// and loopback hosts, but the daemon has its own
// list. What cannot be checked is refused too — a token is not sent on the hope that it is safe.
func checkSecure(ctx context.Context, r remote.Runner, host string) error {
	out, err := r.Run(ctx, "docker", "info", "--format", "{{json .RegistryConfig}}")
	if err != nil {
		return fmt.Errorf("could not ask docker whether it reaches %s over HTTPS: %w", host, err)
	}
	var rc registryConfig
	if err := json.Unmarshal([]byte(out), &rc); err != nil {
		return fmt.Errorf("could not read docker's registry settings: %w", err)
	}
	if ic, ok := rc.IndexConfigs[host]; ok && !ic.Secure {
		return insecure(host, "it is listed in insecure-registries")
	}
	if len(rc.InsecureRegistryCIDRs) == 0 {
		return nil
	}
	name, _, _ := strings.Cut(host, ":")
	addrs := []string{name}
	if net.ParseIP(name) == nil {
		// Resolved where docker resolves it: the server, not the machine boks runs on.
		res, err := r.Run(ctx, "getent", "ahosts", name)
		if err != nil {
			return fmt.Errorf("could not resolve %s on the server to check it against docker's insecure ranges: %w", name, err)
		}
		addrs = nil
		for _, line := range strings.Split(res, "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				addrs = append(addrs, f[0])
			}
		}
		if len(addrs) == 0 {
			return fmt.Errorf("could not resolve %s on the server to check it against docker's insecure ranges: no address", name)
		}
	}
	for _, cidr := range rc.InsecureRegistryCIDRs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("could not read docker's insecure range %q: %w", cidr, err)
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && block.Contains(ip) {
				return insecure(host, a+" is in the insecure range "+cidr)
			}
		}
	}
	return nil
}

func insecure(host, why string) error {
	return fmt.Errorf("docker on this server reaches %s over plain HTTP (%s), and HTTP registries are not supported: "+
		"the token would cross the network in clear\nnothing was changed on this server", host, why)
}
