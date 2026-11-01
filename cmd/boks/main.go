// Command boks deploys pre-built images to servers through Docker and Caddy over SSH.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/cert"
	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/deploy"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

const usage = `usage: boks [-f boks.yml] <command>

  deploy <tag>     pull image:<tag>, start it, switch the proxy once it is healthy, retire the
                   previous version once it has drained; then ask each TLS host from a container
                   on the app's network, and fail if the proxy does not answer
  rollback [id]    return to a recorded release (the previous one by default), reproducing the
                   image by digest, the ports, volumes and environment it actually ran with.
                   The ids are what "boks releases" prints. Then asks each TLS host as deploy does
  ps               containers and proxy routes of this app on every server
  releases         releases recorded on each server, newest last
  version          the commit this boks was built from
  proxy-config     (the server's own boks) the proxy's config of the routes on stdin and the
                   policy of this server; deploy, apply and proxy upgrade ask it for that config;
                   with check, whether it reads the policy on stdin, which apply asks first
  proxy boot       make sure the proxy (Caddy) is running (idempotent)
  proxy list       routes the proxy serves, for every app on each server
  proxy migrate    replace the kamal-proxy an earlier boks ran with Caddy, keeping every route of
                   every app on the server (once per server)
  proxy upgrade    replace the running proxy with proxy_image (a boot leaves a running one alone);
                   80 and 443 are down for the swap, and a failed one puts the old proxy back;
                   an image older than the running one (ban/gate in the tag) needs --force
  unlock           clear a stale deploy lock, and the server's admission lock if this app or a
                   proxy boot left it
  cert issue       obtain the DNS-01 certificate now, install it, reload the routes
  cert renew       same, but lego skips the run unless the certificate is due (safe in a cron)
  cert status      subject and expiry of the certificate each server currently serves
  server install <server.yml>
                   make the servers it lists ready for boks — Docker, cron, flock, the SSH user
                   in group docker, the firewall rule server apply keeps — and start the proxy;
                   refuses, before any change, a server it cannot share (another proxy on
                   80/443, Swarm, an unknown firewall)
  server apply <server.yml> [--force]
                   apply the server's policy (the bot filter, the egress proxy, the ban, the gate)
                   to the servers it lists; the file's revision must be the one after the highest
                   each server applied. It also has each server's firewall let containers reach its
                   proxy on its own addresses, and keeps that through nftables.service reloads and
                   reboots. --force lets a gate group whose site no longer checks the token itself
                   leave enforce — an emergency's override
                   With boks: in server.yml, install and apply also bring each server its one
                   boks — the linux build of that commit from boks's CI, checked against the
                   sha256 server.yml writes on every server before any is changed; apply brings
                   it before the policy
  server rollback <server.yml> <revision> [--force]
                   put back the policy of an earlier revision on those servers; --force as above
  server status <server.yml>
                   the revision each server applies, its egress proxy, a run that never finished,
                   and whether its firewall has the rule server apply keeps
  cert pull        copy the certificate and its lego metadata back from the first server, so a
                   renewal elsewhere can tell whether anything is due without holding the key

Certificates are issued where boks runs, not on the servers: DNS tokens are often bound to an
IP. Export the provider's credentials (e.g. CLOUDFLARE_DNS_API_TOKEN) before cert issue/renew.

An image on a private registry (a registry block in boks.yml) is pulled with the token from the
environment boks runs in, under the name registry.token_env; deploy and rollback refuse without it.
The server is logged in for the pull only and logged out after it.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("boks", flag.ContinueOnError)
	fs.SetOutput(errw)
	cfgPath := fs.String("f", "boks.yml", "path to boks.yml")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	// Before the mux: a server's install checks what `version` prints, and the mux's warning would be part of it.
	if fs.Arg(0) == "version" && fs.NArg() == 1 {
		fmt.Fprintln(out, version())
		return 0
	}
	// The server's boks assembling the proxy's config for whichever boks runs a deploy or an apply
	// there (#154): no boks.yml, no ssh — the server is the machine it runs on.
	if fs.Arg(0) == proxy.AssembleCommand && (fs.NArg() == 1 || fs.NArg() == 2 && fs.Arg(1) == proxy.CheckArg) {
		if err := assembleHere(context.Background(), out, fs.NArg() == 2); err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		return 0
	}
	if m, err := remote.NewMux(socketRoot); err != nil {
		fmt.Fprintf(errw, "warning: %v; every remote call opens its own connection\n", err)
	} else {
		sshMux = m
		defer func() { sshMux.Close(); sshMux = nil }()
	}
	// server.yml belongs to the server, not to an app: no boks.yml is read for it.
	if fs.Arg(0) == "server" {
		if err := serverCmd(context.Background(), fs.Args()[1:], out); err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		return 0
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if err := dispatch(context.Background(), cfg, fs.Args(), out); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return 0
}

type action func(ctx context.Context, r remote.Runner) error

func dispatch(ctx context.Context, cfg *config.Config, args []string, out io.Writer) error {
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "deploy":
		if len(rest) != 1 {
			return fmt.Errorf("deploy needs exactly one <tag>")
		}
		// The token is read before any server is reached: one the config declares and the
		// environment lacks refuses the deploy before it changes anything (E6).
		login, err := deploy.NewLogin(cfg, lookupEnv)
		if err != nil {
			return err
		}
		env, err := cfg.EnvContent()
		if err != nil {
			return err
		}
		files, err := cfg.FileContents()
		if err != nil {
			return err
		}
		o := deploy.Options{Env: env, Files: files, Login: login, Stamp: now()}
		// A CPU cap one server cannot give is asked of every server first: refused halfway through
		// the list, the deploy would leave the app on two versions.
		if len(cfg.Servers) > 1 && cfg.CPUs != "" {
			for _, s := range cfg.Servers {
				if err := deploy.CheckCPUs(ctx, connect(s), cfg); err != nil {
					return fmt.Errorf("%s: %w\nno server was deployed", s, err)
				}
			}
		}
		if err := each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.Run(ctx, r, out, cfg, rest[0], o)
		}); err != nil {
			return err
		}
		// Once the release serves everywhere: a server whose containers cannot reach the app's hosts
		// does not stop the deploy of the next, and every one of them is named.
		return everyServer(cfg.Servers, out, "hairpin", func(r remote.Runner) error { return deploy.CheckHairpin(ctx, r, out, cfg) })
	case "rollback":
		if len(rest) > 1 {
			return fmt.Errorf("rollback takes at most one release id; `boks releases` lists them")
		}
		id := ""
		if len(rest) == 1 {
			id = rest[0]
		}
		// A rollback pulls only an image the server no longer has, but whether it will is known only
		// on the server, after the lock: the token is required up front either way.
		login, err := deploy.NewLogin(cfg, lookupEnv)
		if err != nil {
			return err
		}
		if len(cfg.Servers) > 1 {
			if err := sameRollback(ctx, cfg, id); err != nil {
				return err
			}
		}
		stamp := now()
		if err := each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.Rollback(ctx, r, out, cfg, id, deploy.Options{Login: login, Stamp: stamp})
		}); err != nil {
			return err
		}
		// As after a deploy, once the restored release serves everywhere.
		return everyServer(cfg.Servers, out, "hairpin", func(r remote.Runner) error { return deploy.CheckRolledBackHairpin(ctx, r, out, cfg) })
	case "releases":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error { return releases(ctx, r, out, cfg) })
	case "ps":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error { return ps(ctx, r, out, cfg) })
	case "proxy":
		return proxyCmd(ctx, cfg, rest, out)
	case "cert":
		return certCmd(ctx, cfg, rest, out)
	case "unlock":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error { return deploy.Unlock(ctx, r, cfg.App) })
	}
	return fmt.Errorf("unknown command %q\n%s", cmd, usage)
}

// connect, now and lookupEnv are what a command reaches the servers, the clock and its environment
// through. sshMux is the run's shared SSH connections, their sockets under socketRoot; nil opens
// one per call.
var (
	connect    = func(host string) remote.Runner { return sshMux.SSH(host) }
	now        = time.Now
	lookupEnv  = os.LookupEnv
	sshMux     *remote.Mux
	socketRoot           = "/tmp"
	stdin      io.Reader = os.Stdin
)

// assembleHere prints the config of the routes on stdin and the policy of this machine, the server
// whose boks this is, read from the home as ssh would reach it. With check, stdin is a policy, and the
// answer is whether this boks reads it (proxy.CheckServerBoks).
func assembleHere(ctx context.Context, out io.Writer, check bool) error {
	in, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	if check {
		return proxy.CheckPolicy(in)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	body, err := proxy.ServerConfig(ctx, remote.Local{Dir: home}, in)
	if err != nil {
		return err
	}
	_, err = out.Write(body)
	return err
}

// sameRollback asks every server, before any of them changes, where a rollback would take it, and
// refuses unless that is one release everywhere. A rollback refused halfway through the list would
// leave the app on two versions; so would one that took each server to its own previous release,
// as after a deploy that reached only some of them.
func sameRollback(ctx context.Context, cfg *config.Config, id string) error {
	targets := make([]string, len(cfg.Servers))
	for i, s := range cfg.Servers {
		target, err := deploy.CheckRollback(ctx, connect(s), cfg, id)
		if err != nil {
			return fmt.Errorf("%s: %w\nno server was rolled back", s, err)
		}
		targets[i] = target
	}
	for i, target := range targets {
		if target != targets[0] {
			return fmt.Errorf("the servers would roll back to different releases (%s: %s, %s: %s), so none was; "+
				"name one with `boks rollback <id>`, or deploy again", cfg.Servers[0], targets[0], cfg.Servers[i], target)
		}
	}
	return nil
}

func each(ctx context.Context, cfg *config.Config, out io.Writer, fn action) error {
	for _, s := range cfg.Servers {
		fmt.Fprintf(out, "== %s\n", s)
		if err := fn(ctx, connect(s)); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

// everyServer runs fn on each server, all of them whatever fails, and names every server it failed on.
func everyServer(servers []string, out io.Writer, what string, fn func(r remote.Runner) error) error {
	var errs []error
	for _, s := range servers {
		fmt.Fprintf(out, "== %s (%s)\n", s, what)
		if err := fn(connect(s)); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s, err))
		}
	}
	return errors.Join(errs...)
}

func ps(ctx context.Context, r remote.Runner, out io.Writer, cfg *config.Config) error {
	list, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "label=boks.app="+cfg.App,
		"--format", `table {{.Names}}\t{{.Label "boks.version"}}\t{{.Status}}`)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, list)
	// An app without routes has no proxy to ask, and on such a server the proxy may not even be
	// running — listing routes would fail on a deploy that is perfectly fine.
	if len(cfg.Ports) == 0 {
		return nil
	}
	fs, err := routesOnFile(ctx, r)
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.App == cfg.App {
			printRoutes(out, []proxy.Fragment{f})
		}
	}
	return nil
}

// routesOnFile are the routes boks keeps for the proxy. On a server still on kamal-proxy there are none,
// while kamal-proxy serves every app's: an empty list would say the server routes nothing, so that is
// the refusal that says what to do.
func routesOnFile(ctx context.Context, r remote.Runner) ([]proxy.Fragment, error) {
	state, kind, err := proxy.State(ctx, r)
	if err != nil {
		return nil, err
	}
	if state != "" && kind != proxy.Kind {
		return nil, proxy.NotCaddy()
	}
	return proxy.Fragments(ctx, r)
}

// printRoutes shows routes as the proxy serves them: host, where it goes, and how TLS is served.
func printRoutes(out io.Writer, fs []proxy.Fragment) {
	for _, f := range fs {
		for _, rt := range f.Routes {
			tls := "http"
			switch {
			case rt.TLS && rt.Cert != nil:
				tls = "tls " + rt.Cert.Certificate
			case rt.TLS:
				tls = "tls acme"
			}
			// The path and what reaches the app in its place: two routes of one host differ only there.
			where := rt.Host + rt.Path
			switch {
			case rt.StripPath:
				where += " (stripped)"
			case rt.PathRewrite != "":
				where += " (as " + rt.PathRewrite + ")"
			}
			fmt.Fprintf(out, "%s\t%s → %s\t%s\n", f.App, where, rt.Dial, tls)
		}
	}
}

// releases shows what the server remembers, which is the only way to see that a deploy was
// recorded — and the only place an interrupted operation is visible at all.
func releases(ctx context.Context, r remote.Runner, out io.Writer, cfg *config.Config) error {
	ids, err := release.IDs(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	current, err := release.Current(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	for _, id := range ids {
		s, err := release.Load(ctx, r, cfg.App, id)
		if err != nil {
			fmt.Fprintf(out, "  %s (unreadable: %v)\n", id, err)
			continue
		}
		mark := " "
		if id == current {
			mark = "*"
		}
		fmt.Fprintf(out, "%s %s  %s  %s  %s\n", mark, id, s.Tag, s.Digest, s.CreatedAt.Format(time.RFC3339))
	}
	// This is the only place an interrupted operation is visible, so a journal that cannot be read
	// is said out loud rather than shown as a clean history.
	open, err := release.Unfinished(ctx, r, cfg.App)
	if err != nil {
		return fmt.Errorf("the operation journal could not be read: %w", err)
	}
	if open != nil {
		fmt.Fprintf(out, "  ! %s started %s and never finished\n", open.Action, open.StartedAt.Format(time.RFC3339))
	}
	return nil
}

func certCmd(ctx context.Context, cfg *config.Config, args []string, out io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("cert needs one of: issue, renew, status, pull")
	}
	if cfg.Cert == nil {
		return fmt.Errorf("no `cert` block in the config: plain domains are served by the proxy's automatic HTTPS and need nothing here")
	}
	if args[0] == "status" {
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			s, err := cert.Read(ctx, r, cfg)
			if err != nil {
				return err
			}
			state := "loaded by the proxy"
			if s.Pending {
				state = "ON DISK ONLY — the proxy is still serving the previous one; run `boks cert renew`"
			}
			fmt.Fprintf(out, "%s\n  issuer %s\n  expires %s (in %d days)\n  %s\n", s.Cert.Subject.CommonName,
				s.Cert.Issuer.CommonName, s.Cert.NotAfter.Format(time.DateOnly),
				int(time.Until(s.Cert.NotAfter).Hours()/24), state)
			return nil
		})
	}
	if args[0] == "pull" {
		// One server is enough: they all hold the same certificate, and lego only needs to read
		// it to decide whether a renewal is due.
		fmt.Fprintf(out, "== %s\n", cfg.Servers[0])
		return cert.Pull(ctx, connect(cfg.Servers[0]), out, cfg)
	}
	if args[0] != "issue" && args[0] != "renew" {
		return fmt.Errorf("unknown cert command %q", args[0])
	}
	if err := cert.Obtain(ctx, out, cfg, args[0] == "issue"); err != nil {
		return err
	}
	return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
		return deploy.BootProxy(ctx, r, out, cfg.ProxyImage, func() error {
			if err := cert.Install(ctx, r, out, cfg); err != nil {
				return err
			}
			// Whether a reload is still owed is tracked on the server, not inferred from whether
			// this run wrote a file: a run that installed and then died must not leave the proxy
			// serving the old certificate while later runs report success.
			pending, err := cert.Pending(ctx, r, cfg)
			if err != nil {
				return err
			}
			if !pending {
				fmt.Fprintln(out, "certificate unchanged and already loaded")
				return nil
			}
			return cert.Reload(ctx, r, out, cfg)
		})
	})
}

func proxyCmd(ctx context.Context, cfg *config.Config, args []string, out io.Writer) error {
	// --force has upgrade take an image older than the running one (proxy.Older), for upgrade alone.
	force := false
	if i := slices.Index(args, "--force"); i >= 0 && len(args) > 0 && args[0] == "upgrade" {
		force = true
		args = slices.Delete(slices.Clone(args), i, i+1)
	}
	if len(args) != 1 {
		return fmt.Errorf("proxy needs one of: boot, list, migrate, upgrade")
	}
	switch args[0] {
	case "boot":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.BootProxy(ctx, r, out, cfg.ProxyImage, nil)
		})
	case "list":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			fs, err := routesOnFile(ctx, r)
			printRoutes(out, fs)
			return err
		})
	case "migrate":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.MigrateProxy(ctx, r, out, cfg.ProxyImage, deploy.Options{})
		})
	case "upgrade":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.UpgradeProxy(ctx, r, out, cfg.ProxyImage, deploy.Options{Now: now, Force: force})
		})
	}
	return fmt.Errorf("unknown proxy command %q", args[0])
}

func serverCmd(ctx context.Context, args []string, out io.Writer) error {
	// --force lifts the refusal to leave a site whose own token check is gone without the proxy's
	// (deploy.CheckGateTransition), for apply and rollback alone.
	force := false
	if i := slices.Index(args, "--force"); i >= 0 && len(args) > 0 && (args[0] == "apply" || args[0] == "rollback") {
		force = true
		args = slices.Delete(slices.Clone(args), i, i+1)
	}
	if len(args) < 2 {
		return fmt.Errorf("server needs one of: install <server.yml>, apply <server.yml> [--force], rollback <server.yml> <revision> [--force], status <server.yml>")
	}
	// Rollback and status take the list of servers alone: a range_sets file missing or broken must never
	// stand in the way of going back (rollback takes the sets from the revision in each server's
	// history), and status warns of it rather than fail. Install and apply read server.yml whole.
	load := config.LoadServer
	if args[0] == "rollback" || args[0] == "status" {
		load = config.LoadServerForFleet
	}
	sc, err := load(args[1])
	if err != nil {
		return err
	}
	if args[0] == "status" {
		if _, err := config.LoadServer(args[1]); err != nil {
			fmt.Fprintf(out, "! %v; apply would refuse it\n", err)
		}
	}
	on := func(fn action) error {
		for _, s := range sc.Servers {
			fmt.Fprintf(out, "== %s\n", s)
			if err := fn(ctx, connect(s)); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	}
	// Every server is asked before any changes: a refusal halfway down the list would leave the fleet
	// on two policies.
	askAll := func(ask action) error {
		for _, s := range sc.Servers {
			if err := ask(ctx, connect(s)); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	}
	o := deploy.Options{Now: now, Force: force}
	// The server's boks is checked on every server with the rest, before any is changed: a sum missing for
	// one server's architecture, or a build that does not fetch, would otherwise stop the run halfway down
	// the list. The build is fetched once for all.
	fetch := deploy.Remember(fetchBoks, out)
	checkBoks := func(ctx context.Context, r remote.Runner) error {
		if sc.Boks == nil {
			return nil
		}
		return deploy.CheckBoks(ctx, r, out, sc.Boks, fetch)
	}
	switch {
	case args[0] == "install" && len(args) == 2:
		if err := askAll(func(ctx context.Context, r remote.Runner) error {
			if _, err := deploy.CheckInstall(ctx, r); err != nil {
				return err
			}
			return checkBoks(ctx, r)
		}); err != nil {
			return err
		}
		for _, s := range sc.Servers {
			fmt.Fprintf(out, "== %s\n", s)
			if err := installOn(ctx, s, out, o); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
			if sc.Boks != nil {
				if err := deploy.InstallBoks(ctx, connect(s), out, sc.Boks, fetch); err != nil {
					return fmt.Errorf("%s: %w", s, err)
				}
			}
		}
		return nil
	case args[0] == "apply" && len(args) == 2:
		if sc.Revision < 1 {
			return fmt.Errorf("%s: revision: required for apply, a whole number from 1", args[1])
		}
		next := policyOf(sc)
		if err := proxy.CheckCATerm(next, now()); err != nil {
			return fmt.Errorf("%s: %w", args[1], err)
		}
		// The egress login's password comes from the environment, before any server is asked: a missing
		// one would stop the run halfway down the list.
		if sc.Egress != nil {
			pw, err := sc.Egress.Password()
			if err != nil {
				return fmt.Errorf("%s: %w", args[1], err)
			}
			next.Egress.Password = pw
		}
		// The gate's secrets as well; one not set is left to what each server keeps.
		if sc.Gate != nil {
			secrets, err := sc.Gate.Secrets()
			if err != nil {
				return fmt.Errorf("%s: %w", args[1], err)
			}
			next.GateSecrets = secrets
		}
		// The apps the servers keep, read whole — boks.yml, environment, token — before any server is asked.
		apps, err := sc.LoadApps(lookupEnv, true)
		if err != nil {
			return fmt.Errorf("%s: %w", args[1], err)
		}
		if err := askAll(func(ctx context.Context, r remote.Runner) error {
			if err := deploy.CheckApply(ctx, r, next, force); err != nil {
				return err
			}
			return checkBoks(ctx, r)
		}); err != nil {
			return err
		}
		// The servers' boks first, on every server before the policy on any: the policy is the same either
		// way, and a build one server refuses (a write, its sum or its version there) leaves every server
		// on the policy it had.
		if sc.Boks != nil {
			if err := on(func(ctx context.Context, r remote.Runner) error {
				return deploy.InstallBoks(ctx, r, out, sc.Boks, fetch)
			}); err != nil {
				return err
			}
		}
		// Every server's own boks — the one just installed, or whichever a server kept — is asked whether
		// it reads next before any policy changes: one refusing halfway down the list would leave the
		// fleet on two policies. ApplyServer asks again, under the lock, of the policy as it writes it.
		if err := askAll(func(ctx context.Context, r remote.Runner) error { return proxy.CheckServerBoks(ctx, r, next) }); err != nil {
			return err
		}
		// The apps after the server's boks, which deploys from them, and before the policy. A server.yml
		// without boks: has no apps, and leaves the servers' files alone.
		if sc.Boks != nil {
			for _, s := range sc.Servers {
				fmt.Fprintf(out, "== %s\n", s)
				if err := deploy.PutApps(ctx, connect(s), out, config.AppsOn(apps, s), o); err != nil {
					return fmt.Errorf("%s: %w", s, err)
				}
			}
		}
		if err := on(func(ctx context.Context, r remote.Runner) error { return deploy.ApplyServer(ctx, r, out, next, o) }); err != nil {
			return err
		}
		// After the policy is on every server: a firewall one server refuses to change leaves no server
		// on another policy than the rest.
		return everyServer(sc.Servers, out, "firewall", func(r remote.Runner) error { return deploy.EnsureHairpin(ctx, r, out, o) })
	case args[0] == "rollback" && len(args) == 3:
		rev, err := strconv.Atoi(args[2])
		if err != nil || rev < 1 {
			return fmt.Errorf("rollback needs a revision, a whole number from 1; `boks server status` shows the current one")
		}
		if err := askAll(func(ctx context.Context, r remote.Runner) error {
			return deploy.CheckServerRollback(ctx, r, rev, force)
		}); err != nil {
			return err
		}
		return on(func(ctx context.Context, r remote.Runner) error { return deploy.RollbackServer(ctx, r, out, rev, o) })
	case args[0] == "status" && len(args) == 2:
		// The apps by their boks.yml alone: status reads no secret. One that does not load is a line.
		apps, appsErr := sc.LoadApps(lookupEnv, false)
		if appsErr != nil {
			fmt.Fprintf(out, "! %v\n", appsErr)
		}
		server := 0
		return on(func(ctx context.Context, r remote.Runner) error {
			name := sc.Servers[server]
			server++
			p, open, drift, err := deploy.ServerStatus(ctx, r)
			if err != nil {
				return err
			}
			switch running, err := deploy.RunningBoks(ctx, r); {
			case err != nil:
				return err
			case sc.Boks != nil && running != sc.Boks.Commit:
				fmt.Fprintf(out, "  ! boks %s, and server.yml names %s; `boks server apply` brings it\n", orNone(running), sc.Boks.Commit)
			case running != "":
				fmt.Fprintf(out, "  boks %s\n", running)
			}
			if p.Revision == 0 {
				fmt.Fprintln(out, "  no policy applied")
			} else {
				fmt.Fprintf(out, "  revision %d (highest applied %d): %d blocks, %d allows\n", p.Revision, p.Floor, len(p.Block), len(p.Allow))
			}
			if e := p.Egress; e != nil {
				login := "no login"
				if e.User != "" {
					login = "login " + e.User
				}
				fmt.Fprintf(out, "  egress proxy on port %d for %s, %s\n", e.Port, strings.Join(e.Allow, ", "), login)
			}
			if line := proxy.TrustedString(p); line != "" {
				fmt.Fprintf(out, "  %s\n", line)
			}
			if b := p.Ban; b != nil {
				fmt.Fprintf(out, "  %s\n", b)
			}
			if line := proxy.GateString(p); line != "" {
				fmt.Fprintf(out, "  %s\n", line)
			}
			for _, d := range drift {
				fmt.Fprintf(out, "  ! %s\n", d)
			}
			if sc.Boks != nil && appsErr == nil {
				appDrift, err := deploy.AppsDrift(ctx, r, config.AppsOn(apps, name))
				if err != nil {
					appDrift = []string{fmt.Sprintf("could not compare the apps with server.yml: %v", err)}
				}
				for _, d := range appDrift {
					fmt.Fprintf(out, "  ! %s\n", d)
				}
			}
			if open != nil {
				fmt.Fprintf(out, "  ! %s started %s and never finished; run it again\n", open.Action, open.StartedAt.Format(time.RFC3339))
			}
			for _, line := range deploy.HairpinStatus(ctx, r) {
				fmt.Fprintf(out, "  %s\n", line)
			}
			return nil
		})
	}
	return fmt.Errorf("unknown server command %q", strings.Join(args, " "))
}

// installOn installs on server s. A user just added to group docker has it only in a new login, so
// what follows the install runs on a connection of its own, opened after it: one, shared by those
// calls — a connection per call would trip an SSH rate limit such as ufw's `limit` (6 in 30 s).
func installOn(ctx context.Context, s string, out io.Writer, o deploy.Options) error {
	login, err := remote.NewMux(socketRoot)
	if err != nil {
		fmt.Fprintf(out, "warning: %v; after the install every call opens a login of its own\n", err)
	}
	defer login.Close()
	fresh := func() remote.Runner {
		if login == nil { // BOKS_SSH_MUX=0, or no socket directory
			return remote.SSH{Host: s, Alone: true}
		}
		return login.SSH(s)
	}
	return deploy.Install(ctx, connect(s), fresh, out, config.DefaultProxyImage, o)
}

// policyOf is a server.yml's policy as the proxy applies it.
func policyOf(sc *config.Server) proxy.Policy {
	p := proxy.Policy{Revision: sc.Revision}
	for _, b := range sc.Bots.Block {
		p.Block = append(p.Block, proxy.BotBlock{Name: b.Name, Domains: b.Domains, UserAgent: b.UserAgent})
	}
	for _, a := range sc.Bots.Allow {
		p.Allow = append(p.Allow, proxy.BotAllow{Host: a.Host, Domains: a.Domains, Paths: a.Paths, UserAgent: a.UserAgent, Header: a.Header})
	}
	if e := sc.Egress; e != nil {
		var allow []string
		for _, pr := range e.Prefixes() {
			allow = append(allow, pr.String())
		}
		p.Egress = &proxy.Egress{Port: e.Port, Allow: allow, User: e.User, Ports: e.Ports, HostsFile: e.HostsFile}
	}
	for _, pr := range sc.TrustedPrefixes() {
		p.TrustedProxies = append(p.TrustedProxies, pr.String())
	}
	p.TrustedProxiesCA = sc.TrustedProxiesCerts()
	if b := sc.Ban; b != nil {
		p.Ban = &proxy.Ban{Duration: b.Duration, ExemptPaths: b.ExemptPaths}
		for _, r := range b.Rules {
			p.Ban.Rules = append(p.Ban.Rules, proxy.BanRule{Name: r.Name, Limit: r.Limit, Window: r.Window, Class: r.Class, Paths: r.Paths})
		}
		if h := b.Heuristics; h != nil {
			p.Ban.Heuristics = &proxy.BanHeuristics{Mode: h.Mode, Cluster: proxy.BanCluster{
				Limit: h.Cluster.Limit, Window: h.Cluster.Window, MinAddresses: h.Cluster.MinAddresses}}
		}
		for _, pr := range b.ExemptPrefixes() {
			p.Ban.ExemptRanges = append(p.Ban.ExemptRanges, pr.String())
		}
		for _, pr := range b.DenyPrefixes() {
			p.Ban.DenyRanges = append(p.Ban.DenyRanges, pr.String())
		}
	}
	if g := sc.Gate; g != nil {
		p.Gate = g.JSON
		// A group with a bearer has its partners spared by the ban and the blocks: no step of its own in
		// server.yml, as the key is the group's already. A group that is off spares nothing (gateHandlers
		// leaves it out), so it neither raises the format nor asks the proxy for the ban of the keys.
		p.SpareBearer = slices.ContainsFunc(g.Groups, func(gr config.GateGroup) bool { return gr.Bearer != nil && gr.Mode != "off" })
	}
	return p
}

// commit is boks's own commit, set by its CI's build (-ldflags "-X main.commit=<sha>"); a build without it
// says what Go recorded of the checkout, if anything.
var commit string

func version() string {
	if commit != "" {
		return commit
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
		if bi.Main.Version != "" {
			return bi.Main.Version
		}
	}
	return "unknown"
}

func orNone(commit string) string {
	if commit == "" {
		return "none"
	}
	return commit
}

// fetchURL gets a build of boks: a release asset, which GitHub sends on from its own storage. A build is
// some megabytes; more than maxBuild is no build of boks.
func fetchURL(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBuild+1))
	if err == nil && len(body) > maxBuild {
		err = fmt.Errorf("more than %d bytes", maxBuild)
	}
	return body, err
}

const maxBuild = 200 << 20

// fetchBoks is how install and apply fetch the server's boks; a test answers in its place.
var fetchBoks deploy.Fetch = fetchURL
