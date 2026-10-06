// Command boks deploys pre-built images to servers through Docker and Caddy over SSH.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
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
                   previous version once it has drained
  rollback [id]    return to a recorded release (the previous one by default), reproducing the
                   image by digest, the ports, volumes and environment it actually ran with.
                   The ids are what "boks releases" prints
  ps               containers and proxy routes of this app on every server
  releases         releases recorded on each server, newest last
  proxy boot       make sure the proxy (Caddy) is running (idempotent)
  proxy list       routes the proxy serves, for every app on each server
  proxy migrate    replace the kamal-proxy an earlier boks ran with Caddy, keeping every route of
                   every app on the server (once per server)
  proxy upgrade    replace the running proxy with proxy_image (a boot leaves a running one alone);
                   80 and 443 are down for the swap, and a failed one puts the old proxy back
  unlock           clear a stale deploy lock, and the server's admission lock if this app or a
                   proxy boot left it
  cert issue       obtain the DNS-01 certificate now, install it, reload the routes
  cert renew       same, but lego skips the run unless the certificate is due (safe in a cron)
  cert status      subject and expiry of the certificate each server currently serves
  server install <server.yml>
                   make the servers it lists ready for boks — Docker, cron, flock, the SSH user
                   in group docker — and start the proxy; refuses, before any change, a server
                   it cannot share (another proxy on 80/443, Swarm, an unknown firewall)
  server apply <server.yml>
                   apply the server's policy (the bot filter) to the servers it lists; the
                   file's revision must be the one after the highest each server applied
  server rollback <server.yml> <revision>
                   put back the policy of an earlier revision on those servers
  server status <server.yml>
                   the revision each server applies, and a run that never finished
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
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.Run(ctx, r, out, cfg, rest[0], o)
		})
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
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.Rollback(ctx, r, out, cfg, id, deploy.Options{Login: login, Stamp: stamp})
		})
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
	socketRoot = "/tmp"
)

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
			return deploy.UpgradeProxy(ctx, r, out, cfg.ProxyImage, deploy.Options{Now: now})
		})
	}
	return fmt.Errorf("unknown proxy command %q", args[0])
}

func serverCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("server needs one of: install <server.yml>, apply <server.yml>, rollback <server.yml> <revision>, status <server.yml>")
	}
	sc, err := config.LoadServer(args[1])
	if err != nil {
		return err
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
	o := deploy.Options{Now: now}
	switch {
	case args[0] == "install" && len(args) == 2:
		if err := askAll(func(ctx context.Context, r remote.Runner) error {
			_, err := deploy.CheckInstall(ctx, r)
			return err
		}); err != nil {
			return err
		}
		for _, s := range sc.Servers {
			fmt.Fprintf(out, "== %s\n", s)
			if err := installOn(ctx, s, out, o); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	case args[0] == "apply" && len(args) == 2:
		if sc.Revision < 1 {
			return fmt.Errorf("%s: revision: required for apply, a whole number from 1", args[1])
		}
		next := policyOf(sc)
		if err := askAll(func(ctx context.Context, r remote.Runner) error { return deploy.CheckApply(ctx, r, next) }); err != nil {
			return err
		}
		return on(func(ctx context.Context, r remote.Runner) error { return deploy.ApplyServer(ctx, r, out, next, o) })
	case args[0] == "rollback" && len(args) == 3:
		rev, err := strconv.Atoi(args[2])
		if err != nil || rev < 1 {
			return fmt.Errorf("rollback needs a revision, a whole number from 1; `boks server status` shows the current one")
		}
		if err := askAll(func(ctx context.Context, r remote.Runner) error { return deploy.CheckServerRollback(ctx, r, rev) }); err != nil {
			return err
		}
		return on(func(ctx context.Context, r remote.Runner) error { return deploy.RollbackServer(ctx, r, out, rev, o) })
	case args[0] == "status" && len(args) == 2:
		return on(func(ctx context.Context, r remote.Runner) error {
			p, open, err := deploy.ServerStatus(ctx, r)
			if err != nil {
				return err
			}
			if p.Revision == 0 {
				fmt.Fprintln(out, "  no policy applied")
			} else {
				fmt.Fprintf(out, "  revision %d (highest applied %d): %d blocks, %d allows\n", p.Revision, p.Floor, len(p.Block), len(p.Allow))
			}
			if open != nil {
				fmt.Fprintf(out, "  ! %s started %s and never finished; run it again\n", open.Action, open.StartedAt.Format(time.RFC3339))
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
		p.Allow = append(p.Allow, proxy.BotAllow{Host: a.Host, Paths: a.Paths, UserAgent: a.UserAgent})
	}
	return p
}
