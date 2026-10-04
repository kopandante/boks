// Command boks deploys pre-built images to servers through Docker and kamal-proxy over SSH.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kopandante/boks/internal/cert"
	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/deploy"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

const usage = `usage: boks [-f boks.yml] <command>

  deploy <tag>     pull image:<tag>, start it, switch the proxy, retire the previous version
  rollback [id]    return to a recorded release (the previous one by default), reproducing the
                   image by digest, the ports, volumes and environment it actually ran with.
                   The ids are what "boks releases" prints
  ps               containers and proxy routes of this app on every server
  releases         releases recorded on each server, newest last
  proxy boot       make sure kamal-proxy is running (idempotent)
  proxy list       routes known to kamal-proxy
  unlock           clear a stale deploy lock
  cert issue       obtain the DNS-01 certificate now, install it, reload the routes
  cert renew       same, but lego skips the run unless the certificate is due (safe in a cron)
  cert status      subject and expiry of the certificate each server currently serves
  cert pull        copy the certificate and its lego metadata back from the first server, so a
                   renewal elsewhere can tell whether anything is due without holding the key

Certificates are issued where boks runs, not on the servers: DNS tokens are often bound to an
IP. Export the provider's credentials (e.g. CLOUDFLARE_DNS_API_TOKEN) before cert issue/renew.
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
		stamp := now()
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return runDeploy(ctx, r, out, cfg, rest[0], stamp)
		})
	case "rollback":
		if len(rest) > 1 {
			return fmt.Errorf("rollback takes at most one release id; `boks releases` lists them")
		}
		id := ""
		if len(rest) == 1 {
			id = rest[0]
		}
		if len(cfg.Servers) > 1 {
			if err := sameRollback(ctx, cfg, id); err != nil {
				return err
			}
		}
		stamp := now()
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return deploy.Rollback(ctx, r, out, cfg, id, deploy.Options{Stamp: stamp})
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

// connect and now are what a command reaches the servers and the clock through.
var (
	connect = func(host string) remote.Runner { return remote.SSH{Host: host} }
	now     = time.Now
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

func runDeploy(ctx context.Context, r remote.Runner, out io.Writer, cfg *config.Config, tag string, stamp time.Time) error {
	env, err := cfg.EnvContent()
	if err != nil {
		return err
	}
	return deploy.Run(ctx, r, out, cfg, tag, deploy.Options{Env: env, Stamp: stamp})
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
	routes, err := proxy.List(ctx, r)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, routes)
	return nil
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
		return fmt.Errorf("no `cert` block in the config: plain domains are served by kamal-proxy's autocert and need nothing here")
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
		return cert.Pull(ctx, remote.SSH{Host: cfg.Servers[0]}, out, cfg)
	}
	if args[0] != "issue" && args[0] != "renew" {
		return fmt.Errorf("unknown cert command %q", args[0])
	}
	if err := cert.Obtain(ctx, out, cfg, args[0] == "issue"); err != nil {
		return err
	}
	return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
		if err := proxy.Boot(ctx, r, out, cfg.Network, cfg.ProxyImage); err != nil {
			return err
		}
		if err := cert.Install(ctx, r, out, cfg); err != nil {
			return err
		}
		// Whether a reload is still owed is tracked on the server, not inferred from whether
		// this run wrote a file: a run that installed and then died must not leave the proxy
		// serving the old certificate while later runs report success. The question here is
		// whether the PROXY has re-read the file — not whether this app's routes happen to carry
		// it — because a restart is the only thing that reaches apps this config never names.
		pending, err := cert.ReloadPending(ctx, r, cfg)
		if err != nil {
			return err
		}
		if !pending {
			fmt.Fprintln(out, "certificate unchanged and already loaded")
			return nil
		}
		return cert.Reload(ctx, r, out, cfg)
	})
}

func proxyCmd(ctx context.Context, cfg *config.Config, args []string, out io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("proxy needs one of: boot, list")
	}
	switch args[0] {
	case "boot":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			return proxy.Boot(ctx, r, out, cfg.Network, cfg.ProxyImage)
		})
	case "list":
		return each(ctx, cfg, out, func(ctx context.Context, r remote.Runner) error {
			routes, err := proxy.List(ctx, r)
			fmt.Fprintln(out, routes)
			return err
		})
	}
	return fmt.Errorf("unknown proxy command %q", args[0])
}
