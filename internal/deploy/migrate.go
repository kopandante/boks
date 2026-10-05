package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/cert"
	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

// asideName is where kamal-proxy waits, stopped, while Caddy takes its place: if Caddy does not come
// up, it is renamed back and started, routes and all, and the server is where it was.
const asideName = proxy.Container + ".kamal"

// MigrateProxy replaces the kamal-proxy an earlier boks ran on this server with Caddy, keeping every
// route. The routes are each app's current release — hosts, TLS, certificate — dialling the container
// kamal-proxy sends that host to now, so traffic lands where it landed. A host kamal-proxy routes and
// no recorded release describes would be lost, so it refuses, changing nothing; so does a deploy in
// progress, whose lock it would otherwise race. The swap is seconds without a proxy on 80/443.
//
// It changes the whole server, not one app: every app's deploy lock and the admission lock are held
// throughout.
func MigrateProxy(ctx context.Context, r remote.Runner, log io.Writer, image string, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	adm, err := admit(ctx, r, log, proxyHolder, o)
	if err != nil {
		return err
	}
	defer adm.release(ctx)
	state, kind, err := proxy.State(ctx, r)
	switch {
	case err != nil:
		return err
	case state == "":
		fmt.Fprintln(log, "no proxy on this server: the first deploy of an app with routes starts Caddy")
		return nil
	case kind == proxy.Kind:
		fmt.Fprintln(log, "the proxy is Caddy already")
		return proxy.Boot(ctx, r, log, image)
	case state != "running":
		return fmt.Errorf("%s is %s, and its routes are read from it: `docker start %s`, then migrate again; nothing was changed",
			proxy.Container, state, proxy.Container)
	}
	targets, err := kamalTargets(ctx, r)
	if err != nil {
		return err
	}
	apps, err := recordedApps(ctx, r)
	if err != nil {
		return err
	}
	var locked []string
	defer func() {
		for _, app := range locked {
			unlock(context.WithoutCancel(ctx), r, log, app)
		}
	}()
	for _, app := range apps {
		if err := lock(ctx, r, app); err != nil {
			return fmt.Errorf("%w; nothing was changed", err)
		}
		locked = append(locked, app)
	}
	frags, err := migratedRoutes(ctx, r, log, apps, targets)
	if err != nil {
		return err
	}
	if _, err := proxy.Config(frags); err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	// Fetched before kamal-proxy stops, so the time without a proxy is the swap and not a download.
	fmt.Fprintf(log, "pull %s\n", image)
	if _, err := r.Run(ctx, "docker", "pull", image); err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	// The proxy is not Caddy yet, so this writes the files Caddy will load, and reloads nothing.
	for _, f := range frags {
		if _, err := proxy.SetRoutes(ctx, r, log, f.App, f.Routes); err != nil {
			return fmt.Errorf("%w; kamal-proxy still serves, untouched", err)
		}
	}
	fmt.Fprintf(log, "proxy: replacing kamal-proxy with Caddy\n")
	if _, err := r.Run(ctx, "docker", "stop", proxy.Container); err != nil {
		return fmt.Errorf("stopping kamal-proxy: %w; run `docker start %s` if it is down", err, proxy.Container)
	}
	if _, err := r.Run(ctx, "docker", "rename", proxy.Container, asideName); err != nil {
		best(context.WithoutCancel(ctx), r, log, "docker", "start", proxy.Container)
		return fmt.Errorf("moving kamal-proxy aside: %w; it was started again", err)
	}
	if err := proxy.Boot(ctx, r, log, image); err != nil {
		return errors.Join(fmt.Errorf("Caddy did not come up: %w", err), restoreKamal(context.WithoutCancel(ctx), r, log))
	}
	best(ctx, r, log, "docker", "rm", asideName)
	fmt.Fprintf(log, "Caddy serves the routes now; kamal-proxy's volume boks-proxy-config is left behind and can be removed by hand\n")
	return nil
}

// restoreKamal puts kamal-proxy back after Caddy failed to take its place. Only a container labelled
// as Caddy is removed from the name: anything else there is not this run's to delete.
func restoreKamal(ctx context.Context, r remote.Runner, log io.Writer) error {
	if state, kind, err := proxy.State(ctx, r); err == nil && state != "" && kind == proxy.Kind {
		best(ctx, r, log, "docker", "rm", "-f", proxy.Container)
	}
	_, err := r.Run(ctx, "docker", "rename", asideName, proxy.Container)
	if err == nil {
		_, err = r.Run(ctx, "docker", "start", proxy.Container)
	}
	if err != nil {
		return fmt.Errorf("kamal-proxy could not be put back (%w): `docker rm -f %s; docker rename %s %s; docker start %s`",
			err, proxy.Container, asideName, proxy.Container, proxy.Container)
	}
	fmt.Fprintln(log, "kamal-proxy is back with its routes")
	return nil
}

// kamalTargets reads where kamal-proxy sends each host now: host → `container:port`. A service that
// spreads one host over several containers has no one place to send it, and that is refused rather
// than guessed.
func kamalTargets(ctx context.Context, r remote.Runner) (map[string]string, error) {
	out, err := r.Run(ctx, "docker", "exec", proxy.Container, "kamal-proxy", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("reading kamal-proxy's routes: %w", err)
	}
	var services map[string]struct {
		Hosts   []string `json:"hosts"`
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal([]byte(out), &services); err != nil {
		return nil, fmt.Errorf("reading kamal-proxy's routes: %w", err)
	}
	byHost := map[string]string{}
	for name, s := range services {
		if len(s.Targets) != 1 {
			return nil, fmt.Errorf("kamal-proxy's route %s goes to %v, not to one container; deploy its app once more, then migrate; nothing was changed", name, s.Targets)
		}
		for _, h := range s.Hosts {
			byHost[h] = s.Targets[0]
		}
	}
	return byHost, nil
}

// recordedApps are the apps with a current release on this server, sorted.
func recordedApps(ctx context.Context, r remote.Runner) ([]string, error) {
	out, err := r.Run(ctx, "sh", "-c", "for d in .boks/*/; do [ -f \"${d}current\" ] && basename \"$d\"; done; true")
	if err != nil {
		return nil, fmt.Errorf("listing the apps recorded on the server: %w", err)
	}
	apps := strings.Fields(out)
	sort.Strings(apps)
	return apps, nil
}

// migratedRoutes builds each app's routes from its current release and kamal-proxy's targets, and
// refuses when a host kamal-proxy routes is left without one.
func migratedRoutes(ctx context.Context, r remote.Runner, log io.Writer, apps []string, targets map[string]string) ([]proxy.Fragment, error) {
	taken := map[string]bool{}
	var frags []proxy.Fragment
	for _, app := range apps {
		id, err := release.Current(ctx, r, app)
		if err != nil {
			return nil, err
		}
		s, err := release.Load(ctx, r, app, id)
		if err != nil {
			return nil, err
		}
		var routes []proxy.Route
		for _, p := range s.Ports {
			target, ok := targets[p.Host]
			if !ok {
				fmt.Fprintf(log, "warning: %s of %s is not routed by kamal-proxy now, so it stays unrouted until %s is deployed\n", p.Host, app, app)
				continue
			}
			rt := proxy.Route{Host: p.Host, Dial: target, TLS: s.TLS}
			if c := (&config.Cert{Domains: s.CertDomains}); len(s.CertDomains) > 0 && c.Covers(p.Host) {
				crt, key := cert.ServerPaths(c)
				rt.Cert = &proxy.CertFiles{Certificate: crt, Key: key}
			}
			routes = append(routes, rt)
			taken[p.Host] = true
		}
		if len(routes) > 0 {
			frags = append(frags, proxy.Fragment{App: app, Routes: routes})
		}
	}
	var lost []string
	for h := range targets {
		if !taken[h] {
			lost = append(lost, h)
		}
	}
	if len(lost) > 0 {
		sort.Strings(lost)
		return nil, fmt.Errorf("kamal-proxy routes %v, which no release recorded on this server describes, so Caddy would drop them: "+
			"deploy their apps with this boks first, or remove those routes from kamal-proxy; nothing was changed", lost)
	}
	return frags, nil
}
