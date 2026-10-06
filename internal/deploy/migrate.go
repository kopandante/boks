package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

// asideName is where kamal-proxy waits, stopped, while Caddy takes its place: if Caddy does not come
// up, it is renamed back and started, routes and all, and the server is where it was.
const asideName = proxy.Container + ".kamal"

// MigrateProxy replaces the kamal-proxy an earlier boks ran on this server with Caddy, keeping every
// route. The routes are each app's current release's hosts, served as kamal-proxy serves them now —
// the container it sends the host to, TLS, the certificate files — so traffic lands where it landed. A host kamal-proxy routes and
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
	if err != nil {
		return err
	}
	// kamal-proxy waiting aside is an earlier migration that did not finish: cut between moving it
	// aside and Caddy coming up, or after Caddy came up but before kamal-proxy was removed. Taken for a
	// server without a proxy, it would leave every app down while the run reports success.
	aside, err := asideThere(ctx, r)
	if err != nil {
		return err
	}
	if aside {
		switch {
		case kind == proxy.Kind:
			// Caddy is in place, and may have served for days: kamal-proxy's routes are stale by now, so a
			// failure here does not put it back on its own.
			if err := proxy.Boot(ctx, r, log, image); err != nil {
				return fmt.Errorf("Caddy did not come up: %w\nkamal-proxy waits stopped as %s; `docker rm -f %s; docker rename %s %s; docker start %s` puts it back",
					err, asideName, proxy.Container, asideName, proxy.Container, proxy.Container)
			}
			best(ctx, r, log, "docker", "rm", asideName)
			fmt.Fprintln(log, "Caddy serves the routes; the kamal-proxy an earlier migration left aside is removed")
			return nil
		case state == "":
			fmt.Fprintf(log, "an earlier migration left kamal-proxy stopped as %s: putting it back, then migrating\n", asideName)
			if err := restoreKamal(context.WithoutCancel(ctx), r, log); err != nil {
				return err
			}
			if state, kind, err = proxy.State(ctx, r); err != nil {
				return err
			}
		default:
			return fmt.Errorf("both %s and %s are on this server: remove the one that does not serve, then migrate again; nothing was changed",
				proxy.Container, asideName)
		}
	}
	switch {
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
	// The proxy is not Caddy yet, so this writes the files Caddy will load, and reloads nothing. The
	// fragments are exactly what kamal-proxy serves: one an earlier, cut migration left for an app that
	// has no routes now goes, or Caddy would start with routes to copies retired since.
	left, err := proxy.Fragments(ctx, r)
	if err != nil {
		return fmt.Errorf("%w; nothing was changed", err)
	}
	for _, f := range left {
		if proxy.Of(frags, f.App) == nil {
			if _, err := proxy.SetRoutes(ctx, r, log, f.App, nil); err != nil {
				return fmt.Errorf("%w; kamal-proxy still serves, untouched", err)
			}
		}
	}
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
		// The rename may have gone through with its answer lost: kamal-proxy is looked for under both names.
		return errors.Join(fmt.Errorf("moving kamal-proxy aside: %w", err), restoreKamal(context.WithoutCancel(ctx), r, log))
	}
	if err := proxy.Boot(ctx, r, log, image); err != nil {
		return errors.Join(fmt.Errorf("Caddy did not come up: %w", err), restoreKamal(context.WithoutCancel(ctx), r, log))
	}
	best(ctx, r, log, "docker", "rm", asideName)
	fmt.Fprintf(log, "Caddy serves the routes now; kamal-proxy's volume boks-proxy-config is left behind and can be removed by hand\n")
	return nil
}

// restoreKamal puts kamal-proxy back after Caddy failed to take its place. Only a container labelled
// as Caddy is removed from the name: anything else there is not this run's to delete. kamal-proxy is
// renamed back only when the name is free — a rename whose answer was lost may not have happened.
func restoreKamal(ctx context.Context, r remote.Runner, log io.Writer) error {
	state, kind, err := proxy.State(ctx, r)
	if err == nil && state != "" && kind == proxy.Kind {
		best(ctx, r, log, "docker", "rm", "-f", proxy.Container)
		state = ""
	}
	if err == nil && state == "" {
		_, err = r.Run(ctx, "docker", "rename", asideName, proxy.Container)
	}
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

// asideThere says whether kamal-proxy waits under asideName.
func asideThere(ctx context.Context, r remote.Runner) (bool, error) {
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "name=^"+regexp.QuoteMeta(asideName)+"$", "--format", "{{.Names}}")
	if err != nil {
		return false, fmt.Errorf("looking for %s: %w", asideName, err)
	}
	return strings.TrimSpace(out) != "", nil
}

// kamalTarget is where kamal-proxy sends a host now, whether it serves it with TLS, and from which
// certificate files when not from its own ACME.
type kamalTarget struct {
	dial string
	tls  bool
	cert *proxy.CertFiles
}

// kamalState is kamal-proxy v0.10.0's state file: what `list` does not say, the certificate files a
// service was deployed with, is there.
const kamalState = "/home/kamal-proxy/.config/kamal-proxy/kamal-proxy.state"

// kamalTargets reads where kamal-proxy sends each host now. A service that spreads one host over
// several containers has no one place to send it, and that is refused rather than guessed.
func kamalTargets(ctx context.Context, r remote.Runner) (map[string]kamalTarget, error) {
	out, err := r.Run(ctx, "docker", "exec", proxy.Container, "kamal-proxy", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("reading kamal-proxy's routes: %w", err)
	}
	var services map[string]struct {
		Hosts   []string `json:"hosts"`
		Targets []string `json:"targets"`
		TLS     bool     `json:"tls"`
	}
	if err := json.Unmarshal([]byte(out), &services); err != nil {
		return nil, fmt.Errorf("reading kamal-proxy's routes: %w", err)
	}
	certs, err := kamalCerts(ctx, r)
	if err != nil {
		return nil, err
	}
	byHost := map[string]kamalTarget{}
	for name, s := range services {
		if len(s.Targets) != 1 {
			return nil, fmt.Errorf("kamal-proxy's route %s goes to %v, not to one container; deploy its app once more, then migrate; nothing was changed", name, s.Targets)
		}
		for _, h := range s.Hosts {
			byHost[h] = kamalTarget{dial: s.Targets[0], tls: s.TLS, cert: certs[name]}
		}
	}
	return byHost, nil
}

// kamalCerts reads the certificate files each kamal-proxy service serves, by service name. The
// paths are the proxy's own, and Caddy mounts the same volume at the same place.
func kamalCerts(ctx context.Context, r remote.Runner) (map[string]*proxy.CertFiles, error) {
	out, err := r.Run(ctx, "docker", "exec", proxy.Container, "cat", kamalState)
	if err != nil {
		return nil, fmt.Errorf("reading kamal-proxy's certificates from %s: %w; nothing was changed", kamalState, err)
	}
	var services []struct {
		Name    string `json:"name"`
		Options struct {
			Certificate string `json:"tls_certificate_path"`
			Key         string `json:"tls_private_key_path"`
		} `json:"options"`
	}
	if err := json.Unmarshal([]byte(out), &services); err != nil {
		return nil, fmt.Errorf("reading kamal-proxy's certificates from %s: %w; nothing was changed", kamalState, err)
	}
	certs := map[string]*proxy.CertFiles{}
	for _, s := range services {
		if s.Options.Certificate != "" && s.Options.Key != "" {
			certs[s.Name] = &proxy.CertFiles{Certificate: s.Options.Certificate, Key: s.Options.Key}
		}
	}
	return certs, nil
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
func migratedRoutes(ctx context.Context, r remote.Runner, log io.Writer, apps []string, targets map[string]kamalTarget) ([]proxy.Fragment, error) {
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
			// TLS and its certificate as kamal-proxy serves the host now, not as the release recorded
			// them: a rollback keeps today's tls and cert and points current at a release recorded with
			// others.
			rt := proxy.Route{Host: p.Host, Dial: target.dial, TLS: target.tls}
			if rt.TLS {
				rt.Cert = target.cert
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
			"deploy their apps with the boks that runs kamal-proxy first, so that a release records them, or remove those routes from kamal-proxy "+
			"(`docker exec %s kamal-proxy remove <service>`); nothing was changed", lost, proxy.Container)
	}
	return frags, nil
}
