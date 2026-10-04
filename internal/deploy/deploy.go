// Package deploy implements the boks deploy flow: pull → run → switch proxy → retire → prune.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/cert"
	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

type Options struct {
	Pull bool
	Env  []byte
	Now  func() time.Time
	// Poll is how often the health of a routeless app is checked; zero means once a second.
	Poll time.Duration
}

var unsafe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// ContainerName is unique per deploy so that redeploying the same tag is still a
// start-new-then-retire-old switch with no downtime.
func ContainerName(app, tag string, now time.Time) string {
	return fmt.Sprintf("%s-%s-%d", app, unsafe.ReplaceAllString(tag, "-"), now.Unix())
}

func lockPath(app string) string {
	return "/tmp/boks-" + app + ".lock"
}

func Run(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, tag string, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := lock(ctx, r, cfg.App); err != nil {
		return err
	}
	defer unlock(context.WithoutCancel(ctx), r, log, cfg.App)
	return put(ctx, r, log, cfg, launch{
		action: "deploy", tag: tag, ref: cfg.Image + ":" + tag, pull: o.Pull, prune: true,
		start: func(ctx context.Context, name string) error { return start(ctx, r, log, cfg, name, tag, o.Env) },
		record: func(ctx context.Context, name, op string) error {
			return record(ctx, r, log, cfg, name, tag, op, o.Env, o.Now())
		},
	}, o)
}

// launch is the version an operation puts on the server: a tag being deployed, or a release being
// rolled back to. The two differ in what they run and how they write it down, and in nothing else:
// stopping an app without routes before its new copy starts, switching routes and reverting them,
// the certificate and old-volume checks are one machinery, so a fix to it reaches both.
type launch struct {
	action string // how the journal names the operation
	tag    string // the version label, and part of the container's name
	ref    string // the image docker runs
	pull   bool
	// start runs the container. record writes down that it is now the release serving and closes
	// the journal entry; the previous containers are retired only once it succeeds.
	start  func(ctx context.Context, name string) error
	record func(ctx context.Context, name, op string) error
	// prune removes this repository's images beyond keep once the previous containers are gone.
	prune bool
}

// put runs l on a server whose lock the caller holds. cfg is what l runs with: the current config
// for a deploy, the recorded release over the current server side for a rollback.
func put(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, l launch, o Options) error {
	// Before anything on the server changes, the proxy included: a deploy that has to be refused
	// for its data must leave the server as it found it.
	if err := checkLegacyVolumes(ctx, r, cfg); err != nil {
		return err
	}
	if len(cfg.Ports) == 0 {
		return runRouteless(ctx, r, log, cfg, l, o)
	}
	if err := proxy.Boot(ctx, r, log, cfg.Network, cfg.ProxyImage); err != nil {
		return err
	}
	// Routing a host to a certificate file that isn't there yet either makes kamal-proxy refuse
	// the deploy or, worse, makes it accept and then fail every TLS handshake for that host.
	if covered(cfg) && !cert.Installed(ctx, r, cfg) {
		crt, _ := cert.ServerPaths(cfg.Cert)
		return fmt.Errorf("%s is missing on this server: run `boks cert issue` before deploying an app with a cert block", crt)
	}
	if err := pull(ctx, r, log, l.ref, l.pull); err != nil {
		return err
	}
	old, err := containers(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	// Which service carries each port depends on what the proxy holds right now, so it is read
	// before anything starts: a deploy that cannot tell must not begin.
	held, err := readRoutes(ctx, r, cfg, names(old))
	if err != nil {
		return err
	}
	plan, err := held.plan(cfg)
	if err != nil {
		return err
	}
	name := ContainerName(cfg.App, l.tag, o.Now())
	op, err := beginOperation(ctx, r, log, cfg, l.action, name, o.Now())
	if err != nil {
		return err
	}
	if err := l.start(ctx, name); err != nil {
		finish(ctx, r, log, cfg.App, op, "failed", o.Now())
		return err
	}
	switched, err := switchProxy(ctx, r, log, cfg, name, plan)
	if err != nil {
		revert(ctx, r, log, cfg, plan, switched, old)
		// The entry stays open: a command that failed may still have switched its route on the
		// proxy (the connection can drop after the proxy acted), so how this ended is not known,
		// and the journal is what tells the next run that an operation never finished.
		return fmt.Errorf("%w\nnew container %s is left running for inspection; the route that failed may still have switched to it, "+
			"so see the revert/warning lines above and `boks proxy list` for where traffic goes now — the operation stays open in the journal", err, name)
	}
	// Routing a host at a certificate path makes the proxy read that file, so the deploy is a
	// load: record it, or `cert status` will keep claiming a reload is owed.
	if covered(cfg) {
		if err := cert.MarkLoaded(ctx, r, cfg); err != nil {
			fmt.Fprintf(log, "warning: could not record the loaded certificate: %v\n", err)
		}
	}
	if err := settle(ctx, r, log, cfg, name, plan, held); err != nil {
		return keptOld(err, old)
	}
	if err := l.record(ctx, name, op); err != nil {
		return unrecorded(err, name, old)
	}
	retire(ctx, r, log, names(old))
	if l.prune {
		prune(ctx, r, log, cfg, l.tag)
	}
	return nil
}

// unrecorded reports a deploy whose new version is up but could not be written down. Retiring the
// previous containers would then delete the last trace of what ran before, while the server's
// memory still names that release as current; they stay until a deploy is recorded.
func unrecorded(err error, name string, old []container) error {
	return fmt.Errorf("the new version %s is up, but boks could not record it: %w\n"+
		"the previous containers %v were not removed; deploy again to record a release", name, err, names(old))
}

// keptOld reports a deploy whose new version is up but whose routes could not be brought in line
// with the config. The previous containers are not retired: a stale route that is still there then
// reaches a container that still exists, rather than one this deploy deleted.
func keptOld(err error, old []container) error {
	return fmt.Errorf("the new version is up, but bringing the proxy's routes in line with the config failed: %w\n"+
		"the previous containers %v were not removed, so no route points at a deleted container — but a route left over may still answer "+
		"with an error; check `boks proxy list` and deploy again",
		err, names(old))
}

// runRouteless deploys an app that publishes nothing — a bot, a worker. Two differences from the
// routed path, both forced by the absence of a route. There is no traffic to switch, so the proxy
// is not booted at all; and overlapping the two versions would mean two live copies draining the
// same queue, so the old container is stopped BEFORE the new one starts and brought back if the
// new one never becomes healthy. Only the copies that were actually running are stopped and
// brought back: a container left stopped by an earlier deploy must stay stopped, or a failed
// deploy would end with two copies where there was one.
func runRouteless(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, l launch, o Options) error {
	// The proxy is what normally creates the network every app container joins; without it the
	// network has to be made here, or the first deploy on a fresh server cannot start at all.
	if err := proxy.EnsureNetwork(ctx, r, log, cfg.Network); err != nil {
		return err
	}
	if err := pull(ctx, r, log, l.ref, l.pull); err != nil {
		return err
	}
	// Whether the image declares a HEALTHCHECK is known before anything is touched. A deploy that
	// is bound to be refused must not first take the running copy down.
	if declaresNoHealthcheck(ctx, r, l.ref) {
		return noHealthcheck(cfg)
	}
	old, err := containers(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	live, err := running(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	// Removing every port does not remove the routes the app had: they would keep answering, with
	// a 502, from the container retire is about to delete. They are read before anything is
	// stopped, so a proxy that cannot answer fails the deploy while nothing has changed yet.
	stale, checked, err := ownRoutes(ctx, r, cfg, names(old))
	if err != nil {
		return err
	}
	// The failure path below force-removes the container by name, so that name must not already
	// belong to an earlier copy: two deploys of one tag within a second would otherwise remove the
	// very copy that was meant to come back.
	name := ContainerName(cfg.App, l.tag, o.Now())
	for _, c := range names(old) {
		if c == name {
			return fmt.Errorf("a container named %s already exists (the same tag was deployed less than a second ago); retry in a second", name)
		}
	}
	op, err := beginOperation(ctx, r, log, cfg, l.action, name, o.Now())
	if err != nil {
		return err
	}
	var stopped []string
	for _, c := range live {
		fmt.Fprintf(log, "stop %s\n", c)
		// The stop is the guarantee that two copies never run at once, not cleanup: if it fails,
		// the new copy must not start. `docker start` of a container that is still running is a
		// no-op, so the one that failed to stop is safe to include in the revival.
		stopped = append(stopped, c)
		if _, err := r.Run(ctx, "docker", "stop", c); err != nil {
			revive(ctx, r, log, stopped)
			finish(ctx, r, log, cfg.App, op, "failed", o.Now())
			return fmt.Errorf("could not stop %s, so the new version was not started: %w", c, err)
		}
	}
	err = l.start(ctx, name)
	if err == nil {
		err = waitHealthy(ctx, r, log, cfg, name, o.Poll)
	}
	if err != nil {
		// A failed `docker run` may still have created the container, and a failed stop may have
		// left it running. The old copy comes back only once the new one is verifiably gone;
		// otherwise both would run at once, which is the one outcome this path exists to prevent.
		// The entry closes only after the cleanup, so a run cut during it stays visibly unfinished.
		if !discard(ctx, r, log, name) {
			finish(ctx, r, log, cfg.App, op, "failed", o.Now())
			return fmt.Errorf("%w\n%s could not be confirmed removed, so %v were left stopped rather than risk two copies running at once: remove it, then `docker start` them",
				err, name, stopped)
		}
		revive(ctx, r, log, stopped)
		finish(ctx, r, log, cfg.App, op, "failed", o.Now())
		return err
	}
	if err := removeExcept(ctx, r, log, stale, nil); err != nil {
		return keptOld(err, old)
	}
	// A route named by an earlier boks is known to be this app's only by its targets, so while the
	// proxy cannot be asked, the copies that may be such a target stay, stopped, until a deploy can
	// check. A copy started without routes never was one and goes as usual.
	gone := names(old)
	if !checked {
		gone = nil
		var kept []string
		for _, c := range old {
			if c.startedWithoutRoutes() {
				gone = append(gone, c.name)
			} else {
				kept = append(kept, c.name)
			}
		}
		if len(kept) > 0 {
			fmt.Fprintf(log, "warning: the proxy is not running, so this app's old routes there were not checked; "+
				"%v are kept stopped until a deploy can check them\n", kept)
		}
	}
	if err := l.record(ctx, name, op); err != nil {
		return unrecorded(err, name, old)
	}
	retire(ctx, r, log, gone)
	if l.prune {
		prune(ctx, r, log, cfg, l.tag)
	}
	return nil
}

// startedWithoutRoutes reports a copy whose label records an empty list of ports — one started on
// the routeless path, which no route was ever deployed onto. A copy without the label (started by
// an older boks) may have been one.
func (c container) startedWithoutRoutes() bool {
	return c.ports != nil && len(c.ports) == 0
}

// discard stops and removes a container and reports whether it is verifiably gone. The stop comes
// first so the copy shuts down gracefully; `rm -f` makes sure it goes even if the stop did not.
func discard(ctx context.Context, r remote.Runner, log io.Writer, name string) bool {
	fmt.Fprintf(log, "remove %s\n", name)
	best(ctx, r, log, "docker", "stop", name)
	best(ctx, r, log, "docker", "rm", "-f", name)
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "name=^"+name+"$", "--format", "{{.Names}}")
	return err == nil && strings.TrimSpace(out) == ""
}

// declaresNoHealthcheck reports whether the image is known to declare no HEALTHCHECK (none at all,
// or `HEALTHCHECK NONE`). An image that cannot be inspected — a rollback to a release whose image
// is no longer on the server, which `docker run` will fetch — is not known to lack one; the running
// container is asked instead.
func declaresNoHealthcheck(ctx context.Context, r remote.Runner, ref string) bool {
	out, err := r.Run(ctx, "docker", "image", "inspect", "--format",
		"{{if .Config.Healthcheck}}{{json .Config.Healthcheck.Test}}{{end}}", ref)
	if err != nil {
		return false
	}
	out = strings.TrimSpace(out)
	return out == "" || out == "null" || out == "[]" || out == `["NONE"]`
}

func noHealthcheck(cfg *config.Config) error {
	return fmt.Errorf("%s has no HEALTHCHECK: an app without routes is judged by its own "+
		"health check, so add one to the image or publish a port", cfg.Image)
}

// running lists the containers of this app that are up right now.
func running(ctx context.Context, r remote.Runner, app string) ([]string, error) {
	out, err := r.Run(ctx, "docker", "ps", "--filter", "label=boks.app="+app, "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	var live []string
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			live = append(live, name)
		}
	}
	return live, nil
}

// revive restarts the containers that were stopped to make room for a deploy that then failed.
func revive(ctx context.Context, r remote.Runner, log io.Writer, stopped []string) {
	for _, c := range stopped {
		fmt.Fprintf(log, "restart %s (the new version did not come up)\n", c)
		best(ctx, r, log, "docker", "start", c)
	}
}

// healthFormat asks for the health of a container and says `none` when the image declares no
// HEALTHCHECK — the two cases have to be told apart, because without a route health is the only
// evidence that a deploy worked.
const healthFormat = "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"

func waitHealthy(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name string, poll time.Duration) error {
	if poll <= 0 {
		poll = time.Second
	}
	timeout, err := time.ParseDuration(cfg.DeployTimeout)
	if err != nil {
		return err
	}
	fmt.Fprintf(log, "waiting for %s to report healthy\n", name)
	deadline := time.Now().Add(timeout)
	for {
		state, err := r.Run(ctx, "docker", "inspect", "--format", healthFormat, name)
		if err != nil {
			return err
		}
		switch state {
		case "healthy":
			return nil
		case "none":
			return noHealthcheck(cfg)
		case "unhealthy":
			return fmt.Errorf("%s reported unhealthy", name)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not become healthy within %s (last state %q)", name, cfg.DeployTimeout, state)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// checkLegacyVolumes refuses a deploy that would start the app on a fresh, empty volume because
// its data may still sit under the previous naming scheme. Ownership is read from the containers,
// not from the name: the old name is the ambiguous one (`a-b` with volume `c` and `a` with volume
// `b-c` both called it `a-b-c`). Mounted by a container of this app, it is this app's data;
// mounted only by another app's, it is theirs; mounted by none — the volume was dropped from the
// config once and its container retired — nobody can tell, so the operator decides. Copying is
// the operator's call, not something boks should do behind their back, so this says what to run
// instead — stopping the app first, or the copy would miss whatever it writes until the deploy
// retires it.
func checkLegacyVolumes(ctx context.Context, r remote.Runner, cfg *config.Config) error {
	for _, v := range cfg.Volumes {
		name, _, _ := strings.Cut(v, ":")
		if err := checkLegacyVolume(ctx, r, cfg.App, cfg.App+"-"+name, cfg.App+proxy.NameSep+name); err != nil {
			return err
		}
	}
	return nil
}

func checkLegacyVolume(ctx context.Context, r remote.Runner, app, legacy, current string) error {
	// The data has been moved, or the new volume was made on purpose.
	if moved, err := volumeExists(ctx, r, current); err != nil || moved {
		return err
	}
	if left, err := volumeExists(ctx, r, legacy); err != nil || !left {
		return err
	}
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "volume="+legacy,
		"--format", "{{.Names}}\t{{.Label \"boks.app\"}}")
	if err != nil {
		return fmt.Errorf("checking which containers use %s: %w", legacy, err)
	}
	// A container without the label is nobody's app — a `docker run -v` left behind by hand — and
	// says nothing about whose data this is.
	var mine, theirs []string
	for _, line := range strings.Fields(strings.ReplaceAll(out, "\t", "|")) {
		switch c, owner, _ := strings.Cut(line, "|"); owner {
		case app:
			mine = append(mine, c)
		case "":
		default:
			theirs = append(theirs, c)
		}
	}
	move := fmt.Sprintf("  docker volume create %s\n"+
		"  docker run --rm -v %s:/from -v %s:/to alpine sh -c 'cp -a /from/. /to/'", current, legacy, current)
	switch {
	case len(mine) > 0:
		return fmt.Errorf("volume %s holds this app's data under the old naming scheme (mounted by %s) and %s does not exist yet; "+
			"deploying now would start on an empty volume. Stop the app, move the data, then deploy again "+
			"(the app is down from the stop until that deploy finishes):\n  docker stop %s\n%s",
			legacy, strings.Join(mine, ", "), current, strings.Join(mine, " "), move)
	case len(theirs) > 0:
		return nil // another app's data under a name that happens to read like this app's
	default:
		return fmt.Errorf("volume %s exists under the old naming scheme, no container of a boks app uses it, and %s does not exist yet; "+
			"whose data it holds cannot be told, so deploying now could start on an empty volume. "+
			"If it is this app's, move it, then deploy again:\n%s\n"+
			"If it is not, create the new volume empty, then deploy again:\n  docker volume create %s",
			legacy, current, move, current)
	}
}

func volumeExists(ctx context.Context, r remote.Runner, name string) (bool, error) {
	// The filter is a regular expression, so the dot of the current scheme has to be escaped: bare
	// it would match any character and report a volume that is not there.
	out, err := r.Run(ctx, "docker", "volume", "ls", "--quiet", "--filter",
		"name=^"+regexp.QuoteMeta(name)+"$")
	if err != nil {
		return false, fmt.Errorf("checking for volume %s: %w", name, err)
	}
	return strings.TrimSpace(out) != "", nil
}

// held is this app's share of what kamal-proxy holds: the services it owns, by name, in a stable
// order. A service is the app's when it carries the `<app>.` prefix, or — named by boks before the
// dot, as `<app>-<port>` — when every container it targets is one of this app's. The old name
// alone cannot say whose it is; the targets can.
type held struct {
	services map[string]proxy.Listed
	names    []string
}

func readRoutes(ctx context.Context, r remote.Runner, cfg *config.Config, mine []string) (held, error) {
	all, names, err := proxy.Services(ctx, r)
	if err != nil {
		return held{}, fmt.Errorf("reading the proxy's services: %w", err)
	}
	h := held{services: map[string]proxy.Listed{}}
	for _, n := range names {
		if s := all[n]; proxy.Owns(cfg.App, n) || targetsOnly(s.Targets, mine) {
			h.services[n] = s
			h.names = append(h.names, n)
		}
	}
	return h, nil
}

func targetsOnly(targets, mine []string) bool {
	for _, t := range targets {
		c, _, _ := strings.Cut(t, ":")
		if !slices.Contains(mine, c) {
			return false
		}
	}
	return len(targets) > 0
}

// plan names the service that carries each port through the switch. kamal-proxy gives a host to
// one service at a time and refuses a second, so when a service of this app already holds the
// port's host — the port was renamed, or an earlier boks named it `<app>-<port>` — the new
// container is deployed onto that service, and settle renames it once traffic has moved.
func (h held) plan(cfg *config.Config) (map[string]string, error) {
	plan := make(map[string]string, len(cfg.Ports))
	carries := map[string]string{}
	for _, p := range cfg.Ports {
		svc := proxy.ServiceName(cfg.App, p.Name)
		for _, n := range h.names {
			if slices.Contains(h.services[n].Hosts, p.Host) {
				svc = n
				break
			}
		}
		// A port whose own name is held by the renamed predecessor of another port would take that
		// service, and that port's host with it.
		if q, ok := carries[svc]; ok {
			return nil, fmt.Errorf("ports %s and %s would both go through proxy service %s: deploy once without one of them, then add it back", q, p.Name, svc)
		}
		carries[svc] = p.Name
		plan[p.Name] = svc
	}
	return plan, nil
}

// settle leaves the proxy with exactly the services the config describes, under their own names,
// once traffic has reached the new container and before anything is deleted. A port carried by a
// service of another name is renamed: removed, then deployed under its own name onto the container
// that has just passed this very health check, so its host goes unrouted for one call to the proxy
// and kamal-proxy's first check of the target.
// A rename never takes a name that still carries another port: renamed in a chain (x→y, y→z), y
// waits until z has moved off it; names that only swap places stay as they are, with a warning,
// rather than lose a host. Services this app owns but no longer describes are removed, or they
// would keep pointing at the container retire is about to delete.
func settle(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, target string, plan map[string]string, h held) error {
	type move struct {
		svc  proxy.Service
		was  string
		port string
	}
	keep := map[string]bool{} // not to be removed: the config's own names, and names a rename already removed
	busy := map[string]bool{} // services still carrying a port's traffic under a name not their own
	var pending []move
	for _, p := range cfg.Ports {
		svc := service(cfg, target, p)
		keep[svc.Name] = true
		if was := plan[p.Name]; was != svc.Name {
			busy[was] = true
			pending = append(pending, move{svc, was, p.Name})
		}
	}
	for progress := true; progress; {
		progress = false
		var left []move
		for _, m := range pending {
			if busy[m.svc.Name] {
				left = append(left, m)
				continue
			}
			if err := rename(ctx, r, log, m.svc, m.was); err != nil {
				return err
			}
			delete(busy, m.was)
			keep[m.was] = true
			progress = true
		}
		pending = left
	}
	// What is left is a cycle, and every service in it is some port's own name, so none is removed.
	for _, m := range pending {
		fmt.Fprintf(log, "warning: port %s keeps its route under %s: %s still carries another port\n", m.port, m.was, m.svc.Name)
	}
	return removeExcept(ctx, r, log, h, keep)
}

func rename(ctx context.Context, r remote.Runner, log io.Writer, svc proxy.Service, was string) error {
	fmt.Fprintf(log, "rename route %s → %s\n", was, svc.Name)
	if err := proxy.Remove(ctx, r, was); err != nil {
		return err
	}
	// Neither deploy waits for a health check. The target has just passed one under the old name,
	// and waiting again would only leave the host unrouted for as long as the check takes, or lose
	// the route to one flaky answer. kamal-proxy checks the target right away and answers 503 until
	// that check passes.
	svc.Force = true
	if _, err := r.Run(ctx, proxy.DeployArgs(svc)...); err != nil {
		back := svc
		back.Name = was
		best(context.WithoutCancel(ctx), r, log, proxy.DeployArgs(back)...)
		return fmt.Errorf("renaming route %s to %s: %w", was, svc.Name, err)
	}
	return nil
}

// ownRoutes reads the routes of an app that no longer publishes a port, and reports whether they
// could be checked at all. A server without the proxy has none. A proxy that is there but not
// running cannot be asked, and an app without routes does not need it, so the deploy goes on.
func ownRoutes(ctx context.Context, r remote.Runner, cfg *config.Config, mine []string) (held, bool, error) {
	state, err := proxy.State(ctx, r)
	if err != nil || state == "" {
		return held{}, err == nil, err
	}
	if state != "running" {
		return held{}, false, nil
	}
	h, err := readRoutes(ctx, r, cfg, mine)
	return h, err == nil, err
}

func removeExcept(ctx context.Context, r remote.Runner, log io.Writer, h held, keep map[string]bool) error {
	for _, n := range h.names {
		if keep[n] {
			continue
		}
		fmt.Fprintf(log, "remove stale route %s\n", n)
		if err := proxy.Remove(ctx, r, n); err != nil {
			return err
		}
	}
	return nil
}

// beginOperation opens the journal entry and, on the way, says whether the previous one was ever
// closed. A deploy cut between switching routes and recording the release leaves no trace in
// docker — the journal is the only place that knows.
func beginOperation(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, action, to string, now time.Time) (string, error) {
	// The open entry is closed as abandoned once reported: otherwise every later deploy, however
	// successful, would report the same interruption again.
	if open, err := release.Unfinished(ctx, r, cfg.App); err == nil && open != nil {
		fmt.Fprintf(log, "warning: %s of %s started %s and never finished; this run replaces it\n",
			open.Action, cfg.App, open.StartedAt.Format(time.RFC3339))
		finish(ctx, r, log, cfg.App, open.Op, "abandoned", now)
	}
	from, err := release.Current(ctx, r, cfg.App)
	if err != nil {
		return "", err
	}
	return release.Begin(ctx, r, cfg.App, action, from, to, now)
}

func finish(ctx context.Context, r remote.Runner, log io.Writer, app, op, result string, now time.Time) {
	if op == "" {
		return
	}
	if err := release.Finish(context.WithoutCancel(ctx), r, app, op, result, now); err != nil {
		fmt.Fprintf(log, "warning: could not close the journal entry: %v\n", err)
	}
}

// record writes what this release actually is, points `current` at it and closes the operation.
// The order is deliberate: the snapshot exists before anything claims to be current, and the
// journal closes last, so an interruption always leaves more evidence rather than less. Any of the
// three failing is an error, because the caller retires the previous containers only after it.
func record(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name, tag, op string, env []byte, now time.Time) error {
	digest, err := digestOf(ctx, r, cfg.Image, tag)
	if err != nil {
		return err
	}
	snapshot := release.Snapshot{
		ID: name, App: cfg.App, Image: cfg.Image, Tag: tag, Digest: digest,
		Ports: cfg.Ports, Volumes: cfg.Volumes, TLS: cfg.TLS, Network: cfg.Network,
		EnvPath: envFile(cfg.App, name, env), CreatedAt: now,
	}
	if cfg.Cert != nil {
		snapshot.CertDomains = cfg.Cert.Domains
	}
	if err := release.Save(ctx, r, snapshot); err != nil {
		return err
	}
	if err := serving(ctx, r, cfg.App, name, op, now); err != nil {
		return err
	}
	if err := release.Prune(ctx, r, cfg.App, cfg.Keep); err != nil {
		fmt.Fprintf(log, "warning: could not prune old releases: %v\n", err)
	}
	return nil
}

// serving points `current` at release id and closes the operation that put it there, in that order,
// so an interruption between the two leaves the release named and the operation visibly open.
func serving(ctx context.Context, r remote.Runner, app, id, op string, now time.Time) error {
	if err := release.SetCurrent(ctx, r, app, id); err != nil {
		return fmt.Errorf("mark %s as current: %w", id, err)
	}
	if err := release.Finish(context.WithoutCancel(ctx), r, app, op, "ok", now); err != nil {
		return fmt.Errorf("close the journal entry: %w", err)
	}
	return nil
}

// digestOf pins what was actually pulled: a tag can be overwritten, a digest cannot, so a rollback
// aiming at this snapshot gets the same image rather than whatever the tag means by then.
// An image that came from no registry has no digest, which is an answer; a failed inspect is not,
// and fails the recording rather than leave a snapshot that silently lost its image identity.
func digestOf(ctx context.Context, r remote.Runner, image, tag string) (string, error) {
	out, err := r.Run(ctx, "docker", "inspect", "--type", "image", "--format", "{{json .RepoDigests}}", image+":"+tag)
	if err != nil {
		return "", fmt.Errorf("read the digest of %s:%s: %w", image, tag, err)
	}
	var refs []string
	if err := json.Unmarshal([]byte(out), &refs); err != nil {
		return "", fmt.Errorf("read the digest of %s:%s: %w", image, tag, err)
	}
	// An image pulled under several names has a digest per repository; this app's is the one a
	// rollback can pull again.
	digest := ""
	for _, ref := range refs {
		repo, d, ok := strings.Cut(ref, "@")
		if !ok {
			continue
		}
		if repo == image {
			return d, nil
		}
		if digest == "" {
			digest = d
		}
	}
	return digest, nil
}

// envFile is the environment file a release is started with, or "" when it has no environment and
// so no file is written: the snapshot must not name a file that never existed.
func envFile(app, name string, env []byte) string {
	if len(env) == 0 {
		return ""
	}
	return release.EnvPath(app, name)
}

func lock(ctx context.Context, r remote.Runner, app string) error {
	if _, err := r.Run(ctx, "mkdir", lockPath(app)); err != nil {
		return fmt.Errorf("another deploy of %s seems to be in progress (run `boks unlock` to clear %s)", app, lockPath(app))
	}
	return nil
}

func unlock(ctx context.Context, r remote.Runner, log io.Writer, app string) {
	if err := Unlock(ctx, r, app); err != nil {
		fmt.Fprintf(log, "warning: could not release %s: %v\n", lockPath(app), err)
	}
}

func Unlock(ctx context.Context, r remote.Runner, app string) error {
	_, err := r.Run(ctx, "rmdir", lockPath(app))
	return err
}

func pull(ctx context.Context, r remote.Runner, log io.Writer, ref string, enabled bool) error {
	if !enabled {
		return nil
	}
	fmt.Fprintf(log, "pull %s\n", ref)
	_, err := r.Run(ctx, "docker", "pull", ref)
	return err
}

// container is a previously deployed container of this app: its name plus the port specs it was
// started with, so a revert can aim at what THAT container listens on rather than at whatever
// the current config says.
type container struct {
	name  string
	ports map[string]config.Port
}

func containers(ctx context.Context, r remote.Runner, app string) ([]container, error) {
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "label=boks.app="+app,
		// `.Label "k"` looks a key up; `.Labels` is the flat comma-joined string and cannot be indexed.
		"--format", "{{.Names}}\t{{.Label \"boks.ports\"}}")
	if err != nil {
		return nil, err
	}
	var cs []container
	for _, line := range strings.Split(out, "\n") {
		name, label, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if name == "" {
			continue
		}
		cs = append(cs, container{name: name, ports: parsePorts(label)})
	}
	return cs, nil
}

func names(cs []container) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.name
	}
	return out
}

// portLabel stores the whole port spec, not just the numbers: a revert has to reproduce the
// health check the old container passed too, and JSON keeps that exact instead of inventing a
// format that is only partly faithful.
func portLabel(ports []config.Port) string {
	// An app without routes has no ports at all, and `null` in the label would read as a missing
	// label rather than as an empty list — write the empty list.
	if len(ports) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ports)
	if err != nil {
		return ""
	}
	return string(b)
}

// parsePorts reads portLabel back. Anything absent or malformed yields no entries, which the
// caller treats as "this container predates the label, don't guess".
func parsePorts(label string) map[string]config.Port {
	var ports []config.Port
	if json.Unmarshal([]byte(label), &ports) != nil {
		return nil
	}
	out := make(map[string]config.Port, len(ports))
	for _, p := range ports {
		out[p.Name] = p
	}
	return out
}

func start(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name, tag string, env []byte) error {
	envPath := envFile(cfg.App, name, env)
	if envPath != "" {
		if err := remote.Upload(ctx, r, env, envPath); err != nil {
			return err
		}
	}
	return run(ctx, r, log, cfg, name, tag, cfg.Image+":"+tag, envPath)
}

// run starts container name from image ref, labelled as version tag of the app cfg describes.
func run(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name, tag, ref, envPath string) error {
	fmt.Fprintf(log, "run %s\n", name)
	_, err := r.Run(ctx, runArgs(cfg, name, tag, ref, envPath)...)
	return err
}

func runArgs(cfg *config.Config, name, tag, ref, envPath string) []string {
	a := []string{"docker", "run", "-d", "--name", name, "--network", cfg.Network,
		"--restart", "unless-stopped", "--label", "boks.app=" + cfg.App, "--label", "boks.version=" + tag,
		"--label", "boks.ports=" + portLabel(cfg.Ports)}
	if envPath != "" {
		a = append(a, "--env-file", envPath)
	}
	for _, v := range cfg.Volumes {
		vol, path, _ := strings.Cut(v, ":")
		a = append(a, "-v", cfg.App+proxy.NameSep+vol+":"+path)
	}
	return append(a, ref)
}

// covered reports whether any of the app's hosts is served by the configured certificate.
func covered(cfg *config.Config) bool {
	for _, p := range cfg.Ports {
		if cfg.Cert.Covers(p.Host) {
			return true
		}
	}
	return false
}

func service(cfg *config.Config, target string, p config.Port) proxy.Service {
	svc := proxy.Service{
		Name: proxy.ServiceName(cfg.App, p.Name), Target: fmt.Sprintf("%s:%d", target, p.Port), Host: p.Host,
		TLS: cfg.TLS, HealthPath: p.HealthPath, HealthPort: p.HealthPort, Timeout: cfg.DeployTimeout,
	}
	// Hosts outside the certificate keep kamal-proxy's autocert, so one app can mix a wildcard
	// with plain HTTP-01 domains.
	if cfg.Cert.Covers(p.Host) {
		svc.CertPath, svc.KeyPath = cert.ServerPaths(cfg.Cert)
	}
	return svc
}

// switchProxy points every route at the new container, one port at a time, and returns the
// ports whose routes had already moved when an error stopped it.
func switchProxy(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name string, plan map[string]string) ([]config.Port, error) {
	var done []config.Port
	for _, p := range cfg.Ports {
		svc := service(cfg, name, p)
		svc.Name = plan[p.Name]
		fmt.Fprintf(log, "proxy %s → %s (%s)\n", svc.Name, svc.Target, p.Host)
		if _, err := r.Run(ctx, proxy.DeployArgs(svc)...); err != nil {
			return done, err
		}
		done = append(done, p)
	}
	return done, nil
}

// revert moves routes that already reached the new container back to the previous one, so a
// failed multi-port switch does not leave the app split across two versions. The target port
// comes from the OLD container's own label: if the config changed a port between deploys, the
// old container still listens where it was started, and aiming at the new number would make the
// proxy's health check fail and leave the route on the broken new container.
func revert(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, plan map[string]string, switched []config.Port, old []container) {
	if len(switched) == 0 {
		return
	}
	if len(old) != 1 {
		fmt.Fprintf(log, "warning: %d route(s) already point at the new container and cannot be reverted automatically (previous containers: %v)\n", len(switched), names(old))
		return
	}
	// Every switched route is put back. The label makes the target exact when it has a record
	// for that port; without one the current config is the best guess, which is what boks did
	// before the label existed. Attempting is never worse than skipping: kamal-proxy only moves
	// a route after its own health check passes, and the call goes through best(), so a wrong
	// guess leaves the route exactly where skipping would have left it — on the new container.
	prev := old[0]
	for _, p := range switched {
		target := p
		if recorded, ok := prev.record(p); ok {
			recorded.Host = p.Host // the domain belongs to the route, not to the container
			target = recorded
		} else {
			fmt.Fprintf(log, "warning: %s has no record of port %q; reverting with the current config's %d — if that container listens elsewhere, the health check will refuse and the route stays on the new one\n",
				prev.name, p.Name, p.Port)
		}
		svc := service(cfg, prev.name, target)
		svc.Name = plan[p.Name]
		fmt.Fprintf(log, "revert %s → %s\n", svc.Name, svc.Target)
		best(ctx, r, log, proxy.DeployArgs(svc)...)
	}
}

// record is what the container was started with for the route of p. A route is its host — the
// config gives each host to one port — so the record that served p's host is where that host was,
// even when ports were renamed and p's name meant another port then. The name is the fallback
// for a port whose host changed.
func (c container) record(p config.Port) (config.Port, bool) {
	for _, recorded := range c.ports {
		if recorded.Host == p.Host {
			return recorded, true
		}
	}
	recorded, ok := c.ports[p.Name]
	return recorded, ok
}

// retire stops and removes previous containers. Failures are reported, not fatal: the new
// version is already serving, and a leftover container is cleaned up by the next deploy.
func retire(ctx context.Context, r remote.Runner, log io.Writer, old []string) {
	for _, c := range old {
		fmt.Fprintf(log, "retire %s\n", c)
		best(ctx, r, log, "docker", "stop", c)
		best(ctx, r, log, "docker", "rm", c)
	}
}

// prune removes images of this repository beyond cfg.Keep, never the one just deployed.
// `docker images` lists newest first. Untagged (`<none>`) layers left behind by re-pulling a
// moving tag are removed by ID — without this they accumulate, and the tag-per-SHA workflow the
// architecture recommends produces them steadily. Docker refuses to remove an image a container
// still uses, so a rollback target cannot be pruned away.
func prune(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, current string) {
	out, err := r.Run(ctx, "docker", "images", cfg.Image, "--format", "{{.Tag}} {{.ID}}")
	if err != nil {
		fmt.Fprintf(log, "warning: could not list images: %v\n", err)
		return
	}
	kept := 1
	for _, line := range strings.Split(out, "\n") {
		tag, id, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || tag == current {
			continue
		}
		if tag == "<none>" {
			fmt.Fprintf(log, "prune %s (untagged %s)\n", id, cfg.Image)
			best(ctx, r, log, "docker", "rmi", id)
			continue
		}
		if kept < cfg.Keep {
			kept++
			continue
		}
		fmt.Fprintf(log, "prune %s:%s\n", cfg.Image, tag)
		best(ctx, r, log, "docker", "rmi", cfg.Image+":"+tag)
	}
}

// best runs a cleanup command whose failure must not fail the deploy.
func best(ctx context.Context, r remote.Runner, log io.Writer, args ...string) {
	if _, err := r.Run(ctx, args...); err != nil {
		fmt.Fprintf(log, "warning: %v\n", err)
	}
}
