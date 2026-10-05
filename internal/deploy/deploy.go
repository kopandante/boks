// Package deploy implements the boks deploy flow: pull → run → health check → switch proxy → drain → retire → prune.
package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
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
	Env []byte
	// Files are the files the release mounts, read from the app's repository before any server is reached.
	Files []config.FileContent
	// Login is the registry login every pull of the app's image goes through; nil for a public image.
	Login *Login
	Now   func() time.Time
	// Stamp names this run's containers and releases; zero means Now. A command that goes over
	// several servers passes one, so a release has the same id on each of them and `boks rollback
	// <id>` means one release everywhere, not one that exists on a single server.
	Stamp time.Time
	// Poll is how often a new copy's health is checked, the proxy asked whether the old copy has
	// drained, and the server's admission lock tried again; zero means once a second.
	Poll time.Duration
	// AdmitWait is how long to wait for another deploy on the server to finish admitting its
	// container; zero means five minutes.
	AdmitWait time.Duration
}

func (o Options) stamp() time.Time {
	if o.Stamp.IsZero() {
		return o.Now()
	}
	return o.Stamp
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
		action: "deploy", again: "boks deploy " + tag, tag: tag, ref: cfg.Image + ":" + tag, pull: true,
		start: func(ctx context.Context, name string) error {
			return start(ctx, r, log, cfg, name, tag, o.Env, o.Files)
		},
		record: func(ctx context.Context, name string, op operation) error {
			return record(ctx, r, log, cfg, name, tag, op, o.Env, fileRecords(o.Files), o.Now())
		},
	}, o)
}

// launch is the version an operation puts on the server: a tag being deployed, or a release being
// rolled back to. The two differ in what they run and how they write it down, and in nothing else:
// stopping an app without routes before its new copy starts, switching routes and putting them back,
// the certificate and old-volume checks are one machinery, so a fix to it reaches both.
type launch struct {
	action string // how the journal names the operation
	// again is the command that repeats exactly this operation, for the advice after a failure:
	// a plain `boks rollback` run again after `current` moved would go one release further back.
	again string
	tag   string // the version label, and part of the container's name
	ref   string // the image docker runs
	pull  bool
	// stopFirst is a vote for stop-first from outside the release being put in place: today's
	// config, for a rollback to a release that recorded overlap.
	stopFirst bool
	// start runs the container. record writes down that it is now the release serving and closes
	// the journal entry; the previous containers are retired only once it succeeds.
	start  func(ctx context.Context, name string) error
	record func(ctx context.Context, name string, op operation) error
}

// put runs l on a server whose lock the caller holds. cfg is what l runs with: the current config
// for a deploy, the recorded release over the current server side for a rollback.
//
// There is one flow for every shape of app, and the replace mode is the one fork in it. Overlap
// starts the new copy beside the old, waits until it answers every port's health check, and moves
// the routes to it with one reload of the proxy; the old copy finishes what it holds and goes.
// Stop-first stops the copies that are running before the new one starts, and brings them back if
// it never comes up — the only shape an app without routes can take (two copies of a worker would
// drain one queue twice), and the one storage with a single writer needs (two copies on one SQLite
// volume can corrupt it).
func put(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, l launch, o Options) error {
	// Before anything on the server changes, the proxy included: a deploy that has to be refused
	// for its data must leave the server as it found it.
	if err := checkLegacyVolumes(ctx, r, cfg); err != nil {
		return err
	}
	if err := checkCron(ctx, r, cfg); err != nil {
		return err
	}
	routed := len(cfg.Ports) > 0
	name := ContainerName(cfg.App, l.tag, o.stamp())
	if _, err := checkNetworks(ctx, r, cfg, name); err != nil {
		return err
	}
	// The pull comes before the proxy is booted: a registry that refuses the login, or an image that
	// is not there, is a refusal that leaves the server as it found it.
	if err := pull(ctx, r, log, l.ref, l.pull || missing(ctx, r, l.ref), o.Login); err != nil {
		return err
	}
	// Whether the container will have a health check is known before anything is touched: from the
	// config, or else from the image. A deploy that is bound to be refused must not first take the
	// running copy down.
	if !routed && cfg.Healthcheck == nil && declaresNoHealthcheck(ctx, r, l.ref) {
		return noHealthcheck(cfg)
	}
	if routed {
		if err := bootProxy(ctx, r, log, cfg.App, cfg.ProxyImage, o); err != nil {
			return err
		}
		// Caddy refuses a config that names a certificate file the server lacks — the switch would
		// fail after the new copy started — and a proxy that starts with one exits. The file is read
		// through the proxy, so only once it is booted.
		if covered(cfg) && !cert.Installed(ctx, r, cfg) {
			crt, _ := cert.ServerPaths(cfg.Cert)
			return fmt.Errorf("%s is missing on this server: run `boks cert issue` before deploying an app with a cert block", crt)
		}
	}
	// What the proxy serves for the app now, from the fragments on the server: where a failed switch
	// sends the routes back, and what an app that no longer publishes a port still has — routes that
	// would keep answering, with a 502, from the container retire is about to delete.
	fs, err := proxy.Fragments(ctx, r)
	if err != nil {
		return err
	}
	was := proxy.Of(fs, cfg.App)
	// A host another app routes would make the config the switch reloads with invalid: refused now,
	// while nothing of the app has changed.
	if err := proxy.CheckHosts(fs, cfg.App, routesTo(cfg, name)); err != nil {
		return err
	}
	old, err := containers(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	// The copies on the server have a say in how they are replaced, and it is read from them, not
	// from what the journal believes is serving: a release that started and failed to be recorded
	// still writes its volume. Either side asking for stop-first is enough.
	stopFirst := cfg.ReplaceMode() == config.ReplaceStopFirst || l.stopFirst || anyStopFirst(old)
	var live []string
	if stopFirst {
		if live, err = running(ctx, r, cfg.App); err != nil {
			return err
		}
	}
	// The failure path of stop-first force-removes the new container by name, so that name must not
	// already belong to an earlier copy: two deploys of one tag within a second would otherwise remove
	// the very copy that was meant to come back.
	if slices.Contains(names(old), name) {
		return fmt.Errorf("a container named %s already exists (the same tag was deployed less than a second ago); retry in a second", name)
	}
	adm, err := admit(ctx, r, log, cfg.App, o)
	if err != nil {
		return err
	}
	defer adm.release(ctx)
	// Asked again now that no other deploy is admitting a container: the first answer may be minutes old.
	fresh, err := checkNetworks(ctx, r, cfg, name)
	if err != nil {
		return err
	}
	if err := checkMemory(ctx, r, log, cfg, live); err != nil {
		return fmt.Errorf("%w\nnothing of the app was changed", err)
	}
	if fresh {
		if err := makeNetwork(ctx, r, log, cfg); err != nil {
			return err
		}
	}
	op, err := beginOperation(ctx, r, log, cfg, l.action, name, o.Now())
	if err != nil {
		return err
	}
	if stopFirst {
		err = replaceStopFirst(ctx, r, log, cfg, l, o, op, adm, name, live, was)
	} else {
		err = replaceOverlap(ctx, r, log, cfg, l, o, op, adm, name, was)
	}
	if err != nil {
		return err
	}
	if !routed && len(was) > 0 {
		err := underAdmission(ctx, r, log, cfg.App, o, nil, func() error {
			_, err := proxy.SetRoutes(ctx, r, log, cfg.App, nil)
			return err
		})
		if err != nil {
			return keptOld(err, l.again, old)
		}
	}
	if err := l.record(ctx, name, op); err != nil {
		return unrecorded(err, l.again, name, old)
	}
	// Cron follows the release that now serves, the one just recorded.
	if err := applySchedules(ctx, r, log, cfg); err != nil {
		fmt.Fprintf(log, "warning: the release serves, but its schedules were not applied: %v\nrun `%s` again to apply them\n", err, l.again)
	}
	// Once the release is recorded: leaving waits for the server's admission lock, and a wait before
	// the record would be one more window in which a cut run leaves the new version unrecorded.
	if !routed {
		leaveProxy(ctx, r, log, cfg, o)
	}
	retire(ctx, r, log, names(old))
	prune(ctx, r, log, cfg, l.tag)
	return nil
}

// replaceOverlap starts the new copy beside the old one, waits for it to answer every port's health
// check, and moves the routes to it with one reload; then the old copies finish the requests they
// hold. The server's admission ends once the container exists and the proxy is on its network (or
// the copy is gone again): from then on the memory check of the next deploy counts its limit, and
// the proxy's networks are settled. The switch takes it again, since the config is every app's.
func replaceOverlap(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, l launch, o Options,
	op operation, adm *admission, name string, was []proxy.Route) error {
	err := l.start(ctx, name)
	if err == nil {
		// The proxy joins before it is asked to probe the new copy, under the admission lock, like
		// every change to the proxy's networks.
		err = joinProxy(ctx, r, log, cfg)
	}
	adm.release(ctx)
	if err == nil {
		err = awaitReady(ctx, r, log, cfg, name, o.Poll)
	}
	touched := false
	if err == nil {
		if touched, err = switchRoutes(ctx, r, log, cfg, name, o, nil); err == nil {
			drain(ctx, r, log, cfg, was, o.Poll)
			return nil
		}
	}
	// A copy that never got the routes saw no traffic: it simply goes. One whose switch failed may
	// have them after all — the answer of a reload can be lost after Caddy acted — so they are put
	// back first; until that is known, the copy stays, since it may be what serves.
	if touched {
		if rerr := restoreRoutes(context.WithoutCancel(ctx), r, log, cfg, o, nil, was); rerr != nil {
			return fmt.Errorf("%w\nputting the routes back failed too (%v), so %s may be serving and is left running; "+
				"run `%s` again or check `boks proxy list` — the operation stays open in the journal", err, rerr, name, l.again)
		}
	}
	if !discard(context.WithoutCancel(ctx), r, log, cfg.App, name) {
		err = fmt.Errorf("%w\n%s could not be confirmed removed: it routes nothing, and the next deploy retires it", err, name)
	}
	finish(ctx, r, log, cfg.App, op.id, "failed", o.Now())
	return err
}

// replaceStopFirst stops the copies that are running, starts the new one and waits for it to come
// up: by its own health check without routes, by every port's health check through the proxy with
// them, so no route moves before the new copy answers. When it never comes up, it is removed and the
// stopped copies are brought back — and only those: a container left stopped by an earlier deploy
// must stay stopped, or a failed deploy would end with two copies where there was one. The routes
// still dial the stopped copies (or are put back on them), so they serve again as they come back.
// The server's admission is held until the app is settled one way or the other, because until then
// its memory is in flux: the old copies' share is free, the new copy's is not yet taken.
func replaceStopFirst(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, l launch, o Options,
	op operation, adm *admission, name string, live []string, was []proxy.Route) error {
	defer adm.release(ctx)
	// Cleanup runs to the end even when the run is cancelled: a half-done revival is how two copies,
	// or none, end up running.
	cleanup := context.WithoutCancel(ctx)
	stopped, err := stopAll(ctx, r, log, live)
	if err == nil && len(stopped) > 0 {
		// Measured again, now that the old copies are down: what they gave back is a fact, not the
		// estimate the first check went by.
		if err = checkMemory(ctx, r, log, cfg, nil); err != nil {
			err = fmt.Errorf("%w\nthis was measured after the old copies stopped, so they are being started again", err)
		}
	}
	if err != nil {
		err = errors.Join(err, revive(cleanup, r, log, stopped))
		finish(ctx, r, log, cfg.App, op.id, "failed", o.Now())
		return err
	}
	routed := len(cfg.Ports) > 0
	touched := false
	err = l.start(ctx, name)
	if err == nil && routed {
		// Before the probe: the proxy reaches the new copy only over the app's network.
		err = joinProxy(ctx, r, log, cfg)
	}
	if err == nil {
		if routed {
			if err = awaitReady(ctx, r, log, cfg, name, o.Poll); err == nil {
				touched, err = switchRoutes(ctx, r, log, cfg, name, o, adm)
			}
		} else {
			err = waitHealthy(ctx, r, log, cfg, name, o.Poll)
		}
	}
	if err == nil {
		return nil
	}
	// Routes that may have reached the new copy go back to the stopped ones before anything else: the
	// new copy is not removed while it may be what they dial, and the old ones are not started beside
	// a copy that may still serve — two copies at once is what this mode exists to prevent.
	if touched {
		if rerr := restoreRoutes(cleanup, r, log, cfg, o, adm, was); rerr != nil {
			return fmt.Errorf("%w\nputting the routes back failed too (%v), so %s is left running and %v stopped rather than risk two copies at once; "+
				"run `%s` again or check `boks proxy list` — the operation stays open in the journal", err, rerr, name, stopped, l.again)
		}
	}
	// A failed `docker run` may still have created the container, and a failed stop may have left it
	// running. The old copy comes back only once the new one is verifiably gone; otherwise both would
	// run at once. The entry closes only after the cleanup, so a run cut during it stays visibly
	// unfinished.
	if !discard(cleanup, r, log, cfg.App, name) {
		finish(ctx, r, log, cfg.App, op.id, "failed", o.Now())
		return fmt.Errorf("%w\n%s could not be confirmed removed, so %v were left stopped rather than risk two copies running at once: remove it, then `docker start` them",
			err, name, stopped)
	}
	err = errors.Join(err, revive(cleanup, r, log, stopped))
	finish(ctx, r, log, cfg.App, op.id, "failed", o.Now())
	return err
}

// unrecorded reports a deploy whose new version is up but could not be written down. Retiring the
// previous containers would then delete the last trace of what ran before, while the server's
// memory still names that release as current; they stay until a deploy is recorded.
func unrecorded(err error, again, name string, old []container) error {
	return fmt.Errorf("the new version %s is up, but boks could not record it: %w\n"+
		"the previous containers %v were not removed; run `%s` again to record a release", name, err, names(old), again)
}

// keptOld reports a deploy whose new version is up but whose old routes could not be removed. The
// previous containers are not retired: a route left over then reaches a container that still exists,
// rather than one this deploy deleted.
func keptOld(err error, again string, old []container) error {
	return fmt.Errorf("the new version is up, but removing the app's routes from the proxy failed: %w\n"+
		"the previous containers %v were not removed, so no route points at a deleted container; "+
		"check `boks proxy list` and run `%s` again",
		err, names(old), again)
}

// discard stops and removes a container and reports whether it is verifiably gone. The stop comes
// first so the copy shuts down gracefully; `rm -f` makes sure it goes even if the stop did not.
//
// The name is this run's, but container names are not unique across apps (`a` with tag `b-v1` and
// `a-b` with tag `v1` share one), so a container under it that another app labelled is that app's:
// this run's `docker run` lost the name to it and created nothing, and it is left alone.
func discard(ctx context.Context, r remote.Runner, log io.Writer, app, name string) bool {
	owner, there, err := nameOwner(ctx, r, name)
	if err != nil {
		return false
	}
	// This run's container always carries this app's label from the moment it exists, so one that
	// does not was never this run's.
	if there && owner != app {
		fmt.Fprintf(log, "%s belongs to %q, not to this deploy, and is left alone\n", name, owner)
		return true
	}
	fmt.Fprintf(log, "remove %s\n", name)
	best(ctx, r, log, "docker", "stop", name)
	best(ctx, r, log, "docker", "rm", "-f", name)
	_, there, err = nameOwner(ctx, r, name)
	return err == nil && !there
}

// nameOwner says whether a container is named exactly name and which app labelled it. The name
// filter is a regular expression and tags keep their dots, so it is quoted, and only the line naming
// exactly name is read.
func nameOwner(ctx context.Context, r remote.Runner, name string) (owner string, there bool, err error) {
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "name=^"+regexp.QuoteMeta(name)+"$", "--format", "{{.Names}}\t{{.Label \"boks.app\"}}")
	if err != nil {
		return "", false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if n, o, _ := strings.Cut(strings.TrimSpace(line), "\t"); n == name {
			return strings.TrimSpace(o), true, nil
		}
	}
	return "", false, nil
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
		"health check, so add a healthcheck block to boks.yml (or a HEALTHCHECK to the image), or publish a port", cfg.Image)
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

// stopAll stops the running copies before a new one starts, and returns the ones it touched. The
// stop is the guarantee that two copies never run at once, not cleanup: a copy that did not stop,
// or did not confirm it stopped, keeps the new one from starting. `docker stop` returns once the
// container is down, and its state says so; an answer other than "not running" is not taken as one.
// The copy that failed is among those returned: `docker start` of a container that is still running
// is a no-op, so it is safe to bring back with the rest.
func stopAll(ctx context.Context, r remote.Runner, log io.Writer, live []string) ([]string, error) {
	var stopped []string
	for _, c := range live {
		fmt.Fprintf(log, "stop %s\n", c)
		stopped = append(stopped, c)
		if _, err := r.Run(ctx, "docker", "stop", c); err != nil {
			// A failed call does not say the stop failed: the connection can drop after docker took it,
			// and the container goes on shutting down. Bringing it back then would be a `docker start`
			// that does nothing while it still runs, and it would die right after. Asked again, `docker
			// stop` waits for that shutdown to end — and if it says so, the stop happened after all.
			if _, again := r.Run(ctx, "docker", "stop", c); again != nil {
				return stopped, fmt.Errorf("could not stop %s, so the new version was not started: %w", c, err)
			}
		}
		if up, err := isRunning(ctx, r, c); err != nil || up {
			return stopped, fmt.Errorf("%s was not confirmed stopped (%v), so the new version was not started", c, stateOf(up, err))
		}
	}
	return stopped, nil
}

// isRunning asks docker whether container c is running; an answer other than true or false is an error.
func isRunning(ctx context.Context, r remote.Runner, c string) (bool, error) {
	out, err := r.Run(ctx, "docker", "container", "inspect", "--format", "{{.State.Running}}", c)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(out) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("unexpected state %q", out)
}

func stateOf(up bool, err error) string {
	if err != nil {
		return err.Error()
	}
	if up {
		return "still running"
	}
	return "not running"
}

// revive restarts the containers that were stopped to make room for a deploy that then failed, and
// says which of them are not running afterwards: one `docker start` that returned is not a copy
// that is back.
func revive(ctx context.Context, r remote.Runner, log io.Writer, stopped []string) error {
	var down []string
	for _, c := range stopped {
		fmt.Fprintf(log, "restart %s\n", c)
		best(ctx, r, log, "docker", "start", c)
		if up, err := isRunning(ctx, r, c); err != nil || !up {
			down = append(down, c)
		}
	}
	if len(down) > 0 {
		return fmt.Errorf("%v did not come back up: check them with `docker ps -a` and `docker start` them", down)
	}
	return nil
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
		if err := checkLegacyVolume(ctx, r, cfg.App, cfg.App+"-"+name, volumeName(cfg.App, name)); err != nil {
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

// volumeName joins an app and one of its volumes. A dot rather than a dash because both halves may
// contain dashes: `a-b` with volume `c` and `a` with volume `b-c` used to share one volume. The dot is
// not allowed in either half, so the join is unambiguous.
func volumeName(app, vol string) string { return app + "." + vol }

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

// beginOperation opens the journal entry and, on the way, says whether the previous one was ever
// closed. A deploy cut between switching routes and recording the release leaves no trace in
// docker — the journal is the only place that knows.
func beginOperation(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, action, to string, now time.Time) (operation, error) {
	// The open entry is closed as abandoned once reported: otherwise every later deploy, however
	// successful, would report the same interruption again.
	if open, err := release.Unfinished(ctx, r, cfg.App); err == nil && open != nil {
		fmt.Fprintf(log, "warning: %s of %s started %s and never finished; this run replaces it\n",
			open.Action, cfg.App, open.StartedAt.Format(time.RFC3339))
		finish(ctx, r, log, cfg.App, open.Op, "abandoned", now)
	}
	from, err := release.Current(ctx, r, cfg.App)
	if err != nil {
		return operation{}, err
	}
	id, err := release.Begin(ctx, r, cfg.App, action, from, to, now)
	return operation{id: id, from: from}, err
}

// operation is an open journal entry, and the release that was serving when it began.
type operation struct{ id, from string }

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
func record(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name, tag string, op operation, env []byte,
	files []release.File, now time.Time) error {
	digest, err := digestOf(ctx, r, cfg.Image, tag)
	if err != nil {
		return err
	}
	snapshot := release.Snapshot{
		ID: name, App: cfg.App, Image: cfg.Image, Tag: tag, Digest: digest,
		Ports: cfg.Ports, Volumes: cfg.Volumes, TLS: cfg.TLS, Networks: cfg.Networks(), Uses: cfg.Uses,
		EnvPath: envFile(cfg.App, name, env), Memory: cfg.Memory, Replace: cfg.ReplaceMode(),
		Healthcheck: cfg.Healthcheck, Files: files, Command: cfg.Command, StopSignal: cfg.StopSignal,
		Previous: op.from, CreatedAt: now,
	}
	if cfg.Cert != nil {
		snapshot.CertDomains = cfg.Cert.Domains
	}
	snapshot.Schedules = cfg.Schedules
	// The commands exist before the snapshot names them, as everything a snapshot refers to does.
	if err := writeJobs(ctx, r, cfg.App, name, cfg.Schedules); err != nil {
		return err
	}
	if err := release.Save(ctx, r, snapshot); err != nil {
		return err
	}
	if err := serving(ctx, r, cfg.App, name, name, op.id, now); err != nil {
		return err
	}
	pruneReleases(ctx, r, log, cfg, name)
	return nil
}

// pruneReleases applies keep to the recorded releases once current is id. A failure costs disk,
// not the operation.
func pruneReleases(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, id string) {
	if err := release.Prune(ctx, r, cfg.App, id, cfg.Keep); err != nil {
		fmt.Fprintf(log, "warning: could not prune old releases: %v\n", err)
	}
}

// serving points `current` at release id and closes the operation that put it there, in that order,
// so an interruption between the two leaves the release named and the operation visibly open.
func serving(ctx context.Context, r remote.Runner, app, id, container, op string, now time.Time) error {
	if err := release.SetCurrent(ctx, r, app, id); err != nil {
		return fmt.Errorf("mark %s as current: %w", id, err)
	}
	// What a scheduled job reads to find the copy to run in: the release and its container together.
	if err := release.SetServing(ctx, r, app, id, container); err != nil {
		return fmt.Errorf("record the serving copy %s: %w", container, err)
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

// unlock ends a run's hold on the app. The run has already given the admission lock back.
func unlock(ctx context.Context, r remote.Runner, log io.Writer, app string) {
	if _, err := r.Run(ctx, "rmdir", lockPath(app)); err != nil {
		fmt.Fprintf(log, "warning: could not release %s: %v\n", lockPath(app), err)
	}
}

// Unlock clears the app's deploy lock, and the server's admission lock when this app holds it: a
// deploy that died while admitting its container leaves both behind. Admission held by another app
// is left alone.
func Unlock(ctx context.Context, r remote.Runner, app string) error {
	freed, admErr := unlockAdmission(ctx, r, app)
	if admErr != nil {
		admErr = fmt.Errorf("could not check the admission lock %s: %w", admitLock, admErr)
	}
	_, err := r.Run(ctx, "rmdir", lockPath(app))
	// No app lock at all is fine when the admission lock was what was stale — but only an answer
	// from the server says the app lock is absent; a failed connection does not.
	if err != nil && admErr == nil && freed {
		if out, e := r.Run(ctx, "sh", "-c", "test -e "+lockPath(app)+" && echo present || echo absent"); e == nil && strings.TrimSpace(out) == "absent" {
			return nil
		}
	}
	return errors.Join(err, admErr)
}

// missing reports an image that is not on the server. A rollback runs an image the server is meant
// to have kept; one that was pruned is fetched before anything is stopped, rather than by `docker
// run` while a stop-first app is down — or not at all, with the app already down, if the registry is.
//
// Only docker's own "No such image" counts: an inspect that failed for another reason (a dropped
// connection, a daemon hiccup) says nothing about the image, and pulling then would fail a rollback
// during a registry outage — the usual time for one — whose image is on the server all along.
func missing(ctx context.Context, r remote.Runner, ref string) bool {
	q := remote.Quote(ref)
	out, err := r.Run(ctx, "sh", "-c", "out=$(docker image inspect --format '{{.Id}}' "+q+" 2>&1) && echo present || "+
		"case \"$out\" in *'No such image'*) echo absent;; *) echo unknown;; esac")
	return err == nil && strings.TrimSpace(out) == "absent"
}

// pull is the one place an app's image is fetched, for a deploy and for a rollback alike. An image on
// the private registry goes through the login; any other — a public image, or a release recorded
// before the image moved — is pulled as it always was.
func pull(ctx context.Context, r remote.Runner, log io.Writer, ref string, enabled bool, login *Login) error {
	if !enabled {
		return nil
	}
	if login != nil && login.Logs(ref) {
		fmt.Fprintf(log, "pull %s (logged in to %s for the pull)\n", ref, login.Host)
		return pullWithLogin(ctx, r, login, ref)
	}
	fmt.Fprintf(log, "pull %s\n", ref)
	_, err := r.Run(ctx, "docker", "pull", ref)
	return err
}

// container is a previously deployed container of this app: its name, and the two labels that say
// how it must be replaced.
type container struct {
	name string
	// routeless is a copy whose `boks.ports` label records an empty list — one started on the
	// routeless path. A copy without the label (started by an older boks) may have been one, and is
	// not taken for one.
	routeless bool
	// replace is the mode its release asks for, from its `boks.replace` label; empty on a copy
	// started before the label existed.
	replace string
}

// asksStopFirst reports whether this copy must not run beside the one replacing it. A copy without
// the label was started by a boks that had no stop-first for routed apps, so its shape is what
// decided: one started without routes was stopped first, one with them overlapped.
func (c container) asksStopFirst() bool {
	if c.replace != "" {
		return c.replace == config.ReplaceStopFirst
	}
	return c.routeless
}

func anyStopFirst(cs []container) bool {
	for _, c := range cs {
		if c.asksStopFirst() {
			return true
		}
	}
	return false
}

func containers(ctx context.Context, r remote.Runner, app string) ([]container, error) {
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "label=boks.app="+app,
		// `.Label "k"` looks a key up; `.Labels` is the flat comma-joined string and cannot be indexed.
		"--format", "{{.Names}}\t{{.Label \"boks.ports\"}}\t{{.Label \"boks.replace\"}}")
	if err != nil {
		return nil, err
	}
	var cs []container
	for _, line := range strings.Split(out, "\n") {
		name, rest, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if name == "" {
			continue
		}
		label, replace, _ := strings.Cut(rest, "\t")
		var ports []config.Port
		routeless := json.Unmarshal([]byte(label), &ports) == nil && ports != nil && len(ports) == 0
		cs = append(cs, container{name: name, routeless: routeless, replace: strings.TrimSpace(replace)})
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

// portLabel stores the whole port spec. A later deploy reads only whether the list is empty — a copy
// without routes asks for stop-first when it predates the replace label — but the spec costs nothing
// and says on the container itself what it was started to serve.
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

func start(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name, tag string, env []byte, files []config.FileContent) error {
	envPath := envFile(cfg.App, name, env)
	if envPath != "" {
		if err := remote.Upload(ctx, r, env, envPath); err != nil {
			return err
		}
	}
	if err := uploadFiles(ctx, r, cfg.App, name, files); err != nil {
		return err
	}
	binds, err := mounts(ctx, r, cfg.App, name, fileRecords(files))
	if err != nil {
		return err
	}
	return run(ctx, r, log, cfg, name, tag, cfg.Image+":"+tag, envPath, binds)
}

// fileRecords is what a release records of the files it mounts.
func fileRecords(files []config.FileContent) []release.File {
	var out []release.File
	for _, f := range files {
		out = append(out, release.File{Name: f.Name, Target: f.Target})
	}
	return out
}

// uploadFiles writes a release's files into a directory of its own, so a later deploy never
// changes what an earlier release reads. The directories keep the owner-only mode every boks write
// has, which keeps the files from other users of the server; the files themselves are readable by
// all, because the container reads them as whatever user its image runs as, and a bind-mounted
// file is checked against its own mode, not against the directories above it on the host.
func uploadFiles(ctx context.Context, r remote.Runner, app, id string, files []config.FileContent) error {
	if len(files) == 0 {
		return nil
	}
	chmod := []string{"chmod", "0644"}
	for _, f := range files {
		p := path.Join(release.FilesDir(app, id), f.Name)
		if err := remote.UploadAtomic(ctx, r, f.Body, p); err != nil {
			return err
		}
		chmod = append(chmod, p)
	}
	if _, err := r.Run(ctx, chmod...); err != nil {
		return fmt.Errorf("making the files of %s readable to the container: %w", id, err)
	}
	return nil
}

// mounts are the `docker run -v` arguments for a release's files. Docker takes a bind source only
// as an absolute path — a relative one reads as a volume name — and the release's directory lives
// under the SSH user's home, so it is resolved on the server.
func mounts(ctx context.Context, r remote.Runner, app, id string, files []release.File) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	dir := release.FilesDir(app, id)
	abs, err := r.Run(ctx, "sh", "-c", "cd "+remote.Quote(dir)+" && pwd -P")
	if err != nil {
		return nil, fmt.Errorf("resolving %s on the server: %w", dir, err)
	}
	// The colon separates the parts of -v; a home directory with one in it cannot be written there.
	if !strings.HasPrefix(abs, "/") || strings.Contains(abs, ":") {
		return nil, fmt.Errorf("%s resolves to %q, which docker cannot mount", dir, abs)
	}
	var out []string
	for _, f := range files {
		out = append(out, abs+"/"+f.Name+":"+f.Target+":ro")
	}
	return out, nil
}

// run starts container name from image ref, labelled as version tag of the app cfg describes.
func run(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name, tag, ref, envPath string, binds []string) error {
	fmt.Fprintf(log, "run %s\n", name)
	nets := cfg.Networks()
	if len(nets) == 1 {
		_, err := r.Run(ctx, runArgs(cfg, name, tag, ref, envPath, binds)...)
		return err
	}
	// `docker run` attaches one network; the others are joined before the container starts, or the
	// app would start unable to reach the apps it uses, and fail or retry on its own schedule.
	_, err := r.Run(ctx, append([]string{"docker", "create"}, runOptions(cfg, name, tag, ref, envPath, binds)...)...)
	if err == nil {
		if err = joinAll(ctx, r, name, nets[1:]); err == nil {
			_, err = r.Run(ctx, "docker", "start", name)
		}
	}
	if err != nil {
		// No route reaches the copy yet, so it goes: left behind, it would be one more copy that
		// stop-first must not revive. A failed create may still have created it — the answer can be
		// lost after docker acted — and discard leaves alone a container under the name that another
		// app labelled.
		discard(context.WithoutCancel(ctx), r, log, cfg.App, name)
	}
	return err
}

func joinAll(ctx context.Context, r remote.Runner, name string, nets []config.Network) error {
	for _, n := range nets {
		a := []string{"docker", "network", "connect"}
		for _, alias := range n.Aliases {
			a = append(a, "--alias", alias)
		}
		if _, err := r.Run(ctx, append(a, n.Name, name)...); err != nil {
			return fmt.Errorf("joining network %s: %w", n.Name, err)
		}
	}
	return nil
}

func runArgs(cfg *config.Config, name, tag, ref, envPath string, binds []string) []string {
	return append([]string{"docker", "run", "-d"}, runOptions(cfg, name, tag, ref, envPath, binds)...)
}

// runOptions are what `docker run -d` and `docker create` take after the command: the options, the
// image, then the configured command, if any.
func runOptions(cfg *config.Config, name, tag, ref, envPath string, binds []string) []string {
	// The alias rides on the network the container starts on: it is how whoever shares that network
	// reaches the app, under a name that outlives this container.
	n := cfg.Networks()[0]
	a := []string{"--name", name, "--network", n.Name}
	for _, alias := range n.Aliases {
		a = append(a, "--network-alias", alias)
	}
	a = append(a, "--restart", "unless-stopped", "--label", "boks.app="+cfg.App, "--label", "boks.version="+tag,
		"--label", "boks.ports="+portLabel(cfg.Ports), "--label", "boks.replace="+cfg.ReplaceMode())
	if cfg.Memory != "" {
		a = append(a, "--memory", cfg.Memory)
	}
	if h := cfg.Healthcheck; h != nil {
		// The start period is the deploy's wait: docker calls a copy unhealthy after three failed checks
		// in a row — 15s at the default interval — and waitHealthy gives up on the first unhealthy, so
		// without it a copy that needs longer to come up than that would be refused well inside
		// deploy_timeout. Failures inside the period do not count; the first success still ends it.
		// Inside the period docker checks at its own start interval, 5s unless told, which would put the
		// first check past a deploy_timeout under 5s; it is the configured interval instead.
		a = append(a, "--health-cmd", h.Cmd, "--health-interval", h.Interval,
			"--health-start-period", cfg.DeployTimeout, "--health-start-interval", h.Interval)
	}
	if cfg.StopSignal != "" {
		a = append(a, "--stop-signal", cfg.StopSignal)
	}
	if envPath != "" {
		a = append(a, "--env-file", envPath)
	}
	for _, v := range cfg.Volumes {
		vol, path, _ := strings.Cut(v, ":")
		a = append(a, "-v", volumeName(cfg.App, vol)+":"+path)
	}
	for _, b := range binds {
		a = append(a, "-v", b)
	}
	// An image on the private registry is fetched by pull alone, logged in. Left to itself, docker
	// would fetch one that went missing without the login — refused, or worse, let through by a login
	// some earlier run left behind.
	if cfg.Registry.Logs(ref) {
		a = append(a, "--pull", "never")
	}
	// The command follows the image, as `docker run IMAGE [COMMAND] [ARG...]` takes it.
	return append(append(a, ref), cfg.Command...)
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

// routesTo are the app's routes dialling container target: each port's host to the port the
// container listens on — its own, from the config it was started with, so a port whose number
// changed between releases moves with the switch.
func routesTo(cfg *config.Config, target string) []proxy.Route {
	var routes []proxy.Route
	for _, p := range cfg.Ports {
		rt := proxy.Route{Host: p.Host, Dial: fmt.Sprintf("%s:%d", target, p.Port), TLS: cfg.TLS}
		// Hosts outside the certificate keep the proxy's automatic HTTPS, so one app can mix a
		// wildcard with plain HTTP-01 domains.
		if cfg.Cert.Covers(p.Host) {
			crt, key := cert.ServerPaths(cfg.Cert)
			rt.Cert = &proxy.CertFiles{Certificate: crt, Key: key}
		}
		routes = append(routes, rt)
	}
	return routes
}

// defaultHealthPath is kamal-proxy's, so an app that relied on its default is checked the same way.
const defaultHealthPath = "/up"

// awaitReady waits, within deploy_timeout, until the new copy answers the health check of every port
// from inside the proxy — the network and the name its routes will dial. A port that answered once is
// not asked again. Nothing has moved while this runs, so a copy that never answers simply goes.
func awaitReady(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name string, poll time.Duration) error {
	if poll <= 0 {
		poll = time.Second
	}
	timeout, err := time.ParseDuration(cfg.DeployTimeout)
	if err != nil {
		return err
	}
	fmt.Fprintf(log, "waiting for %s to pass its health checks\n", name)
	deadline := time.Now().Add(timeout)
	pending := cfg.Ports
	for {
		var left []config.Port
		var last error
		for _, p := range pending {
			port, path := p.Port, p.HealthPath
			if p.HealthPort > 0 {
				port = p.HealthPort
			}
			if path == "" {
				path = defaultHealthPath
			}
			if err := proxy.Probe(ctx, r, name, port, path); err != nil {
				left, last = append(left, p), fmt.Errorf("port %s (%s:%d%s): %w", p.Name, name, port, path, err)
			}
		}
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not pass its health check within %s, so no route moved: %w", name, cfg.DeployTimeout, last)
		}
		pending = left
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// switchRoutes moves every route of the app to container name with one reload of the proxy, under
// the server's admission lock — adm when the caller holds it. It reports whether the proxy may now run
// the new routes, which a failed reload does not rule out. A reload re-reads every certificate file,
// so it is recorded as a load of this app's certificate.
func switchRoutes(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name string, o Options, adm *admission) (bool, error) {
	touched := false
	err := underAdmission(ctx, r, log, cfg.App, o, adm, func() error {
		fmt.Fprintf(log, "proxy: routes of %s → %s\n", cfg.App, name)
		reloaded, err := proxy.SetRoutes(ctx, r, log, cfg.App, routesTo(cfg, name))
		touched = reloaded
		if err == nil && reloaded && covered(cfg) {
			if merr := cert.MarkReloaded(ctx, r, cfg); merr != nil {
				fmt.Fprintf(log, "warning: could not record the loaded certificate: %v\n", merr)
			}
		}
		return err
	})
	return touched, err
}

// restoreRoutes puts the app's routes back to what the proxy served before this run, with a reload
// even when the files say nothing changed: the failed reload may have gone through.
func restoreRoutes(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, o Options, adm *admission, was []proxy.Route) error {
	fmt.Fprintf(log, "proxy: putting the routes of %s back\n", cfg.App)
	return underAdmission(ctx, r, log, cfg.App, o, adm, func() error {
		return proxy.RestoreRoutes(ctx, r, log, cfg.App, was)
	})
}

// underAdmission runs fn under the server's admission lock: adm when the caller holds it, otherwise
// taken for fn alone.
func underAdmission(ctx context.Context, r remote.Runner, log io.Writer, app string, o Options, adm *admission, fn func() error) error {
	if adm != nil && adm.held {
		return fn()
	}
	a, err := admit(ctx, r, log, app, o)
	if err != nil {
		return err
	}
	defer a.release(ctx)
	return fn()
}

// drain waits, up to drain_timeout, for the proxy to finish the requests it holds to the copies the
// routes left: after a reload Caddy's previous server goes on with them, and a copy stopped under them
// would cut them off. kamal-proxy drained the same way. A proxy that cannot say is waited out to the
// bound: stopping early is the outcome the wait exists to prevent.
func drain(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, was []proxy.Route, poll time.Duration) {
	if len(was) == 0 {
		return
	}
	if poll <= 0 {
		poll = time.Second
	}
	timeout, err := time.ParseDuration(cfg.DrainTimeout)
	if err != nil || timeout <= 0 {
		return
	}
	var dials []string
	for _, rt := range was {
		dials = append(dials, rt.Dial)
	}
	deadline := time.Now().Add(timeout)
	for {
		n, err := proxy.Busy(ctx, r, dials)
		if err == nil && n == 0 {
			return
		}
		if time.Now().After(deadline) {
			if err != nil {
				fmt.Fprintf(log, "warning: the proxy could not say what it still holds for the previous copies (%v); waited %s\n", err, cfg.DrainTimeout)
			} else {
				fmt.Fprintf(log, "warning: %d requests to the previous copies still in flight after %s; they go now\n", n, cfg.DrainTimeout)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
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
