package deploy

import (
	"context"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

// Rollback returns an app to a release the server recorded, not to whatever a tag means today.
// The difference is the point of the release journal: a tag can be overwritten and the current
// config can have changed its ports, volumes or environment since — the snapshot holds what
// actually ran, so this reproduces it instead of approximating it.
//
// id is empty for "the release before the current one", which is what a rollback usually means.
func Rollback(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, id string, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := lock(ctx, r, cfg.App); err != nil {
		return err
	}
	defer unlock(context.WithoutCancel(ctx), r, log, cfg.App)

	id, snapshot, err := reproducible(ctx, r, cfg, id)
	if err != nil {
		return err
	}
	ref := snapshot.Reference()
	fmt.Fprintf(log, "rolling back to %s (%s)\n", id, ref)

	target := restored(cfg, snapshot)
	if snapshot.Version < 3 {
		fmt.Fprintf(log, "warning: release %s was recorded when every app shared one network; it comes back on %s under the alias %s, "+
			"not on %q, the network it ran on\n", id, config.AppNetwork(cfg.App), cfg.App, snapshot.Network)
	}
	if cfg.Memory != "" && target.Memory == "" {
		fmt.Fprintf(log, "warning: release %s was recorded without a memory limit, so it runs without one and without the memory check; "+
			"today's config asks for %s\n", id, cfg.Memory)
	}
	if cfg.MemoryReservation != "" && target.MemoryReservation == "" && target.Memory != "" {
		fmt.Fprintf(log, "warning: release %s was recorded without a memory_reservation, so it runs without that soft limit, "+
			"and the memory check counts its whole limit %s, not the %s today's config reserves\n", id, target.Memory, cfg.MemoryReservation)
	}
	// The release runs as it was recorded, not with today's command: say so when that falls back to
	// the image's own. The command itself is not printed — it can carry a secret.
	if len(cfg.Command) > 0 && len(target.Command) == 0 {
		fmt.Fprintf(log, "warning: release %s was recorded without a command, so it runs the image's own CMD, not the one in today's config\n", id)
	}
	if cfg.StopSignal != "" && target.StopSignal == "" {
		fmt.Fprintf(log, "warning: release %s was recorded without a stop_signal, so it stops with the image's STOPSIGNAL, not %s\n", id, cfg.StopSignal)
	}
	if len(cfg.Listen) > 0 && len(target.Listen) == 0 {
		fmt.Fprintf(log, "warning: release %s was recorded without listen, so it publishes no port on the host, "+
			"and clients on other servers cannot reach it\n", id)
	}
	// Everything else — stopping an app without routes before its old copy comes back, the route
	// switch and putting the routes back on failure, the certificate checks — is what a deploy does, by the same code.
	return put(ctx, r, log, target, launch{
		action: "rollback", again: "boks rollback " + id, tag: snapshot.Tag, ref: ref,
		stopFirst: cfg.ReplaceMode() == config.ReplaceStopFirst,
		start: func(ctx context.Context, name string) error {
			// The files are the release's own copies, kept under its id, not this run's container name.
			binds, err := mounts(ctx, r, cfg.App, id, snapshot.Files)
			if err != nil {
				return err
			}
			return run(ctx, r, log, target, name, snapshot.Tag, ref, snapshot.EnvPath, binds)
		},
		// The release being restored keeps its own identity: `current` points back at its snapshot,
		// which still names the release it was deployed over, rather than at a copy under a new id.
		// So a second rollback goes one step further back instead of returning to the release this
		// one just left.
		record: func(ctx context.Context, name string, op operation) error {
			return serving(ctx, r, cfg.App, id, name, op.id, o.Now())
		},
		id: id,
	}, o)
}

// restored is what a rollback to snapshot runs with.
func restored(cfg *config.Config, snapshot *release.Snapshot) *config.Config {
	// The snapshot owns what belonged to the release; the current config still owns the server
	// side of things — which proxy image runs, how long a deploy may take, which certificate the
	// hosts are served with.
	target := *cfg
	target.Image = snapshot.Image
	target.Ports = snapshot.Ports
	target.Volumes = snapshot.Volumes
	// The networks are the release's: it comes back where it was, not where today's config would put
	// it. A snapshot from before version 3 ran on the network every app shared then; it comes back on
	// the app's own network, under the app's alias, because the alias is the app's name for whoever
	// reaches it, not a property of one release, and the shared network is what the alias replaced.
	target.Attach = snapshot.Networks
	// And so are the apps it used: their checks are the release's, not today's config's.
	target.Uses = snapshot.Uses
	// The limit is the release's too, absence included: a release recorded without one ran without one.
	// So is the reservation under it.
	target.Memory = snapshot.Memory
	target.MemoryReservation = snapshot.MemoryReservation
	// So is the health check: one the release did not record ran with the image's own.
	target.Healthcheck = snapshot.Healthcheck
	// And the command and stop signal: one the release did not record ran with the image's own.
	target.Command = snapshot.Command
	target.StopSignal = snapshot.StopSignal
	// And its schedules: cron follows the release that serves.
	target.Schedules = snapshot.Schedules
	// And the ports it published on the host: a release recorded without them published none.
	target.Listen = snapshot.Listen
	// The replace mode is the one field where the release and today's config both have a say, and
	// either asking for stop-first wins: the release may have written its volume with one writer, and
	// the config may say that it does now — overlapping on the word of either side alone could put two
	// writers on one volume. put adds the third voice, the copies running now. A version 1 snapshot
	// says nothing, and its shape decides.
	// The restored copy is labelled with the release's own mode, so the config's vote goes to put
	// separately rather than into the label.
	target.Replace = snapshot.Replace
	return &target
}

// CheckRollback says, changing nothing, which release a rollback to id (empty: to the previous
// release) would return this server to, or why it cannot. A command over several servers asks
// every one of them first, so that it does not leave the app split across two versions.
//
// The preliminary memory check is asked here too, with the copies that would be stopped: refused on
// a server further down the list, it would otherwise leave the servers before it rolled back. It is
// asked again, under the server's admission lock, when each server's turn comes.
func CheckRollback(ctx context.Context, r remote.Runner, cfg *config.Config, id string) (string, error) {
	id, snapshot, err := reproducible(ctx, r, cfg, id)
	if err != nil {
		return "", err
	}
	target := restored(cfg, snapshot)
	// A name already taken on the app's network would stop this server, so it is asked with the rest;
	// the container's own name is the run's, not known yet.
	if _, err := checkNetworks(ctx, r, target, ""); err != nil {
		return "", err
	}
	// A server still on kamal-proxy refuses whenever routes are involved — the release's, or the copies'
	// it would replace — as put does, so it is asked here with the rest.
	old, err := containers(ctx, r, cfg.App)
	if err != nil {
		return "", err
	}
	if len(target.Ports) > 0 || !allRouteless(old) {
		state, kind, err := proxy.State(ctx, r)
		if err != nil {
			return "", err
		}
		if state != "" && kind != proxy.Kind {
			return "", proxy.NotCaddy()
		}
	}
	if target.Memory == "" {
		return id, nil
	}
	var live []string
	if target.ReplaceMode() == config.ReplaceStopFirst || cfg.ReplaceMode() == config.ReplaceStopFirst || anyStopFirst(old) {
		if live, err = running(ctx, r, cfg.App); err != nil {
			return "", err
		}
	}
	if err := checkMemory(ctx, r, io.Discard, target, live); err != nil {
		return "", err
	}
	return id, nil
}

// reproducible resolves the release a rollback returns to and makes sure it can be run as it was.
// Without its environment file it could only be approximated, so that is a refusal — known
// before anything on the server changes, which leaves the running version alone.
func reproducible(ctx context.Context, r remote.Runner, cfg *config.Config, id string) (string, *release.Snapshot, error) {
	if id == "" {
		previous, err := release.Previous(ctx, r, cfg.App)
		if err != nil {
			return "", nil, err
		}
		if previous == "" {
			return "", nil, fmt.Errorf("no earlier release of %s is recorded on this server; `boks releases` shows what there is", cfg.App)
		}
		id = previous
	}
	snapshot, err := release.Load(ctx, r, cfg.App, id)
	if err != nil {
		return "", nil, fmt.Errorf("%w\n`boks releases` lists the release ids a rollback can return to", err)
	}
	if err := recordedNetworks(cfg.App, snapshot); err != nil {
		return "", nil, fmt.Errorf("release %s cannot be reproduced: %w", id, err)
	}
	// The health check is the release's and the wait is today's config's, and each passed validation
	// on its own: a recorded interval that today's deploy_timeout does not outlast would stop the
	// running copy for one that cannot answer in time.
	if h := snapshot.Healthcheck; h != nil {
		interval, _ := time.ParseDuration(h.Interval)
		if timeout, _ := time.ParseDuration(cfg.DeployTimeout); interval >= timeout {
			return "", nil, fmt.Errorf("release %s checks its health every %s, and deploy_timeout %s ends before the first check; "+
				"raise deploy_timeout to roll back to it", id, h.Interval, cfg.DeployTimeout)
		}
	}
	// The release's ports with today's TLS and certificate: a wildcard it served without TLS has no
	// certificate to be served with now.
	if err := restored(cfg, snapshot).CheckWildcards(); err != nil {
		return "", nil, fmt.Errorf("release %s cannot be served with today's TLS: %w", id, err)
	}
	// The release's publications meet today's servers here: an address belongs to one of them. And
	// they are checked as a deploy would check them, so a snapshot that names a public address —
	// damaged, or edited by hand — is not published past the firewall.
	if err := restored(cfg, snapshot).CheckListen(); err != nil {
		return "", nil, fmt.Errorf("release %s cannot be reproduced: %w", id, err)
	}
	// The reservation and the limit are checked together as a deploy checks them: docker refuses a
	// reservation above the limit only at `docker run`, after a stop-first rollback stopped the running
	// copy. A snapshot without a reservation is left as it ran.
	if snapshot.MemoryReservation != "" {
		if err := restored(cfg, snapshot).CheckMemory(); err != nil {
			return "", nil, fmt.Errorf("release %s cannot be reproduced: %w", id, err)
		}
	}
	// A connection that drops is not a missing file: only an answer from the server says it is gone.
	if snapshot.EnvPath != "" {
		out, err := r.Run(ctx, "sh", "-c", "test -f "+remote.Quote(snapshot.EnvPath)+" && echo present || true")
		if err != nil {
			return "", nil, fmt.Errorf("checking the environment file of release %s: %w", id, err)
		}
		if strings.TrimSpace(out) != "present" {
			return "", nil, fmt.Errorf("the environment file of release %s is gone (%s): it was pruned or removed, "+
				"so this release cannot be reproduced; deploy the tag again instead", id, snapshot.EnvPath)
		}
	}
	// The same for the files it mounted: without them the container would start on whatever the image
	// ships at those paths.
	if len(snapshot.Files) > 0 {
		gone, err := missingFile(ctx, r, release.FilesDir(cfg.App, id), snapshot.Files)
		if err != nil {
			return "", nil, fmt.Errorf("checking the files of release %s: %w", id, err)
		}
		if gone != "" {
			return "", nil, fmt.Errorf("a file of release %s is gone (%s): it was pruned or removed, "+
				"so this release cannot be reproduced; deploy the tag again instead", id, gone)
		}
	}
	if err := jobsPresent(ctx, r, cfg.App, id, snapshot.Schedules); err != nil {
		return "", nil, err
	}
	return id, snapshot, nil
}

// missingFile is the first of files absent from dir on the server, or "" when all are there.
func missingFile(ctx context.Context, r remote.Runner, dir string, files []release.File) (string, error) {
	var paths []string
	for _, f := range files {
		paths = append(paths, remote.Quote(path.Join(dir, f.Name)))
	}
	out, err := r.Run(ctx, "sh", "-c", "for f in "+strings.Join(paths, " ")+"; do [ -f \"$f\" ] || { echo \"$f\"; exit 0; }; done; echo present")
	if err != nil {
		return "", err
	}
	if out = strings.TrimSpace(out); out != "present" {
		return out, nil
	}
	return "", nil
}

// recordedNetworks checks that a snapshot's networks can be put back as recorded. From version 3 on
// a release names them: the app's own first, under the app's name, then one for each app it used,
// in that order. A snapshot naming others, fewer or more, or dropping the app's alias, was damaged or
// written by another boks — today's networks would restore what the release never ran with, and
// dropping some would restore less than it had.
func recordedNetworks(app string, s *release.Snapshot) error {
	if s.Version < 3 {
		if len(s.Uses) > 0 {
			return fmt.Errorf("its snapshot names apps it used (%v) but no networks, which no boks writes", s.Uses)
		}
		return nil
	}
	want := []string{config.AppNetwork(app)}
	for _, dep := range s.Uses {
		want = append(want, config.AppNetwork(dep))
	}
	got := make([]string, len(s.Networks))
	for i, n := range s.Networks {
		got[i] = n.Name
	}
	// On the networks of the apps it used the release took no alias: one there would answer to the
	// dependency's name beside the dependency.
	aliased := slices.ContainsFunc(s.Networks[min(1, len(s.Networks)):], func(n config.Network) bool { return len(n.Aliases) > 0 })
	if !slices.Equal(got, want) || !slices.Contains(s.Networks[0].Aliases, app) || aliased {
		return fmt.Errorf("its snapshot names the networks %v, and a release of %s using %v runs on %v, under the alias %s", s.Networks, app, s.Uses, want, app)
	}
	return nil
}
