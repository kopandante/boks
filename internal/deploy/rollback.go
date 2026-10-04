package deploy

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
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

	// The snapshot owns what belonged to the release; the current config still owns the server
	// side of things — which proxy image runs and on which network, how long a deploy may take,
	// which certificate the hosts are served with. Mixing them the other way would restore a
	// release into a server that no longer exists: a container put on a network the proxy has
	// since left could not be reached by its own routes.
	target := *cfg
	target.Image = snapshot.Image
	target.Ports = snapshot.Ports
	target.Volumes = snapshot.Volumes
	// The limit is the release's too, absence included: a release recorded without one ran without one.
	target.Memory = snapshot.Memory
	// The replace mode is the one field where the release and today's config both have a say, and
	// either asking for stop-first wins: the release may have written its volume with one writer, and
	// the config may say that it does now — overlapping on the word of either side alone could put two
	// writers on one volume. put adds the third voice, the copies running now. A version 1 snapshot
	// says nothing, and its shape decides.
	target.Replace = ""
	if snapshot.Replace == config.ReplaceStopFirst || cfg.ReplaceMode() == config.ReplaceStopFirst {
		target.Replace = config.ReplaceStopFirst
	}
	// Everything else — stopping an app without routes before its old copy comes back, the route
	// switch and its revert, the certificate checks — is what a deploy does, by the same code.
	return put(ctx, r, log, &target, launch{
		action: "rollback", again: "boks rollback " + id, tag: snapshot.Tag, ref: ref,
		start: func(ctx context.Context, name string) error {
			return run(ctx, r, log, &target, name, snapshot.Tag, ref, snapshot.EnvPath)
		},
		// The release being restored keeps its own identity: `current` points back at its snapshot,
		// which still names the release it was deployed over, rather than at a copy under a new id.
		// So a second rollback goes one step further back instead of returning to the release this
		// one just left.
		record: func(ctx context.Context, _ string, op operation) error {
			if err := serving(ctx, r, cfg.App, id, op.id, o.Now()); err != nil {
				return err
			}
			pruneReleases(ctx, r, log, cfg, id)
			return nil
		},
	}, o)
}

// CheckRollback says, changing nothing, which release a rollback to id (empty: to the previous
// release) would return this server to, or why it cannot. A command over several servers asks
// every one of them first, so that it does not leave the app split across two versions.
func CheckRollback(ctx context.Context, r remote.Runner, cfg *config.Config, id string) (string, error) {
	id, _, err := reproducible(ctx, r, cfg, id)
	return id, err
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
	return id, snapshot, nil
}
