package deploy

import (
	"context"
	"fmt"
	"io"
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

	if id == "" {
		previous, err := release.Previous(ctx, r, cfg.App)
		if err != nil {
			return err
		}
		if previous == "" {
			return fmt.Errorf("no earlier release of %s is recorded on this server; `boks releases` shows what there is", cfg.App)
		}
		id = previous
	}
	snapshot, err := release.Load(ctx, r, cfg.App, id)
	if err != nil {
		return fmt.Errorf("%w\n`boks releases` lists the release ids a rollback can return to", err)
	}
	// Without its environment file the release cannot be reproduced, only approximated. Known
	// before anything on the server changes, so the refusal leaves the running version alone.
	if snapshot.EnvPath != "" {
		if _, err := r.Run(ctx, "test", "-f", snapshot.EnvPath); err != nil {
			return fmt.Errorf("the environment file of release %s is gone (%s): it was pruned or removed, "+
				"so this release cannot be reproduced; deploy the tag again instead", snapshot.ID, snapshot.EnvPath)
		}
	}
	ref := snapshot.Reference()
	fmt.Fprintf(log, "rolling back to %s (%s)\n", snapshot.ID, ref)

	// The snapshot owns what belonged to the release; the current config still owns the server
	// side of things — which proxy image runs, how long a deploy may take, which certificate the
	// hosts are served with. Mixing them the other way would restore a release into a server that
	// no longer exists.
	target := *cfg
	target.Image = snapshot.Image
	target.Ports = snapshot.Ports
	target.Volumes = snapshot.Volumes
	if snapshot.Network != "" {
		target.Network = snapshot.Network
	}
	// Everything else — stopping an app without routes before its old copy comes back, the route
	// switch and its revert, the certificate checks — is what a deploy does, by the same code.
	return put(ctx, r, log, &target, launch{
		action: "rollback", tag: snapshot.Tag, ref: ref,
		start: func(ctx context.Context, name string) error {
			return run(ctx, r, log, &target, name, snapshot.Tag, ref, snapshot.EnvPath)
		},
		// The release being restored keeps its own identity: `current` points back at its snapshot
		// rather than at a copy under a new id, so a second rollback goes one step further back
		// instead of returning to the release this one just left.
		record: func(ctx context.Context, _, op string) error {
			return serving(ctx, r, cfg.App, snapshot.ID, op, o.Now())
		},
	}, o)
}
