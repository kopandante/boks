package deploy

import (
	"context"
	"fmt"
	"io"
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
		return err
	}
	fmt.Fprintf(log, "rolling back to %s (%s)\n", snapshot.ID, snapshot.Reference())

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

	if len(target.Ports) > 0 {
		if err := proxy.Boot(ctx, r, log, target.Network, target.ProxyImage); err != nil {
			return err
		}
	}
	old, err := containers(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	// Which service carries each port depends on what the proxy holds right now — read before
	// anything starts, exactly as a deploy does, so the switch follows the same rename plan.
	var routes held
	var plan map[string]string
	if len(target.Ports) > 0 {
		if routes, err = readRoutes(ctx, r, &target, names(old)); err != nil {
			return err
		}
		if plan, err = routes.plan(&target); err != nil {
			return err
		}
	}
	name := ContainerName(cfg.App, snapshot.Tag, o.Now())
	op, err := beginOperation(ctx, r, log, cfg, "rollback", name, o.Now())
	if err != nil {
		return err
	}
	if err := startRelease(ctx, r, log, &target, snapshot, name); err != nil {
		finish(ctx, r, log, cfg.App, op, "failed", o.Now())
		return err
	}
	if len(target.Ports) == 0 {
		if err := waitHealthy(ctx, r, log, &target, name, o.Poll); err != nil {
			best(ctx, r, log, "docker", "stop", name)
			best(ctx, r, log, "docker", "rm", name)
			finish(ctx, r, log, cfg.App, op, "failed", o.Now())
			return err
		}
	} else {
		switched, err := switchProxy(ctx, r, log, &target, name, plan)
		if err != nil {
			revert(ctx, r, log, &target, plan, switched, old)
			// The entry stays open, as on a deploy: the route that failed may still have switched.
			return fmt.Errorf("%w\nnew container %s is left running for inspection; the route that failed may still have switched to it, "+
				"so see the revert/warning lines above and `boks proxy list` for where traffic goes now — the operation stays open in the journal", err, name)
		}
		if err := settle(ctx, r, log, &target, name, plan, routes); err != nil {
			return keptOld(err, old)
		}
	}
	// The release being restored keeps its own identity: `current` points at the snapshot that is
	// serving again, so a second rollback goes one step further back rather than ping-ponging.
	restored := *snapshot
	restored.ID = name
	restored.CreatedAt = o.Now()
	if err := release.Save(ctx, r, restored); err != nil {
		fmt.Fprintf(log, "warning: could not record the restored release: %v\n", err)
	} else if err := release.SetCurrent(ctx, r, cfg.App, name); err != nil {
		fmt.Fprintf(log, "warning: could not mark %s as current: %v\n", name, err)
	}
	finish(ctx, r, log, cfg.App, op, "ok", o.Now())
	retire(ctx, r, log, names(old))
	return nil
}

// startRelease runs the container described by a snapshot: the image pinned by digest when there
// is one, and the environment file that belonged to that release rather than today's.
func startRelease(ctx context.Context, r remote.Runner, log io.Writer, target *config.Config, s *release.Snapshot, name string) error {
	if s.EnvPath != "" {
		if _, err := r.Run(ctx, "test", "-f", s.EnvPath); err != nil {
			return fmt.Errorf("the environment file of release %s is gone (%s): it was pruned or removed, "+
				"so this release cannot be reproduced; deploy the tag again instead", s.ID, s.EnvPath)
		}
	}
	fmt.Fprintf(log, "run %s\n", name)
	args := runArgs(target, name, s.Tag, s.EnvPath)
	args[len(args)-1] = s.Reference()
	_, err := r.Run(ctx, args...)
	return err
}
