package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/kopandante/boks/internal/remote"
)

// asideName is the proxy container an upgrade set aside, kept until the new one answers.
const asideName = Container + ".old"

// Image is the image the proxy container was created from; "" when there is no proxy.
func Image(ctx context.Context, r remote.Runner) (string, error) {
	out, err := r.Run(ctx, "sh", "-c", "docker inspect -f '{{.Config.Image}}' "+Container+" 2>/dev/null || true")
	return strings.TrimSpace(out), err
}

// Upgrade replaces the running proxy with one created from image — what `boks proxy upgrade` does,
// since a boot leaves a running proxy alone. It is a short outage on 80 and 443, open WebSockets
// included: stop, swap, start. Everything that can refuse does so before the stop: a swap an earlier
// run left cut, a deploy of some app in progress (its reload would meet no proxy), an image that does
// not pull, a config the new Caddy refuses. Then begin is called with the image the proxy runs, and
// an error from it stops the upgrade with nothing touched. After the stop, any failure puts the old
// container back and starts it. The caller holds the server's admission lock.
func Upgrade(ctx context.Context, r remote.Runner, log io.Writer, image string, begin func(from string) error) error {
	// First: a cut swap leaves the old proxy aside and, under the proxy's name, nothing, or a new one
	// that may never have started — whose image is the one asked for.
	if aside, err := exists(ctx, r, asideName); err != nil {
		return err
	} else if aside {
		return fmt.Errorf("%s is left from an upgrade that was cut short: if %s serves, remove it (`docker rm %s`); "+
			"otherwise put it back (`docker rm -f %s; docker rename %s %s; docker start %s`)",
			asideName, Container, asideName, Container, asideName, Container, Container)
	}
	state, kind, err := State(ctx, r)
	if err != nil {
		return err
	}
	switch {
	case state == "":
		return fmt.Errorf("there is no proxy on this server to upgrade; `boks proxy boot` starts one from %s", image)
	case kind != Kind:
		return NotCaddy()
	}
	current, err := Image(ctx, r)
	if err != nil {
		return err
	}
	if current == image {
		if state != "running" {
			return fmt.Errorf("the proxy is made from %s already, but is %s; `boks proxy boot` starts it", image, state)
		}
		fmt.Fprintf(log, "proxy: already runs %s\n", image)
		return nil
	}
	// A deploy holds its app's lock from start to end, and the admission lock only in part: its
	// reload, between two admissions, would find no proxy.
	busy, err := r.Run(ctx, "sh", "-c", "for d in /tmp/boks-*.lock; do [ -d \"$d\" ] && echo \"$d\"; done; true")
	if err != nil {
		return err
	}
	if b := strings.Fields(busy); len(b) > 0 {
		return fmt.Errorf("a deploy is in progress (%s); upgrade the proxy once it is done", strings.Join(b, ", "))
	}
	fmt.Fprintf(log, "pull %s\n", image)
	if _, err := r.Run(ctx, "docker", "pull", image); err != nil {
		return fmt.Errorf("%w; the proxy was not touched", err)
	}
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	// The new proxy loads the applied config when it starts: the one the fragments make, as a boot
	// would bring it, and one the new Caddy takes — asked of the new image before anything stops.
	if lagging, err := Lags(ctx, r, fs); err != nil {
		return err
	} else if lagging {
		if _, err := converge(ctx, r, log, fs, false, "the routes on the server"); err != nil {
			return fmt.Errorf("%w; the proxy was not touched", err)
		}
	}
	abs, err := stateDir(ctx, r)
	if err != nil {
		return err
	}
	if out, err := r.Run(ctx, "docker", "run", "--rm", "-v", DataVolume+":/data", "-v", CertsVolume+":/certs", "-v", abs+":"+mountDir+":ro",
		image, "caddy", "validate", "--config", inProxy(appliedPath())); err != nil {
		return fmt.Errorf("%s refuses the proxy's config, so the proxy was not touched: %w %s", image, err, strings.TrimSpace(out))
	}
	if err := begin(current); err != nil {
		return fmt.Errorf("%w; the proxy was not touched", err)
	}
	fmt.Fprintf(log, "proxy: replacing %s with %s — 80 and 443 are down until it answers\n", current, image)
	if _, err := r.Run(ctx, "docker", "stop", Container); err != nil {
		return putBack(ctx, r, current, fmt.Errorf("stopping the proxy: %w", err))
	}
	if _, err := r.Run(ctx, "docker", "rename", Container, asideName); err != nil {
		return putBack(ctx, r, current, fmt.Errorf("setting the proxy aside: %w", err))
	}
	if err := startNew(ctx, r, log, image, abs, fs); err != nil {
		return putBack(ctx, r, current, fmt.Errorf("the new proxy failed: %w", err))
	}
	if _, err := r.Run(ctx, "docker", "rm", "-v", asideName); err != nil {
		fmt.Fprintf(log, "warning: the old proxy %s could not be removed: %v\n", asideName, err)
	}
	fmt.Fprintf(log, "proxy: runs %s\n", image)
	return nil
}

// startNew creates the proxy from image, on the networks its routes dial, and waits for it to answer
// with the sysctl a lossless reload needs.
func startNew(ctx context.Context, r remote.Runner, log io.Writer, image, abs string, fs []Fragment) error {
	if _, err := r.Run(ctx, CreateArgs(image, abs)...); err != nil {
		return err
	}
	if err := reattach(ctx, r, log, fs); err != nil {
		return err
	}
	if _, err := r.Run(ctx, "docker", "start", Container); err != nil {
		return err
	}
	if err := awaitAnswer(ctx, r); err != nil {
		return err
	}
	return checkMigrateReq(ctx, r)
}

// putBack returns the old proxy to service after cause stopped the swap, from what the server holds
// rather than from the step that failed: an error over SSH does not prove docker did not act, so a
// stop or a rename may have gone through all the same. The old proxy aside means whatever stands
// under the proxy's name is the new one: removed, and the old one renamed back. Otherwise the old
// one is still under its name, and a stop whose reply was lost may still be under way — docker goes
// on with it, and a start meanwhile does nothing — so it is stopped to the end first. Then it is
// started and asked to answer.
func putBack(ctx context.Context, r remote.Runner, current string, cause error) error {
	ctx = context.WithoutCancel(ctx)
	restore := func() error {
		var stopErr error
		aside, err := exists(ctx, r, asideName)
		if err != nil {
			return err
		}
		if aside {
			if made, err := exists(ctx, r, Container); err != nil {
				return err
			} else if made {
				if _, err := r.Run(ctx, "docker", "rm", "-f", Container); err != nil {
					return err
				}
			}
			if _, err := r.Run(ctx, "docker", "rename", asideName, Container); err != nil {
				return err
			}
		} else {
			// Whether this stop fails too is told by whether the proxy answers once started.
			_, stopErr = r.Run(ctx, "docker", "stop", Container)
		}
		if _, err := r.Run(ctx, "docker", "start", Container); err != nil {
			return errors.Join(stopErr, err)
		}
		if err := awaitAnswer(ctx, r); err != nil {
			return errors.Join(stopErr, err)
		}
		return nil
	}
	if err := restore(); err != nil {
		return fmt.Errorf("%w; putting the old proxy back failed too: %v — see `docker ps -a --filter name=%s`, "+
			"then `docker rm -f %s; docker rename %s %s; docker start %s` if %s is there", cause, err, Container,
			Container, asideName, Container, Container, asideName)
	}
	return fmt.Errorf("%w; %s serves again", cause, current)
}

// exists says whether a container is named exactly name.
func exists(ctx context.Context, r remote.Runner, name string) (bool, error) {
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "name=^"+regexp.QuoteMeta(name)+"$", "--format", "{{.Names}}")
	if err != nil {
		return false, fmt.Errorf("looking for %s: %w", name, err)
	}
	return strings.TrimSpace(out) != "", nil
}
