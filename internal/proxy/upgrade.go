package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
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
// included: stop, swap, start. Everything that can refuse does so before the stop: a deploy of some
// app in progress (its reload would meet no proxy), an image that does not pull, a config the new
// Caddy refuses. After the stop, any failure puts the old container back and starts it. The caller
// holds the server's admission lock.
func Upgrade(ctx context.Context, r remote.Runner, log io.Writer, image string) error {
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
	aside, err := r.Run(ctx, "sh", "-c", "docker ps -aq --filter name=^"+asideName+"$")
	if err != nil {
		return err
	}
	if strings.TrimSpace(aside) != "" {
		return fmt.Errorf("%s is left from an upgrade that was cut short: if %s serves, remove it (`docker rm %s`); "+
			"otherwise put it back (`docker rm -f %s; docker rename %s %s; docker start %s`)",
			asideName, Container, asideName, Container, asideName, Container, Container)
	}
	current, err := Image(ctx, r)
	if err != nil {
		return err
	}
	if current == image {
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
	fmt.Fprintf(log, "proxy: replacing %s with %s — 80 and 443 are down until it answers\n", current, image)
	if _, err := r.Run(ctx, "docker", "stop", Container); err != nil {
		return fmt.Errorf("stopping the proxy: %w; run `docker start %s` if it is down", err, Container)
	}
	if _, err := r.Run(ctx, "docker", "rename", Container, asideName); err != nil {
		best := context.WithoutCancel(ctx)
		_, startErr := r.Run(best, "docker", "start", Container)
		return fmt.Errorf("setting the proxy aside: %w; it was started again", errors.Join(err, startErr))
	}
	if err := startNew(ctx, r, log, image, abs, fs); err != nil {
		back := context.WithoutCancel(ctx)
		_, rmErr := r.Run(back, "docker", "rm", "-f", Container)
		_, mvErr := r.Run(back, "docker", "rename", asideName, Container)
		_, startErr := r.Run(back, "docker", "start", Container)
		if restore := errors.Join(rmErr, mvErr, startErr); restore != nil {
			return fmt.Errorf("the new proxy failed: %w; putting the old one back failed too: %v — "+
				"`docker rename %s %s && docker start %s`", err, restore, asideName, Container, Container)
		}
		return fmt.Errorf("the new proxy failed, and %s serves again: %w", current, err)
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
