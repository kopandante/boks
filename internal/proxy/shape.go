package proxy

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/kopandante/boks/internal/remote"
)

// Shape is what of the proxy container the server's policy decides, and only a new container can
// change: the egress port it publishes beside 80 and 443, and the server's hosts file it resolves
// names through.
type Shape struct {
	EgressPort int
	HostsFile  string
}

// ShapeOf is the container p needs.
func ShapeOf(p Policy) Shape {
	if p.Egress == nil {
		return Shape{}
	}
	return Shape{EgressPort: p.Egress.Port, HostsFile: p.Egress.HostsFile}
}

// args are the docker create options of s. The hosts file is mounted with --mount, which refuses a
// source that is not there, where -v would make a directory of it and Caddy would resolve through
// nothing. The mount holds the file's inode: whoever keeps it writes it in place, not by replacing it.
func (s Shape) args() []string {
	var a []string
	if s.EgressPort != 0 {
		p := strconv.Itoa(s.EgressPort)
		a = append(a, "-p", p+":"+p)
	}
	if s.HostsFile != "" {
		a = append(a, "--mount", "type=bind,source="+s.HostsFile+",target=/etc/hosts,readonly")
	}
	return a
}

// shapeQuery reads the published ports and the hosts file of the proxy container.
const shapeQuery = `{{range $p, $b := .HostConfig.PortBindings}}{{$p}} {{end}}|{{range .Mounts}}{{if eq .Destination "/etc/hosts"}}{{.Source}}{{end}}{{end}}`

// currentShape is the shape of the proxy container as it was created.
func currentShape(ctx context.Context, r remote.Runner) (Shape, error) {
	out, err := r.Run(ctx, "docker", "inspect", "-f", shapeQuery, Container)
	if err != nil {
		return Shape{}, fmt.Errorf("reading the proxy's ports: %w", err)
	}
	ports, hosts, _ := strings.Cut(strings.TrimSpace(out), "|")
	var s Shape
	for _, p := range strings.Fields(ports) {
		n, _ := strconv.Atoi(strings.TrimSuffix(p, "/tcp"))
		if n != 80 && n != 443 && n != 0 {
			s.EgressPort = n
		}
	}
	s.HostsFile = hosts
	return s, nil
}

// appliedShape is the shape the policy on the server needs: what every path that creates the proxy
// creates it with — a boot, an upgrade — so none drops the egress port.
func appliedShape(ctx context.Context, r remote.Runner) (Shape, error) {
	p, err := ReadPolicy(ctx, r)
	return ShapeOf(p), err
}

// Reshape makes the running proxy the container next needs, before next is applied: a port is
// published, and a file mounted, only when the container is created. It is the swap of an upgrade with
// the image the proxy runs, and refuses as that does before anything stops — plus an image without the
// forward proxy, and a config with next that the running Caddy refuses. The new container loads the
// config the proxy runs now; the caller applies next after. A proxy that is not running is left to the
// boot that starts it, which creates it in the applied shape. The caller holds the admission lock.
func Reshape(ctx context.Context, r remote.Runner, log io.Writer, next Policy) error {
	want := ShapeOf(next)
	state, kind, err := State(ctx, r)
	if err != nil || state != "running" || kind != Kind {
		return err
	}
	have, err := currentShape(ctx, r)
	if err != nil || have == want {
		return err
	}
	if err := checkAside(ctx, r); err != nil {
		return err
	}
	image, err := Image(ctx, r)
	if err != nil {
		return err
	}
	if next.Egress != nil {
		mods, err := r.Run(ctx, "docker", "exec", Container, "caddy", "list-modules")
		if err != nil {
			return fmt.Errorf("asking the proxy for its modules: %w", err)
		}
		if !slices.Contains(strings.Fields(mods), "http.handlers.forward_proxy") {
			return fmt.Errorf("the proxy runs %s, which has no forward proxy; `boks proxy upgrade` with boks's own image first, then apply again", image)
		}
	}
	if err := checkIdle(ctx, r); err != nil {
		return err
	}
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	if err := loadSecret(ctx, r, &next); err != nil {
		return err
	}
	if err := validate(ctx, r, next, fs); err != nil {
		return fmt.Errorf("%w; the proxy was not touched", err)
	}
	abs, err := stateDir(ctx, r)
	if err != nil {
		return err
	}
	fmt.Fprintf(log, "proxy: creating %s again for the egress port and hosts file — 80 and 443 are down until it answers\n", Container)
	return swapProxy(ctx, r, log, image, image, abs, fs, want)
}

// validate asks the running Caddy whether it takes the config p and fs make, changing nothing.
func validate(ctx context.Context, r remote.Runner, p Policy, fs []Fragment) error {
	body, err := Config(p, fs)
	if err != nil {
		return err
	}
	if err := remote.UploadAtomic(ctx, r, body, checkPath()); err != nil {
		return err
	}
	if out, err := r.Run(ctx, "docker", "exec", Container, "caddy", "validate", "--config", inProxy(checkPath())); err != nil {
		return fmt.Errorf("the proxy refuses the config: %w %s", err, strings.TrimSpace(out))
	}
	return nil
}
