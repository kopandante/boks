// Package deploy implements the boks deploy flow: pull → run → switch proxy → retire → prune.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/remote"
)

type Options struct {
	Pull bool
	Env  []byte
	Now  func() time.Time
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
	if err := proxy.Boot(ctx, r, log, cfg.Network, cfg.ProxyImage); err != nil {
		return err
	}
	if err := pull(ctx, r, log, cfg.Image+":"+tag, o.Pull); err != nil {
		return err
	}
	old, err := containers(ctx, r, cfg.App)
	if err != nil {
		return err
	}
	name := ContainerName(cfg.App, tag, o.Now())
	if err := start(ctx, r, log, cfg, name, tag, o.Env); err != nil {
		return err
	}
	switched, err := switchProxy(ctx, r, log, cfg, name)
	if err != nil {
		revert(ctx, r, log, cfg, switched, old)
		return fmt.Errorf("%w\nnew container %s is left running for inspection; see the revert/warning lines above for where traffic goes now", err, name)
	}
	retire(ctx, r, log, names(old))
	prune(ctx, r, log, cfg, tag)
	return nil
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
	envPath := ""
	if len(env) > 0 {
		envPath = fmt.Sprintf(".boks/%s/%s.env", cfg.App, name)
		if err := r.Upload(ctx, env, envPath); err != nil {
			return err
		}
	}
	fmt.Fprintf(log, "run %s\n", name)
	_, err := r.Run(ctx, runArgs(cfg, name, tag, envPath)...)
	return err
}

func runArgs(cfg *config.Config, name, tag, envPath string) []string {
	a := []string{"docker", "run", "-d", "--name", name, "--network", cfg.Network,
		"--restart", "unless-stopped", "--label", "boks.app=" + cfg.App, "--label", "boks.version=" + tag,
		"--label", "boks.ports=" + portLabel(cfg.Ports)}
	if envPath != "" {
		a = append(a, "--env-file", envPath)
	}
	for _, v := range cfg.Volumes {
		vol, path, _ := strings.Cut(v, ":")
		a = append(a, "-v", cfg.App+"-"+vol+":"+path)
	}
	return append(a, cfg.Image+":"+tag)
}

func service(cfg *config.Config, target string, p config.Port) proxy.Service {
	return proxy.Service{
		Name: proxy.ServiceName(cfg.App, p.Name), Target: fmt.Sprintf("%s:%d", target, p.Port), Host: p.Host,
		TLS: cfg.TLS, HealthPath: p.HealthPath, HealthPort: p.HealthPort, Timeout: cfg.DeployTimeout,
	}
}

// switchProxy points every route at the new container, one port at a time, and returns the
// ports whose routes had already moved when an error stopped it.
func switchProxy(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name string) ([]config.Port, error) {
	var done []config.Port
	for _, p := range cfg.Ports {
		svc := service(cfg, name, p)
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
func revert(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, switched []config.Port, old []container) {
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
		if recorded, ok := prev.ports[p.Name]; ok {
			recorded.Host = p.Host // the domain belongs to the route, not to the container
			target = recorded
		} else {
			fmt.Fprintf(log, "warning: %s has no record of port %q; reverting with the current config's %d — if that container listens elsewhere, the health check will refuse and the route stays on the new one\n",
				prev.name, p.Name, p.Port)
		}
		svc := service(cfg, prev.name, target)
		fmt.Fprintf(log, "revert %s → %s\n", svc.Name, svc.Target)
		best(ctx, r, log, proxy.DeployArgs(svc)...)
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
