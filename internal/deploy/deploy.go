// Package deploy implements the boks deploy flow: pull → run → switch proxy → retire → prune.
package deploy

import (
	"context"
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
		revert(ctx, r, log, switched, old)
		return fmt.Errorf("%w\nnew container %s is left running for inspection; see the revert/warning lines above for where traffic goes now", err, name)
	}
	retire(ctx, r, log, old)
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

func containers(ctx context.Context, r remote.Runner, app string) ([]string, error) {
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "label=boks.app="+app, "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
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
		"--restart", "unless-stopped", "--label", "boks.app=" + cfg.App, "--label", "boks.version=" + tag}
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
// routes that had already moved when an error stopped it.
func switchProxy(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, name string) ([]proxy.Service, error) {
	var done []proxy.Service
	for _, p := range cfg.Ports {
		svc := service(cfg, name, p)
		fmt.Fprintf(log, "proxy %s → %s (%s)\n", svc.Name, svc.Target, p.Host)
		if _, err := r.Run(ctx, proxy.DeployArgs(svc)...); err != nil {
			return done, err
		}
		done = append(done, svc)
	}
	return done, nil
}

// revert moves routes that already reached the new container back to the previous one, so a
// failed multi-port switch does not leave the app split across two versions.
func revert(ctx context.Context, r remote.Runner, log io.Writer, switched []proxy.Service, old []string) {
	if len(switched) == 0 {
		return
	}
	if len(old) != 1 {
		fmt.Fprintf(log, "warning: %d route(s) already point at the new container and cannot be reverted automatically (previous containers: %v)\n", len(switched), old)
		return
	}
	for _, svc := range switched {
		_, port, _ := strings.Cut(svc.Target, ":")
		svc.Target = old[0] + ":" + port
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

// prune removes image tags beyond cfg.Keep, never the one just deployed.
// `docker images` lists newest first.
func prune(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, current string) {
	out, err := r.Run(ctx, "docker", "images", cfg.Image, "--format", "{{.Tag}}")
	if err != nil {
		fmt.Fprintf(log, "warning: could not list images: %v\n", err)
		return
	}
	kept := 1
	for _, t := range strings.Fields(out) {
		if t == current || t == "<none>" {
			continue
		}
		if kept < cfg.Keep {
			kept++
			continue
		}
		fmt.Fprintf(log, "prune %s:%s\n", cfg.Image, t)
		best(ctx, r, log, "docker", "rmi", cfg.Image+":"+t)
	}
}

// best runs a cleanup command whose failure must not fail the deploy.
func best(ctx context.Context, r remote.Runner, log io.Writer, args ...string) {
	if _, err := r.Run(ctx, args...); err != nil {
		fmt.Fprintf(log, "warning: %v\n", err)
	}
}
