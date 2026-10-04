// Package proxy drives kamal-proxy running as the container boks-proxy on a server.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/remote"
)

const (
	Container    = "boks-proxy"
	ConfigVolume = "boks-proxy-config"
	CertsVolume  = "boks-certs"
	// Network is the proxy's own network, the one it is started on. Apps are not on it: each has its
	// own, and the proxy joins those of the apps it routes to (Connect). A proxy started by an earlier
	// boks may sit on another network, the one apps shared then, and is left there.
	Network    = "boks"
	configPath = "/home/kamal-proxy/.config/kamal-proxy"
)

// Service is one kamal-proxy route: host → target, with the health check the proxy
// waits for before switching traffic.
type Service struct {
	Name       string
	Target     string
	Host       string
	TLS        bool
	CertPath   string // set for a DNS-01 certificate; empty leaves TLS to kamal-proxy's autocert
	KeyPath    string
	HealthPath string
	HealthPort int
	Timeout    string
	Force      bool // install without waiting for the target's health check
}

// NameSep joins an app and one of its ports into a service name, and the app with a volume name.
// A dot rather than a dash because both halves may contain dashes: `a-b` with port `c` and `a`
// with port `b-c` used to produce the same service, and the second deploy took the route of the
// first. The dot is not allowed in either half, so the join is unambiguous.
const NameSep = "."

func ServiceName(app, port string) string {
	return app + NameSep + port
}

// Owns reports whether a proxy service carries this app's name. Services named by boks before the
// dot (`app-port`) do not, and are recognised by their targets instead (see Listed.Targets).
func Owns(app, service string) bool {
	return strings.HasPrefix(service, app+NameSep)
}

// Listed is what kamal-proxy reports about one service: the hosts it holds and the
// `container:port` targets it sends them to.
type Listed struct {
	Hosts   []string `json:"hosts"`
	Targets []string `json:"targets"`
}

// Services returns the services kamal-proxy currently holds, keyed by name, with the names sorted
// alongside so callers act on them in a stable order.
func Services(ctx context.Context, r remote.Runner) (map[string]Listed, []string, error) {
	out, err := r.Run(ctx, "docker", "exec", Container, "kamal-proxy", "list", "--json")
	if err != nil {
		return nil, nil, err
	}
	var services map[string]Listed
	if err := json.Unmarshal([]byte(out), &services); err != nil {
		return nil, nil, fmt.Errorf("reading the proxy service list: %w", err)
	}
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	return services, names, nil
}

// State is the proxy container's Docker state — `running`, `exited`, … — or "" when there is none.
func State(ctx context.Context, r remote.Runner) (string, error) {
	return containerState(ctx, r)
}

func containerState(ctx context.Context, r remote.Runner) (string, error) {
	return r.Run(ctx, "docker", "ps", "-a", "--filter", "name=^"+Container+"$", "--format", "{{.State}}")
}

func Remove(ctx context.Context, r remote.Runner, service string) error {
	_, err := r.Run(ctx, "docker", "exec", Container, "kamal-proxy", "remove", service)
	return err
}

// NoForwardHeaders makes kamal-proxy overwrite X-Forwarded-For with the connection's address, and
// X-Forwarded-Proto and -Host with the request's own scheme and host, instead of keeping what the
// visitor sent. kamal-proxy keeps them by default on a route without TLS, and apps take the first
// XFF address as the visitor's, so a forged header would slip past bans and IP-bound tokens.
// Nothing trusted stands in front of boks, so every route gets it, with TLS or without. Every
// deploy of a route passes the flag anew: kamal-proxy does not carry options over from the route
// it replaces.
const NoForwardHeaders = "--forward-headers=false"

func DeployArgs(s Service) []string {
	a := []string{"docker", "exec", Container, "kamal-proxy", "deploy", s.Name,
		"--target", s.Target, "--host", s.Host, NoForwardHeaders}
	if s.TLS {
		a = append(a, "--tls")
	}
	if s.CertPath != "" {
		a = append(a, "--tls-certificate-path", s.CertPath, "--tls-private-key-path", s.KeyPath)
	}
	if s.HealthPath != "" {
		a = append(a, "--health-check-path", s.HealthPath)
	}
	if s.HealthPort > 0 {
		a = append(a, "--health-check-port", strconv.Itoa(s.HealthPort))
	}
	if s.Timeout != "" {
		a = append(a, "--deploy-timeout", s.Timeout)
	}
	if s.Force {
		a = append(a, "--force")
	}
	return a
}

func RunArgs(image string) []string {
	return []string{"docker", "run", "-d", "--name", Container, "--restart", "unless-stopped",
		"--network", Network, "-p", "80:80", "-p", "443:443",
		"-v", ConfigVolume + ":" + configPath, "-v", CertsVolume + ":/certs", image}
}

// Boot makes sure the proxy's network exists, the proxy container is running and it is on the
// networks its routes need. Idempotent. It changes state every app on the server shares — the proxy
// and its networks — so the caller holds the server's admission lock, the one lock all of them take.
func Boot(ctx context.Context, r remote.Runner, log io.Writer, image string) error {
	if err := ensureNetwork(ctx, r, log); err != nil {
		return err
	}
	state, err := containerState(ctx, r)
	if err != nil {
		return err
	}
	switch state {
	case "running":
	case "":
		fmt.Fprintf(log, "proxy: starting %s (%s)\n", Container, image)
		_, err = r.Run(ctx, RunArgs(image)...)
	default:
		fmt.Fprintf(log, "proxy: container is %s, starting it\n", state)
		_, err = r.Run(ctx, "docker", "start", Container)
	}
	if err != nil {
		return err
	}
	if state != "running" {
		if err := awaitAnswer(ctx, r); err != nil {
			return err
		}
	}
	return reattach(ctx, r, log)
}

// reattach puts the proxy on the networks of the containers its routes target that it is not on.
// The routes outlive a removed proxy in its config volume, its networks do not: a new container is
// on Network alone, and every route to an app on its own network — or on the network apps shared
// before — would answer 502 until that app is deployed again. It runs on every boot, so a boot cut
// short between creating the proxy and joining is finished by the next. A route whose target is
// gone has no network to join and costs a warning; any other failure is the boot's, because a route
// to a container that runs and cannot be reached is an outage the boot would otherwise report as a
// success.
func reattach(ctx context.Context, r remote.Runner, log io.Writer) error {
	on, err := networks(ctx, r)
	if err != nil {
		return err
	}
	services, names, err := Services(ctx, r)
	if err != nil {
		return fmt.Errorf("reading the proxy's routes to put it on their networks: %w", err)
	}
	seen, joined := map[string]bool{}, map[string]bool{Network: true}
	for _, n := range on {
		joined[n] = true
	}
	for _, n := range names {
		for _, t := range services[n].Targets {
			c, _, _ := strings.Cut(t, ":")
			if seen[c] {
				continue
			}
			seen[c] = true
			nets, gone, err := targetNetworks(ctx, r, c)
			if err != nil {
				return fmt.Errorf("route %s targets %s, whose networks could not be read: %w", n, c, err)
			}
			if gone {
				fmt.Fprintf(log, "warning: route %s targets %s, which is gone; deploying its app again repairs the route\n", n, c)
				continue
			}
			for _, net := range nets {
				if joined[net] {
					continue
				}
				if err := Connect(ctx, r, log, net); err != nil {
					return fmt.Errorf("route %s cannot reach %s: %w", n, c, err)
				}
				joined[net] = true
			}
		}
	}
	return nil
}

// targetNetworks are the networks container c is attached to. Only docker's own answer that there is
// no such container counts as gone; any other failure is an error.
func targetNetworks(ctx context.Context, r remote.Runner, c string) ([]string, bool, error) {
	out, err := r.Run(ctx, "sh", "-c", "out=$(docker container inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "+
		remote.Quote(c)+" 2>&1) && echo \"$out\" || case \"$out\" in *'No such container'*|*'No such object'*) echo '<gone>';; "+
		"*) echo \"$out\" >&2; exit 1;; esac")
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(out) == "<gone>" {
		return nil, true, nil
	}
	return strings.Fields(out), false, nil
}

// awaitAnswer waits for a proxy that was just started to open its command socket: the deploy
// asks it for its services right away, and a container that is up is not yet a proxy that answers.
func awaitAnswer(ctx context.Context, r remote.Runner) error {
	// The bound covers the calls themselves, not only the pauses between them: a call that hangs
	// past it is cancelled.
	ctx, cancel := context.WithTimeout(ctx, answerWait)
	defer cancel()
	for {
		_, err := r.Run(ctx, "docker", "exec", Container, "kamal-proxy", "list")
		if err == nil && ctx.Err() == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the proxy was started but did not answer within %s: %w", answerWait, errors.Join(err, ctx.Err()))
		case <-time.After(answerPoll):
		}
	}
}

var answerWait, answerPoll = 10 * time.Second, 250 * time.Millisecond

// ensureNetwork creates the proxy's network unless it already exists. Idempotent.
func ensureNetwork(ctx context.Context, r remote.Runner, log io.Writer) error {
	if _, err := r.Run(ctx, "docker", "network", "inspect", Network); err == nil {
		return nil
	}
	fmt.Fprintf(log, "creating network %s\n", Network)
	_, err := r.Run(ctx, "docker", "network", "create", Network)
	return err
}

// On reports whether the proxy is attached to network; no proxy is attached to none.
func On(ctx context.Context, r remote.Runner, network string) (bool, error) {
	on, err := networks(ctx, r)
	return slices.Contains(on, network), err
}

// networks are the networks the proxy is attached to.
func networks(ctx context.Context, r remote.Runner) ([]string, error) {
	out, err := r.Run(ctx, "docker", "container", "ls", "-a", "--filter", "name=^"+Container+"$", "--format", "{{.Networks}}")
	if err != nil {
		return nil, fmt.Errorf("checking the proxy's networks: %w", err)
	}
	return strings.Split(strings.TrimSpace(out), ","), nil
}

// Connect attaches the proxy to an app's network, so that it can reach the containers it routes
// to by name. The proxy joins only the networks of apps whose routes it holds: an app is reached
// through the proxy, not the proxy through every app.
func Connect(ctx context.Context, r remote.Runner, log io.Writer, network string) error {
	fmt.Fprintf(log, "proxy: joining network %s\n", network)
	_, err := r.Run(ctx, "docker", "network", "connect", network, Container)
	return err
}

// Disconnect detaches the proxy from the network of an app it no longer routes to.
func Disconnect(ctx context.Context, r remote.Runner, log io.Writer, network string) error {
	fmt.Fprintf(log, "proxy: leaving network %s\n", network)
	_, err := r.Run(ctx, "docker", "network", "disconnect", network, Container)
	return err
}

func List(ctx context.Context, r remote.Runner) (string, error) {
	return r.Run(ctx, "docker", "exec", Container, "kamal-proxy", "list")
}
