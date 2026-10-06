// Package proxy drives Caddy running as the container boks-proxy on a server.
//
// A deploy moves traffic by reloading Caddy with a config whose routes dial the new copy by its
// container name, as kamal-proxy's targets did. A reload is graceful once the kernel hands the
// pending connections of the closing listener to the new one: measured on boks-lab (10 reloads under
// 40 connections, docs/plans/20261006-caddy.md), resets fell from 93 to 0 with
// net.ipv4.tcp_migrate_req=1, and clients with keep-alive saw no error at all. The proxy is started
// with that sysctl, and a boot refuses a proxy that does not have it.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

const (
	Container   = "boks-proxy"
	CertsVolume = "boks-certs"
	// Network is the proxy's own network, the one it is started on. Apps are not on it: each has its
	// own, and the proxy joins those of the apps it routes to (Connect).
	Network = "boks"
	// adminURL is Caddy's admin endpoint, inside the container only. By address, not as localhost:
	// busybox resolves localhost to ::1, and Caddy listens on 127.0.0.1 (measured, 2.11.7-alpine).
	adminURL = "http://127.0.0.1:2019"
	// migrateReq is the sysctl that makes a reload lose no connection: without it, connections waiting
	// in the accept queue of the listener a reload closes are reset.
	migrateReq = "net.ipv4.tcp_migrate_req"
)

// State is the proxy container's Docker state — `running`, `exited`, … or "" when there is none —
// and its boks.proxy label, Kind for the Caddy boks runs.
func State(ctx context.Context, r remote.Runner) (state, kind string, err error) {
	out, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "name=^"+Container+"$", "--format", "{{.State}}\t{{.Label \"boks.proxy\"}}")
	if err != nil {
		return "", "", err
	}
	state, kind, _ = strings.Cut(strings.TrimSpace(out), "\t")
	return strings.TrimSpace(state), strings.TrimSpace(kind), nil
}

// NotCaddy is the refusal on a server whose boks-proxy is the kamal-proxy an earlier boks ran.
func NotCaddy() error {
	return fmt.Errorf("%s on this server is not the Caddy this boks runs (an earlier boks ran kamal-proxy there): "+
		"run `boks proxy migrate` once to move its routes to Caddy", Container)
}

// Boot makes sure the proxy's network exists, the proxy container is running with the sysctl a
// lossless reload needs, and it is on the networks its routes dial into. Idempotent. It changes state
// every app on the server shares, so the caller holds the server's admission lock.
func Boot(ctx context.Context, r remote.Runner, log io.Writer, image string) error {
	if err := ensureNetwork(ctx, r, log); err != nil {
		return err
	}
	state, kind, err := State(ctx, r)
	if err != nil {
		return err
	}
	if state != "" && kind != Kind {
		return NotCaddy()
	}
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	if state == "running" {
		if err := checkMigrateReq(ctx, r); err != nil {
			return err
		}
		if err := reattach(ctx, r, log, fs); err != nil {
			return err
		}
		// A run cut after writing its fragment left the applied config behind the fragments: the proxy
		// catches up here, so `boks proxy boot` repairs it and a later restart loads the right config.
		// Not a condition of the boot: the proxy runs, and what Caddy refuses here — a certificate file a
		// cut `boks cert` left broken — `boks cert`, which boots first, is what repairs.
		if lagging, err := Lags(ctx, r, fs); err != nil || !lagging {
			return err
		}
		if _, err := converge(ctx, r, log, fs, false, "the routes on the server"); err != nil {
			fmt.Fprintf(log, "warning: the proxy may run an older config than the routes on the server say: %v\n", err)
		}
		return nil
	}
	// Caddy loads the applied config when it starts: the one the fragments make — on a server that
	// never had a proxy, one with no routes — and not one a cut run left behind.
	if _, err := converge(ctx, r, log, fs, false, "the routes on the server"); err != nil {
		return err
	}
	if state == "" {
		fmt.Fprintf(log, "proxy: starting %s (%s)\n", Container, image)
		if err := create(ctx, r, image); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(log, "proxy: container is %s, starting it\n", state)
	}
	// On its networks before it starts, so its first requests reach the copies its routes dial.
	if err := reattach(ctx, r, log, fs); err != nil {
		return err
	}
	if _, err := r.Run(ctx, "docker", "start", Container); err != nil {
		// A kernel older than 5.14 has no such sysctl, and docker refuses to start the container.
		return fmt.Errorf("starting the proxy (it needs %s, Linux 5.14 or newer): %w", migrateReq, err)
	}
	if err := awaitAnswer(ctx, r); err != nil {
		return err
	}
	return checkMigrateReq(ctx, r)
}

// checkMigrateReq refuses a proxy whose network namespace does not have the sysctl: every deploy
// reloads it, and without the sysctl each reload resets connections.
func checkMigrateReq(ctx context.Context, r remote.Runner) error {
	out, err := r.Run(ctx, "docker", "exec", Container, "cat", "/proc/sys/"+strings.ReplaceAll(migrateReq, ".", "/"))
	if err != nil {
		return fmt.Errorf("reading %s in the proxy: %w", migrateReq, err)
	}
	if strings.TrimSpace(out) != "1" {
		return fmt.Errorf("the proxy runs with %s=%s, not 1, so every deploy's reload would reset connections; "+
			"remove the container (`docker rm -f %s`) and boot the proxy again", migrateReq, strings.TrimSpace(out), Container)
	}
	return nil
}

// create makes the proxy container without starting it; the applied config it loads is in place.
func create(ctx context.Context, r remote.Runner, image string) error {
	// Docker takes a bind source only as an absolute path, and Dir lives under the SSH user's home.
	abs, err := r.Run(ctx, "sh", "-c", "cd "+remote.Quote(Dir)+" && pwd -P")
	if err != nil {
		return fmt.Errorf("resolving %s on the server: %w", Dir, err)
	}
	if !strings.HasPrefix(abs, "/") || strings.Contains(abs, ":") {
		return fmt.Errorf("%s resolves to %q, which docker cannot mount", Dir, abs)
	}
	_, err = r.Run(ctx, CreateArgs(image, abs)...)
	return err
}

// reattach puts the proxy on the networks of the containers its routes dial that it is not on. The
// routes outlive a removed proxy in Dir, its networks do not: a new container is on Network alone, and
// every route would answer 502 until its app is deployed again. It runs on every boot, so a boot cut
// short between creating the proxy and joining is finished by the next. A route whose container is
// gone has no network to join and costs a warning; any other failure is the boot's, because a route to
// a container that runs and cannot be reached is an outage the boot would otherwise report as a success.
func reattach(ctx context.Context, r remote.Runner, log io.Writer, fs []Fragment) error {
	on, err := networks(ctx, r)
	if err != nil {
		return err
	}
	seen, joined := map[string]bool{}, map[string]bool{}
	for _, n := range on {
		joined[n] = true
	}
	for _, f := range fs {
		for _, rt := range f.Routes {
			c, _, _ := strings.Cut(rt.Dial, ":")
			if seen[c] {
				continue
			}
			seen[c] = true
			nets, gone, err := targetNetworks(ctx, r, c)
			if err != nil {
				return fmt.Errorf("the route of %s dials %s, whose networks could not be read: %w", rt.Host, c, err)
			}
			if gone {
				fmt.Fprintf(log, "warning: the route of %s dials %s, which is gone; deploying %s again repairs it\n", rt.Host, c, f.App)
				continue
			}
			for _, net := range nets {
				if joined[net] {
					continue
				}
				if err := Connect(ctx, r, log, net); err != nil {
					return fmt.Errorf("the route of %s cannot reach %s: %w", rt.Host, c, err)
				}
				joined[net] = true
			}
		}
	}
	return nil
}

// targetNetworks are the networks through which the proxy reaches container c: its app's own network
// when it is on one, since the others are the networks of apps it uses, and the proxy joins only the
// networks of what it routes to; otherwise — a copy started by an earlier boks on the network apps
// shared — all of them. Only docker's own answer that there is no such container counts as gone; any
// other failure is an error.
func targetNetworks(ctx context.Context, r remote.Runner, c string) ([]string, bool, error) {
	out, err := r.Run(ctx, "sh", "-c", "out=$(docker container inspect --format '{{index .Config.Labels \"boks.app\"}}|{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "+
		remote.Quote(c)+" 2>&1) && echo \"$out\" || case \"$out\" in *'No such container'*|*'No such object'*) echo '<gone>';; "+
		"*) echo \"$out\" >&2; exit 1;; esac")
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(out) == "<gone>" {
		return nil, true, nil
	}
	// The label comes first and may be empty; a bar parts it from the networks, since the runner trims
	// the line and a space would vanish with an empty label.
	app, list, _ := strings.Cut(strings.TrimSpace(out), "|")
	nets := strings.Fields(list)
	if own := config.AppNetwork(app); app != "" && slices.Contains(nets, own) {
		return []string{own}, false, nil
	}
	return nets, false, nil
}

// awaitAnswer waits for a proxy that was just started to answer on its admin endpoint, which it does
// once it has loaded its config: a container that is up is not yet a proxy that routes.
func awaitAnswer(ctx context.Context, r remote.Runner) error {
	// The bound covers the calls themselves, not only the pauses between them: a call that hangs past
	// it is cancelled.
	ctx, cancel := context.WithTimeout(ctx, answerWait)
	defer cancel()
	for {
		_, err := r.Run(ctx, "docker", "exec", Container, "wget", "-q", "-O", "/dev/null", adminURL+"/config/")
		if err == nil && ctx.Err() == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the proxy was started but did not answer within %s (`docker logs %s` says why — "+
				"a certificate file its routes name and the server lacks stops it): %w", answerWait, Container, errors.Join(err, ctx.Err()))
		case <-time.After(answerPoll):
		}
	}
}

var answerWait, answerPoll = 10 * time.Second, 250 * time.Millisecond

// Probe asks, from inside the proxy, whether a container answers on port at path: over the network
// and by the name the route will dial. It passes on a final status in 2xx, after redirects, as
// kamal-proxy's health check did; its 5s timeout is kamal-proxy's too. busybox wget's exit status is
// not that rule (measured, 2.11.7-alpine: a 207 exits 1, a 302 without Location exits 0), so the
// status is read from the response it prints.
func Probe(ctx context.Context, r remote.Runner, target string, port int, healthPath string) error {
	url := "http://" + target + ":" + strconv.Itoa(port) + healthPath
	out, err := r.Run(ctx, "docker", "exec", Container, "sh", "-c", "wget -S -q -O /dev/null -T 5 "+remote.Quote(url)+" 2>&1; true")
	if err != nil {
		return err
	}
	status := 0
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && strings.HasPrefix(f[0], "HTTP/") {
			status, _ = strconv.Atoi(f[1])
		}
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("%s answered %s", url, strings.TrimSpace(out))
	}
	return nil
}

// Busy says how many requests the proxy has in flight to these containers, on any port. After a
// reload the previous config's server finishes the requests it holds, and they count here until it
// does: a container that is not listed, or lists none, has nothing left to drain.
func Busy(ctx context.Context, r remote.Runner, containers []string) (int, error) {
	out, err := r.Run(ctx, "docker", "exec", Container, "wget", "-q", "-O", "-", adminURL+"/reverse_proxy/upstreams")
	if err != nil {
		return 0, fmt.Errorf("asking the proxy for its requests in flight: %w", err)
	}
	var ups []struct {
		Address     string `json:"address"`
		NumRequests int    `json:"num_requests"`
	}
	if err := json.Unmarshal([]byte(out), &ups); err != nil {
		return 0, fmt.Errorf("reading the proxy's requests in flight: %w", err)
	}
	n := 0
	for _, u := range ups {
		if c, _, _ := strings.Cut(u.Address, ":"); slices.Contains(containers, c) {
			n += u.NumRequests
		}
	}
	return n, nil
}

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
