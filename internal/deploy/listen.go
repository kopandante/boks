package deploy

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// binding is a port docker has published on the host for a container, as its NetworkSettings.Ports
// names it: docker writes every address as 0.0.0.0 and ::, and an empty HostIp is read the same way.
type binding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// checkListen refuses, changing nothing, a publication docker could not make: on an address none of
// the server's interfaces holds — docker would refuse it at `docker run`, after stop-first took the
// running copy down, and a WireGuard address is absent whenever the tunnel is down — or on a port that
// a running container of another owner already publishes there, on that address or on all of them.
// The app's own copies are not in the way: stop-first stops them before the new one starts.
func checkListen(ctx context.Context, r remote.Runner, cfg *config.Config, boxes []box) error {
	if len(cfg.Listen) == 0 {
		return nil
	}
	held, err := hostAddrs(ctx, r)
	if err != nil {
		return err
	}
	for _, l := range cfg.Listen {
		a, err := l.ListenAddr()
		if err != nil {
			return fmt.Errorf("listen[%d]: %w", l.Port, err)
		}
		if _, ok := held[a]; !ok {
			return fmt.Errorf("listen[%d]: %s is not an address of this server (its private addresses by `ip -o addr`: %s): docker could not publish on it — "+
				"check servers in boks.yml, or bring the interface up (WireGuard: `systemctl start wg-quick@wg0`); nothing was changed",
				l.Port, a, listAddrs(held))
		}
		for _, b := range boxes {
			if !b.running || b.owner == cfg.App {
				continue
			}
			if on := b.publishes(a, l.Published()); on != "" {
				return fmt.Errorf("listen[%d]: %s already publishes %s, and it belongs to %s, not to %s: one host port takes one container; "+
					"nothing was changed", l.Port, b.name, on, b.owner, cfg.App)
			}
		}
	}
	return nil
}

// publishes is how b holds port on address a, written as docker shows it, or "" when it does not:
// on a itself, or on every address — which takes a's port too.
func (b box) publishes(a netip.Addr, port int) string {
	for spec, bs := range b.ports {
		if !strings.HasSuffix(spec, "/tcp") {
			continue
		}
		for _, p := range bs {
			if p.HostPort != strconv.Itoa(port) {
				continue
			}
			ip, err := netip.ParseAddr(p.HostIP)
			if p.HostIP == "" || (err == nil && (ip.IsUnspecified() || ip.Unmap() == a)) {
				host := p.HostIP
				if host == "" {
					host = "0.0.0.0"
				}
				return host + ":" + p.HostPort
			}
		}
	}
	return ""
}

// hostAddrs are the addresses on the server's interfaces, each with its interface, from `ip -o addr`.
func hostAddrs(ctx context.Context, r remote.Runner) (map[netip.Addr]string, error) {
	out, err := r.Run(ctx, "ip", "-o", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("listing the server's addresses for listen: %w", err)
	}
	held := map[netip.Addr]string{}
	// 3: wg0    inet 10.88.0.5/24 scope global wg0\       valid_lft forever preferred_lft forever
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 2; i+1 < len(f); i++ {
			if f[i] != "inet" && f[i] != "inet6" {
				continue
			}
			if p, err := netip.ParsePrefix(f[i+1]); err == nil {
				held[p.Addr()] = f[1]
			}
			break
		}
	}
	return held, nil
}

// listAddrs writes the server's addresses listen could publish on, for an error, in a stable order.
func listAddrs(held map[netip.Addr]string) string {
	var out []string
	for a, dev := range held {
		if _, err := (config.Listen{Address: a.String()}).ListenAddr(); err == nil {
			out = append(out, a.String()+" on "+dev)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}
