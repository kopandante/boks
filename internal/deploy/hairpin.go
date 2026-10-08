package deploy

// Hairpin: a container on a server reaching the apps that server's proxy serves, through the server's
// own address — an app calling its own public name (Convex Auth, the SSR of a Next.js site) once that
// name points at the server it runs on.
//
// Docker does not translate such a connection: its nat rules return for every bridge, so a connection
// from a container to a published port on one of the host's addresses goes to docker-proxy on the
// host, through the host's input chain. A firewall whose input drops by default drops it, and the
// container gets no answer at all (hb-*, 2026-10-08: every Convex's auth failed with "fetch failed").
// From the host itself the request goes through lo, so a curl on the server sees nothing wrong.
//
// `boks server apply` keeps an accept for it at the top of every input chain that drops by default,
// and EnsureHairpin is that step. A table of boks's own would not do: an accept in one base chain does
// not overrule a drop in another on the same hook. A rule put into the host's chain is gone when the
// host loads its firewall again, so where nftables.service loads it, a drop-in of that unit puts the
// rule back after every start, restart and reload. CheckHairpin is the test from the other side, run
// after a deploy: a request from a container on the app's network to each host the app serves with TLS.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/hostname"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

const (
	// hairpinComment marks boks's rule: the script inserts the rule into a chain that does not have it.
	hairpinComment = "boks hairpin"
	// hairpinRule accepts a container's connection to the proxy's ports on one of the server's own
	// addresses — whatever address: the public one a host's name resolves to, or any other. Every
	// network boks makes is a bridge named br-<id>.
	hairpinRule = `iifname "br-*" tcp dport { 80, 443 } fib daddr type local accept comment "` + hairpinComment + `"`
	// hairpinScript inserts the rule where it is missing; nftables.service runs it through hairpinDropIn
	// once it has loaded the firewall.
	hairpinScript = "/usr/local/lib/boks/hairpin.sh"
	hairpinDropIn = "/etc/systemd/system/nftables.service.d/boks-hairpin.conf"
)

// hairpinFacts reads, without changing anything, what EnsureHairpin decides on: key=value lines, the
// values of the files and nft's JSON in base64. Root is needed to list the firewall at all.
const hairpinFacts = `S=""; [ "$(id -u)" = 0 ] || S="sudo -n"
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
command -v nft >/dev/null || { echo nft=no; exit 0; }
echo nft=yes
echo "uid=$(id -u)"
if [ -n "$S" ] && ! $S true 2>/dev/null; then echo root=no; exit 0; fi
echo root=yes
c=$($S nft -j list chains) || exit 1
echo "chains=$(printf %s "$c" | base64 | tr -d '\n')"
echo "enabled=$(systemctl is-enabled nftables 2>/dev/null)"
echo "script=$($S cat ` + hairpinScript + ` 2>/dev/null | base64 | tr -d '\n')"
echo "dropin=$($S cat ` + hairpinDropIn + ` 2>/dev/null | base64 | tr -d '\n')"
echo "loaded=$(systemctl show -p DropInPaths --value nftables 2>/dev/null)"
`

// nftChain is a chain as `nft -j list chains` reports it; only base chains have a hook and a policy.
type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

func (c nftChain) String() string { return c.Family + " " + c.Table + " " + c.Name }

func chainNames(cs []nftChain) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.String()
	}
	return out
}

// hairpinFirewall is what hairpinFacts found.
type hairpinFirewall struct {
	nft, root bool
	// sudo is what root's commands are prefixed with.
	sudo []string
	// chains are the input chains that drop by default, the ones the rule goes into.
	chains []nftChain
	// iptables are such chains that iptables manages (ufw, iptables-persistent): nft's rules in them
	// would break iptables' view of its table, so they are the owner's to change. odd are chains whose
	// names boks does not write into a script.
	iptables, odd []nftChain
	// persist is whether nftables.service loads the firewall, so that its drop-in can keep the rule.
	persist        bool
	script, dropIn string
	// loaded is whether systemd has read the drop-in: a run cut between writing it and daemon-reload
	// leaves the file in place and the unit without it.
	loaded bool
}

// nftName is a name boks writes into the script as it is: nft's names are not limited to it, but every
// name a host's config is likely to use is.
var nftName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

func readHairpin(ctx context.Context, r remote.Runner) (hairpinFirewall, error) {
	var h hairpinFirewall
	out, err := r.Run(ctx, "sh", "-c", hairpinFacts)
	if err != nil {
		return h, err
	}
	seen := false
	var chainsJSON []byte
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		decoded := func() string {
			b, derr := base64.StdEncoding.DecodeString(v)
			err = errors.Join(err, derr)
			return string(b)
		}
		switch k {
		case "nft":
			seen, h.nft = true, v == "yes"
		case "uid":
			if v != "0" {
				h.sudo = []string{"sudo", "-n"}
			}
		case "root":
			h.root = v == "yes"
		case "enabled":
			h.persist = v == "enabled"
		case "chains":
			chainsJSON = []byte(decoded())
		case "script":
			h.script = decoded()
		case "dropin":
			h.dropIn = decoded()
		case "loaded":
			h.loaded = slices.Contains(strings.Fields(v), hairpinDropIn)
		}
	}
	if err != nil || !seen {
		return h, fmt.Errorf("could not read the server's firewall: %q", out)
	}
	if !h.root {
		return h, nil
	}
	var list struct {
		Nftables []struct {
			Chain *nftChain `json:"chain"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(chainsJSON, &list); err != nil {
		return h, fmt.Errorf("reading the server's nft chains: %w", err)
	}
	for _, e := range list.Nftables {
		c := e.Chain
		if c == nil || c.Hook != "input" || c.Policy != "drop" || !slices.Contains([]string{"ip", "ip6", "inet"}, c.Family) {
			continue
		}
		switch {
		case c.Family != "inet" && c.Table == "filter" && c.Name == "INPUT":
			h.iptables = append(h.iptables, *c)
		case !nftName.MatchString(c.Table) || !nftName.MatchString(c.Name):
			h.odd = append(h.odd, *c)
		default:
			h.chains = append(h.chains, *c)
		}
	}
	return h, nil
}

// unchanged says what of the firewall boks leaves to its owner although the rule belongs there: a chain
// iptables manages, a chain whose name boks does not write.
func (h hairpinFirewall) unchanged() []string {
	var out []string
	for _, c := range h.iptables {
		tool := map[string]string{"ip": "iptables", "ip6": "ip6tables"}[c.Family]
		out = append(out, fmt.Sprintf("%s drops by default and is %s', which boks does not edit: containers here do not reach the proxy "+
			"on this server's own addresses until it has `%s -I INPUT -i br+ -p tcp -m multiport --dports 80,443 -m addrtype --dst-type LOCAL -j ACCEPT`", c, tool, tool))
	}
	for _, c := range h.odd {
		out = append(out, fmt.Sprintf("%s drops by default and its name is not one boks writes; it needs `%s`", c, hairpinRule))
	}
	return out
}

// hairpinScriptFor is the script that inserts the rule into each of chains that does not have it, and
// fails if it could not: a chain gone from the host's config, say.
func hairpinScriptFor(chains []nftChain) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n# Written by `boks server apply`. Containers reach boks-proxy on this server's own addresses:\n" +
		"# Docker hands such a connection to docker-proxy on the host, and an input chain that drops by\n" +
		"# default would drop it. nftables.service runs this after it loads the firewall (" + hairpinDropIn + ").\n" +
		"PATH=\"$PATH:/usr/sbin:/sbin\"\nrc=0\n")
	for _, c := range chains {
		fmt.Fprintf(&b, "%s || { nft %s && echo %s; } || rc=1\n", hairpinIn(c), remote.Quote("insert rule "+c.String()+" "+hairpinRule),
			remote.Quote("inserted into "+c.String()))
	}
	b.WriteString("exit $rc\n")
	return b.String()
}

// hairpinIn is the shell test that chain c has boks's rule: the one the script asks before it inserts
// the rule, and `boks server status` before it says the rule is there.
func hairpinIn(c nftChain) string {
	return "nft list chain " + c.String() + " | grep -qF " + remote.Quote(`comment "`+hairpinComment+`"`)
}

const hairpinDropInBody = "# Written by `boks server apply`: puts boks's hairpin rule back each time this unit loads the firewall.\n" +
	"[Service]\nExecStartPost=-/bin/sh " + hairpinScript + "\nExecReload=-/bin/sh " + hairpinScript + "\n"

// EnsureHairpin has every input chain of the server that drops by default accept a container's
// connection to the proxy on the server's own addresses, and — where nftables.service loads the
// firewall — keeps it so through the unit's reloads and the server's reboots. What it cannot do —
// no root, a chain iptables manages, no unit to keep the rule — is said, not refused: the policy is
// applied either way, and CheckHairpin after a deploy is the test that fails.
//
// It changes what every app on the server shares, so it holds the server's admission lock, as the
// policy does: two applies at once would otherwise write the script through one temporary file.
func EnsureHairpin(ctx context.Context, r remote.Runner, log io.Writer, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	adm, err := admit(ctx, r, log, proxyHolder, o)
	if err != nil {
		return err
	}
	defer adm.release(ctx)
	return ensureHairpin(ctx, r, log)
}

// ensureHairpin is EnsureHairpin under an admission lock the caller holds: `boks server install` makes
// the server ready under its own.
func ensureHairpin(ctx context.Context, r remote.Runner, log io.Writer) error {
	h, err := readHairpin(ctx, r)
	if err != nil {
		return err
	}
	switch {
	case !h.nft:
		fmt.Fprintln(log, "firewall: no nft on this server; hairpin not checked")
		return nil
	case !h.root:
		fmt.Fprintln(log, "warning: firewall: no root or `sudo -n`, so its input chains were not read; "+
			"if one drops by default, containers here do not reach the proxy on this server's own addresses")
		return nil
	}
	for _, w := range h.unchanged() {
		fmt.Fprintf(log, "warning: firewall: %s\n", w)
	}
	if len(h.chains) == 0 {
		fmt.Fprintln(log, "firewall: no nft input chain drops by default; nothing to add")
		return nil
	}
	sudo := h.sudo
	body := hairpinScriptFor(h.chains)
	run := append(slices.Clone(sudo), "sh", "-c", body)
	if h.persist {
		if h.script != body {
			if err := writeRoot(ctx, r, sudo, []byte(body), hairpinScript, false); err != nil {
				return err
			}
		}
		if h.dropIn != hairpinDropInBody {
			if err := writeRoot(ctx, r, sudo, []byte(hairpinDropInBody), hairpinDropIn, false); err != nil {
				return err
			}
		}
		if h.dropIn != hairpinDropInBody || !h.loaded {
			if _, err := r.Run(ctx, append(slices.Clone(sudo), "systemctl", "daemon-reload")...); err != nil {
				return fmt.Errorf("reloading systemd for %s: %w", hairpinDropIn, err)
			}
		}
		// From its file, the one the unit runs: what runs now is what puts the rule back after a reload.
		run = append(slices.Clone(sudo), "sh", hairpinScript)
	}
	out, err := r.Run(ctx, run...)
	if err != nil {
		return fmt.Errorf("putting the hairpin rule into the firewall: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			fmt.Fprintf(log, "firewall: %s\n", line)
		}
	}
	fmt.Fprintf(log, "firewall: containers reach the proxy on this server's addresses (%s)\n", strings.Join(chainNames(h.chains), ", "))
	if !h.persist {
		fmt.Fprintln(log, "warning: firewall: nftables.service is not enabled, so nothing puts the rule back when the firewall is loaded again "+
			"or the server reboots; run `boks server apply` again after either")
	}
	return nil
}

// CheckHairpin asks, from a container on the app's network, for each host the app serves with TLS,
// sent to this server's own address — the one it leaves by (`ip route get`), which is the one a host
// whose DNS points at the server resolves to — with the host's name in SNI and Host. That is the path
// an app calling its own public name takes once the name points here, and it asks this server's proxy,
// whatever DNS says today: before the name moves here, and on a fleet whose DNS names another server.
// Any answer of the proxy passes: a status, or a TLS alert from a Caddy that has no certificate for
// the host yet. No answer — a timeout, a refusal — is an error naming what the container got.
//
// One container asks for every host, from the image of the server's proxy, which is there and has
// wget. wget's -T bounds a silence, not the download, so timeout bounds each request: a host that
// streams at / has printed its status by then.
func CheckHairpin(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	hosts := hairpinHosts(cfg)
	if len(hosts) == 0 {
		return nil
	}
	img, err := r.Run(ctx, "docker", "inspect", "-f", "{{.Image}}", proxy.Container)
	if err != nil {
		return fmt.Errorf("reading the proxy's image for the hairpin check: %w", err)
	}
	addr, err := serverAddress(ctx, r)
	if err != nil {
		return err
	}
	network := config.AppNetwork(cfg.App)
	args := []string{"docker", "run", "--rm", "--pull", "never", "--network", network}
	var script strings.Builder
	for _, h := range hosts {
		url := "https://" + h + "/"
		args = append(args, "--add-host", h+":"+addr)
		fmt.Fprintf(&script, "echo %s; timeout 20 wget --no-check-certificate -S -O /dev/null -T 5 %s 2>&1; ", remote.Quote(hairpinMark+url), remote.Quote(url))
	}
	script.WriteString("true")
	out, err := r.Run(ctx, append(args, "--entrypoint", "sh", strings.TrimSpace(img), "-c", script.String())...)
	if err != nil {
		return fmt.Errorf("running the hairpin check: %w", err)
	}
	got := map[string]string{}
	url := ""
	for _, line := range strings.Split(out, "\n") {
		if u, ok := strings.CutPrefix(strings.TrimSpace(line), hairpinMark); ok {
			url = u
			continue
		}
		got[url] += line + "\n"
	}
	var failed []string
	for _, h := range hosts {
		url := "https://" + h + "/"
		if proxyAnswered(got[url]) {
			fmt.Fprintf(log, "hairpin: %s answers a container on %s at %s\n", url, network, addr)
			continue
		}
		failed = append(failed, fmt.Sprintf("%s: %s", url, strings.Join(strings.Fields(got[url]), " ")))
	}
	if len(failed) > 0 {
		return fmt.Errorf("the release serves, but a container on %s gets no answer from this server's proxy at %s for:\n  %s\n"+
			"once a host's name points at this server, an app that calls it (Convex Auth, server-side rendering) fails the same way. "+
			"The server's firewall drops containers' connections to its own addresses: `boks server apply` puts the rule back",
			network, addr, strings.Join(failed, "\n  "))
	}
	return nil
}

// CheckRolledBackHairpin is CheckHairpin after a rollback: the hosts asked for are the ones the restored
// release serves — its own ports, under today's tls, as the rollback routed them — read from the release
// the server now records as current.
func CheckRolledBackHairpin(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	if !cfg.TLS {
		return nil
	}
	id, err := release.Current(ctx, r, cfg.App)
	if err != nil {
		return fmt.Errorf("reading the restored release for the hairpin check: %w", err)
	}
	snapshot, err := release.Load(ctx, r, cfg.App, id)
	if err != nil {
		return fmt.Errorf("reading the restored release for the hairpin check: %w", err)
	}
	return CheckHairpin(ctx, r, log, restored(cfg, snapshot))
}

// HairpinStatus says, changing nothing, whether containers on the server reach its proxy on its own
// addresses: whether each input chain that drops by default has boks's rule now — a `nft -f` run past
// nftables.service since the last apply takes it out — and whether the unit puts it back. A line that
// starts with "! " is one to act on.
func HairpinStatus(ctx context.Context, r remote.Runner) []string {
	h, err := readHairpin(ctx, r)
	switch {
	case err != nil:
		return []string{"! firewall: " + err.Error()}
	case !h.nft:
		return []string{"firewall: no nft on this server; hairpin not checked"}
	case !h.root:
		return []string{"! firewall: no root or `sudo -n`, so its input chains were not read: whether containers here reach the proxy " +
			"on this server's own addresses is not known"}
	}
	var lines []string
	for _, w := range h.unchanged() {
		lines = append(lines, "! firewall: "+w)
	}
	if len(h.chains) == 0 {
		if len(lines) == 0 {
			lines = append(lines, "firewall: no nft input chain drops by default; boks's hairpin rule has none to go into")
		}
		return lines
	}
	script := "PATH=\"$PATH:/usr/sbin:/sbin\"\n"
	for _, c := range h.chains {
		script += fmt.Sprintf("if %s; then echo %s; else echo %s; fi\n", hairpinIn(c), remote.Quote("has "+c.String()), remote.Quote("lacks "+c.String()))
	}
	out, err := r.Run(ctx, append(slices.Clone(h.sudo), "sh", "-c", script)...)
	if err != nil {
		return append(lines, "! firewall: reading boks's hairpin rule: "+err.Error())
	}
	answered := strings.Split(out, "\n")
	for i := range answered {
		answered[i] = strings.TrimSpace(answered[i])
	}
	var has, lacks []string
	for _, c := range h.chains {
		switch {
		case slices.Contains(answered, "has "+c.String()):
			has = append(has, c.String())
		case slices.Contains(answered, "lacks "+c.String()):
			lacks = append(lacks, c.String())
		default:
			return append(lines, fmt.Sprintf("! firewall: reading boks's hairpin rule: no answer for %s in %q", c, out))
		}
	}
	if len(lacks) > 0 {
		lines = append(lines, fmt.Sprintf("! firewall: %s drops by default without boks's hairpin rule: containers here do not reach the proxy "+
			"on this server's own addresses; `boks server apply` puts it back", strings.Join(lacks, ", ")))
	}
	if len(has) == 0 {
		return lines
	}
	in := strings.Join(has, ", ")
	switch {
	case !h.persist:
		lines = append(lines, "firewall: hairpin rule in "+in+"; nftables.service is not enabled, so nothing puts it back when the firewall "+
			"is loaded again or the server reboots")
	case h.dropIn != hairpinDropInBody || !h.loaded:
		lines = append(lines, "! firewall: hairpin rule in "+in+", but nftables.service would not put it back after a reload: "+
			"`boks server apply` writes "+hairpinDropIn)
	case h.script != hairpinScriptFor(h.chains):
		// The script may still put the rule back into these chains: it is not the one for the chains the
		// server has now, an input chain added since the last apply, say.
		lines = append(lines, "! firewall: hairpin rule in "+in+", but "+hairpinScript+" is not the one `boks server apply` writes "+
			"for this server's input chains now; apply writes it again")
	default:
		lines = append(lines, "firewall: hairpin rule in "+in+", kept by nftables.service")
	}
	return lines
}

// hairpinMark starts the line the probe prints before each host's request.
const hairpinMark = "boks-hairpin "

// serverAddress is the IPv4 address the server leaves by: the source `ip route get` names.
func serverAddress(ctx context.Context, r remote.Runner) (string, error) {
	out, err := r.Run(ctx, "ip", "-4", "route", "get", "1.1.1.1")
	if err != nil {
		return "", fmt.Errorf("reading the server's address for the hairpin check: %w", err)
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "src" {
			if ip := net.ParseIP(f[i+1]); ip != nil && ip.To4() != nil {
				return f[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("reading the server's address for the hairpin check: no source address in %q", out)
}

// hairpinHosts are the hosts the app serves with TLS, as the proxy matches them; a wildcard names no
// host to ask for, and an address is not one --add-host can point at this server: wget dials it as it is.
func hairpinHosts(cfg *config.Config) []string {
	if !cfg.TLS {
		return nil
	}
	var hosts []string
	for _, p := range cfg.Ports {
		h := hostname.Canonical(p.Host)
		if h == "" || strings.HasPrefix(h, "*.") || net.ParseIP(h) != nil || slices.Contains(hosts, h) {
			continue
		}
		hosts = append(hosts, h)
	}
	return hosts
}

// proxyAnswered reads busybox wget's output: a status line from the server, or an alert in the TLS
// handshake, which is Caddy answering for a host it has no certificate for yet (measured, busybox
// 1.37 with OpenSSL's ssl_client: "SSL alert number 80").
func proxyAnswered(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && strings.HasPrefix(f[0], "HTTP/") {
			return true
		}
		if strings.Contains(line, "SSL alert number") {
			return true
		}
	}
	return false
}
