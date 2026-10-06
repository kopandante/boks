package deploy

// `boks server install`: make an empty — or already compatible — Debian or Ubuntu server ready for
// boks, and start the proxy. It does not migrate what it does not know: anything that would break
// boks or be broken by it is refused before any change, with what to do instead.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

// addressPool is the pool Docker hands networks out of, a /24 each, when the server has none of its
// own: boks makes a network per app, and Docker's default pools are the 172.16/12 and 192.168/16 a
// VPN or a LAN is likely to use.
const addressPool = "10.240.0.0/16"

// minDockerAPI is the oldest Docker Engine API boks drives: `--health-start-interval` came with 1.44
// (Docker 25).
const minDockerAPI = 1.44

// factsScript reads, without changing anything, what the install decides on: one call, key=value
// lines, a key repeated for a list. As the SSH user, with sudo -n where root is needed.
const factsScript = `S=""; [ "$(id -u)" = 0 ] || S="sudo -n"
echo "user=$(id -un)"
echo "uid=$(id -u)"
if [ -n "$S" ]; then $S true 2>/dev/null && echo sudo=yes || echo sudo=no; fi
if [ -r /etc/os-release ]; then . /etc/os-release; echo "os=$ID"; echo "version=$VERSION_ID"; fi
[ -d /run/systemd/system ] && echo systemd=yes
[ -f /proc/sys/net/ipv4/tcp_migrate_req ] && echo migratereq=yes
echo "kernel=$(uname -r)"
command -v dockerd >/dev/null && echo dockerd=yes
command -v crontab >/dev/null && echo crontab=yes
command -v flock >/dev/null && echo flock=yes
id -nG "$(id -un)" | tr ' ' '\n' | grep -qx docker && echo indocker=yes
echo "dockerenabled=$(systemctl is-enabled docker 2>/dev/null)"
echo "cronactive=$(systemctl is-active cron 2>/dev/null)"
if ! command -v dockerd >/dev/null; then echo "candidate=$(apt-cache policy docker.io 2>/dev/null | awk '/Candidate:/{print $2}')"; fi
if $S docker info >/dev/null 2>&1; then
  echo dockerup=yes
  echo "api=$($S docker version --format '{{.Server.APIVersion}}' 2>/dev/null)"
  echo "swarm=$($S docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)"
  $S docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -q rootless && echo rootless=yes
  echo "running=$($S docker ps -q | wc -l | tr -d ' ')"
  $S docker network ls --format '{{.Name}}' | grep -vxE 'bridge|host|none' | sed 's/^/network=/'
  $S docker ps --format '{{.Names}} {{.Ports}}' | sed 's/^/ports=/'
fi
$S ss -Htlnp '( sport = :80 or sport = :443 )' 2>/dev/null | sed 's/^/listen=/'
[ -f /etc/docker/daemon.json ] && echo "daemon=$($S cat /etc/docker/daemon.json | base64 | tr -d '\n')"
M=$(systemctl show -p MainPID --value docker 2>/dev/null)
if [ -n "$M" ] && [ "$M" != 0 ]; then echo "dockerdcmd=$($S cat /proc/$M/cmdline 2>/dev/null | tr '\0' ' ')"
else echo "dockerdcmd=$(systemctl show -p ExecStart --value docker 2>/dev/null | tr '\n' ' ')"; fi
if [ "$(systemctl is-enabled nftables 2>/dev/null)" = enabled ]; then
  for f in /etc/nftables.conf /etc/nftables.d/*.nft; do [ -f "$f" ] && grep -q 'flush ruleset' "$f" && echo "nftflush=$f"; done
fi
ip -4 route show table all 2>/dev/null | awk '{print "route=" $1 " " $2}'
`

// hostFacts is what factsScript found.
type hostFacts struct {
	user, os, version, kernel, candidate, api, swarm string
	// dockerdCmd is the command line dockerd runs with — of the running daemon, so flags from a drop-in
	// or an environment file count — or, with none running, the ExecStart systemd would run.
	dockerdCmd                                              string
	uid, running                                            int
	sudo, systemd, migrateReq, dockerd, crontab, flock      bool
	inDocker, dockerUp, rootless, dockerEnabled, cronActive bool
	networks, publish, listen, nftFlush                     []string
	routes                                                  []netip.Prefix
	daemon                                                  map[string]any
	daemonPresent                                           bool
}

func parseFacts(out string) (hostFacts, error) {
	var f hostFacts
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		yes := v == "yes"
		switch k {
		case "user":
			f.user = v
		case "uid":
			f.uid, _ = strconv.Atoi(v)
		case "sudo":
			f.sudo = yes
		case "os":
			f.os = v
		case "version":
			f.version = v
		case "kernel":
			f.kernel = v
		case "systemd":
			f.systemd = yes
		case "migratereq":
			f.migrateReq = yes
		case "dockerd":
			f.dockerd = yes
		case "crontab":
			f.crontab = yes
		case "flock":
			f.flock = yes
		case "indocker":
			f.inDocker = yes
		case "dockerenabled":
			f.dockerEnabled = v == "enabled"
		case "cronactive":
			f.cronActive = v == "active"
		case "candidate":
			f.candidate = v
		case "dockerup":
			f.dockerUp = yes
		case "api":
			f.api = v
		case "swarm":
			f.swarm = v
		case "rootless":
			f.rootless = yes
		case "running":
			f.running, _ = strconv.Atoi(v)
		case "network":
			f.networks = append(f.networks, v)
		case "ports":
			name, ports, _ := strings.Cut(v, " ")
			if holdsWebPort(ports) {
				f.publish = append(f.publish, name)
			}
		case "listen":
			f.listen = append(f.listen, v)
		case "nftflush":
			f.nftFlush = append(f.nftFlush, v)
		case "route":
			if r, ok := routeDest(v); ok {
				f.routes = append(f.routes, r)
			}
		case "dockerdcmd":
			f.dockerdCmd = v
		case "daemon":
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return f, fmt.Errorf("reading /etc/docker/daemon.json: %w", err)
			}
			f.daemonPresent = true
			if strings.TrimSpace(string(raw)) != "" {
				if err := json.Unmarshal(raw, &f.daemon); err != nil {
					return f, fmt.Errorf("/etc/docker/daemon.json is not JSON (%v); fix it before installing", err)
				}
			}
		}
	}
	return f, nil
}

// installPlan is what an install does on one server: packages to add, the daemon.json to write (nil:
// leave it), whether dockerd must restart for it, services to enable, the user to add to the docker
// group — and what it leaves alone and why.
type installPlan struct {
	packages      []string
	daemon        map[string]any
	restartDocker bool
	enableDocker  bool
	enableCron    bool
	addToDocker   bool
	notes         []string
}

func (p installPlan) empty() bool {
	return len(p.packages) == 0 && p.daemon == nil && !p.restartDocker && !p.enableDocker && !p.enableCron && !p.addToDocker
}

// planInstall decides from the facts, changing nothing; an error is a refusal, with what to do.
func planInstall(f hostFacts) (installPlan, error) {
	var p installPlan
	if f.uid != 0 && !f.sudo {
		return p, fmt.Errorf("%s is not root and has no passwordless sudo; install as root, or allow `sudo -n` for this user", f.user)
	}
	if !supportedOS(f.os, f.version) || !f.systemd {
		return p, fmt.Errorf("%s %s%s is not a system boks installs on (Debian 12+ or Ubuntu 22.04+ with systemd); prepare it by hand: "+
			"Docker Engine 25+, cron, flock, the SSH user in group docker, ports 80 and 443 free — then `boks proxy boot`",
			f.os, f.version, map[bool]string{true: "", false: " without systemd"}[f.systemd])
	}
	if !f.migrateReq {
		return p, fmt.Errorf("kernel %s has no net.ipv4.tcp_migrate_req (Linux 5.14+), without which every deploy's reload resets connections", f.kernel)
	}
	if f.swarm == "active" || f.swarm == "pending" {
		return p, fmt.Errorf("Docker runs in Swarm mode here (a Dokploy server?); boks runs plain containers and does not share a server with Swarm")
	}
	if f.rootless {
		return p, fmt.Errorf("Docker runs rootless here; boks needs the system daemon to publish 80 and 443")
	}
	if err := portsFree(f); err != nil {
		return p, err
	}
	if len(f.nftFlush) > 0 {
		return p, fmt.Errorf("nftables is enabled and %s starts with `flush ruleset`, which removes Docker's rules on every reload of the "+
			"firewall: published ports and the containers' way out stop working. Replace the flush with deleting and recreating only "+
			"the tables that file defines, keep Docker's and fail2ban's, let the bridges of boks networks through every forward chain "+
			"that drops by default, and keep net.ipv4.ip_forward=1 in a file under /etc/sysctl.d — then install again",
			strings.Join(f.nftFlush, ", "))
	}
	if v, ok := f.daemon["iptables"].(bool); (ok && !v) || flagValue(f.dockerdCmd, "--iptables") == "false" {
		return p, fmt.Errorf("Docker runs with \"iptables\": false (daemon.json or a dockerd flag): published ports would show every visitor as the Docker gateway, " +
			"so one ban shuts the site for all. Let Docker manage its rules, then install again")
	}
	if f.daemon["bridge"] == "none" || flagValue(f.dockerdCmd, "--bridge") == "none" || flagValue(f.dockerdCmd, "-b") == "none" {
		return p, fmt.Errorf("Docker runs with \"bridge\": \"none\" (daemon.json or a dockerd flag); boks networks need Docker's bridge driver")
	}
	if f.dockerUp {
		if api, err := strconv.ParseFloat(f.api, 64); err != nil || api < minDockerAPI {
			return p, fmt.Errorf("Docker Engine API %s here is older than %.2f (Docker 25), which boks needs; upgrade Docker, then install again", f.api, minDockerAPI)
		}
	} else if !f.dockerd {
		if major, _, _ := strings.Cut(f.candidate, "."); f.candidate == "" || atoi(major) < 25 {
			return p, fmt.Errorf("this system's docker.io package is %q, older than Docker 25 that boks needs; install Docker Engine from "+
				"Docker's own repository (docs.docker.com/engine/install), then install again", f.candidate)
		}
		p.packages = append(p.packages, "docker.io")
	} else {
		return p, fmt.Errorf("dockerd is installed but does not answer; start it (`systemctl start docker`) and install again")
	}
	if !f.crontab {
		p.packages = append(p.packages, "cron")
	}
	if !f.flock {
		p.packages = append(p.packages, "util-linux")
	}
	if !f.dockerEnabled {
		p.enableDocker = true
	}
	if !f.cronActive || !f.crontab {
		p.enableCron = true
	}
	if f.uid != 0 && !f.inDocker {
		p.addToDocker = true
	}
	planDaemon(f, &p)
	return p, nil
}

// planDaemon puts in /etc/docker/daemon.json what boks wants of the daemon and it does not have
// yet: log rotation for containers boks did not start (its own carry explicit options), and an address
// pool, before the first network boks makes. A key systemd already passes as a flag stays out — dockerd
// refuses to start with an option given both ways — and a change that needs a restart is not made
// while containers run.
func planDaemon(f hostFacts, p *installPlan) {
	want := map[string]any{}
	_, driver := f.daemon["log-driver"]
	_, opts := f.daemon["log-opts"]
	if !driver && !opts && !hasFlag(f.dockerdCmd, "--log-driver") && !hasFlag(f.dockerdCmd, "--log-opt") {
		want["log-driver"] = "json-file"
		want["log-opts"] = map[string]any{"max-size": "10m", "max-file": "3"}
	}
	if _, set := f.daemon["default-address-pools"]; !set && !hasFlag(f.dockerdCmd, "--default-address-pool") {
		if pool, why := poolFree(f); pool {
			want["default-address-pools"] = []any{map[string]any{"base": addressPool, "size": float64(24)}}
		} else {
			p.notes = append(p.notes, why)
		}
	}
	if len(want) == 0 {
		return
	}
	if f.dockerUp && f.running > 0 {
		keys := slices.Sorted(maps.Keys(want))
		p.notes = append(p.notes, fmt.Sprintf("%s in /etc/docker/daemon.json would need a dockerd restart, which stops the %d "+
			"running container(s): left as it is — set them at a quiet moment", strings.Join(keys, ", "), f.running))
		return
	}
	d := maps.Clone(f.daemon)
	if d == nil {
		d = map[string]any{}
	}
	maps.Copy(d, want)
	p.daemon = d
	p.restartDocker = f.dockerUp
}

// poolFree says whether Docker's networks can come out of addressPool: nothing on the host routes into
// it, and Docker has no network of its own yet that a new pool would leave numbered differently.
func poolFree(f hostFacts) (bool, string) {
	pool := netip.MustParsePrefix(addressPool)
	for _, r := range f.routes {
		if r.Overlaps(pool) {
			return false, fmt.Sprintf("the host routes %s, which overlaps %s: Docker's address pool is left as it is — "+
				"set default-address-pools in /etc/docker/daemon.json to a range nothing here uses", r, addressPool)
		}
	}
	if len(f.networks) > 0 {
		return false, fmt.Sprintf("Docker already has networks (%s): its address pool is left as it is; set "+
			"default-address-pools yourself if they collide with a VPN or the LAN", strings.Join(f.networks, ", "))
	}
	return true, ""
}

// portsFree refuses 80 and 443 held by anything but the proxy boks runs.
func portsFree(f hostFacts) error {
	for _, c := range f.publish {
		if c != proxy.Container {
			return fmt.Errorf("container %s publishes port 80 or 443; boks needs both for its proxy (a Dokploy or Traefik server is not one boks shares)", c)
		}
	}
	for _, l := range f.listen {
		// Docker's userland proxy listens for a container that publishes; whose it is, publish says.
		if strings.Contains(l, `"docker-proxy"`) {
			continue
		}
		return fmt.Errorf("port 80 or 443 is taken: %s; stop that service (or move it behind boks), then install again", strings.TrimSpace(l))
	}
	return nil
}

func supportedOS(id, version string) bool {
	major, minor, _ := strings.Cut(version, ".")
	switch id {
	case "ubuntu":
		return atoi(major) > 22 || (atoi(major) == 22 && atoi(minor) >= 4)
	case "debian":
		return atoi(major) >= 12
	}
	return false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// holdsWebPort says whether docker's Ports column — "0.0.0.0:80->80/tcp, [::]:8000-8090->8000-8090/tcp"
// — binds host port 80 or 443. A container port alone ("80/tcp") binds nothing on the host, and a
// container port 80 published on another host port leaves 80 free.
func holdsWebPort(ports string) bool {
	for _, m := range strings.Split(ports, ",") {
		host, _, ok := strings.Cut(strings.TrimSpace(m), "->")
		if !ok {
			continue
		}
		lo, hi, isRange := strings.Cut(host[strings.LastIndex(host, ":")+1:], "-")
		if !isRange {
			hi = lo
		}
		a, b := atoi(lo), atoi(hi)
		if (a <= 80 && 80 <= b) || (a <= 443 && 443 <= b) {
			return true
		}
	}
	return false
}

// routeDest is the destination of one `ip -4 route` line, given by its first two fields. The first is
// the destination, unless the line starts with a route type (blackhole, local, broadcast…) — then the
// second is. A host route is printed without a length and is a /32; default is no destination a pool
// could collide with.
func routeDest(v string) (netip.Prefix, bool) {
	for _, d := range strings.Fields(v) {
		if p, err := netip.ParsePrefix(d); err == nil {
			return p.Masked(), true
		}
		if a, err := netip.ParseAddr(d); err == nil && a.Is4() {
			return netip.PrefixFrom(a, 32), true
		}
	}
	return netip.Prefix{}, false
}

// hasFlag says whether the dockerd command line cmd gives the option name, as `name value` or `name=value`.
func hasFlag(cmd, name string) bool {
	for _, a := range strings.Fields(cmd) {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// flagValue is the value cmd gives the option name — the last one, as dockerd takes it — or "". A boolean
// given bare is "true".
func flagValue(cmd, name string) string {
	args, v := strings.Fields(cmd), ""
	for i, a := range args {
		if val, ok := strings.CutPrefix(a, name+"="); ok {
			v = val
		} else if a == name {
			v = "true"
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				v = args[i+1]
			}
		}
	}
	return v
}

// CheckInstall reads the server and says what an install would do there, or why it would refuse:
// asked of every server before any changes.
func CheckInstall(ctx context.Context, r remote.Runner) (installPlan, error) {
	out, err := r.Run(ctx, "sh", "-c", factsScript)
	if err != nil {
		return installPlan{}, fmt.Errorf("reading the server: %w", err)
	}
	f, err := parseFacts(out)
	if err != nil {
		return installPlan{}, err
	}
	return planInstall(f)
}

const installAction = "server install"

// Install makes the server ready for boks and starts the proxy from image. r is the run's connection;
// fresh makes a new one — a user just added to group docker has it only in a new login. The plan is
// read again under the admission lock, so what was checked is what is changed.
func Install(ctx context.Context, r remote.Runner, fresh func() remote.Runner, log io.Writer, image string, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	adm, err := admit(ctx, r, log, proxyHolder, o)
	if err != nil {
		return err
	}
	defer adm.release(ctx)
	out, err := r.Run(ctx, "sh", "-c", factsScript)
	if err != nil {
		return fmt.Errorf("reading the server: %w", err)
	}
	f, err := parseFacts(out)
	if err != nil {
		return err
	}
	p, err := planInstall(f)
	if err != nil {
		return err
	}
	for _, n := range p.notes {
		fmt.Fprintf(log, "note: %s\n", n)
	}
	sudo := []string{}
	if f.uid != 0 {
		sudo = []string{"sudo", "-n"}
	}
	as := func(args ...string) []string { return append(slices.Clone(sudo), args...) }
	op := ""
	if !p.empty() {
		if op, err = beginServer(ctx, r, log, o, installAction, "", strings.Join(p.packages, " ")); err != nil {
			return err
		}
	}
	fail := func(err error) error {
		finish(ctx, r, log, serverJournal, op, "failed", o.Now())
		return err
	}
	// daemon.json goes in before Docker is installed: the package starts dockerd as it installs, and a
	// dockerd that started without it would need a restart.
	if p.daemon != nil {
		body, _ := json.MarshalIndent(p.daemon, "", "  ")
		fmt.Fprintln(log, "docker: writing /etc/docker/daemon.json (log rotation, address pool)")
		if err := writeRoot(ctx, r, sudo, append(body, '\n'), "/etc/docker/daemon.json", f.dockerd); err != nil {
			return fail(err)
		}
	}
	if len(p.packages) > 0 {
		fmt.Fprintf(log, "apt: installing %s\n", strings.Join(p.packages, " "))
		if _, err := r.Run(ctx, as("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=300", "update", "-q")...); err != nil {
			return fail(fmt.Errorf("apt-get update: %w", err))
		}
		if _, err := r.Run(ctx, as(append([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=300", "install", "-y", "-q", "--no-install-recommends"}, p.packages...)...)...); err != nil {
			return fail(fmt.Errorf("apt-get install: %w", err))
		}
	}
	if p.enableDocker || slices.Contains(p.packages, "docker.io") {
		if _, err := r.Run(ctx, as("systemctl", "enable", "--now", "docker")...); err != nil {
			return fail(fmt.Errorf("enabling docker: %w", err))
		}
	}
	if p.restartDocker {
		fmt.Fprintln(log, "docker: restarting dockerd for the new daemon.json (no container runs)")
		if _, err := r.Run(ctx, as("systemctl", "restart", "docker")...); err != nil {
			return fail(fmt.Errorf("restarting docker: %w", err))
		}
	}
	if p.enableCron {
		if _, err := r.Run(ctx, as("systemctl", "enable", "--now", "cron")...); err != nil {
			return fail(fmt.Errorf("enabling cron: %w", err))
		}
	}
	if p.addToDocker {
		fmt.Fprintf(log, "user: adding %s to group docker\n", f.user)
		if _, err := r.Run(ctx, as("usermod", "-aG", "docker", f.user)...); err != nil {
			return fail(fmt.Errorf("adding %s to group docker: %w", f.user, err))
		}
	}
	// From here on as boks will run: the user's own docker access, in a new login.
	nr := fresh()
	if _, err := nr.Run(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		return fail(fmt.Errorf("docker does not answer %s without sudo in a new login: %w", f.user, err))
	}
	if err := proxy.Boot(ctx, nr, log, image); err != nil {
		return fail(err)
	}
	if op != "" {
		finish(ctx, r, log, serverJournal, op, "ok", o.Now())
		fmt.Fprintln(log, "server ready for boks")
	} else {
		// An install a cut run left open got as far as this one has nothing left to do: it is closed.
		if open, err := release.Unfinished(ctx, r, serverJournal); err == nil && open != nil && open.Action == installAction {
			finish(ctx, r, log, serverJournal, open.Op, "ok", o.Now())
		}
		fmt.Fprintln(log, "server ready for boks; nothing to change")
	}
	fmt.Fprintln(log, "not checked from here: the provider's firewall in front of 80 and 443, and a reboot")
	return nil
}

// writeRoot puts body at a root-owned path through sudo when needed: a temporary file next to it,
// checked by dockerd when it is installed, then moved over atomically. The previous file, if any, is
// kept as path.boks-bak.
func writeRoot(ctx context.Context, r remote.Runner, sudo []string, body []byte, path string, validate bool) error {
	q, tmp := remote.Quote(path), remote.Quote(path+".boks-new")
	script := "mkdir -p \"$(dirname " + q + ")\" && cat > " + tmp
	if validate {
		script += " && dockerd --validate --config-file " + tmp + " >/dev/null"
	}
	script += " && { [ ! -f " + q + " ] || cp -p " + q + " " + remote.Quote(path+".boks-bak") + "; } && mv " + tmp + " " + q
	if _, err := r.Pipe(ctx, body, append(slices.Clone(sudo), "sh", "-c", script)...); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
