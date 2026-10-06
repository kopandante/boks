package deploy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/remote"
)

// emptyNoble is what factsScript prints on a fresh Ubuntu 24.04 where the SSH user is root: no Docker,
// no cron, flock there.
const emptyNoble = `user=root
uid=0
os=ubuntu
version=24.04
systemd=yes
migratereq=yes
kernel=6.8.0
flock=yes
dockerenabled=
cronactive=inactive
candidate=27.5.1-0ubuntu3~24.04.2
dockerdcmd=
route=10.0.0.0/24 dev
route=default via
`

// readyNoble is the same server after an install, as a sudo user in group docker.
const readyNoble = `user=deploy
uid=1000
sudo=yes
os=ubuntu
version=24.04
systemd=yes
migratereq=yes
kernel=6.8.0
dockerd=yes
crontab=yes
flock=yes
indocker=yes
dockerenabled=enabled
cronactive=active
dockerup=yes
api=1.47
swarm=inactive
running=1
network=boks-web
ports=boks-proxy 0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp, [::]:443->443/tcp
listen=LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("docker-proxy",pid=812,fd=7))
dockerdcmd=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock --log-level warn
`

func daemonLine(json string) string {
	return "daemon=" + base64.StdEncoding.EncodeToString([]byte(json)) + "\n"
}

func plan(t *testing.T, facts string) (installPlan, error) {
	t.Helper()
	f, err := parseFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	return planInstall(f)
}

func TestPlanInstallOnAnEmptyServer(t *testing.T) {
	p, err := plan(t, emptyNoble)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.packages, " ") != "docker.io cron" || !p.enableDocker || !p.enableCron || p.addToDocker || p.restartDocker {
		t.Errorf("plan: %+v", p)
	}
	if p.daemon["log-driver"] != "json-file" || p.daemon["default-address-pools"] == nil {
		t.Errorf("daemon.json: %v", p.daemon)
	}
}

func TestPlanInstallOnAReadyServerChangesNothing(t *testing.T) {
	ready := readyNoble + daemonLine(`{"log-driver":"json-file","log-opts":{"max-size":"10m"},"default-address-pools":[{"base":"10.240.0.0/16","size":24}]}`)
	p, err := plan(t, ready)
	if err != nil {
		t.Fatal(err)
	}
	if !p.empty() || len(p.notes) > 0 {
		t.Errorf("a second install would change something: %+v", p)
	}
}

func TestPlanInstallKeepsTheDaemonsOtherKeys(t *testing.T) {
	p, err := plan(t, strings.Replace(readyNoble, "running=1", "running=0", 1)+daemonLine(`{"registry-mirrors":["https://m.example"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.daemon["registry-mirrors"] == nil || p.daemon["log-driver"] != "json-file" || !p.restartDocker {
		t.Errorf("plan: %+v", p)
	}
	// Docker's existing networks keep their numbers: the pool is not set under them.
	if p.daemon["default-address-pools"] != nil || len(p.notes) != 1 || !strings.Contains(p.notes[0], "boks-web") {
		t.Errorf("pool set under existing networks: %+v", p)
	}
}

func TestPlanInstallDoesNotRestartDockerUnderRunningContainers(t *testing.T) {
	p, err := plan(t, readyNoble)
	if err != nil {
		t.Fatal(err)
	}
	if p.daemon != nil || p.restartDocker || len(p.notes) != 2 || !strings.Contains(p.notes[1], "1 running") {
		t.Errorf("plan: %+v", p)
	}
}

func TestPlanInstallLeavesFlagsSystemdPasses(t *testing.T) {
	facts := strings.Replace(emptyNoble, "dockerdcmd=", "dockerdcmd=/usr/bin/dockerd --log-opt max-size=5m --default-address-pool base=10.9.0.0/16,size=24", 1)
	p, err := plan(t, facts)
	if err != nil {
		t.Fatal(err)
	}
	if p.daemon != nil {
		t.Errorf("an option given as a flag written again in daemon.json stops dockerd: %v", p.daemon)
	}
	// The running daemon's command line counts, whatever put the flag there (a drop-in's continued
	// ExecStart, an environment file): --log-driver alone keeps both log keys out, --log-level keeps none.
	idle := strings.Replace(strings.Replace(readyNoble, "running=1", "running=0", 1), "network=boks-web\n", "", 1)
	for cmd, wantLog := range map[string]bool{
		"/usr/bin/dockerd -H fd:// --log-driver=journald": false,
		"/usr/bin/dockerd -H fd:// --log-level=warn":      true,
	} {
		p, err := plan(t, strings.Replace(idle, "dockerdcmd=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock --log-level warn", "dockerdcmd="+cmd, 1))
		if err != nil {
			t.Fatal(err)
		}
		_, driver := p.daemon["log-driver"]
		_, opts := p.daemon["log-opts"]
		if driver != wantLog || opts != wantLog || p.daemon["default-address-pools"] == nil {
			t.Errorf("%s: daemon.json %v", cmd, p.daemon)
		}
	}
}

// A container port published elsewhere leaves 80 free; host port 80 published to any container port does not.
func TestPlanInstallReadsHostPorts(t *testing.T) {
	if _, err := plan(t, strings.Replace(readyNoble, "network=boks-web", "network=boks-web\nports=web 0.0.0.0:8080->80/tcp, 443/tcp", 1)); err != nil {
		t.Errorf("8080:80 refused: %v", err)
	}
	for _, ports := range []string{"web 0.0.0.0:80->8080/tcp", "web [::]:443->8443/tcp", "web 0.0.0.0:400-500->400-500/tcp"} {
		if _, err := plan(t, strings.Replace(readyNoble, "network=boks-web", "network=boks-web\nports="+ports, 1)); err == nil || !strings.Contains(err.Error(), "container web") {
			t.Errorf("%s: want a refusal naming web, got %v", ports, err)
		}
	}
}

func TestPlanInstallSkipsAPoolTheHostRoutes(t *testing.T) {
	// `ip route` prints a host route without a length, and a typed route with its type first.
	for route, want := range map[string]string{
		"10.0.0.0/8 dev":          "10.0.0.0/8",
		"10.240.1.10 via":         "10.240.1.10/32",
		"blackhole 10.240.0.0/16": "10.240.0.0/16",
		"local 10.240.3.4":        "10.240.3.4/32",
	} {
		p, err := plan(t, emptyNoble+"route="+route+"\n")
		if err != nil {
			t.Fatal(err)
		}
		if p.daemon["default-address-pools"] != nil || len(p.notes) != 1 || !strings.Contains(p.notes[0], want) {
			t.Errorf("%s: plan %+v", route, p)
		}
	}
}

func TestPlanInstallAddsASudoUserToDocker(t *testing.T) {
	facts := strings.Replace(emptyNoble, "user=root\nuid=0", "user=deploy\nuid=1000\nsudo=yes", 1)
	p, err := plan(t, facts)
	if err != nil || !p.addToDocker {
		t.Errorf("plan: %+v, %v", p, err)
	}
}

func TestPlanInstallRefuses(t *testing.T) {
	sudoUser := strings.Replace(emptyNoble, "user=root\nuid=0", "user=deploy\nuid=1000\nsudo=no", 1)
	for want, facts := range map[string]string{
		"passwordless sudo":                   sudoUser,
		"not a system":                        strings.Replace(emptyNoble, "os=ubuntu", "os=fedora", 1),
		"Ubuntu 22.04+":                       strings.Replace(emptyNoble, "version=24.04", "version=20.04", 1),
		"without systemd":                     strings.Replace(emptyNoble, "systemd=yes\n", "", 1),
		"tcp_migrate_req":                     strings.Replace(emptyNoble, "migratereq=yes\n", "", 1),
		"older than Docker 25":                strings.Replace(emptyNoble, "candidate=27.5.1-0ubuntu3~24.04.2", "candidate=24.0.7-0ubuntu4", 1),
		"Swarm":                               strings.Replace(readyNoble, "swarm=inactive", "swarm=active", 1),
		"rootless":                            readyNoble + "rootless=yes\n",
		"Engine API 1.43":                     strings.Replace(readyNoble, "api=1.47", "api=1.43", 1),
		"container dokploy-traefik publishes": strings.Replace(readyNoble, "ports=boks-proxy", "ports=dokploy-traefik", 1),
		"port 80 or 443 is taken":             emptyNoble + `listen=LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=700,fd=6))` + "\n",
		"flush ruleset":                       emptyNoble + "nftflush=/etc/nftables.conf\n",
		`"iptables": false`:                   emptyNoble + daemonLine(`{"iptables": false}`),
		`"iptables": false (`:                 strings.Replace(readyNoble, "--log-level warn", "--log-level warn --iptables=false", 1),
		`"bridge": "none"`:                    emptyNoble + daemonLine(`{"bridge": "none"}`),
		`"bridge": "none" (`:                  strings.Replace(readyNoble, "--log-level warn", "--log-level warn -b none", 1),
		"does not answer":                     strings.Replace(emptyNoble, "flock=yes", "flock=yes\ndockerd=yes", 1),
	} {
		if _, err := plan(t, facts); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want a refusal containing %q, got %v", want, err)
		}
	}
	if _, err := parseFacts(emptyNoble + daemonLine(`{"log-driver": `)); err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("a broken daemon.json: %v", err)
	}
}

const factsCall = "sh -c " + factsScript

// installFake is a server answering facts, with the proxy already running.
func installFake(facts string) *fake {
	f := newFake()
	f.out[factsCall] = facts
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	return f
}

func install(f, fresh *fake) error {
	return Install(context.Background(), f, func() remote.Runner { return fresh }, io.Discard, "caddy:2.11.7-alpine", fixed)
}

func TestInstallOnAnEmptyServer(t *testing.T) {
	f, fresh := installFake(emptyNoble), installFake("")
	if err := install(f, fresh); err != nil {
		t.Fatal(err)
	}
	lock, facts := f.callAt(admitTake("_proxy")), f.callAt(factsCall)
	daemon := f.writeAt("/etc/docker/daemon.json", `"max-file": "3"`)
	apt := f.callAt("env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q --no-install-recommends docker.io cron")
	enable, cron := f.callAt("systemctl enable --now docker"), f.callAt("systemctl enable --now cron")
	unlock := f.callAt(admitGive("_proxy"))
	// daemon.json is there before the package starts dockerd; the facts are read again under the lock.
	if lock < 0 || facts < lock || daemon < facts || apt < daemon || enable < apt || cron < enable || unlock < cron {
		t.Errorf("order: lock %d facts %d daemon.json %d apt %d enable %d cron %d unlock %d\n%v", lock, facts, daemon, apt, enable, cron, unlock, f.calls)
	}
	if !strings.Contains(f.uploads["/etc/docker/daemon.json"], `"base": "10.240.0.0/16"`) {
		t.Errorf("daemon.json: %s", f.uploads["/etc/docker/daemon.json"])
	}
	// The proxy is booted, and docker asked, in the new login.
	if !fresh.has("docker info") || !fresh.has("docker ps -a --filter name=^boks-proxy$") || f.has("docker ps -a --filter name=^boks-proxy$") {
		t.Errorf("want docker checked and the proxy booted in a new login: %v", fresh.calls)
	}
	if f.has("systemctl restart docker") || f.has("usermod") {
		t.Errorf("nothing ran to restart or add: %v", f.calls)
	}
	if j := f.appends[serverLog]; !strings.Contains(j, `"action":"server install"`) || !strings.Contains(j, `"result":"ok"`) {
		t.Errorf("journal: %s", j)
	}
}

func TestInstallAsASudoUser(t *testing.T) {
	facts := strings.Replace(emptyNoble, "user=root\nuid=0", "user=deploy\nuid=1000\nsudo=yes", 1)
	f, fresh := installFake(facts), installFake("")
	// The new login has the group only once usermod has run: docker asked before it would fail.
	fresh.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, "docker info") && !f.has("sudo -n usermod") {
			fresh.fail["docker info"] = errors.New("permission denied")
		}
	}
	if err := install(f, fresh); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		for _, root := range []string{"env DEBIAN", "systemctl", "usermod"} {
			if strings.HasPrefix(c, root) {
				t.Errorf("a root step without sudo -n: %s", c)
			}
		}
	}
	usermod := f.callAt("sudo -n usermod -aG docker deploy")
	if usermod < 0 || !f.has("sudo -n env DEBIAN_FRONTEND=noninteractive apt-get") || !f.has("sudo -n systemctl enable --now docker") {
		t.Errorf("want root's steps through sudo -n: %v", f.calls)
	}
	var wrote string
	for cmd, body := range f.stdin {
		if strings.HasPrefix(cmd, "sudo -n sh -c mkdir -p") && strings.Contains(cmd, "/etc/docker/daemon.json") {
			wrote = body
		}
	}
	if !strings.Contains(wrote, `"log-driver": "json-file"`) {
		t.Errorf("want daemon.json written through sudo: %v", f.stdin)
	}
	if fresh.callAt("docker info") != 0 {
		t.Errorf("want docker asked without sudo first thing in the new login: %v", fresh.calls)
	}
}

func TestInstallTwiceChangesNothing(t *testing.T) {
	ready := readyNoble + daemonLine(`{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"default-address-pools":[{"base":"10.240.0.0/16","size":24}]}`)
	f, fresh := installFake(ready), installFake("")
	if err := install(f, fresh); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if c == factsCall {
			continue
		}
		if strings.Contains(c, "apt-get") || strings.Contains(c, "systemctl") || strings.Contains(c, "usermod") {
			t.Errorf("a ready server changed: %s", c)
		}
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 {
		t.Errorf("want nothing written, not even the journal: %v %v", f.uploads, f.appends)
	}
}

func TestInstallRefusesUnderTheLockBeforeAnyChange(t *testing.T) {
	f := installFake(emptyNoble + `listen=LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=700,fd=6))` + "\n")
	fresh := installFake("")
	err := install(f, fresh)
	if err == nil || !strings.Contains(err.Error(), "nginx") {
		t.Fatalf("want a refusal naming nginx, got %v", err)
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 || f.has("env DEBIAN") || len(fresh.calls) > 0 || !f.has(admitGive("_proxy")) {
		t.Errorf("want nothing changed and the lock given back: %v", f.calls)
	}
}

func TestInstallJournalsAFailedStep(t *testing.T) {
	f, fresh := installFake(emptyNoble), installFake("")
	f.fail["env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install"] = errors.New("E: Unable to locate package")
	err := install(f, fresh)
	if err == nil || !strings.Contains(err.Error(), "apt-get install") {
		t.Fatalf("got %v", err)
	}
	if j := f.appends[serverLog]; !strings.Contains(j, `"result":"failed"`) || len(fresh.calls) > 0 {
		t.Errorf("journal: %s; fresh: %v", j, fresh.calls)
	}
}

func TestInstallSaysWhenDockerNeedsANewLoginAndDoesNotAnswer(t *testing.T) {
	facts := strings.Replace(emptyNoble, "user=root\nuid=0", "user=deploy\nuid=1000\nsudo=yes", 1)
	f, fresh := installFake(facts), installFake("")
	fresh.fail["docker info"] = errors.New("permission denied while trying to connect to the Docker daemon socket")
	if err := install(f, fresh); err == nil || !strings.Contains(err.Error(), "without sudo in a new login") || fresh.has("docker ps") {
		t.Errorf("got %v; fresh: %v", err, fresh.calls)
	}
}

// An install a cut run left open is closed, not named by `boks server status` forever: as abandoned by
// a run that has steps of its own, as done by one that finds nothing left to do.
func TestInstallClosesAnInstallACutRunLeftOpen(t *testing.T) {
	open := `{"op":"1","action":"server install","from":"","to":"docker.io cron","started_at":"2026-01-01T00:00:00Z"}`
	ready := readyNoble + daemonLine(`{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"default-address-pools":[{"base":"10.240.0.0/16","size":24}]}`)
	for facts, want := range map[string]string{emptyNoble: "abandoned", ready: "ok"} {
		f, fresh := installFake(facts), installFake("")
		f.out["sh -c cat '.boks/_server/journal.jsonl'"] = open
		if err := install(f, fresh); err != nil {
			t.Fatal(err)
		}
		if j := f.appends[serverLog]; !strings.Contains(j, `{"op":"1","finished_at":`) || !strings.Contains(j, `"result":"`+want+`"`) {
			t.Errorf("want the open install closed %s: %s", want, j)
		}
	}
	// Another command's open entry is its own to close.
	f, fresh := installFake(ready), installFake("")
	f.out["sh -c cat '.boks/_server/journal.jsonl'"] = `{"op":"1","action":"server apply","from":"3","to":"4","started_at":"2026-01-01T00:00:00Z"}`
	if err := install(f, fresh); err != nil || f.appends[serverLog] != "" {
		t.Errorf("got %v, journal %s", err, f.appends[serverLog])
	}
}
