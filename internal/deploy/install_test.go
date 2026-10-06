package deploy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
proxy=running caddy
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
		"Swarm mode":                          strings.Replace(readyNoble, "swarm=inactive", "swarm=locked", 1),
		"rootless":                            readyNoble + "rootless=yes\n",
		"Engine API 1.43":                     strings.Replace(readyNoble, "api=1.47", "api=1.43", 1),
		"container dokploy-traefik publishes": strings.Replace(readyNoble, "ports=boks-proxy", "ports=dokploy-traefik", 1),
		"port 80 or 443 is taken":             emptyNoble + `listen=LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=700,fd=6))` + "\n",
		"flush ruleset":                       emptyNoble + "nftflush=/etc/nftables.conf\n",
		"boks proxy migrate":                  strings.Replace(readyNoble, "proxy=running caddy", "proxy=running ", 1),
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

// aptCall is how apt-get is run, before its arguments.
const aptCall = "sh -c " + aptScript + " apt-get "

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
	apt := f.callAt(aptCall + "install -y -q --no-install-recommends docker.io cron")
	enable, cron := f.callAt("systemctl enable --now docker"), f.callAt("systemctl enable --now cron")
	unlock := f.callAt(admitGive("_proxy"))
	// daemon.json is there before the package starts dockerd; the facts are read again under the lock.
	// The package index is fresh before the plan is final: the docker.io checked is the one installed.
	if update := f.callAt(aptCall + "update"); update < facts || daemon < update {
		t.Errorf("want apt-get update between the facts and daemon.json: %v", f.calls)
	}
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
		for _, root := range []string{aptCall, "systemctl", "usermod"} {
			if strings.HasPrefix(c, root) {
				t.Errorf("a root step without sudo -n: %s", c)
			}
		}
	}
	usermod := f.callAt("sudo -n usermod -aG docker deploy")
	if usermod < 0 || !f.has("sudo -n "+aptCall) || !f.has("sudo -n systemctl enable --now docker") {
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
	if len(f.uploads) > 0 || len(f.appends) > 0 || len(f.stdin) > 0 {
		t.Errorf("want nothing written, not even the journal: %v %v %v", f.uploads, f.appends, f.stdin)
	}
	// The running proxy is left as it is.
	for _, c := range fresh.calls {
		for _, change := range []string{"docker create", "docker run", "docker start", "docker network create", "docker rm"} {
			if strings.HasPrefix(c, change) {
				t.Errorf("a ready server's proxy changed: %s", c)
			}
		}
	}
	if len(fresh.uploads) > 0 || len(fresh.appends) > 0 || len(fresh.stdin) > 0 {
		t.Errorf("the new login wrote: %v %v %v", fresh.uploads, fresh.appends, fresh.stdin)
	}
}

// A server prepared but without its proxy — a first run that failed pulling it — gets the proxy as a
// change of its own: journaled, and not reported as nothing to change.
func TestInstallJournalsAProxyBootAlone(t *testing.T) {
	ready := strings.Replace(readyNoble, "proxy=running caddy", "proxy=exited caddy", 1) + daemonLine(`{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"default-address-pools":[{"base":"10.240.0.0/16","size":24}]}`)
	f, fresh := installFake(ready), installFake("")
	var log strings.Builder
	if err := Install(context.Background(), f, func() remote.Runner { return fresh }, &log, "caddy:2.11.7-alpine", fixed); err != nil {
		t.Fatal(err)
	}
	if j := f.appends[serverLog]; !strings.Contains(j, `"action":"server install"`) || !strings.Contains(j, `"result":"ok"`) || strings.Contains(log.String(), "nothing to change") {
		t.Errorf("journal %s, log %s", j, log.String())
	}
	if f.has("sudo -n " + aptCall) {
		t.Errorf("a prepared server ran apt: %v", f.calls)
	}
}

// A fresh image may ship no package index: the check refreshes it and reads the server again, so an
// old docker.io is refused by the check of every server, before any of them changes.
func TestInstallReadsAFreshImagesCandidateAfterUpdate(t *testing.T) {
	noIndex := strings.Replace(emptyNoble, "candidate=27.5.1-0ubuntu3~24.04.2", "candidate=", 1)
	server := func(candidate string) *fake {
		f := installFake(noIndex)
		f.onRun = func(cmd string) {
			if strings.HasPrefix(cmd, aptCall+"update") {
				f.out[factsCall] = strings.Replace(noIndex, "candidate=", "candidate="+candidate, 1)
			}
		}
		return f
	}
	for _, candidate := range []string{"24.0.7-0ubuntu4", "(none)"} {
		f := server(candidate)
		if _, err := CheckInstall(context.Background(), f); err == nil || !strings.Contains(err.Error(), "older than Docker 25") {
			t.Errorf("%s: want the check to refuse, got %v", candidate, err)
		}
		if len(f.uploads) > 0 || len(f.appends) > 0 || f.has(aptCall+"install") {
			t.Errorf("%s: the check changed the server: %v", candidate, f.calls)
		}
	}
	f, fresh := server("29.1.3-0ubuntu3~24.04.2"), installFake("")
	if err := install(f, fresh); err != nil {
		t.Fatal(err)
	}
	update, daemon := f.callAt(aptCall+"update"), f.writeAt("/etc/docker/daemon.json", "")
	if update < 0 || daemon < update || !f.has(aptCall+"install -y -q --no-install-recommends docker.io") {
		t.Errorf("update %d daemon.json %d: %v", update, daemon, f.calls)
	}
}

// An old docker.io in apt's index may be the index's age, not the repository's: it is refreshed before
// the refusal stands.
func TestInstallRefreshesAnOldCandidateBeforeRefusing(t *testing.T) {
	old := strings.Replace(emptyNoble, "candidate=27.5.1-0ubuntu3~24.04.2", "candidate=24.0.7-0ubuntu4", 1)
	for fresh, ok := range map[string]bool{"29.1.3-0ubuntu3~24.04.2": true, "24.0.7-0ubuntu4": false} {
		f := installFake(old)
		f.onRun = func(cmd string) {
			if strings.HasPrefix(cmd, aptCall+"update") {
				f.out[factsCall] = strings.Replace(old, "candidate=24.0.7-0ubuntu4", "candidate="+fresh, 1)
			}
		}
		_, err := CheckInstall(context.Background(), f)
		if !f.has(aptCall+"update") || (err == nil) != ok || (!ok && !strings.Contains(err.Error(), "older than Docker 25")) {
			t.Errorf("index refreshed to %s: got %v; %v", fresh, err, f.calls)
		}
	}
}

// aptScript, run by sh against a stand-in apt-get: a lock held by another apt is waited for until the
// deadline, anything else fails at once with apt's words. date and sleep are stand-ins too, so the
// five minutes pass in no time.
func TestAptScriptWaitsForALockAndNothingElse(t *testing.T) {
	run := func(t *testing.T, answers ...string) (string, int, error) {
		t.Helper()
		dir := t.TempDir()
		stub := func(name, body string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		// Each call of apt-get gives the next answer: "ok" succeeds, anything else is printed and fails.
		var script strings.Builder
		script.WriteString("n=$(cat " + dir + "/n 2>/dev/null || echo 0); echo $((n+1)) > " + dir + "/n\ncase $n in\n")
		for i, a := range answers {
			if a == "ok" {
				fmt.Fprintf(&script, "%d) exit 0 ;;\n", i)
			} else {
				fmt.Fprintf(&script, "%d) echo %q; exit 100 ;;\n", i, a)
			}
		}
		script.WriteString("*) echo 'E: Could not get lock /var/lib/apt/lists/lock'; exit 100 ;;\nesac\n")
		stub("apt-get", script.String())
		stub("sleep", "")
		// Every call of date is a minute later than the one before.
		stub("date", "t=$(cat "+dir+"/t 2>/dev/null || echo 0); echo $((t+60)) > "+dir+"/t; echo $t\n")
		cmd := exec.Command("sh", "-c", aptScript, "apt-get", "update", "-q")
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		n, _ := os.ReadFile(filepath.Join(dir, "n"))
		calls, _ := strconv.Atoi(strings.TrimSpace(string(n)))
		return string(out), calls, err
	}
	lock := "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 812 (apt-get)"
	if out, calls, err := run(t, lock, lock, "ok"); err != nil || calls != 3 {
		t.Errorf("a lock let go of: want success on the third try, got %v after %d: %s", err, calls, out)
	}
	if out, calls, err := run(t, "E: Unable to locate package docker.io"); err == nil || calls != 1 || !strings.Contains(out, "Unable to locate") {
		t.Errorf("another failure: want it at once with apt's words, got %v after %d: %s", err, calls, out)
	}
	if out, calls, err := run(t); err == nil || calls < 3 || calls > 7 || !strings.Contains(out, "Could not get lock") {
		t.Errorf("a lock never let go of: want a failure after about five minutes, got %v after %d: %s", err, calls, out)
	}
}

// A failed refresh of the package index stops the install before anything is written.
func TestInstallStopsOnAFailedUpdateBeforeAnyChange(t *testing.T) {
	f, fresh := installFake(emptyNoble), installFake("")
	f.fail[aptCall+"update"] = errors.New("E: Could not get lock")
	if err := install(f, fresh); err == nil || !strings.Contains(err.Error(), "apt-get update") {
		t.Fatalf("got %v", err)
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 || f.has(aptCall+"install") || !f.has(admitGive("_proxy")) {
		t.Errorf("want nothing written and the lock given back: %v %v", f.uploads, f.calls)
	}
}

// dockerd restarts right after daemon.json is written: a step failing later must not leave the keys in
// the file and the daemon without them.
func TestInstallRestartsDockerRightAfterTheWrite(t *testing.T) {
	idle := strings.NewReplacer("running=1\n", "running=0\n", "network=boks-web\n", "", "crontab=yes\n", "").Replace(readyNoble)
	f, fresh := installFake(idle), installFake("")
	f.fail["sudo -n "+aptCall+"install"] = errors.New("E: broken")
	if err := install(f, fresh); err == nil {
		t.Fatal("want the apt failure")
	}
	write, restart := f.callAt(`sudo -n sh -c mkdir -p "$(dirname '/etc/docker/daemon.json')"`), f.callAt("sudo -n systemctl restart docker")
	if write < 0 || restart < write || f.callAt("sudo -n "+aptCall+"install") < restart {
		t.Errorf("want daemon.json written, then dockerd restarted, then apt: write %d restart %d: %v", write, restart, f.calls)
	}
}

// A daemon.json cut short on the way is not moved into place: its length is checked first.
func TestWriteRootChecksTheLength(t *testing.T) {
	f := newFake()
	body := []byte(`{"log-driver": "json-file"}` + "\n")
	if err := writeRoot(context.Background(), f, []string{"sudo", "-n"}, body, "/etc/docker/daemon.json", true); err != nil {
		t.Fatal(err)
	}
	for cmd := range f.stdin {
		if want := "-eq " + strconv.Itoa(len(body)) + " ]"; !strings.Contains(cmd, want) || strings.Index(cmd, want) > strings.Index(cmd, " mv ") {
			t.Errorf("want the length checked before the move: %s", cmd)
		}
	}
	if len(f.stdin) != 1 {
		t.Errorf("writes: %v", f.stdin)
	}
}

func TestInstallRefusesUnderTheLockBeforeAnyChange(t *testing.T) {
	f := installFake(emptyNoble + `listen=LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=700,fd=6))` + "\n")
	fresh := installFake("")
	err := install(f, fresh)
	if err == nil || !strings.Contains(err.Error(), "nginx") {
		t.Fatalf("want a refusal naming nginx, got %v", err)
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 || f.has(aptCall) || len(fresh.calls) > 0 || !f.has(admitGive("_proxy")) {
		t.Errorf("want nothing changed and the lock given back: %v", f.calls)
	}
}

func TestInstallJournalsAFailedStep(t *testing.T) {
	f, fresh := installFake(emptyNoble), installFake("")
	f.fail[aptCall+"install"] = errors.New("E: Unable to locate package")
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

// Where Docker answers, daemon.json is checked by dockerd before it replaces the old one — also when the
// SSH user's PATH has no dockerd (Debian keeps it in /usr/sbin), since the check runs under sudo.
func TestInstallValidatesDaemonJSONWhereDockerRuns(t *testing.T) {
	idle := strings.NewReplacer("running=1\n", "running=0\n", "network=boks-web\n", "", "dockerd=yes\n", "").Replace(readyNoble)
	f, fresh := installFake(idle), installFake("")
	if err := install(f, fresh); err != nil {
		t.Fatal(err)
	}
	validated := false
	for cmd := range f.stdin {
		validated = validated || strings.Contains(cmd, "/etc/docker/daemon.json") && strings.Contains(cmd, "dockerd --validate")
	}
	if !validated {
		t.Errorf("daemon.json not validated: %v", f.stdin)
	}
}
