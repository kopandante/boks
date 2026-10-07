package deploy

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// withListen is a routeless app publishing two ports on private addresses of its one server.
const withListen = noPorts + `listen:
  - {port: 6379, address: 10.88.0.5, host_port: 6390}
  - {port: 5432, address: "fd00::5"}
`

// hostAddrsOut is `ip -o addr show` of a server on WireGuard 10.88.0.5, with a ULA beside it.
const hostAddrsOut = `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 136.234.12.162/24 brd 136.234.12.255 scope global eth0\       valid_lft forever preferred_lft forever
9: wg0    inet 10.88.0.5/24 scope global wg0\       valid_lft forever preferred_lft forever
9: wg0    inet6 fd00::5/64 scope global \       valid_lft forever preferred_lft forever`

// published is one container of the inventory, on no network, publishing ports as docker records them.
func published(name, app string, running bool, ports string) string {
	r := "false"
	if running {
		r = "true"
	}
	return `{"id":"0123456789abcdef","name":"/` + name + `","hostname":"h","labels":{"boks.app":"` + app + `"},"networks":{},` +
		`"ports":` + ports + `,"running":` + r + `,"health":""}`
}

func listenFake() *fake {
	f := routelessFake("healthy")
	f.out["ip -o addr show"] = hostAddrsOut
	return f
}

// The container's ports go to `docker run -p` on the address the config names, and nowhere else,
// and the release records them.
func TestListenPublishesOnThePrivateAddress(t *testing.T) {
	f := listenFake()
	if err := Run(context.Background(), f, io.Discard, parse(t, withListen), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	run := f.calls[f.callAt("docker run")]
	if !strings.Contains(run, " -p 10.88.0.5:6390:6379/tcp -p [fd00::5]:5432:5432/tcp ") {
		t.Errorf("the ports must be published on the private addresses: %s", run)
	}
	if strings.Count(run, " -p ") != 2 {
		t.Errorf("nothing else is published: %s", run)
	}
	snap := f.uploads[".boks/bot/releases/bot-v2-1700000000.json"]
	if !strings.Contains(snap, `"address": "10.88.0.5"`) || !strings.Contains(snap, `"host_port": 6390`) || !strings.Contains(snap, `"address": "fd00::5"`) {
		t.Errorf("the release must record what it published: %s", snap)
	}
	// An app without listen publishes nothing, as before.
	g := routelessFake("healthy")
	if err := Run(context.Background(), g, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if run := g.calls[g.callAt("docker run")]; strings.Contains(run, " -p ") || g.has("ip -o addr") {
		t.Errorf("an app without listen publishes nothing and asks nothing: %s", run)
	}
}

// docker could not publish on an address the server lacks — a WireGuard address while the tunnel is
// down — and would say so at `docker run`, after stop-first took the running copy down. Refused first.
func TestListenRefusesAnAddressTheServerLacks(t *testing.T) {
	for name, addrs := range map[string]string{
		"another server's address": strings.Replace(hostAddrsOut, "10.88.0.5", "10.88.0.4", 1),
		"the tunnel is down":       strings.Split(hostAddrsOut, "\n9:")[0],
		"no answer":                "",
	} {
		f := listenFake()
		f.out["ip -o addr show"] = addrs
		err := Run(context.Background(), f, io.Discard, parse(t, withListen), "v2", quick())
		if err == nil || !strings.Contains(err.Error(), "is not an address of this server") || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
		if !changedNothing(f) {
			t.Errorf("%s: the refusal must come first: %v", name, f.calls)
		}
	}
	f := listenFake()
	f.fail["ip -o addr show"] = io.ErrUnexpectedEOF
	if err := Run(context.Background(), f, io.Discard, parse(t, withListen), "v2", quick()); err == nil || !changedNothing(f) {
		t.Errorf("a failed listing is a refusal, not an answer: %v %v", err, f.calls)
	}
}

// One host port takes one container: a port a running container of another owner publishes on the
// address, or on every address, is refused before anything changes. The app's own copies are
// stopped first, and a stopped container, another address or another protocol hold nothing.
func TestListenRefusesAPortAnotherContainerPublishes(t *testing.T) {
	for name, line := range map[string]string{
		"on the address":       published("cache-v1-1", "cache", true, `{"6379/tcp":[{"HostIp":"10.88.0.5","HostPort":"6390"}]}`),
		"on every address":     published("boks-proxy", "", true, `{"6390/tcp":[{"HostIp":"","HostPort":"6390"}]}`),
		"on 0.0.0.0":           published("x", "other", true, `{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"6390"}]}`),
		"on :: for the ULA":    published("x", "other", true, `{"80/tcp":[{"HostIp":"::","HostPort":"5432"}]}`),
		"on the ULA":           published("x", "other", true, `{"5432/tcp":[{"HostIp":"fd00::5","HostPort":"5432"}]}`),
		"by a container of no": published("x", "", true, `{"5432/tcp":[{"HostIp":"10.88.0.5","HostPort":"6390"}]}`),
	} {
		f := listenFake()
		f.out[boxes] = line
		err := Run(context.Background(), f, io.Discard, parse(t, withListen), "v2", quick())
		if err == nil || !strings.Contains(err.Error(), "one host port takes one container") || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
		if !changedNothing(f) {
			t.Errorf("%s: the refusal must come first: %v", name, f.calls)
		}
	}
	for name, line := range map[string]string{
		"the app's own copy":  published("bot-v1-1", "bot", true, `{"6379/tcp":[{"HostIp":"10.88.0.5","HostPort":"6390"}]}`),
		"a stopped container": published("x", "other", false, `{"6379/tcp":[{"HostIp":"10.88.0.5","HostPort":"6390"}]}`),
		"another address":     published("x", "other", true, `{"6379/tcp":[{"HostIp":"10.88.0.4","HostPort":"6390"}]}`),
		"another port":        published("x", "other", true, `{"6379/tcp":[{"HostIp":"10.88.0.5","HostPort":"6379"}]}`),
		"udp":                 published("x", "other", true, `{"6390/udp":[{"HostIp":"10.88.0.5","HostPort":"6390"}]}`),
		"no bindings":         published("x", "other", true, `null`),
	} {
		f := listenFake()
		f.out[boxes] = line
		if err := Run(context.Background(), f, io.Discard, parse(t, withListen), "v2", quick()); err != nil {
			t.Errorf("%s: no conflict, got %v", name, err)
		}
	}
}

// What runs on the server can change while a deploy pulls: the port is asked again once the server's
// admission is held, and a container that took it meanwhile stops the deploy before the running copy.
func TestListenIsAskedAgainUnderAdmission(t *testing.T) {
	f := listenFake()
	asked := 0
	f.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, boxes) {
			if asked++; asked == 2 {
				f.out[boxes] = published("cache-v1-1", "cache", true, `{"6379/tcp":[{"HostIp":"10.88.0.5","HostPort":"6390"}]}`)
			}
		}
	}
	err := Run(context.Background(), f, io.Discard, parse(t, withListen), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "cache-v1-1 already publishes 10.88.0.5:6390") {
		t.Fatalf("want a refusal under admission, got %v", err)
	}
	if f.has("docker stop") || f.has("docker run") || f.callAt("docker pull") > f.lastAt(boxes) {
		t.Errorf("the second answer comes after the pull and before any stop: %v", f.calls)
	}
}

// A rollback publishes what its release published, not what today's config says, and says so when
// that is nothing; a recorded publication the config would refuse is refused before anything stops.
func TestRollbackRestoresTheListenOfTheRelease(t *testing.T) {
	const v1 = `{"version":10,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1","digest":"sha256:old","ports":[],
		"networks":[{"name":"boks-bot","aliases":["bot"]}],"env_path":".boks/bot/bot-v1-1.env","replace":"stop-first",
		"listen":[{"port":6379,"address":"10.88.0.5","host_port":6390}]}`
	f := botReleases("healthy")
	f.out["ip -o addr show"] = hostAddrsOut
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = v1
	if err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick()); err != nil {
		t.Fatal(err)
	}
	if run := f.calls[f.callAt("docker run")]; !strings.Contains(run, " -p 10.88.0.5:6390:6379/tcp ") || strings.Count(run, " -p ") != 1 {
		t.Errorf("the restored copy must publish what its release did: %s", run)
	}

	g := botReleases("healthy")
	g.out["ip -o addr show"] = hostAddrsOut
	var log bytes.Buffer
	if err := Rollback(context.Background(), g, &log, parse(t, withListen), "", quick()); err != nil {
		t.Fatal(err)
	}
	if run := g.calls[g.callAt("docker run")]; strings.Contains(run, " -p ") {
		t.Errorf("a release recorded without listen publishes nothing: %s", run)
	}
	if !strings.Contains(log.String(), "recorded without listen") {
		t.Errorf("the rollback must say the clients on other servers lose it: %s", log.String())
	}

	for name, snap := range map[string]string{
		"a public address": strings.Replace(v1, "10.88.0.5", "136.234.12.162", 1),
		"every address":    strings.Replace(v1, "10.88.0.5", "0.0.0.0", 1),
		"an overlap":       strings.Replace(strings.Replace(v1, `"stop-first"`, `"overlap"`, 1), `"ports":[]`, `"ports":[{"name":"w","port":3000,"host":"w.example.com"}]`, 1),
	} {
		h := botReleases("healthy")
		h.out["ip -o addr show"] = hostAddrsOut
		h.out["cat .boks/bot/releases/bot-v1-1.json"] = snap
		err := Rollback(context.Background(), h, io.Discard, parse(t, noPorts), "", quick())
		if err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
		if h.has("docker stop") || h.has("docker run") {
			t.Errorf("%s: the running copy must be left alone: %v", name, h.calls)
		}
	}
	// And the address of the release must be on the server, as for a deploy.
	k := botReleases("healthy")
	k.out["cat .boks/bot/releases/bot-v1-1.json"] = v1
	if err := Rollback(context.Background(), k, io.Discard, parse(t, noPorts), "", quick()); err == nil || k.has("docker stop") {
		t.Errorf("an address the server lacks refuses the rollback first: %v %v", err, k.calls)
	}
}

// A fleet rollback asks every server before the first changes: the release's address is among it.
func TestCheckRollbackAsksForTheListenAddress(t *testing.T) {
	f := botReleases("healthy")
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = `{"version":10,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1",
		"ports":[],"networks":[{"name":"boks-bot","aliases":["bot"]}],"env_path":".boks/bot/bot-v1-1.env","replace":"stop-first",
		"listen":[{"port":6379,"address":"10.88.0.5"}]}`
	if _, err := CheckRollback(context.Background(), f, parse(t, noPorts), ""); err == nil || !strings.Contains(err.Error(), "not an address of this server") {
		t.Errorf("want a refusal, got %v", err)
	}
	f.out["ip -o addr show"] = hostAddrsOut
	if _, err := CheckRollback(context.Background(), f, parse(t, noPorts), ""); err != nil {
		t.Errorf("want it taken, got %v", err)
	}
}
