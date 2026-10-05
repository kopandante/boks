package deploy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

const (
	kamalList  = "docker exec boks-proxy kamal-proxy list --json"
	appsListed = "sh -c for d in .boks/*/"
	proxyState = "docker ps -a --filter name=^boks-proxy$"
)

// kamalServer is a server where kamal-proxy, as an earlier boks ran it, routes convex-lab's two hosts
// to its running copy; the current release records them, one under the wildcard certificate. What
// kamal-proxy v0.10.0 prints for `list --json`, in shape.
func kamalServer() *fake {
	f := newFake()
	f.out[proxyState] = "running\t"
	f.out[kamalList] = `{"convex-lab.api":{"hosts":["api.lab.example.com"],"path_prefixes":["/"],"tls":true,` +
		`"targets":["convex-lab-latest-1:3210"],"read_targets":[],"state":"running"},` +
		`"convex-lab.site":{"hosts":["site.other.com"],"tls":true,"targets":["convex-lab-latest-1:3211"]}}`
	f.out[appsListed] = "convex-lab"
	f.out["sh -c cat '.boks/convex-lab/current'"] = "convex-lab-latest-1\n"
	f.out["cat .boks/convex-lab/releases/convex-lab-latest-1.json"] = `{"version":6,"id":"convex-lab-latest-1","app":"convex-lab",` +
		`"image":"ghcr.io/get-convex/convex-backend","tag":"latest","tls":true,"cert_domains":["*.lab.example.com"],` +
		`"ports":[{"name":"api","port":3210,"host":"api.lab.example.com"},{"name":"site","port":3211,"host":"site.other.com"}]}`
	// The container under the proxy's name changes as the swap goes: kamal-proxy moves aside, then
	// Caddy is created there.
	f.onRun = func(cmd string) {
		switch {
		case strings.HasPrefix(cmd, "docker rename boks-proxy boks-proxy.kamal"):
			f.out[proxyState] = ""
		case strings.HasPrefix(cmd, "docker create --name boks-proxy"):
			f.out[proxyState] = "created\tcaddy"
		case strings.HasPrefix(cmd, "docker start boks-proxy"):
			f.out[proxyState] = "running\tcaddy"
		}
	}
	return f
}

// The routes Caddy gets are the current release's hosts, TLS and certificate, dialling the container
// kamal-proxy sends each host to now; they are on disk before kamal-proxy stops, the image is pulled
// before it stops, and Caddy takes its name, ports and networks. Every app's deploy lock is held.
func TestMigrateMovesEveryRouteToCaddy(t *testing.T) {
	f := kamalServer()
	if err := MigrateProxy(context.Background(), f, io.Discard, "caddy:2.11.7-alpine", fixed); err != nil {
		t.Fatal(err)
	}
	frag := f.fragmentWrite("convex-lab")
	for _, want := range []string{`"dial": "convex-lab-latest-1:3210"`, `"dial": "convex-lab-latest-1:3211"`,
		`"certificate": "/certs/boks/_.lab.example.com.crt"`} {
		if !strings.Contains(frag, want) {
			t.Errorf("fragment lacks %s:\n%s", want, frag)
		}
	}
	if strings.Count(frag, `"cert"`) != 1 || strings.Count(frag, `"tls": true`) != 2 {
		t.Errorf("both hosts TLS, only the one under the wildcard from its file:\n%s", frag)
	}
	locked, pulled, written := f.at("mkdir /tmp/boks-convex-lab.lock"), f.at("docker pull caddy:2.11.7-alpine"), f.writeAt(".boks/_proxy/caddy.json", "convex-lab")
	stopped, aside, created, started := f.at("docker stop boks-proxy"), f.at("docker rename boks-proxy boks-proxy.kamal"),
		f.at("docker create --name boks-proxy"), f.at("docker start boks-proxy")
	if locked < 0 || pulled < locked || written < pulled || stopped < written || aside < stopped || created < aside || started < created {
		t.Errorf("want lock < pull < files < stop < aside < create < start: %d %d %d %d %d %d %d\n%v",
			locked, pulled, written, stopped, aside, created, started, f.calls)
	}
	if !f.has("docker rm boks-proxy.kamal") || f.has("docker exec boks-proxy caddy reload") || !f.has("rmdir /tmp/boks-convex-lab.lock") {
		t.Errorf("kamal-proxy goes once Caddy serves; nothing is reloaded, the locks are given back: %v", f.calls)
	}
}

// A host kamal-proxy routes and no recorded release describes would be dropped by Caddy: refused,
// with kamal-proxy and the files untouched.
func TestMigrateRefusesToDropAHost(t *testing.T) {
	f := kamalServer()
	f.out[kamalList] = strings.Replace(f.out[kamalList], `"site.other.com"`, `"site.other.com","hand.made.com"`, 1)
	err := MigrateProxy(context.Background(), f, io.Discard, "caddy:2.11.7-alpine", fixed)
	if err == nil || !strings.Contains(err.Error(), "hand.made.com") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("want the host named, got %v", err)
	}
	if f.has("docker stop") || f.has("docker pull") || proxyWrites(f) {
		t.Errorf("nothing may change: %v %v", f.calls, f.uploads)
	}
	// One host spread over two containers has no one place to go.
	g := kamalServer()
	g.out[kamalList] = strings.Replace(g.out[kamalList], `"targets":["convex-lab-latest-1:3211"]`, `"targets":["convex-lab-latest-1:3211","convex-lab-latest-2:3211"]`, 1)
	if err := MigrateProxy(context.Background(), g, io.Discard, "img", fixed); err == nil || g.has("docker stop") {
		t.Errorf("want a refusal, got %v %v", err, g.calls)
	}
}

// A deploy in progress holds its app's lock; the migration would race it, so it refuses and gives
// back the locks it took.
func TestMigrateWaitsForNoDeploy(t *testing.T) {
	f := kamalServer()
	f.fail["mkdir /tmp/boks-convex-lab.lock"] = errors.New("File exists")
	err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed)
	if err == nil || !strings.Contains(err.Error(), "in progress") || f.has("docker stop") || f.has("rmdir /tmp/boks-convex-lab.lock") {
		t.Errorf("want a refusal that leaves the other run's lock alone: %v %v", err, f.calls)
	}
	if !f.has(admitGive("_proxy")) {
		t.Errorf("the admission lock is given back: %v", f.calls)
	}
}

// Caddy that does not come up is removed and kamal-proxy put back under its name, routes and all.
func TestMigratePutsKamalBackWhenCaddyFails(t *testing.T) {
	f := kamalServer()
	f.out[migrateReq] = "0" // a Caddy that starts, and is refused
	err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed)
	if err == nil || !strings.Contains(err.Error(), "Caddy did not come up") {
		t.Fatalf("want Caddy's failure, got %v", err)
	}
	removed, back, restarted := f.at("docker rm -f boks-proxy"), f.at("docker rename boks-proxy.kamal boks-proxy"), f.lastAt("docker start boks-proxy")
	if removed < 0 || back < removed || restarted < back {
		t.Errorf("want Caddy removed, kamal-proxy renamed back and started: %d %d %d %v", removed, back, restarted, f.calls)
	}
	if f.has("docker rm boks-proxy.kamal") {
		t.Errorf("kamal-proxy must survive: %v", f.calls)
	}
}

// A server already on Caddy is only booted; one without any proxy has nothing to move.
func TestMigrateIsIdempotent(t *testing.T) {
	f := newFake()
	f.out[proxyState] = caddyUp
	var log strings.Builder
	if err := MigrateProxy(context.Background(), f, &log, "img", fixed); err != nil || !strings.Contains(log.String(), "Caddy already") || f.has(kamalList) {
		t.Errorf("want a boot only: %v %q %v", err, log.String(), f.calls)
	}
	g := newFake()
	if err := MigrateProxy(context.Background(), g, &log, "img", fixed); err != nil || g.has("docker create") || g.has("docker pull") {
		t.Errorf("no proxy, nothing to move: %v %v", err, g.calls)
	}
	// A stopped kamal-proxy cannot say where its routes go.
	h := kamalServer()
	h.out[proxyState] = "exited\t"
	if err := MigrateProxy(context.Background(), h, &log, "img", fixed); err == nil || h.has("docker rename") {
		t.Errorf("want a refusal, got %v", err)
	}
}
