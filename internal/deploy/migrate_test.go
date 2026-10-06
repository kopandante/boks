package deploy

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

const (
	kamalList  = "docker exec boks-proxy kamal-proxy list --json"
	kamalCat   = "docker exec boks-proxy cat /home/kamal-proxy/.config/kamal-proxy/kamal-proxy.state"
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
	f.out[kamalCat] = `[{"name":"convex-lab.api","options":{"hosts":["api.lab.example.com"],"tls_enabled":true,` +
		`"tls_certificate_path":"/certs/boks/_.lab.example.com.crt","tls_private_key_path":"/certs/boks/_.lab.example.com.key"}},` +
		`{"name":"convex-lab.site","options":{"hosts":["site.other.com"],"tls_enabled":true,"tls_certificate_path":"","tls_private_key_path":""}}]`
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
	// kamal-proxy's targets are read once no deploy can move them: after every app's lock.
	if read := f.at(kamalList); read < locked {
		t.Errorf("want kamal-proxy's routes read after the app locks: %d %d", read, locked)
	}
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
}

// kamal-proxy stopped under its own name — a migration cut after stopping it, before moving it aside —
// is started again and migrated, not left down.
func TestMigrateResumesAfterACutStop(t *testing.T) {
	f := kamalServer()
	f.out[proxyState] = "exited\t"
	inner := f.onRun
	f.onRun = func(cmd string) {
		if cmd == "docker start boks-proxy" && f.out[proxyState] == "exited\t" {
			f.out[proxyState] = "running\t"
			return
		}
		inner(cmd)
	}
	if err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	started, read, created := f.at("docker start boks-proxy"), f.at(kamalList), f.at("docker create --name boks-proxy")
	if started < 0 || read < started || created < read {
		t.Errorf("want kamal-proxy started, its routes read, then Caddy: %d %d %d %v", started, read, created, f.calls)
	}
}

const asideState = `docker ps -a --filter name=^boks-proxy\.kamal$`

// TLS and its certificate are taken from kamal-proxy as it serves the host now: a rollback keeps
// today's tls and cert and points current at a release recorded with others, and the migration must
// neither turn HTTPS off nor bring back a certificate the host no longer uses.
func TestMigrateKeepsTheTLSKamalServes(t *testing.T) {
	f := kamalServer()
	f.out["cat .boks/convex-lab/releases/convex-lab-latest-1.json"] = strings.NewReplacer(`"tls":true`, `"tls":false`,
		`"cert_domains":["*.lab.example.com"]`, `"cert_domains":["api.lab.example.com"]`).Replace(
		f.out["cat .boks/convex-lab/releases/convex-lab-latest-1.json"])
	if err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	if frag := f.fragmentWrite("convex-lab"); strings.Count(frag, `"tls": true`) != 2 || strings.Count(frag, `"cert"`) != 1 ||
		!strings.Contains(frag, "/certs/boks/_.lab.example.com.crt") {
		t.Errorf("want both hosts on TLS, the api host from the wildcard file, as kamal-proxy serves them:\n%s", frag)
	}
	// kamal-proxy's certificates unread: refused, nothing changed.
	h := kamalServer()
	h.fail[kamalCat] = errors.New("No such file")
	if err := MigrateProxy(context.Background(), h, io.Discard, "img", fixed); err == nil || h.has("docker stop") || proxyWrites(h) {
		t.Errorf("want a refusal that changes nothing: %v", err)
	}
	// And a host kamal-proxy serves without TLS stays so, certificate or not.
	g := kamalServer()
	g.out[kamalList] = strings.ReplaceAll(g.out[kamalList], `"tls":true`, `"tls":false`)
	if err := MigrateProxy(context.Background(), g, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	if frag := g.fragmentWrite("convex-lab"); strings.Contains(frag, `"tls": true`) || strings.Contains(frag, `"cert"`) {
		t.Errorf("want plain HTTP as kamal-proxy serves it:\n%s", frag)
	}
}

// A migration cut after kamal-proxy moved aside, before Caddy came up, leaves no boks-proxy at all.
// The next one puts kamal-proxy back and migrates, rather than reporting a server without a proxy.
func TestMigrateResumesASwapCutShort(t *testing.T) {
	f := kamalServer()
	f.out[proxyState] = ""
	f.out[asideState] = "boks-proxy.kamal"
	inner := f.onRun
	f.onRun = func(cmd string) {
		switch {
		case strings.HasPrefix(cmd, "docker rename boks-proxy.kamal boks-proxy"):
			f.out[proxyState], f.out[asideState] = "exited\t", ""
		case strings.HasPrefix(cmd, "docker start boks-proxy") && f.out[proxyState] == "exited\t":
			f.out[proxyState] = "running\t"
		default:
			if strings.HasPrefix(cmd, "docker rename boks-proxy boks-proxy.kamal") {
				f.out[asideState] = "boks-proxy.kamal"
			}
			inner(cmd)
		}
	}
	if err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	back, read, created := f.at("docker rename boks-proxy.kamal boks-proxy"), f.at(kamalList), f.at("docker create --name boks-proxy")
	if back < 0 || read < back || created < read || f.fragmentWrite("convex-lab") == "" {
		t.Errorf("want kamal-proxy back, its routes read, then Caddy: %d %d %d %v", back, read, created, f.calls)
	}
}

// Caddy in place with kamal-proxy still aside — a migration cut before the removal — is booted and
// kamal-proxy removed; kamal-proxy's routes are never read again, they are stale by then.
func TestMigrateFinishesWhenCaddyServesAndKamalWaitsAside(t *testing.T) {
	f := newFake()
	f.out[proxyState] = caddyUp
	f.out[asideState] = "boks-proxy.kamal"
	if err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker rm boks-proxy.kamal") || f.has(kamalList) || f.has("docker rename") {
		t.Errorf("want kamal-proxy removed and nothing else: %v", f.calls)
	}
	// A removal that fails is reported as such, not as done; Caddy serves either way.
	h := newFake()
	h.out[proxyState] = caddyUp
	h.out[asideState] = "boks-proxy.kamal"
	h.fail["docker rm boks-proxy.kamal"] = errors.New("connection lost")
	var log strings.Builder
	if err := MigrateProxy(context.Background(), h, &log, "img", fixed); err != nil || strings.Contains(log.String(), "is removed") ||
		!strings.Contains(log.String(), "could not be removed") {
		t.Errorf("want the failed removal reported: %v %q", err, log.String())
	}
	// A Caddy that does not come up then is reported, and kamal-proxy, stale, is not put back on its own.
	g := newFake()
	g.out[proxyState] = caddyUp
	g.out[asideState] = "boks-proxy.kamal"
	g.out[migrateReq] = "0"
	err := MigrateProxy(context.Background(), g, io.Discard, "img", fixed)
	if err == nil || g.has("docker rename") || g.has("docker rm") {
		t.Errorf("want the failure reported and both containers kept: %v %v", err, g.calls)
	}
	// Caddy may well be serving, and kamal-proxy's routes are stale: the advice is to migrate again, and
	// to put kamal-proxy back only as the last resort.
	if err != nil && (!strings.Contains(err.Error(), "run `boks proxy migrate` again") || !strings.Contains(err.Error(), "only if Caddy cannot serve")) {
		t.Errorf("want migrate again first, kamal-proxy back only if Caddy cannot serve: %v", err)
	}
}

// A rename whose answer was lost after it went through: kamal-proxy is found under the aside name
// and put back, not started under a name it no longer has.
func TestMigratePutsKamalBackAfterALostRename(t *testing.T) {
	f := kamalServer()
	f.fail["docker rename boks-proxy boks-proxy.kamal"] = errors.New("connection lost")
	err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed)
	if err == nil || !strings.Contains(err.Error(), "moving kamal-proxy aside") {
		t.Fatalf("want the failure, got %v", err)
	}
	back, started := f.at("docker rename boks-proxy.kamal boks-proxy"), f.lastAt("docker start boks-proxy")
	if back < 0 || started < back || f.has("docker create") {
		t.Errorf("want kamal-proxy renamed back and started: %v", f.calls)
	}
	// A rename that did not happen leaves kamal-proxy under its name: it is only started again.
	g := kamalServer()
	g.fail["docker rename boks-proxy boks-proxy.kamal"] = errors.New("refused")
	inner := g.onRun
	g.onRun = func(cmd string) {
		if !strings.HasPrefix(cmd, "docker rename") {
			inner(cmd)
		}
	}
	if err := MigrateProxy(context.Background(), g, io.Discard, "img", fixed); err == nil || g.has("docker rename boks-proxy.kamal") || !g.has("docker start boks-proxy") {
		t.Errorf("want kamal-proxy started where it is: %v %v", err, g.calls)
	}
	// A stop that may still be finishing is waited for: stopped again, then started.
	if stop, start := g.lastAt("docker stop boks-proxy"), g.lastAt("docker start boks-proxy"); start < stop {
		t.Errorf("want stop, then start: %v", g.calls)
	}
}

// Fragments are exactly what kamal-proxy serves: what an earlier, cut migration left is removed before
// the new ones are written — an app with no routes now would have Caddy route its hosts to retired
// copies, and a host since moved to another app would refuse the new fragments.
func TestMigrateDropsTheFragmentsACutMigrationLeft(t *testing.T) {
	f := kamalServer()
	gone := fragment(t, "gone", "gone-v1-1", config.Port{Name: "web", Port: 80, Host: "gone.example.com"})
	// A host kamal-proxy now sends to convex-lab, left in another app's fragment.
	moved := fragment(t, "other", "other-v1-1", config.Port{Name: "web", Port: 80, Host: "api.lab.example.com"})
	f.out[frags] = gone + "\n" + moved
	inner := f.onRun
	f.onRun = func(cmd string) {
		inner(cmd)
		switch cmd {
		case "rm -f .boks/_proxy/routes/gone.json":
			f.out[frags] = strings.Replace(f.out[frags], gone, "", 1)
		case "rm -f .boks/_proxy/routes/other.json":
			f.out[frags] = strings.Replace(f.out[frags], moved, "", 1)
		}
	}
	if err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	stopped := f.at("docker stop boks-proxy")
	for _, rm := range []string{"rm -f .boks/_proxy/routes/gone.json", "rm -f .boks/_proxy/routes/other.json"} {
		if at := f.at(rm); at < 0 || stopped < at {
			t.Errorf("want %q before kamal-proxy stops: %v", rm, f.calls)
		}
	}
	if !strings.Contains(f.fragmentWrite("convex-lab"), "api.lab.example.com") {
		t.Errorf("want convex-lab's fragment written: %q", f.fragmentWrite("convex-lab"))
	}
}

// The host moved between two apps that both still have routes: the stale fragment of one is removed
// before the other's new fragment is checked against it.
func TestMigrateRetriesAfterAHostMovedBetweenApps(t *testing.T) {
	f := kamalServer()
	f.out[appsListed] = "aaa\nconvex-lab"
	f.out["sh -c cat '.boks/aaa/current'"] = "aaa-1\n"
	f.out["cat .boks/aaa/releases/aaa-1.json"] = `{"version":6,"id":"aaa-1","app":"aaa","image":"x","tag":"1","tls":false,` +
		`"ports":[{"name":"web","port":80,"host":"moved.example.com"}]}`
	f.out[kamalList] = strings.TrimSuffix(f.out[kamalList], "}") + `,"aaa.web":{"hosts":["moved.example.com"],"tls":false,"targets":["aaa-1:80"]}}`
	stale := fragment(t, "convex-lab", "convex-lab-old", config.Port{Name: "web", Port: 80, Host: "moved.example.com"})
	f.out[frags] = stale
	inner := f.onRun
	f.onRun = func(cmd string) {
		inner(cmd)
		if cmd == "rm -f .boks/_proxy/routes/convex-lab.json" {
			f.out[frags] = ""
		}
	}
	if err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.fragmentWrite("aaa"), "moved.example.com") {
		t.Errorf("want aaa's fragment written: %v", f.calls)
	}
}

// A deploy lock this run did not take is an app's first deploy, with no current release to lock it by:
// it could still add a route to kamal-proxy after the read, so the migration refuses, changing nothing.
func TestMigrateRefusesWhileAFirstDeployRuns(t *testing.T) {
	f := kamalServer()
	f.out["sh -c for d in /tmp/boks-*.lock"] = "/tmp/boks-convex-lab.lock\n/tmp/boks-newapp.lock"
	err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed)
	if err == nil || !strings.Contains(err.Error(), "newapp") || f.has("docker stop") || f.has(kamalList) || proxyWrites(f) {
		t.Errorf("want a refusal naming newapp, nothing changed: %v %v", err, f.calls)
	}
}

// A stop whose answer was lost after it went through: kamal-proxy is started again, not left down.
func TestMigrateStartsKamalAgainAfterAFailedStop(t *testing.T) {
	f := kamalServer()
	f.fail["docker stop boks-proxy"] = errors.New("connection lost")
	inner, stops := f.onRun, 0
	f.onRun = func(cmd string) {
		inner(cmd)
		if cmd == "docker stop boks-proxy" {
			if stops++; stops > 1 {
				delete(f.fail, "docker stop boks-proxy") // the connection is back for the next call
			}
		}
	}
	err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed)
	if err == nil || !strings.Contains(err.Error(), "stopping kamal-proxy") || !f.has("docker start boks-proxy") || f.has("docker rename") {
		t.Errorf("want kamal-proxy started where it is: %v %v", err, f.calls)
	}
}

// BootProxy runs what follows the boot — a certificate's install and reload — under the same admission
// lock, after the boot, and not at all when the boot fails; its error is the command's.
func TestBootProxyRunsTheCertificateStepUnderTheLock(t *testing.T) {
	f := newFake()
	f.out[proxyState] = caddyUp
	ran := -1
	err := BootProxy(context.Background(), f, io.Discard, "img", func() error {
		ran = len(f.calls)
		return errors.New("reload refused")
	})
	if err == nil || err.Error() != "reload refused" {
		t.Errorf("want the step's error, got %v", err)
	}
	// BootProxy stamps its lock with the clock, not the fixed time of the other tests.
	taken, given := f.at("ln -sn _proxy."), f.lastAt(`sh -c [ "$(readlink /tmp/boks.admit.lock)" = '_proxy.`)
	if ran < 0 || taken < 0 || ran <= taken || given < ran {
		t.Errorf("want lock < boot < step < release: %d %d %d %v", taken, ran, given, f.calls)
	}
	g := newFake()
	g.out[proxyState] = "running\t" // kamal-proxy: the boot refuses
	called := false
	if err := BootProxy(context.Background(), g, io.Discard, "img", func() error { called = true; return nil }); err == nil || called {
		t.Errorf("want the boot's refusal and no step: %v %v", err, called)
	}
}

// The advice printed when kamal-proxy cannot be put back holds whichever step failed: here kamal-proxy
// is renamed back and its start fails, so it lies under its own name with nothing aside, and the advice
// must start it rather than delete it. Run against a stub docker from both states.
func TestMigrateAdviceKeepsARestoredKamal(t *testing.T) {
	f := kamalServer()
	f.out[proxyState] = ""
	f.out[asideState] = "boks-proxy.kamal"
	f.fail["docker start boks-proxy"] = errors.New("connection lost")
	err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed)
	if err == nil || !strings.Contains(err.Error(), "could not be put back") {
		t.Fatalf("want the failure to put kamal-proxy back, got %v", err)
	}
	msg := err.Error()
	end := strings.LastIndex(msg, "`")
	start := strings.LastIndex(msg[:max(end, 0)], "`")
	if start < 0 || end <= start {
		t.Fatalf("no command in %q", msg)
	}
	advice := msg[start+1 : end]
	dir := t.TempDir()
	stub := "#!/bin/sh\necho \"$*\" >> \"$DIR/calls\"\n" +
		"[ \"$1 $2 $3\" = 'container inspect boks-proxy.kamal' ] && { [ \"$ASIDE\" = 1 ]; exit; }\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		aside string
		want  []string
	}{
		{"", []string{"container inspect boks-proxy.kamal", "start boks-proxy"}},
		{"1", []string{"container inspect boks-proxy.kamal", "rm -f boks-proxy", "rename boks-proxy.kamal boks-proxy", "start boks-proxy"}},
	} {
		_ = os.Remove(filepath.Join(dir, "calls"))
		cmd := exec.Command("sh", "-c", advice)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "DIR="+dir, "ASIDE="+c.aside)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("advice %q failed: %v %s", advice, err, out)
		}
		calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
		if got := strings.Split(strings.TrimSpace(string(calls)), "\n"); !slices.Equal(got, c.want) {
			t.Errorf("aside=%q: advice ran %q, want %q", c.aside, got, c.want)
		}
	}
}

// A kamal-proxy that never routed anything — booted by `boks cert issue` before the first deploy —
// has no state file (kamal-proxy v0.10.0 writes it on the first deploy): it is migrated, not refused
// for want of a file it never had, since every later deploy on that server refuses until it is.
func TestMigrateTakesAKamalThatNeverRouted(t *testing.T) {
	f := kamalServer()
	f.out[kamalList] = "{}"
	f.out[appsListed] = ""
	f.fail[kamalCat] = errors.New("cat: can't open kamal-proxy.state: No such file or directory")
	if err := MigrateProxy(context.Background(), f, io.Discard, "img", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker create --name boks-proxy") || !f.has("docker rm boks-proxy.kamal") {
		t.Errorf("want Caddy in kamal-proxy's place: %v", f.calls)
	}
}
