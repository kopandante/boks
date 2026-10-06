package deploy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
)

// boxLine is one container as the inventory prints it, attached to boks-demo with these aliases.
func boxLine(name, app, hostname, aliases string) string {
	labels := `{}`
	if app != "" {
		labels = `{"boks.app":"` + app + `"}`
	}
	return `{"id":"0123456789abcdef","name":"/` + name + `","hostname":"` + hostname + `","labels":` + labels +
		`,"networks":{"boks-demo":{"Aliases":` + aliases + `,"DNSNames":null}}}`
}

// changedNothing reports a run that refused before anything of the app or the server changed.
func changedNothing(f *fake) bool {
	return !f.has("docker pull") && !f.has("docker network create") && !f.has("docker network connect") &&
		!f.has("docker run") && !f.has("docker stop") && !f.has("docker exec boks-proxy kamal-proxy deploy") &&
		!f.has("docker ps -a --filter name=^boks-proxy$") && len(f.appends) == 0
}

// A name on the app's network that a container of another owner already answers to would split the
// app's traffic between the two: Docker gives one alias to as many containers as ask. Refused before
// the proxy, the image or the network are touched — whoever holds the name, and whichever of the
// container's names it is.
func TestANameTakenOnTheNetworkIsRefusedBeforeAnyChange(t *testing.T) {
	for name, line := range map[string]string{
		"another app's alias":          boxLine("demo-v1-1", "demo", "abc", `["demo"]`) + "\n" + boxLine("other-v1-1", "other", "abc", `["demo"]`),
		"a container boks did not run": boxLine("demo", "", "abc", `null`),
		"a hostname":                   boxLine("x", "other", "demo", `null`),
		"the new container's own name": boxLine("x", "other", "abc", `["demo-v2-1700000000"]`),
	} {
		f := routedFake(t)
		f.out[boxes] = line
		err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
		if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
		if !changedNothing(f) {
			t.Errorf("%s: the refusal must come first: %v", name, f.calls)
		}
	}
}

// Overlap runs two copies of the app under its one alias on purpose: its own copies are no conflict.
func TestTheAppsOwnCopiesShareItsAlias(t *testing.T) {
	f := routedFake(t)
	f.out[boxes] = boxLine("demo-v1-1", "demo", "abc", `["demo"]`)
	f.out[netOwner] = `{"boks.app":"demo"}`
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	// A network made by boks for this app is used as it is, not made again.
	if f.has("docker network create") {
		t.Errorf("the app's network exists already: %v", f.calls)
	}
}

// The proxy joins the network of a routed app with the names it has, so an app the proxy's names
// would collide with is refused too — the proxy that is yet to be started included.
func TestTheProxysNamesAreTakenOnARoutedAppsNetwork(t *testing.T) {
	f := routedFake(t)
	f.out[boxes] = `{"id":"0123456789abcdef","name":"/boks-proxy","hostname":"demo","labels":{},"networks":{"boks":{"Aliases":null}}}`
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil || !changedNothing(f) {
		t.Errorf("want a refusal before any change, got %v: %v", err, f.calls)
	}
	g := newFake()
	if err := Run(context.Background(), g, io.Discard, parse(t, strings.Replace(onePort, "app: demo", "app: boks-proxy", 1)), "v2", fixed); err == nil || !changedNothing(g) {
		t.Errorf("an app named like the proxy: want a refusal before any change, got %v: %v", err, g.calls)
	}
	// Without routes the proxy does not join, and its names are no conflict.
	h := routelessFake("healthy")
	h.out[boxes] = `{"id":"0123456789abcdef","name":"/boks-proxy","hostname":"bot","labels":{},"networks":{"boks":{"Aliases":null}}}`
	if err := Run(context.Background(), h, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Errorf("an app without routes: %v", err)
	}
}

// A network under the app's name that boks did not make for it would put the app among containers it
// was never meant to see; and a check that could not be answered is no answer that the network is
// free.
func TestTheAppsNetworkMustBeItsOwn(t *testing.T) {
	for name, set := range map[string]func(*fake){
		"another app's":   func(f *fake) { f.out[netOwner] = `{"boks.app":"other"}` },
		"unlabelled":      func(f *fake) { f.out[netOwner] = `{}` },
		"unanswered":      func(f *fake) { f.fail[netOwner] = errors.New("connection reset") },
		"unreadable list": func(f *fake) { f.fail[boxes] = errors.New("No such object") },
	} {
		f := routedFake(t)
		set(f)
		if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil || !changedNothing(f) {
			t.Errorf("%s: want a refusal before any change, got %v: %v", name, err, f.calls)
		}
	}
}

// A container another app removes between the listing and the inspect fails one listing, not the
// deploy: it is asked again. The network the apps shared before is not to be removed on boks's word.
func TestTheListingIsAskedAgainAndTheSharedNetworkLeftAlone(t *testing.T) {
	f := routedFake(t)
	f.fail[boxes] = errors.New("Error: No such object: 0123")
	listings := 0
	f.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, boxes) {
			if listings++; listings == 2 {
				delete(f.fail, boxes) // the second ask finds the container gone from the listing too
			}
		}
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatalf("a listing that fails once is asked again: %v", err)
	}
	g := routedFake(t)
	g.out[netOwner] = `{}`
	err := Run(context.Background(), g, io.Discard, parse(t, strings.Replace(onePort, "app: demo", "app: test", 1)), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "rename the app") {
		t.Errorf("an unlabelled network may be the shared one: want the advice to rename the app, got %v", err)
	}
}

// What runs on the server can change while a deploy pulls and waits for its admission, so the names
// are asked again under the lock; a conflict found then still changes nothing of the app.
func TestTheNetworkIsAskedAgainUnderTheAdmissionLock(t *testing.T) {
	f := routedFake(t)
	f.onRun = func(cmd string) {
		if cmd == admitTake("demo") {
			f.out[boxes] = boxLine("other-v1-1", "other", "abc", `["demo"]`)
		}
	}
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "answers to demo") {
		t.Fatalf("want the late conflict, got %v", err)
	}
	if f.has("docker network create") || f.has("docker run") || len(f.appends) != 0 || !f.has(admitGive("demo")) {
		t.Errorf("nothing of the app changes, and the admission is given back: %v", f.calls)
	}
}

// A proxy already on the app's network is not connected again; one that cannot be put there moves no
// route and leaves the old copy serving.
func TestTheProxyJoinsTheAppsNetworkOnce(t *testing.T) {
	f := routedFake(t)
	f.out[proxyNets] = "boks,boks-demo"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if f.has("docker network connect") {
		t.Errorf("the proxy is on the network already: %v", f.calls)
	}
	g := routedFake(t)
	g.fail["docker network connect"] = errors.New("network not found")
	if err := Run(context.Background(), g, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want the failed connect")
	}
	if g.has(reloadVia) || g.has("docker rm demo-v1-1") || !g.has("docker rm -f "+newCopy) {
		t.Errorf("no route moves, the old copy stays and the new one goes: %v", g.calls)
	}
	if journalOpen(g, journal) || !strings.Contains(g.appends[journal], `"result":"failed"`) {
		t.Errorf("no route moved, so the outcome is known: %q", g.appends[journal])
	}
	// A new copy that cannot be confirmed gone is named.
	k := routedFake(t)
	k.fail["docker network connect"] = errors.New("network not found")
	k.out["docker ps -a --filter name=^"+newCopy+"$"] = newCopy + "\tdemo"
	if err := Run(context.Background(), k, io.Discard, parse(t, onePort), "v2", fixed); err == nil || !strings.Contains(err.Error(), "could not be confirmed removed") {
		t.Errorf("want the leftover named, got %v", err)
	}
	// Stop-first: the old copy comes back, and no route is sent back to where it never left.
	h := stopFirstFake(t)
	h.fail["docker network connect"] = errors.New("network not found")
	if err := Run(context.Background(), h, io.Discard, parse(t, stopFirst), "v2", fixed); err == nil {
		t.Fatal("want the failed connect")
	}
	if h.has(reloadVia) || !h.has("docker start demo-v1-1") || journalOpen(h, journal) {
		t.Errorf("want the old copy back, no route touched, the operation closed: %v / %q", h.calls, h.appends[journal])
	}
}

// The proxy joins only to move a route: a deploy that fails before then leaves it where it was.
func TestAFailedStartDoesNotPutTheProxyOnTheNetwork(t *testing.T) {
	f := routedFake(t)
	f.fail["docker run"] = errors.New("no such image")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker network connect") {
		t.Errorf("nothing was routed, so the proxy stays off the network: %v", f.calls)
	}
}

// The deploy that moves an app off the shared network, as convex-lab's will (stop-first, the proxy
// on the shared boks-test): the old copy is on the shared network, and the proxy joins the app's own
// network to probe the new copy there. When the new copy never passes, the old one comes back where
// it was — `docker start` keeps its networks — and the routes, which never moved, reach it over the
// shared network the proxy never left.
func TestTheFirstDeployMovesTheAppOffTheSharedNetwork(t *testing.T) {
	f := stopFirstFake(t)
	f.out[proxyNets] = "boks-test"
	f.fail[probe] = errors.New("wget: server returned error: HTTP/1.1 502 Bad Gateway")
	if err := Run(context.Background(), f, io.Discard, parse(t, stopFirst+"deploy_timeout: 1ms\n"), "v2", quick()); err == nil {
		t.Fatal("want the failed health check")
	}
	run, joined := f.callAt("docker run -d --name "+newCopy+" --network boks-demo --network-alias demo "), f.callAt("docker network connect boks-demo boks-proxy")
	probed, revived := f.callAt(probe+"http://"+newCopy+":3000/up"), f.callAt("docker start demo-v1-1")
	if run < 0 || joined < run || probed < joined || revived < probed {
		t.Errorf("want run < proxy joins < probe < revive: %d %d %d %d\n%v", run, joined, probed, revived, f.calls)
	}
	if f.has(reloadVia) || f.has("docker network disconnect") || f.has("docker rm demo-v1-1") {
		t.Errorf("no route moved, and the old copy and the proxy's networks stay: %v", f.calls)
	}
}

// An app that loses its routes takes the proxy off its network once they are gone, whether or not the
// proxy runs: the fragments, not the proxy, say what it routes.
func TestAnAppWithoutRoutesTakesTheProxyOffItsNetwork(t *testing.T) {
	f := routelessFake("healthy")
	f.out[proxyProbe] = caddyUp
	f.out[proxyNets] = "boks,boks-bot"
	f.out[frags] = fragment(t, "bot", "bot-v1-1", botPort)
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	removed, left := f.callAt(reloadVia), f.callAt("docker network disconnect boks-bot boks-proxy")
	recorded := f.writeAt(".boks/bot/current", "bot-v2")
	if removed < 0 || left < removed || left < recorded {
		t.Errorf("the proxy leaves once the app's last route is gone and the release is recorded: %d %d %d %v", removed, left, recorded, f.calls)
	}
	// A route that could not be removed keeps the proxy where it reaches the old copy.
	k := routelessFake("healthy")
	k.out[proxyProbe] = caddyUp
	k.out[proxyNets] = "boks,boks-bot"
	k.out[frags] = f.out[frags]
	k.fail[reloadVia] = errors.New("connection reset")
	if err := Run(context.Background(), k, io.Discard, parse(t, noPorts), "v2", quick()); err == nil || k.has("docker network disconnect") {
		t.Errorf("want the failed removal, and the proxy kept on the network: %v: %v", err, k.calls)
	}
	g := routelessFake("healthy")
	g.out[proxyProbe] = "exited\tcaddy"
	g.out[proxyNets] = "boks,boks-bot"
	g.out[frags] = f.out[frags]
	if err := Run(context.Background(), g, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if !g.has("docker network disconnect boks-bot boks-proxy") {
		t.Errorf("a stopped proxy leaves the network too: %v", g.calls)
	}
	// A disconnect that fails costs isolation, not the deploy.
	h := routelessFake("healthy")
	h.out[proxyProbe] = caddyUp
	h.out[proxyNets] = "boks-bot"
	h.fail["docker network disconnect"] = errors.New("connection reset")
	var log strings.Builder
	if err := Run(context.Background(), h, &log, parse(t, noPorts), "v2", quick()); err != nil || !strings.Contains(log.String(), "may still be on network boks-bot") {
		t.Errorf("want a warning, got %v: %q", err, log.String())
	}
}

// A release recorded with its networks comes back on them, aliases and all, rather than on what
// today's config would give it.
func TestRollbackPutsTheReleaseBackOnItsNetworks(t *testing.T) {
	f := demoReleases(t, `{"version":3,`+v1Release+`,"networks":[{"name":"boks-demo","aliases":["demo","api"]}]}`)
	var log strings.Builder
	if err := Rollback(context.Background(), f, &log, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker run -d --name demo-v1-1700000000 --network boks-demo --network-alias demo --network-alias api ") {
		t.Errorf("want the recorded networks: %v", f.calls)
	}
	if strings.Contains(log.String(), "shared one network") {
		t.Errorf("a release with networks is not an old one: %q", log.String())
	}
	// One recorded before networks were says where it comes back instead.
	g := demoReleases(t, `{`+v1Release+`}`)
	log.Reset()
	if err := Rollback(context.Background(), g, &log, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), `comes back on boks-demo under the alias demo, not on "boks"`) {
		t.Errorf("want the move off the shared network named: %q", log.String())
	}
}

// A snapshot of version 3 or later without its networks, or with networks it could not have run on,
// was damaged; today's networks would restore what the release never ran with.
func TestRollbackRefusesDamagedNetworks(t *testing.T) {
	for name, networks := range map[string]string{
		"none":          `[]`,
		"another":       `[{"name":"boks-other","aliases":["demo"]}]`,
		"more than one": `[{"name":"boks-demo","aliases":["demo"]},{"name":"boks-other"}]`,
		"no alias":      `[{"name":"boks-demo"}]`,
	} {
		f := demoReleases(t, `{"version":3,`+v1Release+`,"networks":`+networks+`}`)
		err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed)
		if err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
		if f.has("docker") {
			t.Errorf("%s: the refusal must come before anything changes: %v", name, f.calls)
		}
	}
}

// A fleet rollback asks every server first; a name taken on the app's network of one of them stops
// it there, before any server changes — and before the memory check, which a release without a
// limit skips.
func TestCheckRollbackAsksTheNetwork(t *testing.T) {
	f := demoReleases(t, `{`+v1Release+`}`)
	f.out[boxes] = boxLine("other-v1-1", "other", "abc", `["demo"]`)
	if _, err := CheckRollback(context.Background(), f, parse(t, onePort), ""); err == nil || !strings.Contains(err.Error(), "answers to demo") {
		t.Fatalf("want the conflict, got %v", err)
	}
	if f.has("docker network") || f.has("docker run") || len(f.appends) != 0 {
		t.Errorf("a check changes nothing: %v", f.calls)
	}
	// The container's name is not known yet, and an empty one is nobody's name.
	g := demoReleases(t, `{`+v1Release+`}`)
	g.out[boxes] = boxLine("other-v1-1", "other", "", `null`)
	if _, err := CheckRollback(context.Background(), g, parse(t, onePort), ""); err != nil {
		t.Errorf("no name is taken: %v", err)
	}
}

// The names the proxy brings to a routed app's network must be free there too.
func TestTheProxysOwnNameMustBeFreeOnTheNetwork(t *testing.T) {
	f := routedFake(t)
	f.out[boxes] = boxLine("other-v1-1", "other", "abc", `["boks-proxy"]`)
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil || !changedNothing(f) {
		t.Errorf("want a refusal before any change, got %v: %v", err, f.calls)
	}
}

// A proxy that cannot reach the copy another app's route dials fails the boot, and with it the deploy,
// before anything of this app changes; the admission lock is given back. The image is already pulled
// by then — the pull goes first, so that a registry refusing the login leaves the proxy untouched —
// and an image on disk changes nothing that runs.
func TestAProxyThatCannotReachARouteStopsTheDeploy(t *testing.T) {
	f := routedFake(t)
	f.out[frags] = fragment(t, "other", "other-v1-1", config.Port{Name: "web", Port: 80, Host: "o.example.com"})
	f.fail["sh -c out=$(docker container inspect"] = errors.New("connection reset")
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "other-v1-1") {
		t.Fatalf("want the boot's failure, got %v", err)
	}
	if f.has("docker run") || len(f.appends) != 0 || !f.has(admitGive("demo")) {
		t.Errorf("nothing of the app changes, and the lock is given back: %v", f.calls)
	}
}

// A lock left by a proxy boot outside any deploy is named as that, with the way to clear it.
func TestALeftoverProxyBootLockIsNamed(t *testing.T) {
	f := routedFake(t)
	f.fail["ln -sn"] = errors.New("File exists")
	f.out["sh -c readlink /tmp/boks.admit.lock"] = "_proxy.1699999999000000000"
	o := fixed
	o.Poll, o.AdmitWait = time.Millisecond, 5*time.Millisecond
	var log strings.Builder
	err := Run(context.Background(), f, &log, parse(t, onePort), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "`boks proxy boot` or `boks cert` run has held") {
		t.Fatalf("want the proxy boot named, got %v", err)
	}
	if !strings.Contains(log.String(), "waiting for a `boks proxy boot` or `boks cert` run") {
		t.Errorf("the wait names it too: %q", log.String())
	}
}

// Two proxy boots outside any deploy can run at once (`boks cert renew` of two apps from cron), and
// neither holds a deploy lock: one waits for the other rather than take its lock as a leftover.
func TestAProxyBootWaitsForAnotherProxyBoot(t *testing.T) {
	f := newFake()
	f.fail["ln -sn"] = errors.New("File exists")
	f.out["sh -c readlink /tmp/boks.admit.lock"] = "_proxy.1699999999000000000"
	o := fixed
	o.Poll, o.AdmitWait = time.Millisecond, 5*time.Millisecond
	err := bootProxy(context.Background(), f, io.Discard, proxyHolder, "img", o)
	if err == nil || f.has("sh -c [ ") || f.has("docker network inspect") {
		t.Errorf("want a wait that ends in a refusal, the other boot's lock left alone: %v %v", err, f.calls)
	}
}
