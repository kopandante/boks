package deploy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/release"
)

// usesCache is onePort with a dependency on the app cache.
const usesCache = onePort + "uses: [cache]\n"

// depLine is one container of the inventory on network, answering to aliases there.
func depLine(name, app, network, aliases string, running bool, health string) string {
	labels := `{}`
	if app != "" {
		labels = `{"boks.app":"` + app + `"}`
	}
	run := "false"
	if running {
		run = "true"
	}
	return `{"id":"fedcba9876543210","name":"/` + name + `","hostname":"h-` + name + `","labels":` + labels +
		`,"networks":{"` + network + `":{"Aliases":` + aliases + `,"DNSNames":null}},"running":` + run + `,"health":"` + health + `"}`
}

// cacheFake is a routed demo whose dependency cache runs healthy on its own network.
func cacheFake(t *testing.T) *fake {
	f := routedFake(t, nil)
	f.out[netOwnerQuery("boks-cache")] = `{"boks.app":"cache"}`
	f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, true, "healthy")
	return f
}

// A container that uses another app joins its network before it starts — so the app never runs
// unable to reach what it uses — and is recorded with it. The proxy joins only the app's own network.
func TestAContainerJoinsTheNetworksOfTheAppsItUses(t *testing.T) {
	f := cacheFake(t)
	if err := Run(context.Background(), f, io.Discard, parse(t, usesCache), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	created := f.callAt("docker create --name " + newCopy + " --network boks-demo --network-alias demo ")
	joined := f.callAt("docker network connect boks-cache " + newCopy)
	started := f.callAt("docker start " + newCopy)
	if created < 0 || joined < created || started < joined || f.has("docker run -d --name "+newCopy) {
		t.Errorf("want create < join < start, and no docker run: %d %d %d\n%v", created, joined, started, f.calls)
	}
	if f.has("docker network connect boks-cache boks-proxy") || !f.has("docker network connect boks-demo boks-proxy") {
		t.Errorf("the proxy joins the app's network, not those it uses: %v", f.calls)
	}
	snap := f.uploads[".boks/demo/releases/"+newCopy+".json"]
	if !strings.Contains(snap, `"uses": [`) || !strings.Contains(snap, `"name": "boks-cache"`) || !strings.Contains(snap, fmt.Sprintf(`"version": %d`, release.FormatVersion)) {
		t.Errorf("the snapshot records the app used and its network: %s", snap)
	}
}

// A dependency that is not there to be reached refuses the deploy before anything changes: not
// deployed by this boks, a network that is not its, no running copy, a copy not healthy or without a
// HEALTHCHECK, its name answered by another owner, or the new container's name taken there.
func TestADependencyThatCannotBeReachedRefusesTheDeploy(t *testing.T) {
	for name, set := range map[string]func(*fake){
		"no network":     func(f *fake) { delete(f.out, netOwnerQuery("boks-cache")) },
		"another's":      func(f *fake) { f.out[netOwnerQuery("boks-cache")] = `{"boks.app":"other"}` },
		"stopped":        func(f *fake) { f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, false, "") },
		"none answering": func(f *fake) { f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `null`, true, "healthy") },
		"unhealthy": func(f *fake) {
			f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, true, "unhealthy")
		},
		"starting": func(f *fake) {
			f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, true, "starting")
		},
		"no HEALTHCHECK": func(f *fake) { f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, true, "") },
		"one copy starts": func(f *fake) {
			f.out[boxes] += "\n" + depLine("cache-v2-2", "cache", "boks-cache", `["cache"]`, true, "starting")
		},
		"another owner": func(f *fake) {
			f.out[boxes] += "\n" + depLine("x", "other", "boks-cache", `["cache"]`, true, "healthy")
		},
		"the new name taken": func(f *fake) {
			f.out[boxes] += "\n" + depLine("x", "other", "boks-cache", `["`+newCopy+`"]`, true, "healthy")
		},
		"a listing error": func(f *fake) { f.fail[netOwnerQuery("boks-cache")] = errors.New("connection reset") },
	} {
		f := cacheFake(t)
		set(f)
		err := Run(context.Background(), f, io.Discard, parse(t, usesCache), "v2", fixed)
		if err == nil || !changedNothing(f) {
			t.Errorf("%s: want a refusal before any change, got %v: %v", name, err, f.calls)
		}
		if name == "no HEALTHCHECK" && (err == nil || !strings.Contains(err.Error(), "has no HEALTHCHECK") ||
			!strings.Contains(err.Error(), "healthcheck block to its boks.yml")) {
			t.Errorf("an image without a health check is named as that, with both remedies: %v", err)
		}
	}
	// A stopped copy beside the healthy one answers nothing and is no obstacle.
	g := cacheFake(t)
	g.out[boxes] += "\n" + depLine("cache-v0-0", "cache", "boks-cache", `["cache"]`, false, "")
	if err := Run(context.Background(), g, io.Discard, parse(t, usesCache), "v2", fixed); err != nil {
		t.Errorf("a stopped copy of the dependency is no obstacle: %v", err)
	}
}

// What the dependency is can change while the deploy pulls and waits, so it is asked again under the
// admission lock; a dependency gone by then still changes nothing of the app.
func TestTheDependencyIsAskedAgainUnderTheAdmissionLock(t *testing.T) {
	f := cacheFake(t)
	took := 0
	f.onRun = func(cmd string) {
		// The first take is the proxy boot's, the second the container's.
		if cmd == admitTake("demo") {
			if took++; took == 2 {
				f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, false, "")
			}
		}
	}
	err := Run(context.Background(), f, io.Discard, parse(t, usesCache), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "no running copy") {
		t.Fatalf("want the late refusal, got %v", err)
	}
	if f.has("docker create") || len(f.appends) != 0 {
		t.Errorf("nothing of the app changes: %v", f.calls)
	}
}

// A join or a start that fails after the container was created removes it: no route reaches it yet,
// and left behind it would be one more copy for stop-first to revive. In stop-first the old copy then
// comes back.
func TestACreatedContainerThatCannotJoinIsRemoved(t *testing.T) {
	for _, failing := range []string{"docker create", "docker network connect boks-cache", "docker start " + newCopy} {
		f := cacheFake(t)
		f.fail[failing] = errors.New("connection reset")
		if err := Run(context.Background(), f, io.Discard, parse(t, usesCache), "v2", fixed); err == nil {
			t.Fatalf("%s: want an error", failing)
		}
		// A failed create may have created the copy all the same, so it is removed too.
		if !f.has("docker rm -f "+newCopy) || f.has(deployVia) {
			t.Errorf("%s: want the new container removed and no route moved: %v", failing, f.calls)
		}
	}
	g := stopFirstFake(t)
	g.out[netOwnerQuery("boks-cache")] = `{"boks.app":"cache"}`
	g.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, true, "healthy")
	g.fail["docker network connect boks-cache"] = errors.New("connection reset")
	if err := Run(context.Background(), g, io.Discard, parse(t, stopFirst+"uses: [cache]\n"), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if !g.has("docker start demo-v1-1") || journalOpen(g, journal) {
		t.Errorf("the old copy comes back and the operation is closed: %v / %q", g.calls, g.appends[journal])
	}
}

// A rollback puts the release back with the apps it used then, not those today's config names:
// their checks and their networks are the release's.
func TestRollbackRestoresTheAppsTheReleaseUsed(t *testing.T) {
	f := demoReleases(t, `{"version":4,`+v1Release+`,"uses":["cache"],`+
		`"networks":[{"name":"boks-demo","aliases":["demo"]},{"name":"boks-cache"}]}`)
	f.out[netOwnerQuery("boks-cache")] = `{"boks.app":"cache"}`
	f.out[boxes] = depLine("cache-v1-1", "cache", "boks-cache", `["cache"]`, true, "healthy")
	if err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker network connect boks-cache demo-v1-1700000000") {
		t.Errorf("want the release's dependency joined: %v", f.calls)
	}
	// Today's config uses the cache, the release did not: the rollback does not join it.
	g := demoReleases(t, `{"version":4,`+v1Release+`,"networks":[{"name":"boks-demo","aliases":["demo"]}]}`)
	if err := Rollback(context.Background(), g, io.Discard, parse(t, usesCache), "", fixed); err != nil {
		t.Fatal(err)
	}
	if g.has("docker network connect boks-cache") || g.has("docker create") {
		t.Errorf("want the release's networks only: %v", g.calls)
	}
	// The dependency the release used is checked like a deploy's: gone, the rollback is refused first.
	h := demoReleases(t, `{"version":4,`+v1Release+`,"uses":["cache"],`+
		`"networks":[{"name":"boks-demo","aliases":["demo"]},{"name":"boks-cache"}]}`)
	if _, err := CheckRollback(context.Background(), h, parse(t, onePort), ""); err == nil || !strings.Contains(err.Error(), "uses: cache") {
		t.Errorf("a fleet rollback asks the release's dependency first: %v", err)
	}
}

// A snapshot whose networks do not match the apps it used, in order, was damaged.
func TestRollbackRefusesNetworksThatDoNotMatchTheUses(t *testing.T) {
	for name, body := range map[string]string{
		"a network missing": `"uses":["cache"],"networks":[{"name":"boks-demo","aliases":["demo"]}]`,
		"an extra network":  `"networks":[{"name":"boks-demo","aliases":["demo"]},{"name":"boks-cache"}]`,
		"another order":     `"uses":["a","b"],"networks":[{"name":"boks-demo","aliases":["demo"]},{"name":"boks-b"},{"name":"boks-a"}]`,
		"an alias there":    `"uses":["cache"],"networks":[{"name":"boks-demo","aliases":["demo"]},{"name":"boks-cache","aliases":["cache"]}]`,
	} {
		f := demoReleases(t, `{"version":4,`+v1Release+`,`+body+`}`)
		err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed)
		if err == nil || !strings.Contains(err.Error(), "cannot be reproduced") || f.has("docker") {
			t.Errorf("%s: want a refusal before anything changes, got %v", name, err)
		}
	}
	// A snapshot from before networks were recorded never names apps it used.
	g := demoReleases(t, `{`+v1Release+`,"uses":["cache"]}`)
	if err := Rollback(context.Background(), g, io.Discard, parse(t, onePort), "", fixed); err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
		t.Errorf("want a refusal, got %v", err)
	}
}

// Docker's DNS ignores case: a name answered as DEMO by another owner is the app's name too.
func TestANameTakenInAnotherCaseIsTaken(t *testing.T) {
	f := routedFake(t, nil)
	f.out[boxes] = boxLine("x", "other", "abc", `["DEMO"]`)
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil || !changedNothing(f) {
		t.Errorf("want a refusal before any change, got %v: %v", err, f.calls)
	}
	g := routedFake(t, nil)
	g.out[boxes] = `{"id":"0123456789abcdef","name":"/x","hostname":"abc","labels":{},"networks":{"boks-demo":{"Aliases":["BOKS-PROXY"]}}}`
	if err := Run(context.Background(), g, io.Discard, parse(t, onePort), "v2", fixed); err == nil || !changedNothing(g) {
		t.Errorf("the proxy's name in another case: want a refusal, got %v: %v", err, g.calls)
	}
}
