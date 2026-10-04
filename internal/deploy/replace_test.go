package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
)

var (
	webPort     = config.Port{Name: "web", Port: 3000, Host: "demo.example.com", HealthPath: "/up"}
	actionsPort = config.Port{Name: "actions", Port: 3001, Host: "actions.example.com", HealthPort: 3000}
)

const (
	memInfo  = "cat /proc/meminfo"
	psIDs    = "docker ps -q --no-trunc"
	limits   = "docker container inspect --format {{.Id}}"
	memStats = "docker stats --no-stream"
	newCopy  = "demo-v2-1700000000"
)

// meminfo is /proc/meminfo with MemAvailable at mib.
func meminfo(mib int) string {
	return "MemTotal:        2000000 kB\nMemFree:          100000 kB\nMemAvailable:   " + itoa(mib*1024) + " kB\n"
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// server sets the containers running on it: name → limit and use, in MiB (limit 0 for none).
func (f *fake) server(availMiB int, running map[string][2]int) {
	f.out[memInfo] = meminfo(availMiB)
	var ids, lims, stats []string
	for name, m := range running {
		id := "id-" + name
		ids = append(ids, id)
		lims = append(lims, id+"\t/"+name+"\t"+itoa(m[0]<<20))
		stats = append(stats, id+"\t"+itoa(m[1])+"MiB / "+itoa(max(m[0], 2000))+"MiB")
	}
	f.out[psIDs] = strings.Join(ids, "\n")
	f.out[limits] = strings.Join(lims, "\n")
	f.out[memStats] = strings.Join(stats, "\n")
}

// stopFirstFake is a routed app on stop-first whose one copy, demo-v1-1, is running.
func stopFirstFake(t *testing.T) *fake {
	f := routedFake(t, nil)
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" + ports(t, webPort) + "\n"
	f.out["docker ps --filter label=boks.app=demo"] = "demo-v1-1\n"
	return f
}

const stopFirst = onePort + "replace: stop-first\n"

// The limit reaches `docker run`, and the snapshot records it with the replace mode, so a rollback
// can put the release back as it ran.
func TestDeployRunsAndRecordsTheLimit(t *testing.T) {
	f := routedFake(t, nil)
	f.server(1500, nil)
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	run := f.calls[f.callAt("docker run")]
	if !strings.Contains(run, " --memory 512m ") {
		t.Errorf("the limit must reach docker run: %s", run)
	}
	var snap release.Snapshot
	if err := json.Unmarshal([]byte(f.uploads[".boks/demo/releases/"+newCopy+".json"]), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Memory != "512m" || snap.Replace != "overlap" {
		t.Errorf("snapshot must keep the limit and the mode: %+v", snap)
	}

	bot := routelessFake("healthy")
	if err := Run(context.Background(), bot, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bot.calls[bot.callAt("docker run")], "--memory") || bot.has(memInfo) {
		t.Errorf("no limit, no flag and no check: %v", bot.calls)
	}
	if !strings.Contains(bot.uploads[".boks/bot/releases/bot-v2-1700000000.json"], `"replace": "stop-first"`) {
		t.Errorf("an app without routes records the mode it was replaced with: %s", bot.uploads[".boks/bot/releases/bot-v2-1700000000.json"])
	}
}

// In overlap the old copy keeps running beside the new one, and what it may still grow into up to
// its limit is not free: 700 available − (512−300) it may grow − 256 reserve leaves 232 for 512.
// The refusal comes before anything changes, the journal included, and gives the lock back.
func TestOverlapMustFitBesideTheOldCopy(t *testing.T) {
	f := routedFake(t, nil)
	f.server(700, map[string][2]int{"demo-v1-1": {512, 300}})
	err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "preliminary memory check") || !strings.Contains(err.Error(), "not a guarantee against OOM") {
		t.Fatalf("want a preliminary-check refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "232MiB is free") {
		t.Errorf("the refusal must give the arithmetic: %v", err)
	}
	if f.has("docker run") || f.has("docker stop") || f.has(deployVia) || len(f.appends) != 0 {
		t.Errorf("nothing may change before the check: %v / %v", f.calls, f.appends)
	}
	if !f.has(admitGive("demo")) {
		t.Errorf("a refused deploy gives the admission back: %v", f.calls)
	}
}

// Stop-first counts the stop of the old copy: what it uses comes back, and its growth no longer
// matters — the same server that refuses the overlap admits it (700 + 300 − 256 = 744). Once the old
// copy is down the server is measured again, and that second answer is the one that lets it start.
func TestStopFirstCountsTheStopOfTheOldCopy(t *testing.T) {
	f := stopFirstFake(t)
	f.server(700, map[string][2]int{"demo-v1-1": {512, 300}})
	f.onRun = func(cmd string) {
		if cmd == "docker stop demo-v1-1" {
			f.server(1000, nil)
		}
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, stopFirst+"memory: 512m\n"), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	checks := 0
	for _, c := range f.calls {
		if c == memInfo {
			checks++
		}
	}
	if checks != 2 || f.callAt(memInfo) > f.callAt("docker stop demo-v1-1") || f.at("docker run") < f.callAt("docker stop demo-v1-1") {
		t.Errorf("want a check before the stop and one after it, both before the start: %v", f.calls)
	}
}

// The second measurement is a fact the estimate was not: if the stopped copy gave back less than it
// seemed to use, the new copy does not start and the old one comes back.
func TestStopFirstRefusesWhenTheStopFreedTooLittle(t *testing.T) {
	f := stopFirstFake(t)
	f.server(700, map[string][2]int{"demo-v1-1": {512, 300}})
	f.onRun = func(cmd string) {
		if cmd == "docker stop demo-v1-1" {
			f.server(710, nil)
		}
	}
	err := Run(context.Background(), f, io.Discard, parse(t, stopFirst+"memory: 512m\n"), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "preliminary memory check") || !strings.Contains(err.Error(), "measured after the old copies stopped") {
		t.Fatalf("want a refusal after the stop that says so, got %v", err)
	}
	if f.has("docker run") {
		t.Errorf("the new copy must not start: %v", f.calls)
	}
	if !f.has("docker start demo-v1-1") || !strings.Contains(f.appends[journal], `"result":"failed"`) {
		t.Errorf("the old copy comes back and the operation is closed as failed: %v / %q", f.calls, f.appends[journal])
	}
}

// A container admitted a moment ago has not taken its memory yet; MemAvailable alone would hand that
// memory to the next deploy. Its whole limit is counted until it uses it.
func TestTheCheckCountsWhatAdmittedContainersMayStillTake(t *testing.T) {
	f := routedFake(t, nil)
	f.server(1100, map[string][2]int{"other-v1-1": {512, 0}, "unlimited-v1-1": {0, 100}})
	err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "332MiB is free") {
		t.Fatalf("1100 − 512 promised − 256 reserve leaves 332, got %v", err)
	}
	f = routedFake(t, nil)
	f.server(1100, map[string][2]int{"other-v1-1": {512, 512}})
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed); err != nil {
		t.Errorf("a container at its limit promises nothing more: %v", err)
	}
}

// A check that cannot read the server cannot tell, and refuses rather than start on a guess.
func TestTheCheckRefusesWhatItCannotRead(t *testing.T) {
	for name, broke := range map[string]func(*fake){
		"meminfo":   func(f *fake) { f.fail[memInfo] = errors.New("boom") },
		"no line":   func(f *fake) { f.out[memInfo] = "MemTotal: 1 kB\n" },
		"limits":    func(f *fake) { f.fail[limits] = errors.New("boom") },
		"stats":     func(f *fake) { f.fail[memStats] = errors.New("boom") },
		"bad stats": func(f *fake) { f.out[memStats] = "id-other-v1-1\tlots / --" },
	} {
		f := routedFake(t, nil)
		f.server(4000, map[string][2]int{"other-v1-1": {512, 10}})
		broke(f)
		err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed)
		if err == nil || !strings.Contains(err.Error(), "preliminary memory check") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
		if f.has("docker run") {
			t.Errorf("%s: nothing may start: %v", name, f.calls)
		}
	}
}

// Admission is serialized server-wide: a deploy of another app holding the lock is waited for, and
// one that never lets go is named, not overruled.
func TestAdmissionWaitsForAnotherApp(t *testing.T) {
	f := routedFake(t, nil)
	f.fail["ln -sn"] = errors.New("File exists")
	f.out["sh -c readlink /tmp/boks.admit.lock"] = "convex.1699999999000000000"
	o := fixed
	o.Poll, o.AdmitWait = time.Millisecond, 5*time.Millisecond
	var log strings.Builder
	err := Run(context.Background(), f, &log, parse(t, onePort), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "deploy of convex has held the admission lock") {
		t.Fatalf("want a refusal naming the owner, got %v", err)
	}
	if !strings.Contains(log.String(), "waiting for the deploy of convex") {
		t.Errorf("the wait must be visible: %q", log.String())
	}
	if f.has("docker run") || len(f.appends) != 0 || f.has("sh -c [ ") {
		t.Errorf("nothing changes, and a lock that is not ours is not removed: %v", f.calls)
	}

	tries := 0
	g := routedFake(t, nil)
	g.out["sh -c readlink /tmp/boks.admit.lock"] = "convex.1699999999000000000"
	g.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, "ln -sn") {
			if tries++; tries < 3 {
				g.fail["ln -sn"] = errors.New("File exists")
			} else {
				delete(g.fail, "ln -sn")
			}
		}
	}
	if err := Run(context.Background(), g, io.Discard, parse(t, onePort), "v2", o); err != nil {
		t.Fatalf("a lock let go of is taken: %v", err)
	}
	if tries != 3 || g.at("ln -sn") > g.at("docker run") {
		t.Errorf("want the run to start after the third try: %d %v", tries, g.calls)
	}
}

// `boks unlock` clears a stale admission lock this app left, and only that one.
func TestUnlockClearsTheAdmissionLockOfThisApp(t *testing.T) {
	f := newFake()
	f.fail["rmdir"] = errors.New("No such file or directory")
	f.out["sh -c case"] = "freed"
	f.out["sh -c test -e /tmp/boks-demo.lock"] = "absent"
	if err := Unlock(context.Background(), f, "demo"); err != nil {
		t.Errorf("a freed admission lock is an unlock: %v", err)
	}
	if !strings.Contains(f.calls[0], " demo.*) rm -f /tmp/boks.admit.lock") {
		t.Errorf("only this app's admission lock is removed: %v", f.calls)
	}
	g := newFake()
	g.fail["rmdir"] = errors.New("No such file or directory")
	if err := Unlock(context.Background(), g, "demo"); err == nil {
		t.Error("nothing to unlock is still an error")
	}
}

// Stop-first with routes: the old copy is stopped and confirmed down before the new one starts, the
// journal is open before the stop, and the routes move only through the proxy's health check of the
// new copy. Admission lasts until the routes have moved.
func TestStopFirstStopsTheOldCopyBeforeTheNewOneStarts(t *testing.T) {
	f := stopFirstFake(t)
	if err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	opened := f.writeAt(journal, `"action":"deploy"`)
	stop, confirmed := f.callAt("docker stop demo-v1-1"), f.callAt(isRunningQuery+"demo-v1-1")
	run, route, given := f.callAt("docker run"), f.callAt(deployVia+"demo.web --target "+newCopy), f.callAt(admitGive("demo"))
	if opened < 0 || opened > stop || stop > confirmed || confirmed > run || run > route || route > given {
		t.Errorf("want journal < stop < confirmed < run < route < admission given back: %d %d %d %d %d %d\n%v",
			opened, stop, confirmed, run, route, given, f.calls)
	}
	if !strings.Contains(f.calls[route], "--health-check-path /up") {
		t.Errorf("the route moves through the health check: %s", f.calls[route])
	}
	if !f.has("docker rm demo-v1-1") || f.uploads[".boks/demo/current"] != newCopy+"\n" {
		t.Errorf("a successful stop-first deploy records and retires as usual: %v", f.calls)
	}
}

// The stop is the guarantee, so a stop that failed — or one docker does not confirm — keeps the new
// copy from starting; the old copy is brought back and the operation closed as failed.
func TestStopFirstDoesNotStartWithoutAConfirmedStop(t *testing.T) {
	for name, broke := range map[string]func(*fake){
		"failed":      func(f *fake) { f.fail["docker stop demo-v1-1"] = errors.New("connection reset") },
		"unconfirmed": func(f *fake) { f.out[isRunningQuery+"demo-v1-1"] = "true" },
		"unknown":     func(f *fake) { f.fail[isRunningQuery+"demo-v1-1"] = errors.New("connection reset") },
	} {
		f := stopFirstFake(t)
		broke(f)
		err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed)
		if err == nil || !strings.Contains(err.Error(), "the new version was not started") {
			t.Errorf("%s: want a refusal to start, got %v", name, err)
		}
		if f.has("docker run") || f.has(deployVia) {
			t.Errorf("%s: nothing may start or move: %v", name, f.calls)
		}
		if !f.has("docker start demo-v1-1") || !strings.Contains(f.appends[journal], `"result":"failed"`) {
			t.Errorf("%s: the old copy comes back and the operation is closed: %v / %q", name, f.calls, f.appends[journal])
		}
	}
}

// A new copy that fails the proxy's health check is removed, the old copy brought back, and the route
// — which may have moved even though the command failed — put back on it. The proxy's outcome is not
// known, so the operation stays open.
func TestStopFirstBringsTheOldCopyAndItsRoutesBack(t *testing.T) {
	f := stopFirstFake(t)
	f.fail[deployVia+"demo.web --target "+newCopy] = errors.New("target failed to become healthy")
	err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "healthy") {
		t.Fatalf("want the health failure, got %v", err)
	}
	removed, restarted := f.callAt("docker rm -f "+newCopy), f.callAt("docker start demo-v1-1")
	reverted := f.callAt(deployVia + "demo.web --target demo-v1-1:3000")
	if removed < 0 || restarted < 0 || reverted < 0 || removed > restarted || restarted > reverted {
		t.Errorf("want removed < restarted < route reverted: %d %d %d\n%v", removed, restarted, reverted, f.calls)
	}
	if !journalOpen(f, journal) {
		t.Errorf("the entry must stay open: %q", f.appends[journal])
	}
	if f.has("docker rm demo-v1-1") || f.uploads[".boks/demo/current"] != "" {
		t.Errorf("a failed deploy neither retires nor records: %v", f.calls)
	}
}

// With two ports, the one that moved and the one whose switch failed both go back.
func TestStopFirstRevertsTheFailedPortToo(t *testing.T) {
	f := stopFirstFake(t)
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" + ports(t, webPort, actionsPort) + "\n"
	f.fail[deployVia+"demo.actions --target "+newCopy] = errors.New("connection reset")
	if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts+"replace: stop-first\n"), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	for _, p := range []string{"demo.web --target demo-v1-1:3000", "demo.actions --target demo-v1-1:3001"} {
		if !f.has(deployVia + p) {
			t.Errorf("route %s must go back: %v", p, f.calls)
		}
	}
}

// A new copy that does not start touched no route: the old copy comes back and the operation is
// closed as failed.
func TestStopFirstFailedStartClosesTheJournal(t *testing.T) {
	f := stopFirstFake(t)
	f.fail["docker run"] = errors.New("no such image")
	if err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if !f.has("docker start demo-v1-1") || f.has(deployVia) {
		t.Errorf("the old copy comes back and no route is touched: %v", f.calls)
	}
	closed, cleaned := f.writeAt(journal, `"result":"failed"`), f.callAt("docker start demo-v1-1")
	if closed < 0 || closed <= cleaned {
		t.Errorf("the entry closes after the cleanup: %d %d", closed, cleaned)
	}
}

// If the new copy cannot be confirmed gone, the old one is not brought back beside it.
func TestStopFirstKeepsTheOldCopyStoppedWhenTheNewOneWillNotGo(t *testing.T) {
	f := stopFirstFake(t)
	f.fail[deployVia+"demo.web --target "+newCopy] = errors.New("unhealthy")
	f.out["docker ps -a --filter name=^"+newCopy+"$"] = newCopy + "\tdemo\n"
	err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "could not be confirmed removed") {
		t.Fatalf("want the leftover named, got %v", err)
	}
	if f.has("docker start demo-v1-1") {
		t.Errorf("the old copy must stay stopped: %v", f.calls)
	}
}

// A copy that does not come back after `docker start` is reported, not taken for revived.
func TestRevivalIsConfirmed(t *testing.T) {
	f := routelessFake("unhealthy")
	f.onRun = func(cmd string) {
		if cmd == "docker start bot-v1-1" {
			f.out[isRunningQuery+"bot-v1-1"] = "false"
		}
	}
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "[bot-v1-1] did not come back up") {
		t.Fatalf("want the copy that stayed down named, got %v", err)
	}
}

// demoReleases is a server where demo-v2-2 is current and running and demo-v1-1 is the release
// before it; the snapshot of demo-v1-1 is the one given.
func demoReleases(t *testing.T, v1 string) *fake {
	f := stopFirstFake(t)
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v2-2\t" + ports(t, webPort) + "\n"
	f.out["docker ps --filter label=boks.app=demo"] = "demo-v2-2\n"
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v2-2\n"
	f.out["cat .boks/demo/releases/demo-v2-2.json"] = `{"version":2,"id":"demo-v2-2","previous":"demo-v1-1","replace":"overlap",
		"ports":[{"name":"web","port":3000,"host":"demo.example.com","health_path":"/up","health_port":0}]}`
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = v1
	return f
}

const v1Release = `"id":"demo-v1-1","app":"demo","image":"ghcr.io/x/y","tag":"v1",
	"ports":[{"name":"web","port":3000,"host":"demo.example.com","health_path":"/up","health_port":0}],"network":"boks"`

// The limit belongs to the release: a rollback runs it with the limit it ran with, and without one
// when it had none, whatever the config says today.
func TestRollbackRestoresTheLimitOfTheRelease(t *testing.T) {
	f := demoReleases(t, `{`+v1Release+`,"memory":"256m"}`)
	f.server(4000, nil)
	if err := Rollback(context.Background(), f, io.Discard, parse(t, onePort+"memory: 1g\n"), "", fixed); err != nil {
		t.Fatal(err)
	}
	if run := f.calls[f.callAt("docker run")]; !strings.Contains(run, " --memory 256m ") {
		t.Errorf("want the release's limit: %s", run)
	}
	g := demoReleases(t, `{`+v1Release+`}`)
	if err := Rollback(context.Background(), g, io.Discard, parse(t, onePort+"memory: 1g\n"), "", fixed); err != nil {
		t.Fatal(err)
	}
	if run := g.calls[g.callAt("docker run")]; strings.Contains(run, "--memory") || g.has(memInfo) {
		t.Errorf("a release without a limit runs without one: %s", run)
	}
}

// Either side asking for stop-first is enough for a rollback: the release being restored, or the
// config, which may say today what the release never recorded.
func TestRollbackStopsFirstWhenEitherSideAsks(t *testing.T) {
	cases := []struct {
		name, v1, cfg string
		stopFirst     bool
	}{
		{"release asks", `{` + v1Release + `,"replace":"stop-first"}`, onePort, true},
		{"config asks, version 1 snapshot", `{` + v1Release + `}`, stopFirst, true},
		{"neither", `{` + v1Release + `,"replace":"overlap"}`, onePort, false},
	}
	for _, c := range cases {
		f := demoReleases(t, c.v1)
		if err := Rollback(context.Background(), f, io.Discard, parse(t, c.cfg), "", fixed); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		stopped := f.callAt("docker stop demo-v2-2") >= 0 && f.callAt("docker stop demo-v2-2") < f.callAt("docker run")
		if stopped != c.stopFirst {
			t.Errorf("%s: want stop-first %v: %v", c.name, c.stopFirst, f.calls)
		}
	}
}

// Container use is read before MemAvailable: growth between the two readings is then counted
// twice rather than not at all.
func TestTheCheckReadsUseBeforeAvailable(t *testing.T) {
	f := routedFake(t, nil)
	f.server(4000, map[string][2]int{"other-v1-1": {512, 10}})
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if f.callAt(memStats) < 0 || f.callAt(memStats) > f.callAt(memInfo) {
		t.Errorf("want docker stats before /proc/meminfo: %v", f.calls)
	}
}

// An admission lock that could not even be checked is not reported as unlocked.
func TestUnlockReportsAnAdmissionLockItCouldNotCheck(t *testing.T) {
	f := newFake()
	f.fail["sh -c case"] = errors.New("connection reset")
	if err := Unlock(context.Background(), f, "demo"); err == nil || !strings.Contains(err.Error(), "admission lock") {
		t.Errorf("want the admission failure reported, got %v", err)
	}
}

// When the copy that took a route cannot be confirmed removed, the routes are not where they were:
// the operation stays open and the error says where they may point.
func TestStopFirstLeftoverAfterASwitchLeavesTheJournalOpen(t *testing.T) {
	f := stopFirstFake(t)
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" + ports(t, webPort, actionsPort) + "\n"
	f.fail[deployVia+"demo.actions --target "+newCopy] = errors.New("unhealthy")
	f.out["docker ps -a --filter name=^"+newCopy+"$"] = newCopy + "\tdemo\n"
	err := Run(context.Background(), f, io.Discard, parse(t, twoPorts+"replace: stop-first\n"), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "routes may still point at "+newCopy) {
		t.Fatalf("want the routes named, got %v", err)
	}
	if !journalOpen(f, journal) {
		t.Errorf("the entry must stay open: %q", f.appends[journal])
	}
}

// With two copies of the app running (an overlap deploy that failed and left its copy), a route goes
// back to the copy the proxy sent it to before this run, not nowhere.
func TestARouteGoesBackToTheCopyThatServedIt(t *testing.T) {
	routes := map[string]proxy.Listed{
		"demo.web":     {Hosts: []string{"demo.example.com"}, Targets: []string{"demo-v1-1:3000"}},
		"demo.actions": {Hosts: []string{"actions.example.com"}, Targets: []string{"demo-v1-1:3001"}},
	}
	two := "demo-v1-1\t" + ports(t, webPort, actionsPort) + "\ndemo-v1-2\t" + ports(t, webPort, actionsPort) + "\n"
	for _, mode := range []string{"overlap", "stop-first"} {
		f := routedFake(t, routes)
		f.out["docker ps -a --filter label=boks.app=demo"] = two
		f.out["docker ps --filter label=boks.app=demo"] = "demo-v1-1\ndemo-v1-2\n"
		f.fail[deployVia+"demo.actions --target "+newCopy] = errors.New("unhealthy")
		if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts+"replace: "+mode+"\n"), "v2", fixed); err == nil {
			t.Fatalf("%s: want an error", mode)
		}
		if !f.has(deployVia+"demo.web --target demo-v1-1:3000") || f.has(deployVia+"demo.web --target demo-v1-2") {
			t.Errorf("%s: the route must go back to demo-v1-1, which served it: %v", mode, f.calls)
		}
	}
}

// `ln` that succeeded but whose answer was lost leaves this run's own token in the link: the run
// owns the lock, rather than waiting for itself and leaving every app blocked.
func TestAdmissionRecognizesItsOwnLock(t *testing.T) {
	f := routedFake(t, nil)
	f.fail["ln -sn"] = errors.New("connection reset")
	f.out["sh -c readlink /tmp/boks.admit.lock"] = "demo.1700000000000000000"
	o := fixed
	o.Poll, o.AdmitWait = time.Millisecond, 5*time.Millisecond
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", o); err != nil {
		t.Fatal(err)
	}
	if !f.has(admitGive("demo")) {
		t.Errorf("the lock it owns is given back: %v", f.calls)
	}
}

// A container removed between listing and inspecting (another app retiring its old copy) is asked
// about again rather than failing the check; a failure that persists still refuses.
func TestTheCheckAsksAgainWhenAContainerGoesMeanwhile(t *testing.T) {
	f := routedFake(t, nil)
	f.server(4000, map[string][2]int{"other-v1-1": {512, 10}})
	inspects := 0
	f.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, limits) {
			if inspects++; inspects == 1 {
				f.fail[limits] = errors.New("No such container: id-gone")
			} else {
				delete(f.fail, limits)
			}
		}
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed); err != nil {
		t.Fatalf("a container gone meanwhile is not a failure: %v", err)
	}
	if inspects != 2 {
		t.Errorf("want one more try, got %d inspects", inspects)
	}
}

// Freeing a stale admission lock excuses a missing app lock only when the server says it is
// missing; a failed rmdir with the lock still there is an error.
func TestUnlockReportsAnAppLockItCouldNotRemove(t *testing.T) {
	f := newFake()
	f.fail["rmdir"] = errors.New("connection reset")
	f.out["sh -c case"] = "freed"
	f.out["sh -c test -e /tmp/boks-demo.lock"] = "present"
	if err := Unlock(context.Background(), f, "demo"); err == nil {
		t.Error("an app lock still there is not unlocked")
	}
	f.out["sh -c test -e /tmp/boks-demo.lock"] = "absent"
	if err := Unlock(context.Background(), f, "demo"); err != nil {
		t.Errorf("an absent app lock with the admission lock freed is an unlock: %v", err)
	}
}

// docker has no stats for a container stuck restarting and prints `--`; that container's use is
// unknown, counted as nothing, rather than blocking every deploy on the server.
func TestAContainerWithoutStatsCountsItsWholeLimit(t *testing.T) {
	f := routedFake(t, nil)
	f.server(1100, map[string][2]int{"looping-v1-1": {512, 0}})
	f.out[memStats] = "id-looping-v1-1\t-- / --"
	err := Run(context.Background(), f, io.Discard, parse(t, onePort+"memory: 512m\n"), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "332MiB is free") {
		t.Fatalf("1100 − 512 still to come − 256 leaves 332, got %v", err)
	}
}

// A lock this app left under another token is a leftover: the caller holds the app's deploy lock,
// so no other run of the app can be holding it. It is taken back instead of waited for.
func TestAdmissionTakesBackALeftoverOfThisApp(t *testing.T) {
	f := routedFake(t, nil)
	f.out["sh -c readlink /tmp/boks.admit.lock"] = "demo.1699999999000000000"
	f.onRun = func(cmd string) {
		switch {
		case strings.Contains(cmd, "'demo.1699999999000000000' ] && rm -f"):
			delete(f.out, "sh -c readlink /tmp/boks.admit.lock")
			delete(f.fail, "ln -sn")
		case strings.HasPrefix(cmd, "ln -sn") && f.out["sh -c readlink /tmp/boks.admit.lock"] != "":
			f.fail["ln -sn"] = errors.New("File exists")
		}
	}
	o := fixed
	o.Poll, o.AdmitWait = time.Millisecond, time.Second
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", o); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker run") {
		t.Errorf("the deploy goes on once the leftover is gone: %v", f.calls)
	}
}

// `ln` that fails with no lock in the way is the server failing, said after a few tries rather
// than after the whole wait.
func TestAdmissionFailsFastWithoutALockInTheWay(t *testing.T) {
	f := routedFake(t, nil)
	f.fail["ln -sn"] = errors.New("Read-only file system")
	o := fixed
	o.Poll, o.AdmitWait = time.Millisecond, 3*time.Second
	start := time.Now()
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "Read-only file system") {
		t.Fatalf("want the ln failure, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("must not wait the whole AdmitWait: %s", time.Since(start))
	}
}

// Container names are not unique across apps: a container under this run's name that another app
// labelled is that app's, and a failed start does not remove it.
func TestAFailedStartLeavesAnotherAppsContainerAlone(t *testing.T) {
	f := stopFirstFake(t)
	f.fail["docker run"] = errors.New("Conflict. The container name is already in use")
	f.out["docker ps -a --filter name=^"+newCopy+"$ --format {{.Names}}\t"] = newCopy + "\tdemo-v2\n"
	err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("want the start error, got %v", err)
	}
	if f.has("docker stop "+newCopy) || f.has("docker rm -f "+newCopy) {
		t.Errorf("another app's container must be left alone: %v", f.calls)
	}
	if !f.has("docker start demo-v1-1") {
		t.Errorf("this app's old copy comes back: %v", f.calls)
	}
}

// A leftover of this app that cannot be removed is taken back once, then waited for like any lock.
func TestAnUnremovableLeftoverIsNotRetriedForever(t *testing.T) {
	f := routedFake(t, nil)
	f.fail["ln -sn"] = errors.New("File exists")
	f.out["sh -c readlink /tmp/boks.admit.lock"] = "demo.1699999999000000000"
	o := fixed
	o.Poll, o.AdmitWait = time.Millisecond, 20*time.Millisecond
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "held the admission lock") {
		t.Fatalf("want the wait to end with the lock named, got %v", err)
	}
	tries := 0
	for _, c := range f.calls {
		if strings.Contains(c, "'demo.1699999999000000000' ] && rm -f") {
			tries++
		}
	}
	if tries != 1 {
		t.Errorf("want one take-back, got %d", tries)
	}
}

// The copies on the server say how they may be replaced, by the label they were started with — not
// the journal's idea of what serves: a stop-first copy that started and was never recorded still
// writes its volume. With every copy on overlap, overlap it is; the new copy records its own mode.
func TestTheRunningCopiesCanAskForStopFirst(t *testing.T) {
	f := stopFirstFake(t)
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" + ports(t, webPort) + "\tstop-first\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if f.callAt("docker stop demo-v1-1") < 0 || f.callAt("docker stop demo-v1-1") > f.callAt("docker run") {
		t.Errorf("want the old copy stopped before the new one starts: %v", f.calls)
	}
	if run := f.calls[f.callAt("docker run")]; !strings.Contains(run, "--label boks.replace=overlap") {
		t.Errorf("the new copy carries its own mode: %s", run)
	}

	g := stopFirstFake(t)
	g.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" + ports(t, webPort) + "\toverlap\n"
	if err := Run(context.Background(), g, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if g.callAt("docker stop demo-v1-1") < g.callAt("docker run") {
		t.Errorf("with every side on overlap the old copy goes only after the switch: %v", g.calls)
	}
}

// A copy started before the label existed is judged by its shape: one started without routes was
// always replaced stop-first, so a worker that gains a port is not run beside its old copy.
func TestAnUnlabelledCopyIsJudgedByItsShape(t *testing.T) {
	f := stopFirstFake(t)
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t[]\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if f.callAt("docker stop demo-v1-1") < 0 || f.callAt("docker stop demo-v1-1") > f.callAt("docker run") {
		t.Errorf("want the old worker stopped first: %v", f.calls)
	}
	g := stopFirstFake(t) // labelled with its ports, no replace label: a routed copy that overlapped
	if err := Run(context.Background(), g, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if g.callAt("docker stop demo-v1-1") < g.callAt("docker run") {
		t.Errorf("an unlabelled routed copy overlaps, as it did: %v", g.calls)
	}
}

// Tags keep their dots, and the name filter is a regular expression: the dot is quoted, and only the
// line naming exactly this run's container counts — a lookalike of another app is neither this run's
// copy nor proof that it is still there.
func TestDiscardReadsExactlyItsOwnName(t *testing.T) {
	const query = `docker ps -a --filter name=^bot-v1\.0-1700000000$`
	f := routelessFake("unhealthy")
	f.out[query] = "bot-v1-0-1700000000\tbot-v1\nbot-v1.0-1700000000\tbot\n"
	f.onRun = func(cmd string) {
		if cmd == "docker rm -f bot-v1.0-1700000000" {
			f.out[query] = "bot-v1-0-1700000000\tbot-v1\n"
		}
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v1.0", quick()); err == nil {
		t.Fatal("want the health failure")
	}
	if !f.has("docker rm -f bot-v1.0-1700000000") {
		t.Errorf("this run's own copy is removed, whatever line it is on: %v", f.calls)
	}
	if !f.has(query) {
		t.Errorf("the dot of the tag must be quoted in the name filter: %v", f.calls)
	}
	if !f.has("docker start bot-v1-1") {
		t.Errorf("a lookalike of another app does not keep the old copy down: %v", f.calls)
	}

	g := routelessFake("unhealthy")
	g.out["docker ps -a --filter name=^bot-v2-1700000000$"] = "bot-v2-1700000000\t\n" // made by hand, no label
	if err := Run(context.Background(), g, io.Discard, parse(t, noPorts), "v2", quick()); err == nil {
		t.Fatal("want the health failure")
	}
	if g.has("docker rm -f bot-v2-1700000000") {
		t.Errorf("a container this app never labelled is not removed: %v", g.calls)
	}
}

// A rollback whose image was pruned fetches it before anything stops, not while the app is down.
func TestRollbackFetchesAMissingImageBeforeTheStop(t *testing.T) {
	f := demoReleases(t, `{`+v1Release+`,"digest":"sha256:old","replace":"stop-first"}`)
	f.out["sh -c out=$(docker image inspect"] = "absent"
	if err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	pulled, stopped := f.callAt("docker pull ghcr.io/x/y@sha256:old"), f.callAt("docker stop demo-v2-2")
	if pulled < 0 || stopped < 0 || pulled > stopped {
		t.Errorf("want the pull before the stop: %d %d %v", pulled, stopped, f.calls)
	}
	g := demoReleases(t, `{`+v1Release+`,"digest":"sha256:old"}`)
	if err := Rollback(context.Background(), g, io.Discard, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	if g.has("docker pull") {
		t.Errorf("an image still on the server is not pulled again: %v", g.calls)
	}
	// An inspect that failed for another reason says nothing about the image: no pull, which would
	// fail the rollback during a registry outage.
	h := demoReleases(t, `{`+v1Release+`,"digest":"sha256:old"}`)
	h.out["sh -c out=$(docker image inspect"] = "unknown"
	if err := Rollback(context.Background(), h, io.Discard, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	if h.has("docker pull") {
		t.Errorf("an unknown answer is not taken for a missing image: %v", h.calls)
	}
}

// Today's config asking for stop-first makes the rollback stop first, but the restored copy carries
// the mode its own release asked for: the config's vote is not baked into the label.
func TestRollbackLabelsTheReleasesOwnMode(t *testing.T) {
	f := demoReleases(t, `{`+v1Release+`,"replace":"overlap"}`)
	if err := Rollback(context.Background(), f, io.Discard, parse(t, stopFirst), "", fixed); err != nil {
		t.Fatal(err)
	}
	if f.callAt("docker stop demo-v2-2") < 0 || f.callAt("docker stop demo-v2-2") > f.callAt("docker run") {
		t.Errorf("want stop-first: %v", f.calls)
	}
	if run := f.calls[f.callAt("docker run")]; !strings.Contains(run, "--label boks.replace=overlap") {
		t.Errorf("want the release's own mode on the label: %s", run)
	}
}

// A stop whose answer was lost — the connection dropped after docker took it — is asked again, which
// waits for the shutdown to end; confirmed, it is a stop, and the deploy goes on rather than reviving
// a copy that is still on its way down.
func TestALostStopAnswerIsAskedAgain(t *testing.T) {
	f := stopFirstFake(t)
	stops := 0
	f.onRun = func(cmd string) {
		if cmd == "docker stop demo-v1-1" {
			if stops++; stops == 1 {
				f.fail["docker stop demo-v1-1"] = errors.New("connection reset")
			} else {
				delete(f.fail, "docker stop demo-v1-1")
			}
		}
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if f.has("docker start demo-v1-1") || !f.has("docker run") {
		t.Errorf("a stop that completed on the second ask is a stop: %v", f.calls)
	}
}

// The check a fleet rollback asks every server before any of them changes includes the memory check
// of the release it would restore — refused on one server, none is rolled back — and it reads only.
func TestCheckRollbackAsksTheMemoryCheck(t *testing.T) {
	f := demoReleases(t, `{`+v1Release+`,"memory":"1g"}`)
	f.server(700, nil)
	if _, err := CheckRollback(context.Background(), f, parse(t, onePort), ""); err == nil || !strings.Contains(err.Error(), "preliminary memory check") {
		t.Fatalf("want the memory refusal, got %v", err)
	}
	if f.has("docker stop") || f.has("docker run") || f.has("ln -sn") || len(f.appends) != 0 || len(f.uploads) != 0 {
		t.Errorf("a check changes nothing: %v", f.calls)
	}
	g := demoReleases(t, `{`+v1Release+`,"memory":"256m"}`)
	g.server(4000, nil)
	if id, err := CheckRollback(context.Background(), g, parse(t, onePort), ""); err != nil || id != "demo-v1-1" {
		t.Errorf("a release that fits passes: %q %v", id, err)
	}
}

// A rollback to a release recorded without a limit runs without one, as it did — and says so when
// today's config asks for one.
func TestRollbackSaysWhenItDropsTheLimit(t *testing.T) {
	f := demoReleases(t, `{`+v1Release+`}`)
	var log strings.Builder
	if err := Rollback(context.Background(), f, &log, parse(t, onePort+"memory: 512m\n"), "", fixed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "recorded without a memory limit") {
		t.Errorf("want the dropped limit named: %q", log.String())
	}
}

// A copy that did not come back is no target for the routes: no proxy deploy waits out its health
// check on every port.
func TestStopFirstDoesNotRevertOntoACopyThatStayedDown(t *testing.T) {
	f := stopFirstFake(t)
	f.fail[deployVia+"demo.web --target "+newCopy] = errors.New("unhealthy")
	f.onRun = func(cmd string) {
		if cmd == "docker start demo-v1-1" {
			f.out[isRunningQuery+"demo-v1-1"] = "false"
		}
	}
	err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "did not come back up") {
		t.Fatalf("want the copy that stayed down named, got %v", err)
	}
	if f.has(deployVia + "demo.web --target demo-v1-1") {
		t.Errorf("no route goes back to a copy that is not running: %v", f.calls)
	}
	if !strings.Contains(err.Error(), "no route was moved back") || strings.Contains(err.Error(), "sent back") {
		t.Errorf("the error must not claim routes went back: %v", err)
	}
}

// A copy whose state could not be read after its restart may well be back, so its routes are still
// sent to it; only one docker says is not running is skipped.
func TestStopFirstRevertsOntoACopyOfUnknownState(t *testing.T) {
	f := stopFirstFake(t)
	f.fail[deployVia+"demo.web --target "+newCopy] = errors.New("unhealthy")
	f.onRun = func(cmd string) {
		if cmd == "docker start demo-v1-1" {
			f.fail[isRunningQuery+"demo-v1-1"] = errors.New("connection reset")
		}
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, stopFirst), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if !f.has(deployVia + "demo.web --target demo-v1-1:3000") {
		t.Errorf("the route goes back to a copy that may be up: %v", f.calls)
	}
}
