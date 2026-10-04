package deploy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// The point of the journal: a rollback reproduces what actually ran — the image by digest, the
// ports and volumes of that release — rather than today's config with an old tag.
func TestRollbackRunsTheRecordedRelease(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v2-2\n"
	f.out["cat .boks/demo/releases/demo-v2-2.json"] = `{"id":"demo-v2-2","previous":"demo-v1-1"}`
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{
		"id":"demo-v1-1","app":"demo","image":"ghcr.io/x/y","tag":"v1","digest":"sha256:old",
		"ports":[{"name":"web","port":3000,"host":"demo.example.com","health_path":"/up","health_port":0}],
		"volumes":["data:/data"],"network":"boks","env_path":".boks/demo/demo-v1-1.env"}`
	f.out["sh -c test -f"] = "present"
	if err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker run -d --name demo-v1-1700000000") {
		t.Fatalf("no container started: %v", f.calls)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "ghcr.io/x/y@sha256:old") {
		t.Errorf("the image must be pinned by the recorded digest: %v", f.calls)
	}
	if !strings.Contains(joined, "--env-file .boks/demo/demo-v1-1.env") {
		t.Errorf("the environment of that release must be used: %v", f.calls)
	}
	if !strings.Contains(joined, "kamal-proxy deploy demo.web --target demo-v1-1700000000:3000") {
		t.Errorf("routes must point at the restored container: %v", f.calls)
	}
	if !strings.Contains(f.appends[".boks/demo/journal.jsonl"], `"action":"rollback"`) {
		t.Errorf("the rollback must be journalled: %q", f.appends[".boks/demo/journal.jsonl"])
	}
}

// Without the environment file the release cannot be reproduced, only approximated — say so
// instead of starting the app with today's variables under an old image.
func TestRollbackRefusesWhenTheReleaseEnvIsGone(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v2-2\n"
	f.out["cat .boks/demo/releases/demo-v2-2.json"] = `{"id":"demo-v2-2","previous":"demo-v1-1"}`
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{"id":"demo-v1-1","app":"demo","image":"ghcr.io/x/y","tag":"v1","env_path":".boks/demo/demo-v1-1.env"}`
	err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed)
	if err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
		t.Fatalf("want a refusal about the missing environment, got %v", err)
	}
	if f.has("docker") || len(f.appends) > 0 {
		t.Errorf("the refusal must come before anything on the server changes: %v", f.calls)
	}

	// An app without routes is where it matters most: the running copy would be stopped first.
	bot := botReleases("healthy")
	delete(bot.out, "sh -c test -f")
	if err := Rollback(context.Background(), bot, io.Discard, parse(t, noPorts), "", quick()); err == nil {
		t.Fatal("want a refusal about the missing environment")
	}
	if bot.has("docker") || len(bot.appends) > 0 {
		t.Errorf("the running copy must be left alone: %v", bot.calls)
	}
}

func TestRollbackWithoutAnyEarlierRelease(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed)
	if err == nil || !strings.Contains(err.Error(), "no earlier release") {
		t.Fatalf("want a clear refusal, got %v", err)
	}
}

// botReleases is a server where bot-v2-2 is current and running, and bot-v1-1 is the release
// before it, recorded with its digest and environment file.
func botReleases(health string) *fake {
	f := newFake()
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v2-2\t[]\n"
	f.out["docker ps --filter label=boks.app=bot"] = "bot-v2-2\n"
	f.out["docker image inspect"] = `["CMD-SHELL","redis-cli ping"]`
	f.out["docker inspect --format"] = health
	f.out["sh -c test -f"] = "present"
	f.out["sh -c ls -1"] = "bot-v1-1.json\nbot-v2-2.json\n"
	f.out["sh -c cat '.boks/bot/current'"] = "bot-v2-2\n"
	f.out["cat .boks/bot/releases/bot-v2-2.json"] = `{"id":"bot-v2-2","previous":"bot-v1-1"}`
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = `{"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1",
		"digest":"sha256:old","ports":[],"volumes":["data:/data"],"network":"boks","env_path":".boks/bot/bot-v1-1.env"}`
	return f
}

// A rollback of an app without routes replaces it in place, exactly as a deploy does: two copies
// of Redis on one volume, or two workers on one queue, are what this path exists to prevent.
func TestRoutelessRollbackStopsTheRunningCopyFirst(t *testing.T) {
	f := botReleases("healthy")
	// The config publishes a port today; the release being restored did not, and it is the
	// release that decides how it runs.
	routedNow := noPorts + "ports:\n  - {name: web, port: 80, host: bot.example.com}\n"
	if err := Rollback(context.Background(), f, io.Discard, parse(t, routedNow), "", quick()); err != nil {
		t.Fatal(err)
	}
	stop, run := f.callAt("docker stop bot-v2-2"), f.callAt("docker run -d --name bot-v1-1700000000")
	if stop < 0 || run < 0 || stop > run {
		t.Fatalf("the running copy must be stopped before the restored one starts: %v", f.calls)
	}
	if !strings.HasSuffix(f.calls[run], "-v bot.data:/data ghcr.io/x/bot@sha256:old") {
		t.Errorf("the recorded volumes and digest must be run: %s", f.calls[run])
	}
	if f.has("docker pull") || touchesProxy(f) {
		t.Errorf("a rollback of an app without routes neither pulls nor touches the proxy: %v", f.calls)
	}
	if !f.has("docker images ghcr.io/x/bot") {
		t.Errorf("images beyond keep are pruned after a rollback too: %v", f.calls)
	}
}

// A restored release that never becomes healthy is removed before the copy it replaced comes back.
func TestRoutelessRollbackBringsTheOldCopyBack(t *testing.T) {
	f := botReleases("unhealthy")
	err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick())
	if err == nil {
		t.Fatal("want the unhealthy release to fail the rollback")
	}
	removed, restarted := f.callAt("docker rm -f bot-v1-1700000000"), f.callAt("docker start bot-v2-2")
	if removed < 0 || restarted < 0 || removed > restarted {
		t.Errorf("the restored copy must be gone before the old one restarts: %v", f.calls)
	}
	if f.uploads[".boks/bot/current"] != "" {
		t.Errorf("a failed rollback must not move current: %v", f.uploads)
	}
}

// A stop that fails is the guarantee failing: the restored copy must not start next to it.
func TestRoutelessRollbackRefusesWhenTheStopFails(t *testing.T) {
	f := botReleases("healthy")
	f.fail["docker stop bot-v2-2"] = errors.New("daemon busy")
	err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick())
	if err == nil || !strings.Contains(err.Error(), "could not stop bot-v2-2") {
		t.Fatalf("want a refusal about the stop, got %v", err)
	}
	if f.has("docker run") {
		t.Errorf("nothing may start after a failed stop: %v", f.calls)
	}
}

// The restored release keeps its id, so the next rollback goes further back instead of returning
// to the release just left.
func TestRollbackPointsCurrentAtTheRestoredRelease(t *testing.T) {
	f := botReleases("healthy")
	if err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick()); err != nil {
		t.Fatal(err)
	}
	if got := f.uploads[".boks/bot/current"]; got != "bot-v1-1\n" {
		t.Errorf("current must name the restored release, got %q", got)
	}
	for path := range f.uploads {
		if strings.HasPrefix(path, ".boks/bot/releases/") {
			t.Errorf("a rollback must not record a copy of the release under a new id: %s", path)
		}
	}
	if !strings.Contains(f.appends[botJournal], `"result":"ok"`) {
		t.Errorf("the rollback's entry must be closed: %q", f.appends[botJournal])
	}
}

// Without a record of what serves now, retiring the copy that served before would delete the last
// trace of it while `current` still names it.
func TestRollbackKeepsTheOldCopyWhenCurrentCannotBeMoved(t *testing.T) {
	f := botReleases("healthy")
	f.pipeFail = func(path, _ string) error {
		if path == ".boks/bot/current" {
			return errors.New("disk full")
		}
		return nil
	}
	err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick())
	if err == nil || !strings.Contains(err.Error(), "could not record it") || !strings.Contains(err.Error(), "`boks rollback bot-v1-1` again") {
		t.Fatalf("want the unrecorded rollback reported with the rollback to repeat, got %v", err)
	}
	if f.has("docker rm bot-v2-2") {
		t.Errorf("the previous copy must be kept: %v", f.calls)
	}
}

// A rollback routes the hosts through the current certificate, as a deploy does: it refuses while
// the file is missing and, once routed, records that the proxy has loaded it.
func TestRollbackHandlesTheCertificateLikeADeploy(t *testing.T) {
	withCert := onePort + "cert: {domains: [\"*.example.com\"], dns: cloudflare, email: a@example.com}\n"
	snapshot := func(f *fake) {
		f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\n"
		f.out["sh -c cat '.boks/demo/current'"] = "demo-v2-2\n"
		f.out["cat .boks/demo/releases/demo-v2-2.json"] = `{"id":"demo-v2-2","previous":"demo-v1-1"}`
		f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{"id":"demo-v1-1","app":"demo","image":"ghcr.io/x/y","tag":"v1",
			"ports":[{"name":"web","port":3000,"host":"demo.example.com"}],"network":"boks"}`
	}

	missing := routedFake(t, nil)
	snapshot(missing)
	err := Rollback(context.Background(), missing, io.Discard, parse(t, withCert), "", fixed)
	if err == nil || !strings.Contains(err.Error(), "boks cert issue") {
		t.Fatalf("want a refusal while the certificate is missing, got %v", err)
	}
	if missing.has("docker run") {
		t.Errorf("nothing may start without the certificate: %v", missing.calls)
	}

	f := routedFake(t, nil)
	snapshot(f)
	f.out["docker exec boks-proxy cat /certs/boks/_.example.com.crt"] = "-----BEGIN CERTIFICATE-----"
	if err := Rollback(context.Background(), f, io.Discard, parse(t, withCert), "", fixed); err != nil {
		t.Fatal(err)
	}
	marked := false
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker exec -i -u 0 boks-proxy sh -c") && strings.Contains(c, ".demo.loaded") {
			marked = true
		}
	}
	if !marked {
		t.Errorf("the certificate the routes now load must be recorded as loaded: %v", f.calls)
	}
}

// An explicit id is the release returned to, whatever the current one was deployed over; and the
// route and mounts are the recorded ones, not those the config names today.
func TestRollbackToAnExplicitRelease(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\ndemo-v3-3.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v3-3\n"
	f.out["cat .boks/demo/releases/demo-v3-3.json"] = `{"id":"demo-v3-3","previous":"demo-v2-2"}`
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{"id":"demo-v1-1","app":"demo","image":"ghcr.io/x/y","tag":"v1",
		"digest":"sha256:one","ports":[{"name":"web","port":4000,"host":"old.example.com"}],"volumes":["data:/data"],"network":"legacy"}`
	cfg := parse(t, strings.Replace(onePort, "volumes: [data:/data]", "volumes: [cache:/cache]", 1))
	if err := Rollback(context.Background(), f, io.Discard, cfg, "demo-v1-1", fixed); err != nil {
		t.Fatal(err)
	}
	run := f.callAt("docker run")
	if run < 0 || !strings.HasSuffix(f.calls[run], "-v demo.data:/data ghcr.io/x/y@sha256:one") || strings.Contains(f.calls[run], "cache") {
		t.Errorf("want release v1 with its own mounts only, got %v", f.calls)
	}
	// The network is the server's: the proxy is on today's one, and the routes have to reach it.
	if run >= 0 && !strings.Contains(f.calls[run], "--network boks ") {
		t.Errorf("want today's network, got %s", f.calls[run])
	}
	if !f.has("docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v1-1700000000:4000 --host old.example.com") {
		t.Errorf("the route must be the recorded one, port and host: %v", f.calls)
	}
	if got := f.uploads[".boks/demo/current"]; got != "demo-v1-1\n" {
		t.Errorf("current must name the release asked for, got %q", got)
	}
}

// A connection that drops while asking is not an answer that the file is gone.
func TestRollbackDoesNotMistakeAFailedCheckForAMissingEnv(t *testing.T) {
	f := botReleases("healthy")
	f.fail["sh -c test -f"] = errors.New("connection reset")
	err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick())
	if err == nil || strings.Contains(err.Error(), "cannot be reproduced") || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("want the connection failure reported as such, got %v", err)
	}
	if f.has("docker") {
		t.Errorf("nothing may change: %v", f.calls)
	}
}

// keep applies to the recorded releases after a rollback too, as it did when a rollback was a
// deploy; the restored release is current, so it is never the one that goes.
func TestRollbackPrunesReleasesBeyondKeep(t *testing.T) {
	f := botReleases("healthy")
	cfg := parse(t, noPorts+"keep: 1\n")
	if err := Rollback(context.Background(), f, io.Discard, cfg, "", quick()); err != nil {
		t.Fatal(err)
	}
	if !f.has("rm -f .boks/bot/releases/bot-v2-2.json") || f.has("rm -f .boks/bot/releases/bot-v1-1.json") {
		t.Errorf("want the release left behind pruned and the restored one kept: %v", f.calls)
	}
}

// A command over several servers names its releases with one stamp, so a release has one id
// everywhere: the id `boks releases` prints for one server is the one `boks rollback` finds on all.
func TestStampNamesTheRelease(t *testing.T) {
	f := routedFake(t, nil)
	o := fixed
	o.Stamp = time.Unix(1600000000, 0)
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", o); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker run -d --name demo-v2-1600000000") || f.uploads[".boks/demo/current"] != "demo-v2-1600000000\n" {
		t.Errorf("want the release named by the stamp, not by the clock: %v", f.calls)
	}
}

// The check a multi-server rollback runs on every server first: it refuses where the release is
// not recorded and changes nothing anywhere.
func TestCheckRollbackChangesNothing(t *testing.T) {
	f := botReleases("healthy")
	if err := CheckRollback(context.Background(), f, parse(t, noPorts), ""); err != nil {
		t.Fatalf("the previous release is there and reproducible: %v", err)
	}
	if err := CheckRollback(context.Background(), f, parse(t, noPorts), "bot-v9-9"); err == nil {
		t.Error("want a refusal for a release this server does not have")
	}
	if f.has("docker") || f.has("mkdir") || len(f.uploads) > 0 || len(f.appends) > 0 {
		t.Errorf("a check must not change the server: %v", f.calls)
	}
}
