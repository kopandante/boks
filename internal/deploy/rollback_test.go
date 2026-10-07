package deploy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/release"
)

// The point of the journal: a rollback reproduces what actually ran — the image by digest, the
// ports and volumes of that release — rather than today's config with an old tag.
func TestRollbackRunsTheRecordedRelease(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
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
	if !strings.Contains(f.uploads[".boks/_proxy/caddy.next.json"], `"dial": "demo-v1-1700000000:3000"`) {
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
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
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
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
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
}

// A restored release that never becomes healthy is removed before the copy it replaced comes back.
func TestRoutelessRollbackBringsTheOldCopyBack(t *testing.T) {
	f := botReleases("unhealthy")
	err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick())
	if err == nil {
		t.Fatal("want the unhealthy release to fail the rollback")
	}
	removed, restarted := f.callAt("docker rm -f -v bot-v1-1700000000"), f.callAt("docker start bot-v2-2")
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
	if f.has("docker rm -v bot-v2-2") {
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

	missing := routedFake(t)
	snapshot(missing)
	err := Rollback(context.Background(), missing, io.Discard, parse(t, withCert), "", fixed)
	if err == nil || !strings.Contains(err.Error(), "boks cert issue") {
		t.Fatalf("want a refusal while the certificate is missing, got %v", err)
	}
	if missing.has("docker run") {
		t.Errorf("nothing may start without the certificate: %v", missing.calls)
	}

	f := routedFake(t)
	snapshot(f)
	f.out["docker exec boks-proxy cat /certs/boks/_.example.com.crt"] = "-----BEGIN CERTIFICATE-----"
	if err := Rollback(context.Background(), f, io.Discard, parse(t, withCert), "", fixed); err != nil {
		t.Fatal(err)
	}
	marked := false
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker exec -i -u 0 boks-proxy sh -c") && strings.Contains(c, "_.example.com.restarted") {
			marked = true
		}
	}
	if !marked {
		t.Errorf("the reload read the certificate, which must be recorded as loaded: %v", f.calls)
	}
	if !strings.Contains(f.uploads[".boks/_proxy/caddy.next.json"], `"certificate": "/certs/boks/_.example.com.crt"`) {
		t.Errorf("the host under the certificate is served from its file:\n%s", f.uploads[".boks/_proxy/caddy.next.json"])
	}
}

// An explicit id is the release returned to, whatever the current one was deployed over; and the
// route and mounts are the recorded ones, not those the config names today.
func TestRollbackToAnExplicitRelease(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
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
	// A release recorded before networks were (no version, a shared network named) comes back on the
	// app's own network under its alias, not on the shared network it ran on.
	if run >= 0 && !strings.Contains(f.calls[run], "--network boks-demo --network-alias demo ") {
		t.Errorf("want the app's own network, got %s", f.calls[run])
	}
	if next := f.uploads[".boks/_proxy/caddy.next.json"]; !strings.Contains(next, `"dial": "demo-v1-1700000000:4000"`) || !strings.Contains(next, `"old.example.com"`) {
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
	f.out["cat .boks/bot/releases/bot-v2-2.json"] = `{"id":"bot-v2-2","image":"ghcr.io/x/bot","tag":"v2","previous":"bot-v1-1"}`
	f.out["find .boks"] = `{"image":"ghcr.io/x/bot","tag":"v1","digest":"sha256:old"}`
	f.out["docker images --digests ghcr.io/x/bot"] = "v2 <none> id-v2\nv1 sha256:old id-v1\n"
	cfg := parse(t, noPorts+"keep: 1\n")
	if err := Rollback(context.Background(), f, io.Discard, cfg, "", quick()); err != nil {
		t.Fatal(err)
	}
	if !f.has("rm -rf .boks/bot/releases/bot-v2-2.json") || f.has("rm -rf .boks/bot/releases/bot-v1-1.json") {
		t.Errorf("want the release left behind pruned and the restored one kept: %v", f.calls)
	}
	// And the image of the release left behind goes with it, once its copy is retired.
	if !f.has("docker rmi ghcr.io/x/bot:v2") || f.has("docker rmi ghcr.io/x/bot:v1") || f.lastAt("docker rm -v bot-v2-2") > f.callAt("docker rmi") {
		t.Errorf("want v2's image pruned after its copy is gone, v1's kept: %v", f.calls)
	}
}

// A command over several servers names its releases with one stamp, so a release has one id
// everywhere: the id `boks releases` prints for one server is the one `boks rollback` finds on all.
func TestStampNamesTheRelease(t *testing.T) {
	f := routedFake(t)
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
	if target, err := CheckRollback(context.Background(), f, parse(t, noPorts), ""); err != nil || target != "bot-v1-1" {
		t.Fatalf("want the previous release, which is there and reproducible: %q %v", target, err)
	}
	if _, err := CheckRollback(context.Background(), f, parse(t, noPorts), "bot-v9-9"); err == nil {
		t.Error("want a refusal for a release this server does not have")
	}
	// It reads (the proxy's state is asked, as below); it runs nothing that changes the server.
	for _, change := range []string{"docker run", "docker stop", "docker rm", "docker start", "docker create", "docker rename", "docker network create", "mkdir"} {
		if f.has(change) {
			t.Errorf("a check must not change the server (%s): %v", change, f.calls)
		}
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 {
		t.Errorf("a check must not change the server: %v %v", f.uploads, f.appends)
	}
}

// A server still on kamal-proxy refuses a rollback with routes partway through: the check asks first,
// so a rollback over several servers does not leave the earlier ones on another release.
func TestCheckRollbackAsksForTheMigration(t *testing.T) {
	f := botReleases("healthy")
	f.out[proxyState] = "running\t"
	if _, err := CheckRollback(context.Background(), f, parse(t, noPorts), ""); err != nil {
		t.Errorf("no routes either side: kamal-proxy is not in the way, got %v", err)
	}
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = strings.Replace(f.out["cat .boks/bot/releases/bot-v1-1.json"],
		`"ports":[]`, `"ports":[{"name":"web","port":80,"host":"bot.example.com"}]`, 1)
	if _, err := CheckRollback(context.Background(), f, parse(t, noPorts), ""); err == nil || !strings.Contains(err.Error(), "boks proxy migrate") {
		t.Errorf("want the migration asked for, got %v", err)
	}
}

// The health check belongs to the release: a rollback starts the restored copy with the one it
// recorded — a stock image would otherwise come back with none — and with none when it recorded
// none, whatever the config says today.
func TestRollbackRestoresTheHealthcheckOfTheRelease(t *testing.T) {
	f := botReleases("healthy")
	f.out["docker image inspect"] = ""
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = `{"version":5,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1",
		"digest":"sha256:old","ports":[],"volumes":["data:/data"],"networks":[{"name":"boks-bot","aliases":["bot"]}],
		"env_path":".boks/bot/bot-v1-1.env","healthcheck":{"cmd":"pg_isready","interval":"1s"}}`
	today := parse(t, noPorts+"healthcheck: {cmd: \"true\", interval: 1500ms}\n")
	if err := Rollback(context.Background(), f, io.Discard, today, "", quick()); err != nil {
		t.Fatal(err)
	}
	if run := f.calls[f.callAt("docker run")]; !strings.Contains(run, " --health-cmd pg_isready --health-interval 1s ") {
		t.Errorf("the restored copy must run the recorded check, not today's: %s", run)
	}

	g := botReleases("healthy")
	if err := Rollback(context.Background(), g, io.Discard, parse(t, noPorts+"healthcheck: {cmd: true, interval: 1s}\n"), "", quick()); err != nil {
		t.Fatal(err)
	}
	if run := g.calls[g.callAt("docker run")]; strings.Contains(run, "--health-cmd") {
		t.Errorf("a release recorded without a check runs with the image's own, not today's: %s", run)
	}
}

// The recorded check meets today's deploy_timeout only at a rollback: an interval the wait does not
// outlast is refused before anything is stopped, by the check as well as by the rollback.
func TestRollbackRefusesAHealthcheckTheDeployTimeoutCannotWaitFor(t *testing.T) {
	f := botReleases("healthy")
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = `{"version":5,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1",
		"digest":"sha256:old","ports":[],"volumes":["data:/data"],"networks":[{"name":"boks-bot","aliases":["bot"]}],
		"env_path":".boks/bot/bot-v1-1.env","healthcheck":{"cmd":"pg_isready","interval":"2s"}}`
	cfg := parse(t, noPorts) // deploy_timeout 2s: equal is not shorter
	if _, err := CheckRollback(context.Background(), f, cfg, ""); err == nil || !strings.Contains(err.Error(), "raise deploy_timeout") {
		t.Errorf("the check must refuse, got %v", err)
	}
	if err := Rollback(context.Background(), f, io.Discard, cfg, "", quick()); err == nil || !strings.Contains(err.Error(), "raise deploy_timeout") {
		t.Fatalf("want a refusal naming deploy_timeout, got %v", err)
	}
	if f.has("docker stop") || f.has("docker run") || f.has("docker create") {
		t.Errorf("nothing may be stopped or started: %v", f.calls)
	}
}

// A rollback serves the release's ports with today's TLS and certificate: a wildcard the release
// served without TLS cannot be served with TLS and no certificate for it — HTTP-01 does not issue one.
func TestRollbackRefusesAWildcardTodaysTLSCannotServe(t *testing.T) {
	f := botReleases("healthy")
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = `{"version":9,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1",
		"digest":"sha256:old","ports":[{"name":"web","port":80,"host":"*.example.com","health_path":"","health_port":0}],
		"volumes":["data:/data"],"networks":[{"name":"boks-bot","aliases":["bot"]}],"env_path":".boks/bot/bot-v1-1.env"}`
	cfg := parse(t, noPorts+"tls: true\nports: [{name: web, port: 80, host: bot.example.com}]\n")
	if _, err := CheckRollback(context.Background(), f, cfg, ""); err == nil || !strings.Contains(err.Error(), "needs a cert") {
		t.Errorf("the check must refuse, got %v", err)
	}
	if err := Rollback(context.Background(), f, io.Discard, cfg, "", quick()); err == nil || !strings.Contains(err.Error(), "needs a cert") {
		t.Fatalf("want a refusal naming the certificate, got %v", err)
	}
	if f.has("docker stop") || f.has("docker run") || f.has("docker create") {
		t.Errorf("nothing may be stopped or started: %v", f.calls)
	}
}

// A rollback mounts the files its release ran with, from that release's own directory, and refuses
// before anything changes when they are gone.
func TestRollbackMountsTheFilesOfTheRelease(t *testing.T) {
	v1 := `{"version":6,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1","digest":"sha256:old","ports":[],
		"networks":[{"name":"boks-bot","aliases":["bot"]}],"env_path":".boks/bot/bot-v1-1.env",
		"files":[{"name":"0-site.conf","target":"/etc/site.conf"},{"name":"1-mime.types","target":"/etc/mime.types"}]}`
	f := botReleases("healthy")
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = v1
	f.out["sh -c for f in '.boks/bot/files/bot-v1-1/0-site.conf' '.boks/bot/files/bot-v1-1/1-mime.types';"] = "present"
	f.out["sh -c cd '.boks/bot/files/bot-v1-1' && pwd -P"] = "/home/u/.boks/bot/files/bot-v1-1"
	if err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick()); err != nil {
		t.Fatal(err)
	}
	if run := f.calls[f.callAt("docker run")]; !strings.Contains(run, " -v /home/u/.boks/bot/files/bot-v1-1/0-site.conf:/etc/site.conf:ro ") ||
		!strings.Contains(run, " -v /home/u/.boks/bot/files/bot-v1-1/1-mime.types:/etc/mime.types:ro ") {
		t.Errorf("the restored copy must mount the release's own files: %s", run)
	}

	g := botReleases("healthy")
	g.out["cat .boks/bot/releases/bot-v1-1.json"] = v1
	g.out["sh -c for f in"] = ".boks/bot/files/bot-v1-1/1-mime.types"
	err := Rollback(context.Background(), g, io.Discard, parse(t, noPorts), "", quick())
	if err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
		t.Fatalf("want a refusal naming the missing file, got %v", err)
	}
	if g.has("docker stop") || g.has("docker run") {
		t.Errorf("a release that cannot be reproduced must leave the running copy alone: %v", g.calls)
	}
	// A fleet rollback asks every server first, by the same check.
	h := botReleases("healthy")
	h.out["cat .boks/bot/releases/bot-v1-1.json"] = v1
	h.out["sh -c for f in"] = ".boks/bot/files/bot-v1-1/0-site.conf"
	if _, err := CheckRollback(context.Background(), h, parse(t, noPorts), ""); err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
		t.Fatalf("the check must refuse a release whose files are gone, got %v", err)
	}
}

// sh runs the commands for real, in a directory of its own: the check of a release's files is a
// shell script, and only the shell tells what it decides.
type sh struct{ dir string }

func (l sh) Run(ctx context.Context, args ...string) (string, error) {
	return l.Pipe(ctx, nil, args...)
}

func (l sh) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir, cmd.Stdin = l.dir, bytes.NewReader(content)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// The check finds a missing file wherever it is in the list, and passes when every one is there.
func TestMissingFileAsksTheShell(t *testing.T) {
	l := sh{t.TempDir()}
	const dir = ".boks/bot/files/bot-v1-1"
	if err := os.MkdirAll(filepath.Join(l.dir, dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.dir, dir, "0-site.conf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []release.File{{Name: "0-site.conf", Target: "/etc/a"}, {Name: "1-mime.types", Target: "/etc/b"}}
	if gone, err := missingFile(context.Background(), l, dir, files); err != nil || gone != dir+"/1-mime.types" {
		t.Errorf("want the second file reported missing, got %q (%v)", gone, err)
	}
	if err := os.WriteFile(filepath.Join(l.dir, dir, "1-mime.types"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	if gone, err := missingFile(context.Background(), l, dir, files); err != nil || gone != "" {
		t.Errorf("all files are there, got %q (%v)", gone, err)
	}
	// A directory in a file's place is not the file the container would mount.
	if gone, _ := missingFile(context.Background(), l, ".boks/bot/files", []release.File{{Name: "bot-v1-1"}}); gone == "" {
		t.Errorf("a directory must not pass for a file")
	}
}

// The command and the stop signal belong to the release: a rollback runs the recorded ones, and the
// image's own when the release recorded none, whatever the config says today.
func TestRollbackRestoresTheCommandOfTheRelease(t *testing.T) {
	f := botReleases("healthy")
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = `{"version":7,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1",
		"digest":"sha256:old","ports":[],"networks":[{"name":"boks-bot","aliases":["bot"]}],"env_path":".boks/bot/bot-v1-1.env",
		"command":["redis-server","--save",""],"stop_signal":"SIGQUIT"}`
	if err := Rollback(context.Background(), f, io.Discard, parse(t, noPorts), "", quick()); err != nil {
		t.Fatal(err)
	}
	if run := f.calls[f.callAt("docker run")]; !strings.HasSuffix(run, "ghcr.io/x/bot@sha256:old redis-server --save ") || !strings.Contains(run, " --stop-signal SIGQUIT ") {
		t.Errorf("the restored copy must run the recorded command and signal: %s", run)
	}

	g := botReleases("healthy")
	if err := Rollback(context.Background(), g, io.Discard, parse(t, noPorts+"command: [x]\nstop_signal: SIGINT\n"), "", quick()); err != nil {
		t.Fatal(err)
	}
	if run := g.calls[g.callAt("docker run")]; !strings.HasSuffix(run, "ghcr.io/x/bot@sha256:old") || strings.Contains(run, "--stop-signal") {
		t.Errorf("a release recorded without them runs the image's own, not today's: %s", run)
	}
}

// A rollback brings back the schedules its release had, records the restored copy — a new container
// under the release's old id — as the serving one, and refuses before anything changes when the
// release's job commands are gone.
func TestRollbackRestoresTheSchedulesOfTheRelease(t *testing.T) {
	v1 := `{"version":8,"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1","digest":"sha256:old","ports":[],
		"networks":[{"name":"boks-bot","aliases":["bot"]}],"env_path":".boks/bot/bot-v1-1.env",
		"schedules":[{"name":"nightly","cron":"0 3 * * *","command":"./nightly"}]}`
	f := botReleases("healthy")
	f.out["cat .boks/bot/releases/bot-v1-1.json"] = v1
	f.out["sh -c command -v crontab"] = "yes"
	f.out["sh -c for f in '.boks/bot/jobs/bot-v1-1/nightly.sh'"] = "present"
	if err := Rollback(context.Background(), f, io.Discard, parse(t, withSchedule), "", quick()); err != nil {
		t.Fatal(err)
	}
	if got := f.uploads[".boks/bot/serving"]; got != "bot-v1-1 bot-v1-1700000000\n" {
		t.Errorf("the serving line must pair the release's id with the restored container: %q", got)
	}
	if !strings.Contains(f.uploads[".boks/bot/crontab"], "0 3 * * * sh $HOME/.boks/bot/boks-job bot nightly") || strings.Contains(f.uploads[".boks/bot/crontab"], "warm") {
		t.Errorf("cron must carry the release's schedules, not today's: %q", f.uploads[".boks/bot/crontab"])
	}

	g := botReleases("healthy")
	g.out["cat .boks/bot/releases/bot-v1-1.json"] = v1
	g.out["sh -c command -v crontab"] = "yes"
	g.out["sh -c for f in"] = ".boks/bot/jobs/bot-v1-1/nightly.sh"
	err := Rollback(context.Background(), g, io.Discard, parse(t, noPorts), "", quick())
	if err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
		t.Fatalf("want a refusal naming the missing job, got %v", err)
	}
	if g.has("docker stop") || g.has("docker run") {
		t.Errorf("the running copy must be left alone: %v", g.calls)
	}
}
