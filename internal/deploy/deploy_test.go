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
)

type fake struct {
	calls   []string
	uploads map[string]string
	out     map[string]string
	fail    map[string]error
}

func newFake() *fake {
	return &fake{uploads: map[string]string{}, out: map[string]string{}, fail: map[string]error{}}
}

func (f *fake) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	for prefix, err := range f.fail {
		if strings.HasPrefix(cmd, prefix) {
			return "", err
		}
	}
	for prefix, out := range f.out {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	return "", nil
}

// Pipe records what an upload would have written: the deploy's env-file goes through
// `sh -c '... cat > <path>'`, so the path is the last quoted token of the script.
func (f *fake) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	if len(args) == 3 && args[0] == "sh" {
		if _, path, ok := strings.Cut(args[2], "cat > "); ok {
			f.uploads[strings.Trim(path, "'")] = string(content)
			return "", nil
		}
	}
	return f.Run(ctx, args...)
}

func (f *fake) has(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func parse(t *testing.T, yaml string) *config.Config {
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const onePort = `
app: demo
image: ghcr.io/x/y
servers: [lab]
keep: 2
volumes: [data:/data]
ports:
  - {name: web, port: 3000, host: demo.example.com, health_path: /up}
tls: true
`

const twoPorts = `
app: demo
image: ghcr.io/x/y
servers: [lab]
ports:
  - {name: web, port: 3000, host: demo.example.com}
  - {name: actions, port: 3001, host: actions.example.com, health_port: 3000}
`

var fixed = Options{Pull: true, Env: []byte("SECRET=1\n"), Now: func() time.Time { return time.Unix(1700000000, 0) }}

func TestRunHappyPath(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t[{\"name\":\"web\",\"port\":3000,\"host\":\"demo.example.com\",\"health_path\":\"/up\",\"health_port\":0}]\n"
	f.out["docker images ghcr.io/x/y"] = "v2 sha-a\nv1 sha-b\nv0 sha-c\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mkdir /tmp/boks-demo.lock",
		"docker network inspect boks",
		"docker ps -a --filter name=^boks-proxy$ --format {{.State}}",
		"docker pull ghcr.io/x/y:v2",
		"docker ps -a --filter label=boks.app=demo --format {{.Names}}\t{{.Label \"boks.ports\"}}",
		"docker run -d --name demo-v2-1700000000 --network boks --restart unless-stopped " +
			"--label boks.app=demo --label boks.version=v2 " +
			"--label boks.ports=[{\"name\":\"web\",\"port\":3000,\"host\":\"demo.example.com\",\"health_path\":\"/up\",\"health_port\":0}] " +
			"--env-file .boks/demo/demo-v2-1700000000.env -v demo-data:/data ghcr.io/x/y:v2",
		"docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v2-1700000000:3000 " +
			"--host demo.example.com --tls --health-check-path /up --deploy-timeout 60s",
		"docker stop demo-v1-1",
		"docker rm demo-v1-1",
		"docker images ghcr.io/x/y --format {{.Tag}} {{.ID}}",
		"docker rmi ghcr.io/x/y:v0",
		"rmdir /tmp/boks-demo.lock",
	}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}
	if f.uploads[".boks/demo/demo-v2-1700000000.env"] != "SECRET=1\n" {
		t.Errorf("env not uploaded: %v", f.uploads)
	}
}

const noPorts = `
app: bot
image: ghcr.io/x/bot
servers: [lab]
deploy_timeout: 2s
`

// An app with no routes is replaced in place: the proxy is never touched and the old container is
// stopped BEFORE the new one starts, so two copies never drain the same queue at once.
func TestRoutelessStopsTheOldCopyFirst(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t\n"
	f.out["docker inspect --format"] = "healthy"
	o := fixed
	o.Poll = time.Nanosecond
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", o); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mkdir /tmp/boks-bot.lock",
		"docker pull ghcr.io/x/bot:v2",
		"docker ps -a --filter label=boks.app=bot --format {{.Names}}\t{{.Label \"boks.ports\"}}",
		"docker stop bot-v1-1",
		"docker run -d --name bot-v2-1700000000 --network boks --restart unless-stopped " +
			"--label boks.app=bot --label boks.version=v2 --label boks.ports=[] " +
			"--env-file .boks/bot/bot-v2-1700000000.env ghcr.io/x/bot:v2",
		"docker inspect --format {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} bot-v2-1700000000",
		"docker stop bot-v1-1",
		"docker rm bot-v1-1",
		"docker images ghcr.io/x/bot --format {{.Tag}} {{.ID}}",
		"rmdir /tmp/boks-bot.lock",
	}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}
	if f.has("docker network inspect") || f.has("docker exec boks-proxy") {
		t.Errorf("the proxy must not be touched for an app without routes: %v", f.calls)
	}
}

// Without a route, the image's own HEALTHCHECK is the only evidence a deploy worked. An image that
// declares none gets a refusal, not a deploy that reports success and proves nothing.
func TestRoutelessRefusesAnImageWithoutHealthcheck(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t\n"
	f.out["docker inspect --format"] = "none"
	o := fixed
	o.Poll = time.Nanosecond
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "HEALTHCHECK") {
		t.Fatalf("want a refusal naming HEALTHCHECK, got %v", err)
	}
	if !f.has("docker rm bot-v2-1700000000") || !f.has("docker start bot-v1-1") {
		t.Errorf("the new copy must go and the old one must come back: %v", f.calls)
	}
}

func TestRoutelessBringsTheOldCopyBackWhenTheNewOneIsUnhealthy(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t\n"
	f.out["docker inspect --format"] = "unhealthy"
	o := fixed
	o.Poll = time.Nanosecond
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("want an unhealthy error, got %v", err)
	}
	if !f.has("docker start bot-v1-1") {
		t.Errorf("old copy must be restarted: %v", f.calls)
	}
}

func TestRunLocked(t *testing.T) {
	f := newFake()
	f.fail["mkdir"] = errors.New("File exists")
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "boks unlock") {
		t.Fatalf("want lock error, got %v", err)
	}
	if len(f.calls) != 1 {
		t.Errorf("nothing must run while locked, got %v", f.calls)
	}
}

// ports encodes a boks.ports label the way a previous deploy would have written it.
func ports(t *testing.T, spec ...config.Port) string {
	t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunKeepsOldWhenSwitchFails(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\n"
	f.fail["docker exec boks-proxy kamal-proxy deploy"] = errors.New("health check failed")
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "left running for inspection") {
		t.Fatalf("want switch error, got %v", err)
	}
	if f.has("docker stop") || f.has("docker rm ") {
		t.Errorf("old container must survive a failed switch, got %v", f.calls)
	}
	if f.calls[len(f.calls)-1] != "rmdir /tmp/boks-demo.lock" {
		t.Errorf("lock must be released on failure, last call %s", f.calls[len(f.calls)-1])
	}
}

func TestRunRevertsSwitchedRoutesWhenLaterPortFails(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" +
		ports(t, config.Port{Name: "web", Port: 3000, Host: "demo.example.com"}) + "\n"
	f.fail["docker exec boks-proxy kamal-proxy deploy demo-actions"] = errors.New("host is used by another service")
	err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", Options{Now: fixed.Now})
	if err == nil {
		t.Fatal("want error")
	}
	revert := "docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v1-1:3000 --host demo.example.com --deploy-timeout 60s"
	if !f.has(revert) {
		t.Errorf("web route must be pointed back at the old container, calls:\n%s", strings.Join(f.calls, "\n"))
	}
	if f.has("docker stop") {
		t.Errorf("old container must not be retired after a failed switch")
	}
}

// The port a route is reverted to must come from the old container, not from a config that
// changed since: the old container listens where it was started.
func TestRunRevertsToThePortTheOldContainerActuallyListensOn(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" +
		ports(t, config.Port{Name: "web", Port: 8080, Host: "demo.example.com", HealthPath: "/healthz"}) + "\n"
	f.fail["docker exec boks-proxy kamal-proxy deploy demo-actions"] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	want := "docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v1-1:8080 " +
		"--host demo.example.com --health-check-path /healthz --deploy-timeout 60s"
	if !f.has(want) {
		t.Errorf("revert must use the old container's port and health check, calls:\n%s", strings.Join(f.calls, "\n"))
	}
	if f.has("--target demo-v1-1:3000") {
		t.Error("revert must not aim at the current config's port")
	}
}

// A container started by a boks without the label — the first deploy after an upgrade — must
// still get its routes back, using the current config's ports, exactly as boks did before the
// label existed. Refusing here would make the upgrade itself a regression.
func TestRunRevertsWithoutTheLabelUsingTheCurrentConfig(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\n"
	f.fail["docker exec boks-proxy kamal-proxy deploy demo-actions"] = errors.New("boom")
	var log strings.Builder
	if err := Run(context.Background(), f, &log, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	want := "docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v1-1:3000 --host demo.example.com --deploy-timeout 60s"
	if !f.has(want) {
		t.Errorf("route must go back to the old container, calls:\n%s", strings.Join(f.calls, "\n"))
	}
	if !strings.Contains(log.String(), "no record of port") {
		t.Errorf("the assumption must be stated, log:\n%s", log.String())
	}
}

// A port name added to the config since the old container started is not in its label, but the
// container may well listen on that port anyway — two hosts can share one container port. The
// route must still be attempted: kamal-proxy's health check is what decides, and skipping would
// strand the route on the failed release for nothing.
func TestRunRevertsPortsMissingFromTheLabel(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" +
		ports(t, config.Port{Name: "actions", Port: 3001, Host: "actions.example.com"}) + "\n"
	f.fail["docker exec boks-proxy kamal-proxy deploy demo-actions"] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	want := "docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v1-1:3000 --host demo.example.com --deploy-timeout 60s"
	if !f.has(want) {
		t.Errorf("an unrecorded port must still be reverted with the config's value, calls:\n%s", strings.Join(f.calls, "\n"))
	}
}

func TestPruneRemovesUntaggedImages(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker images ghcr.io/x/y"] = "v2 sha-new\n<none> sha-dangling\nv1 sha-b\nv0 sha-c\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker rmi sha-dangling") {
		t.Errorf("untagged layers must be pruned, calls:\n%s", strings.Join(f.calls, "\n"))
	}
	if f.has("docker rmi sha-new") || f.has("docker rmi ghcr.io/x/y:v2") {
		t.Error("the image just deployed must never be pruned")
	}
	// keep=2 counts tagged versions only: v2 (current) + v1 retained, v0 removed.
	if !f.has("docker rmi ghcr.io/x/y:v0") || f.has("docker rmi ghcr.io/x/y:v1") {
		t.Errorf("keep=2 must retain v1 and drop v0, calls:\n%s", strings.Join(f.calls, "\n"))
	}
}

func TestRunDoesNotGuessRevertTargetAmongSeveralOld(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	// Both are labelled: what stops the revert here is the ambiguity, not a missing label.
	p := ports(t, config.Port{Name: "web", Port: 3000, Host: "demo.example.com"})
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" + p + "\ndemo-v0-9\t" + p + "\n"
	f.fail["docker exec boks-proxy kamal-proxy deploy demo-actions"] = errors.New("boom")
	var log strings.Builder
	if err := Run(context.Background(), f, &log, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	if f.has("docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v1-1") ||
		f.has("docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v0-9") {
		t.Errorf("must not revert to an arbitrary previous container, calls:\n%s", strings.Join(f.calls, "\n"))
	}
	if !strings.Contains(log.String(), "cannot be reverted automatically") {
		t.Errorf("operator must be told the routes are split, log:\n%s", log.String())
	}
}

func TestRollbackSkipsPull(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v1", Options{Now: fixed.Now}); err != nil {
		t.Fatal(err)
	}
	if f.has("docker pull") {
		t.Errorf("rollback must not pull, calls %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "--env-file") {
			t.Errorf("no env → no env-file, got %s", c)
		}
	}
}

func TestContainerNameSanitizes(t *testing.T) {
	got := ContainerName("app", "sha:ab/12", time.Unix(5, 0))
	if got != "app-sha-ab-12-5" {
		t.Errorf("got %s", got)
	}
}
