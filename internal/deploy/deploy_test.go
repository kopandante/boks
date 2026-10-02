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
)

type fake struct {
	calls   []string
	uploads map[string]string
	out     map[string]string
	fail    map[string]error
}

func newFake() *fake {
	f := &fake{uploads: map[string]string{}, out: map[string]string{}, fail: map[string]error{}}
	f.out[proxyList] = "{}" // what kamal-proxy prints when it holds no services
	return f
}

const proxyList = "docker exec boks-proxy kamal-proxy list --json"

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
		"docker ps -a --filter volume=demo-data --filter label=boks.app=demo --format {{.Names}}",
		"docker network inspect boks",
		"docker ps -a --filter name=^boks-proxy$ --format {{.State}}",
		"docker pull ghcr.io/x/y:v2",
		"docker ps -a --filter label=boks.app=demo --format {{.Names}}\t{{.Label \"boks.ports\"}}",
		proxyList,
		"docker run -d --name demo-v2-1700000000 --network boks --restart unless-stopped " +
			"--label boks.app=demo --label boks.version=v2 " +
			"--label boks.ports=[{\"name\":\"web\",\"port\":3000,\"host\":\"demo.example.com\",\"health_path\":\"/up\",\"health_port\":0}] " +
			"--env-file .boks/demo/demo-v2-1700000000.env -v demo.data:/data ghcr.io/x/y:v2",
		"docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v2-1700000000:3000 " +
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

// routelessFake is a server where bot-v1-1 is the one running copy of the app.
func routelessFake(health string) *fake {
	f := newFake()
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t\n"
	f.out["docker ps --filter label=boks.app=bot"] = "bot-v1-1\n"
	f.out["docker image inspect"] = `["CMD-SHELL","redis-cli ping"]`
	f.out["docker inspect --format"] = health
	return f
}

func quick() Options {
	o := fixed
	o.Poll = time.Nanosecond
	return o
}

// touchesProxy reports any call that boots, starts or routes through the proxy. Asking whether
// the proxy container exists is not one: an app that lost its ports has routes to drop.
func touchesProxy(f *fake) bool {
	for _, c := range f.calls {
		if strings.Contains(c, proxy.Container) && c != proxyProbe {
			return true
		}
	}
	return false
}

const proxyProbe = "docker ps -a --filter name=^boks-proxy$ --format {{.State}}"

// An app with no routes is replaced in place: the proxy is never touched and the old container is
// stopped BEFORE the new one starts, so two copies never drain the same queue at once.
func TestRoutelessStopsTheOldCopyFirst(t *testing.T) {
	f := routelessFake("healthy")
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mkdir /tmp/boks-bot.lock",
		"docker network inspect boks",
		"docker pull ghcr.io/x/bot:v2",
		"docker image inspect --format {{if .Config.Healthcheck}}{{json .Config.Healthcheck.Test}}{{end}} ghcr.io/x/bot:v2",
		"docker ps -a --filter label=boks.app=bot --format {{.Names}}\t{{.Label \"boks.ports\"}}",
		"docker ps --filter label=boks.app=bot --format {{.Names}}",
		proxyProbe,
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
	if touchesProxy(f) {
		t.Errorf("the proxy must not be touched for an app without routes: %v", f.calls)
	}
}

// The proxy is what creates the network on the routed path. A server that only ever runs an app
// without routes (Redis on a small box) has no proxy, so the deploy has to create the network
// itself — or `docker run --network` fails on the very first deploy.
func TestRoutelessCreatesTheNetworkOnAFreshServer(t *testing.T) {
	f := newFake()
	f.fail["docker network inspect"] = errors.New("network boks not found")
	f.out["docker image inspect"] = `["CMD-SHELL","true"]`
	f.out["docker inspect --format"] = "healthy"
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v1", quick()); err != nil {
		t.Fatal(err)
	}
	created, ran := -1, -1
	for i, c := range f.calls {
		switch {
		case c == "docker network create boks":
			created = i
		case strings.HasPrefix(c, "docker run"):
			ran = i
		}
	}
	if created < 0 || ran < 0 || created > ran {
		t.Errorf("the network must be created before the container starts: %v", f.calls)
	}
	if touchesProxy(f) {
		t.Errorf("creating the network must not boot the proxy: %v", f.calls)
	}
}

// Without a route, the image's own HEALTHCHECK is the only evidence a deploy worked. An image that
// declares none gets a refusal, not a deploy that reports success and proves nothing — and since
// that is known from the image alone, the running copy is not taken down for a deploy that cannot
// succeed.
func TestRoutelessRefusesAnImageWithoutHealthcheck(t *testing.T) {
	for _, declared := range []string{"", `["NONE"]`} {
		f := routelessFake("healthy")
		f.out["docker image inspect"] = declared
		err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
		if err == nil || !strings.Contains(err.Error(), "HEALTHCHECK") {
			t.Fatalf("%q: want a refusal naming HEALTHCHECK, got %v", declared, err)
		}
		if f.has("docker stop") || f.has("docker run") {
			t.Errorf("%q: the running copy must not be touched: %v", declared, f.calls)
		}
	}
}

// An image that cannot be inspected up front (a rollback to a tag `docker run` will fetch) is
// judged by the running container instead, and still refused when it has no health check.
func TestRoutelessRefusesAContainerWithoutHealthcheck(t *testing.T) {
	f := routelessFake("none")
	f.fail["docker image inspect"] = errors.New("No such image")
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "HEALTHCHECK") {
		t.Fatalf("want a refusal naming HEALTHCHECK, got %v", err)
	}
	if !f.has("docker rm -f bot-v2-1700000000") || !f.has("docker start bot-v1-1") {
		t.Errorf("the new copy must go and the old one must come back: %v", f.calls)
	}
}

// If the failed new copy cannot be confirmed gone, bringing the old one back could leave two
// copies running at once: the old one stays stopped and the error says so.
func TestRoutelessKeepsTheOldCopyStoppedWhenTheNewOneWillNotGo(t *testing.T) {
	f := routelessFake("unhealthy")
	f.out["docker ps -a --filter name=^bot-v2-1700000000$"] = "bot-v2-1700000000\n"
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "could not be confirmed removed") {
		t.Fatalf("want an error naming the leftover copy, got %v", err)
	}
	if f.has("docker start bot-v1-1") {
		t.Errorf("the old copy must not come back beside a new one that may still run: %v", f.calls)
	}
}

func TestRoutelessBringsTheOldCopyBackWhenTheNewOneIsUnhealthy(t *testing.T) {
	f := routelessFake("unhealthy")
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("want an unhealthy error, got %v", err)
	}
	if !f.has("docker stop bot-v2-1700000000") || !f.has("docker rm -f bot-v2-1700000000") {
		t.Errorf("the unhealthy new copy must be stopped and removed: %v", f.calls)
	}
	if !f.has("docker start bot-v1-1") {
		t.Errorf("old copy must be restarted: %v", f.calls)
	}
	if f.has("docker rm bot-v1-1") {
		t.Errorf("the old copy must not be retired when the new one failed: %v", f.calls)
	}
}

// A copy that never leaves `starting` is given up on at deploy_timeout, and the old one comes back.
func TestRoutelessGivesUpAtTheDeployTimeout(t *testing.T) {
	f := routelessFake("starting")
	cfg := parse(t, strings.Replace(noPorts, "deploy_timeout: 2s", "deploy_timeout: 20ms", 1))
	o := quick()
	o.Poll = time.Millisecond
	err := Run(context.Background(), f, io.Discard, cfg, "v2", o)
	if err == nil || !strings.Contains(err.Error(), "did not become healthy within 20ms") {
		t.Fatalf("want a timeout, got %v", err)
	}
	if !f.has("docker rm -f bot-v2-1700000000") || !f.has("docker start bot-v1-1") {
		t.Errorf("the new copy must go and the old one must come back: %v", f.calls)
	}
}

func TestRoutelessBringsTheOldCopyBackWhenTheNewOneCannotStart(t *testing.T) {
	f := routelessFake("healthy")
	f.fail["docker run"] = errors.New("no such image")
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil {
		t.Fatal("want the start error")
	}
	if !f.has("docker start bot-v1-1") {
		t.Errorf("old copy must be restarted: %v", f.calls)
	}
}

// Container names carry Unix seconds. A second deploy of the same tag within that second must not
// start, because its failure cleanup would force-remove the earlier copy by the shared name.
func TestRoutelessRefusesANameThatAlreadyExists(t *testing.T) {
	f := routelessFake("unhealthy")
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v2-1700000000\t\n"
	f.out["docker ps --filter label=boks.app=bot"] = "bot-v2-1700000000\n"
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want a name-collision refusal, got %v", err)
	}
	if f.has("docker stop") || f.has("docker rm") || f.has("docker run") {
		t.Errorf("nothing may be touched: %v", f.calls)
	}
}

// The stop is what keeps two copies from running at once. If it fails, the new copy must not start.
func TestRoutelessDoesNotStartWhenTheOldCopyWouldNotStop(t *testing.T) {
	f := routelessFake("healthy")
	f.fail["docker stop bot-v1-1"] = errors.New("connection reset")
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "could not stop bot-v1-1") {
		t.Fatalf("want a stop failure, got %v", err)
	}
	if f.has("docker run") {
		t.Errorf("the new copy must not start while the old one may still run: %v", f.calls)
	}
}

// A container an earlier deploy left stopped is cleaned up on success but never revived on
// failure: reviving it would turn one running copy into two on the same volume.
func TestRoutelessRevivesOnlyWhatWasRunning(t *testing.T) {
	f := routelessFake("unhealthy")
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t\nbot-v0-1\t\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err == nil {
		t.Fatal("want an unhealthy error")
	}
	if f.has("docker start bot-v0-1") || f.has("docker stop bot-v0-1") {
		t.Errorf("a container that was not running must be left alone: %v", f.calls)
	}
	if !f.has("docker start bot-v1-1") {
		t.Errorf("the running copy must come back: %v", f.calls)
	}

	ok := routelessFake("healthy")
	ok.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t\nbot-v0-1\t\n"
	if err := Run(context.Background(), ok, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if !ok.has("docker rm bot-v0-1") || !ok.has("docker rm bot-v1-1") {
		t.Errorf("a successful deploy retires every previous container: %v", ok.calls)
	}
}

// at returns the position of the first call starting with prefix, or -1.
func (f *fake) at(prefix string) int {
	for i, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

const (
	deployVia = "docker exec boks-proxy kamal-proxy deploy "
	removeVia = "docker exec boks-proxy kamal-proxy remove "
	legacyUse = "docker ps -a --filter volume=demo-data --filter label=boks.app=demo"
)

// Renaming the volume would hand the app an empty one and lose the data silently, so the deploy
// stops before anything happens and says how to move it — stopping the app first, or the copy
// would miss what it writes until the deploy retires it.
func TestRunRefusesWhenDataStillSitsUnderTheOldVolumeName(t *testing.T) {
	f := newFake()
	f.out[legacyUse] = "demo-v1-1\n"
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "old naming scheme") {
		t.Fatalf("want a refusal naming the old volume, got %v", err)
	}
	for _, step := range []string{"docker stop demo-v1-1", "docker volume create demo.data", "-v demo-data:/from -v demo.data:/to"} {
		if !strings.Contains(err.Error(), step) {
			t.Errorf("the refusal must say %q: %v", step, err)
		}
	}
	if strings.Index(err.Error(), "docker stop") > strings.Index(err.Error(), "cp -a") {
		t.Errorf("the app has to stop before the copy: %v", err)
	}
	if f.has("docker pull") || f.has("docker run -d --name demo-") || f.has("docker network") || f.has(proxyProbe) {
		t.Errorf("nothing may happen before the data is moved, the proxy included: %v", f.calls)
	}
}

// Once the data has been moved the deploy goes ahead. The volume filter is a regular expression,
// so the dot has to be escaped: unescaped, this lookup would not be the one that answers.
func TestRunProceedsOnceTheVolumeWasMoved(t *testing.T) {
	f := newFake()
	f.out[legacyUse] = "demo-v1-1\n"
	f.out[`docker volume ls --quiet --filter name=^demo\.data$`] = "demo.data"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker run -d --name demo-v2-1700000000") {
		t.Errorf("the deploy must go ahead: %v", f.calls)
	}
}

// A check that cannot run is not a check that passed: the app would start on an empty volume.
func TestRunRefusesWhenTheVolumeCheckFails(t *testing.T) {
	f := newFake()
	f.fail["docker ps -a --filter volume="] = errors.New("ssh: connection reset")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker run -d --name demo-") {
		t.Errorf("the app must not start: %v", f.calls)
	}
}

// listed is one service as `kamal-proxy list --json` reports it.
func listed(t *testing.T, services map[string]proxy.Listed) string {
	t.Helper()
	b, err := json.Marshal(services)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// routedFake is a server where demo-v1-1 is the running copy of the app and the proxy holds the
// given services.
func routedFake(t *testing.T, services map[string]proxy.Listed) *fake {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t\n"
	f.out[proxyList] = listed(t, services)
	return f
}

// A port moved to another host leaves its old service behind; it has to go before the old
// container does, or it keeps pointing at a container this deploy removed. Services of other
// apps — by name or by target — stay.
func TestRunRemovesRoutesTheConfigNoLongerDescribes(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.web":    {Hosts: []string{"demo.example.com"}, Targets: []string{"demo-v1-1:3000"}},
		"demo.legacy": {Hosts: []string{"old.example.com"}, Targets: []string{"demo-v1-1:3000"}},
		"other.web":   {Hosts: []string{"other.example.com"}, Targets: []string{"other-v1-1:80"}},
		"demo-web":    {Hosts: []string{"x.example.com"}, Targets: []string{"demo-web-v1-1:80"}},
		"idle":        {Hosts: []string{"idle.example.com"}},
	})
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	switched, removed, retired := f.at(deployVia+"demo.web"), f.at(removeVia+"demo.legacy"), f.at("docker rm demo-v1-1")
	if switched < 0 || removed < switched || retired < removed {
		t.Errorf("the stale route must go after the switch and before the old container: %v", f.calls)
	}
	for _, keep := range []string{"demo.web", "other.web", "demo-web", "idle"} {
		if f.has(removeVia + keep) {
			t.Errorf("%s is not a stale route of this app: %v", keep, f.calls)
		}
	}
}

// A switch that fails leaves the stale route in place: until the new routes are live it may still
// be what serves the app.
func TestRunKeepsStaleRoutesWhenTheSwitchFails(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.legacy": {Hosts: []string{"old.example.com"}, Targets: []string{"demo-v1-1:3000"}},
	})
	f.fail[deployVia+"demo.web"] = errors.New("unhealthy")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has(removeVia) {
		t.Errorf("no route may be removed after a failed switch: %v", f.calls)
	}
}

// A service named by an earlier boks (`demo-web`) holds the host, and kamal-proxy gives a host to
// one service at a time: deploying `demo.web` next to it would be refused. The new container goes
// onto the old service, which is then renamed, and only then is the old container retired.
func TestRunTakesOverTheRouteOfAnEarlierNamingScheme(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo-web": {Hosts: []string{"demo.example.com"}, Targets: []string{"demo-v1-1:3000"}},
	})
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	order := []int{
		f.at(deployVia + "demo-web --target demo-v2-1700000000:3000"),
		f.at(removeVia + "demo-web"),
		f.at(deployVia + "demo.web --target demo-v2-1700000000:3000 --host demo.example.com"),
		f.at("docker stop demo-v1-1"),
	}
	for i, at := range order {
		if at < 0 || (i > 0 && at < order[i-1]) {
			t.Fatalf("want switch onto demo-web, rename to demo.web, then retire; calls:\n%s", strings.Join(f.calls, "\n"))
		}
	}
}

// The same holds for a port renamed in the config while its host stays.
func TestRunRenamesAPortThatKeepsItsHost(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.site": {Hosts: []string{"demo.example.com"}, Targets: []string{"demo-v1-1:3000"}},
	})
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if f.at(deployVia+"demo.web") < 0 || f.at(deployVia+"demo.site") > f.at(removeVia+"demo.site") ||
		f.at(removeVia+"demo.site") > f.at(deployVia+"demo.web") {
		t.Errorf("want switch onto demo.site, then rename to demo.web: %v", f.calls)
	}
}

// A rename that fails half way puts the old name back on the new container, and the old
// container is kept: the command says so instead of reporting success.
func TestRunRestoresARouteWhoseRenameFailed(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.site": {Hosts: []string{"demo.example.com"}, Targets: []string{"demo-v1-1:3000"}},
	})
	f.fail[deployVia+"demo.web"] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	restored := f.at(deployVia + "demo.site --target demo-v2-1700000000:3000 --host demo.example.com --tls --health-check-path /up --deploy-timeout 60s --force")
	if restored < 0 || restored < f.at(deployVia+"demo.web") {
		t.Errorf("the old name must be put back after the failed rename, without waiting for a health check: %v", f.calls)
	}
	if f.has("docker stop demo-v1-1") || f.has("docker rm demo-v1-1") {
		t.Errorf("the old container must be kept: %v", f.calls)
	}
}

// A stale route that cannot be removed leaves the deploy unfinished: retiring the old container
// would leave that route pointing at nothing, which is the failure this exists to prevent.
func TestRunKeepsTheOldContainerWhenAStaleRouteStays(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.legacy": {Hosts: []string{"old.example.com"}, Targets: []string{"demo-v1-1:3000"}},
	})
	f.fail[removeVia] = errors.New("boom")
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "demo-v1-1") {
		t.Fatalf("want an error naming the kept container, got %v", err)
	}
	if f.has("docker stop demo-v1-1") || f.has("docker rm demo-v1-1") {
		t.Errorf("the old container must be kept: %v", f.calls)
	}
}

// What the proxy holds decides which service carries each port, so a deploy that cannot read it
// does not start.
func TestRunDoesNotStartWithoutTheProxyList(t *testing.T) {
	f := routedFake(t, nil)
	f.fail[proxyList] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker run -d --name demo-") {
		t.Errorf("nothing may start: %v", f.calls)
	}
}

// Port `web` was renamed to `site` and a new port took the name `web`: the new port's own service
// carries the other port's host, and deploying it would take that host away. Refused before
// anything starts.
func TestRunRefusesTwoPortsThroughOneService(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.web": {Hosts: []string{"actions.example.com"}, Targets: []string{"demo-v1-1:3001"}},
	})
	if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker run -d --name demo-") {
		t.Errorf("nothing may start: %v", f.calls)
	}
}

// A port carried by its predecessor's service was recorded under the predecessor's name, and
// that record is what a revert aims at.
func TestRunRevertsARenamedPortToItsRecordedPort(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.site": {Hosts: []string{"demo.example.com"}, Targets: []string{"demo-v1-1:4000"}},
	})
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" +
		ports(t, config.Port{Name: "site", Port: 4000, Host: "demo.example.com"}) + "\n"
	f.fail[deployVia+"demo.actions"] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want an error")
	}
	if !f.has(deployVia + "demo.site --target demo-v1-1:4000") {
		t.Errorf("the route must go back through demo.site to the port the old container listens on: %v", f.calls)
	}
}

const chainPorts = `
app: demo
image: ghcr.io/x/y
servers: [lab]
ports:
  - {name: y, port: 3000, host: one.example.com}
  - {name: z, port: 3001, host: two.example.com}
`

// Ports renamed in a chain (x→y, y→z): y may take its own name only after z has moved off it, or
// deploying demo.y would take two.example.com away from z.
func TestRunRenamesAChainInOrder(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.x": {Hosts: []string{"one.example.com"}, Targets: []string{"demo-v1-1:3000"}},
		"demo.y": {Hosts: []string{"two.example.com"}, Targets: []string{"demo-v1-1:3001"}},
	})
	if err := Run(context.Background(), f, io.Discard, parse(t, chainPorts), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	zMoved, yRemoved := f.at(deployVia+"demo.z --target demo-v2-1700000000:3001"), f.at(removeVia+"demo.y")
	yRenamed := f.at(deployVia + "demo.y --target demo-v2-1700000000:3000 --host one.example.com")
	if zMoved < 0 || yRemoved < 0 || yRenamed < 0 || yRemoved > zMoved || zMoved > yRenamed {
		t.Errorf("want demo.y → demo.z first, then demo.x → demo.y: %v", f.calls)
	}
	removes := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, removeVia) {
			removes++
		}
	}
	if removes != 2 {
		t.Errorf("only the two renamed services may be removed, once each: %v", f.calls)
	}
}

// Names that swap places cannot be renamed without one host losing its route; they stay as they
// are and nothing that carries traffic is removed.
func TestRunKeepsSwappedNamesRatherThanLoseAHost(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.z": {Hosts: []string{"one.example.com"}, Targets: []string{"demo-v1-1:3000"}},
		"demo.y": {Hosts: []string{"two.example.com"}, Targets: []string{"demo-v1-1:3001"}},
	})
	if err := Run(context.Background(), f, io.Discard, parse(t, chainPorts), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if f.has(removeVia) {
		t.Errorf("a service that carries a port must not be removed: %v", f.calls)
	}
	if !f.has(deployVia+"demo.z --target demo-v2-1700000000:3000 --host one.example.com") ||
		!f.has(deployVia+"demo.y --target demo-v2-1700000000:3001 --host two.example.com") {
		t.Errorf("both hosts must reach the new container through the services that hold them: %v", f.calls)
	}
}

// An app without routes reads the proxy before it stops anything: a proxy that cannot answer
// fails the deploy while the old copy is still running.
func TestRoutelessReadsTheProxyBeforeStoppingTheOldCopy(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.fail[proxyList] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker stop") || f.has("docker run -d") {
		t.Errorf("nothing may be stopped or started: %v", f.calls)
	}
}

// The legacy-volume refusal holds on the path without routes too.
func TestRoutelessRefusesWhenDataStillSitsUnderTheOldVolumeName(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter volume=bot-data --filter label=boks.app=bot"] = "bot-v1-1\n"
	cfg := parse(t, noPorts+"volumes: [data:/data]\n")
	err := Run(context.Background(), f, io.Discard, cfg, "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "old naming scheme") {
		t.Fatalf("want a refusal naming the old volume, got %v", err)
	}
	if f.has("docker pull") || f.has("docker stop") || f.has("docker run -d") {
		t.Errorf("nothing may happen before the data is moved: %v", f.calls)
	}
}

// In a rename chain (x→y, y→z) the name y meant another port on the old container, so a revert
// that went by name would send one.example.com to the old y's port. The route is its host.
func TestRunRevertsARenameChainByHost(t *testing.T) {
	f := routedFake(t, map[string]proxy.Listed{
		"demo.x": {Hosts: []string{"one.example.com"}, Targets: []string{"demo-v1-1:3000"}},
		"demo.y": {Hosts: []string{"two.example.com"}, Targets: []string{"demo-v1-1:3001"}},
	})
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t" + ports(t,
		config.Port{Name: "x", Port: 3000, Host: "one.example.com"},
		config.Port{Name: "y", Port: 3001, Host: "two.example.com"}) + "\n"
	f.fail[deployVia+"demo.y --target demo-v2-1700000000:3001"] = errors.New("unhealthy")
	if err := Run(context.Background(), f, io.Discard, parse(t, chainPorts), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if !f.has(deployVia+"demo.x --target demo-v1-1:3000 --host one.example.com") || f.has(deployVia+"demo.x --target demo-v1-1:3001") {
		t.Errorf("one.example.com must go back to the old x port: %v", f.calls)
	}
}

// A route of a removed port that cannot be dropped keeps the old copy: retiring it would leave
// the route pointing at a removed container. The new copy stays up, the old one is not revived.
func TestRoutelessKeepsTheOldCopyWhenARouteStays(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out[proxyList] = listed(t, map[string]proxy.Listed{
		"bot.web": {Hosts: []string{"bot.example.com"}, Targets: []string{"bot-v1-1:3000"}},
	})
	f.fail[removeVia] = errors.New("boom")
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "bot-v1-1") {
		t.Fatalf("want an error naming the kept container, got %v", err)
	}
	if f.has("docker rm bot-v1-1") || f.has("docker start bot-v1-1") || f.has("docker rm -f bot-v2") {
		t.Errorf("the old copy is kept stopped and the new one stays: %v", f.calls)
	}
}

// An app whose ports were all removed still has the routes it had; left alone they answer with a
// 502 from a container this deploy removes. They go after the new copy is healthy and before the
// old one is retired — without booting or routing through the proxy.
func TestRoutelessDropsTheRoutesOfRemovedPorts(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out[proxyList] = listed(t, map[string]proxy.Listed{
		"bot.web":   {Hosts: []string{"bot.example.com"}, Targets: []string{"bot-v1-1:3000"}},
		"bot-api":   {Hosts: []string{"api.example.com"}, Targets: []string{"bot-v1-1:3001"}},
		"other.web": {Hosts: []string{"other.example.com"}, Targets: []string{"other-v1-1:80"}},
	})
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	healthy, retired := f.at("docker inspect --format"), f.at("docker rm bot-v1-1")
	for _, gone := range []string{"bot.web", "bot-api"} {
		if at := f.at(removeVia + gone); at < healthy || at > retired {
			t.Errorf("%s must go after the new copy is healthy and before the old one is retired: %v", gone, f.calls)
		}
	}
	if f.has(removeVia+"other.web") || f.has(deployVia) || f.has("docker start boks-proxy") {
		t.Errorf("only this app's routes may go, and the proxy is not routed through: %v", f.calls)
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
	f.fail["docker exec boks-proxy kamal-proxy deploy demo.actions"] = errors.New("host is used by another service")
	err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", Options{Now: fixed.Now})
	if err == nil {
		t.Fatal("want error")
	}
	revert := "docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v1-1:3000 --host demo.example.com --deploy-timeout 60s"
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
	f.fail["docker exec boks-proxy kamal-proxy deploy demo.actions"] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	want := "docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v1-1:8080 " +
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
	f.fail["docker exec boks-proxy kamal-proxy deploy demo.actions"] = errors.New("boom")
	var log strings.Builder
	if err := Run(context.Background(), f, &log, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	want := "docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v1-1:3000 --host demo.example.com --deploy-timeout 60s"
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
	f.fail["docker exec boks-proxy kamal-proxy deploy demo.actions"] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	want := "docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v1-1:3000 --host demo.example.com --deploy-timeout 60s"
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
	f.fail["docker exec boks-proxy kamal-proxy deploy demo.actions"] = errors.New("boom")
	var log strings.Builder
	if err := Run(context.Background(), f, &log, parse(t, twoPorts), "v2", Options{Now: fixed.Now}); err == nil {
		t.Fatal("want error")
	}
	if f.has("docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v1-1") ||
		f.has("docker exec boks-proxy kamal-proxy deploy demo.web --target demo-v0-9") {
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
