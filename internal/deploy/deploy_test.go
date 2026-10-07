package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
)

type fake struct {
	calls   []string
	uploads map[string]string
	appends map[string]string
	out     map[string]string
	fail    map[string]error
	// writes is every upload and append in order, each with the number of commands run before it,
	// so a test can tell whether the journal was written before or after a given command.
	writes []write
	// pipeFail, when set, decides whether the write of content to path fails.
	pipeFail func(path, content string) error
	// stopped is what `docker stop` and `docker start` did, so asking whether a container is running
	// answers as docker would: not after a stop, yes after a start, and yes before either.
	stopped map[string]bool
	// onRun, when set, sees every command as it runs, before its answer is looked up: a test can
	// change what the server says from then on.
	onRun func(cmd string)
	// stdin is what each command that is not a file write was given on its standard input.
	stdin map[string]string
	// hang is the commands that never answer: they return only when their context ends, as an SSH
	// call over a connection that stalled does once it is cut off.
	hang []string
}

type write struct {
	at            int
	path, content string
}

// writeAt is the number of commands run before the first write to path whose content contains
// substr, or -1.
func (f *fake) writeAt(path, substr string) int {
	if i := f.writeIndex(path, substr); i >= 0 {
		return f.writes[i].at
	}
	return -1
}

// writeIndex is the position of that write among the writes, or -1: consecutive writes have the
// same writeAt, so their order is told by this.
func (f *fake) writeIndex(path, substr string) int {
	for i, w := range f.writes {
		if w.path == path && strings.Contains(w.content, substr) {
			return i
		}
	}
	return -1
}

// lastAt is the position of the last command starting with prefix, or -1.
func (f *fake) lastAt(prefix string) int {
	for i := len(f.calls) - 1; i >= 0; i-- {
		if strings.HasPrefix(f.calls[i], prefix) {
			return i
		}
	}
	return -1
}

// callAt is the position of the first command starting with prefix, or -1.
func (f *fake) callAt(prefix string) int {
	for i, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func (f *fake) wrote(path, content string, appended bool) error {
	if f.pipeFail != nil {
		if err := f.pipeFail(path, content); err != nil {
			return err
		}
	}
	f.writes = append(f.writes, write{at: len(f.calls), path: path, content: content})
	if appended {
		f.appends[path] += content
	} else {
		f.uploads[path] = content
	}
	return nil
}

func newFake() *fake {
	f := &fake{uploads: map[string]string{}, appends: map[string]string{}, out: map[string]string{}, fail: map[string]error{},
		stopped: map[string]bool{}}
	f.out[digests] = "[]"              // an image that came from no registry; tests that need a digest override it
	f.out[netOwner] = "absent"         // the app's network is not made yet
	f.out[applied] = "absent"          // the proxy has no applied config yet
	f.out[migrateReq] = "1"            // the proxy runs with the sysctl a lossless reload needs
	f.out[upstreams] = "[]"            // and holds no request in flight
	f.out[probe] = "  HTTP/1.1 200 OK" // and every copy it probes answers
	f.out["sh -c cd '.boks/_proxy' && pwd -P"] = "/home/u/.boks/_proxy"
	return f
}

const (
	netOwner  = "sh -c out=$(docker network inspect"
	boxes     = "sh -c ids=$(docker ps -aq --no-trunc)"
	proxyNets = "docker container ls -a --filter name=^boks-proxy$ --format {{.Networks}}"
	digests   = "docker inspect --type image"
	// frags is the read of every app's routes fragment; applied, of the config the proxy runs.
	frags      = "sh -c for f in '.boks/_proxy/routes'/*.json"
	applied    = "sh -c if [ -f '.boks/_proxy/caddy.json' ]"
	migrateReq = "docker exec boks-proxy cat /proc/sys/net/ipv4/tcp_migrate_req"
	proxyImage = "sh -c docker inspect -f '{{.Config.Image}}' boks-proxy 2>/dev/null || true"
	upstreams  = "docker exec boks-proxy wget -q -O - http://127.0.0.1:2019/reverse_proxy/upstreams"
	probe      = "docker exec boks-proxy sh -c wget -S -q -O /dev/null -T 5 '"
	probeEnd   = "' 2>&1; true"
	reloadVia  = "docker exec boks-proxy caddy reload --config /etc/boks/caddy.next.json"
	caddyUp    = "running\tcaddy"
)

// fragment is one app's routes as the server keeps them, dialling target on each port.
func fragment(t *testing.T, app, target string, ports ...config.Port) string {
	t.Helper()
	var routes []proxy.Route
	for _, p := range ports {
		routes = append(routes, proxy.Route{Host: p.Host, Dial: target + ":" + itoa(p.Port)})
	}
	b, err := json.Marshal(proxy.Fragment{App: app, Routes: routes})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// proxyWrites reports any write to the proxy's state.
func proxyWrites(f *fake) bool {
	for p := range f.uploads {
		if strings.HasPrefix(p, ".boks/_proxy/") {
			return true
		}
	}
	return false
}

// fragsRead is the whole command that reads every fragment.
const fragsRead = frags + `; do [ -f "$f" ] && cat "$f"; done; true`

// inspectOf is the read of container c's app and networks, as the proxy boot asks it.
func inspectOf(c string) string {
	return `sh -c out=$(docker container inspect --format '{{index .Config.Labels "boks.app"}}|{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' '` +
		c + `' 2>&1) && echo "$out" || case "$out" in *'No such container'*|*'No such object'*) echo '<gone>';; *) echo "$out" >&2; exit 1;; esac`
}

// fragmentWrite is the content written to app's fragment, or "".
func (f *fake) fragmentWrite(app string) string { return f.uploads[".boks/_proxy/routes/"+app+".json"] }

func (f *fake) Run(ctx context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if f.onRun != nil {
		f.onRun(cmd)
	}
	for _, h := range f.hang {
		if strings.HasPrefix(cmd, h) {
			<-ctx.Done()
			return "", ctx.Err()
		}
	}
	// The longest prefix answers, so a test can answer one network or container apart from the rest.
	if err, ok := longest(f.fail, cmd); ok {
		return "", err
	}
	if out, ok := longest(f.out, cmd); ok {
		return out, nil
	}
	switch c := args[len(args)-1]; {
	case strings.HasPrefix(cmd, "docker stop "):
		f.stopped[c] = true
	case strings.HasPrefix(cmd, "docker start "):
		f.stopped[c] = false
	case strings.HasPrefix(cmd, isRunningQuery):
		return map[bool]string{true: "false", false: "true"}[f.stopped[c]], nil
	}
	return "", nil
}

func longest[V any](answers map[string]V, cmd string) (V, bool) {
	var v V
	best := -1
	for prefix, a := range answers {
		if strings.HasPrefix(cmd, prefix) && len(prefix) > best {
			v, best = a, len(prefix)
		}
	}
	return v, best >= 0
}

const isRunningQuery = "docker container inspect --format {{.State.Running}} "

// admitTake and admitGive are the commands that take and give back the server's admission lock for
// a run of app at the fixed time.
func admitTake(app string) string {
	return "ln -sn " + app + ".1700000000000000000 /tmp/boks.admit.lock"
}
func admitGive(app string) string {
	return `sh -c [ "$(readlink /tmp/boks.admit.lock)" = '` + app + `.1700000000000000000' ] && rm -f /tmp/boks.admit.lock || true`
}

// Pipe records what an upload would have written: the deploy's env-file goes through
// `sh -c '... cat > <path>'`, so the path is the last quoted token of the script.
func (f *fake) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	if len(args) == 3 && args[0] == "sh" {
		// An atomic write ends in `mv <tmp> <path>`; a plain one ends in `cat > <path>`. Either way
		// the destination is the last quoted token.
		if _, tail, ok := strings.Cut(args[2], " && mv "); ok {
			_, dest, _ := strings.Cut(tail, "' '")
			return "", f.wrote(strings.Trim(dest, "'"), string(content), false)
		}
		if _, path, ok := strings.Cut(args[2], "cat > "); ok {
			return "", f.wrote(strings.Trim(path, "'"), string(content), false)
		}
		if _, path, ok := strings.Cut(args[2], "cat >> "); ok {
			return "", f.wrote(strings.Trim(path, "'"), string(content), true)
		}
	}
	if f.stdin == nil {
		f.stdin = map[string]string{}
	}
	f.stdin[strings.Join(args, " ")] = string(content)
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

var fixed = Options{Env: []byte("SECRET=1\n"), Now: func() time.Time { return time.Unix(1700000000, 0) }}

func TestRunHappyPath(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t[{\"name\":\"web\",\"port\":3000,\"host\":\"demo.example.com\",\"health_path\":\"/up\",\"health_port\":0}]\n"
	f.out["docker images ghcr.io/x/y"] = "v2 sha-a\nv1 sha-b\nv0 sha-c\n"
	f.out[frags] = fragment(t, "demo", "demo-v1-1", webPort)
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mkdir /tmp/boks-demo.lock",
		`docker volume ls --quiet --filter name=^demo\.data$`,
		"docker volume ls --quiet --filter name=^demo-data$",
		// Whether the app's network is free for its alias is known before anything changes.
		netOwnerQuery("boks-demo"),
		boxesQuery,
		// The image comes before the proxy: a pull the registry refuses leaves the server as it was.
		"docker pull ghcr.io/x/y:v2",
		// The proxy and its networks are every app's, so booting it takes the server's admission lock.
		admitTake("demo"),
		"docker network inspect boks",
		proxyProbe,
		fragsRead,
		// A running proxy is checked for the sysctl every reload relies on.
		migrateReq,
		// And for the image it runs: a boot leaves a running proxy alone, but says when the config names another.
		proxyImage,
		// The proxy is on the networks of the copies its routes dial.
		proxyNets,
		inspectOf("demo-v1-1"),
		// And runs what the fragments and the server's policy make: a cut run may have left the applied
		// config behind them.
		"sh -c if [ -f '.boks/_server/policy.json' ]; then echo present; cat '.boks/_server/policy.json'; else echo absent; fi",
		"sh -c if [ -f '.boks/_proxy/caddy.json' ]; then echo present; cat '.boks/_proxy/caddy.json'; else echo absent; fi",
		admitGive("demo"),
		// What the proxy serves for the app now: where a failed switch would send the routes back.
		fragsRead,
		"docker ps -a --filter label=boks.app=demo --format {{.Names}}\t{{.Label \"boks.ports\"}}\t{{.Label \"boks.replace\"}}",
		admitTake("demo"),
		// Asked again under the admission lock, then the network is made.
		netOwnerQuery("boks-demo"),
		boxesQuery,
		"docker network create --label boks.app=demo boks-demo",
		"sh -c cat '.boks/demo/journal.jsonl' 2>/dev/null || true",
		"sh -c cat '.boks/demo/current' 2>/dev/null || true",
		"docker run -d --name demo-v2-1700000000 --network boks-demo --network-alias demo --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 --restart unless-stopped " +
			"--label boks.app=demo --label boks.version=v2 " +
			"--label boks.ports=[{\"name\":\"web\",\"port\":3000,\"host\":\"demo.example.com\",\"health_path\":\"/up\",\"health_port\":0}] " +
			"--label boks.replace=overlap --env-file .boks/demo/demo-v2-1700000000.env -v demo.data:/data ghcr.io/x/y:v2",
		// The proxy joins the app's network to reach the new copy, still under the lock.
		proxyNets,
		"docker network connect boks-demo boks-proxy",
		// In overlap the server's admission ends once the container exists and the proxy can reach
		// it: the next deploy's memory check sees it from then on, and the health wait does not hold
		// every other app up.
		admitGive("demo"),
		// The health check, from the proxy, by the name the route will dial.
		probe + "http://demo-v2-1700000000:3000/up" + probeEnd,
		// One reload moves every route, under the lock again: the config is every app's.
		admitTake("demo"),
		fragsRead,
		"sh -c if [ -f '.boks/_server/policy.json' ]; then echo present; cat '.boks/_server/policy.json'; else echo absent; fi",
		applied + "; then echo present; cat '.boks/_proxy/caddy.json'; else echo absent; fi",
		proxyProbe,
		reloadVia,
		"mv .boks/_proxy/caddy.next.json .boks/_proxy/caddy.json",
		admitGive("demo"),
		// The old copy finishes what the proxy still holds for it before it goes.
		upstreams,
		"docker inspect --type image --format {{json .RepoDigests}} ghcr.io/x/y:v2",
		"sh -c ls -1 '.boks/demo/releases' 2>/dev/null || true",
		cronClear("demo"),
		"docker stop demo-v1-1",
		"docker rm -v demo-v1-1",
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
	// The fragment is written before the reload, so a run cut after it leaves the next run a config to
	// catch up with, and the applied config is moved in once Caddy took it.
	if !strings.Contains(f.fragmentWrite("demo"), `"dial": "demo-v2-1700000000:3000"`) || !strings.Contains(f.fragmentWrite("demo"), `"tls": true`) ||
		f.writeAt(".boks/_proxy/routes/demo.json", "demo-v2") >= f.at(reloadVia) || f.at("mv .boks/_proxy/caddy.next.json .boks/_proxy/caddy.json") < f.at(reloadVia) {
		t.Errorf("want the fragment recorded before the reload, the applied config after: %q", f.fragmentWrite("demo"))
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
		if strings.Contains(c, proxy.Container) && c != proxyProbe && c != proxyNets {
			return true
		}
	}
	return false
}

// cronClear is the one call a deploy of an app without schedules makes about cron: it removes the
// app's block only if an earlier release left one.
func cronClear(app string) string {
	b := "'.boks/" + app + "/crontab'"
	return "sh -c [ -s " + b + " ] || exit 0; command -v crontab >/dev/null || { : > " + b + "; exit 0; }; " +
		"{ ! command -v flock >/dev/null || { mkdir -p .boks && exec 9>> .boks/crontab.lock && flock 9; }; } && " +
		"{ crontab -l 2>/dev/null || true; } | sed -e '/^# boks:" + app + " begin$/','/^# boks:" + app + " end$/'d > " + b + ".new && " +
		"crontab " + b + ".new && rm -f " + b + ".new && : > " + b
}

const proxyProbe = "docker ps -a --filter name=^boks-proxy$ --format {{.State}}\t{{.Label \"boks.proxy\"}}"

const boxesQuery = boxes + ` || exit 1; [ -z "$ids" ] || exec docker inspect --format '{"id":{{json .Id}},"name":{{json .Name}},` +
	`"hostname":{{json .Config.Hostname}},"labels":{{json .Config.Labels}},"networks":{{json .NetworkSettings.Networks}},` +
	`"running":{{json .State.Running}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}""{{end}}}' $ids`

func netOwnerQuery(network string) string {
	return netOwner + ` --format '{{json .Labels}}' '` + network + `' 2>&1) && echo "$out" || ` +
		`case "$out" in *'No such network'*|*'network '*' not found'*) echo absent;; *) echo "$out" >&2; exit 1;; esac`
}

// An app with no routes is replaced in place: the proxy is never touched and the old container is
// stopped BEFORE the new one starts, so two copies never drain the same queue at once.
func TestRoutelessStopsTheOldCopyFirst(t *testing.T) {
	f := routelessFake("healthy")
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mkdir /tmp/boks-bot.lock",
		netOwnerQuery("boks-bot"),
		boxesQuery,
		"docker pull ghcr.io/x/bot:v2",
		"docker image inspect --format {{if .Config.Healthcheck}}{{json .Config.Healthcheck.Test}}{{end}} ghcr.io/x/bot:v2",
		// Whether the app has routes to drop is its fragment's to say, not the proxy's.
		frags + `; do [ -f "$f" ] && cat "$f"; done; true`,
		"docker ps -a --filter label=boks.app=bot --format {{.Names}}\t{{.Label \"boks.ports\"}}\t{{.Label \"boks.replace\"}}",
		// A copy an older boks started, without the ports label, may have had routes: the proxy must not
		// be the kamal-proxy whose routes to it this boks cannot drop.
		proxyState + " --format {{.State}}\t{{.Label \"boks.proxy\"}}",
		// A removal a cut run wrote to the fragments but never got into the proxy's config.
		"sh -c if [ -f '.boks/_server/policy.json' ]; then echo present; cat '.boks/_server/policy.json'; else echo absent; fi",
		applied + "; then echo present; cat '.boks/_proxy/caddy.json'; else echo absent; fi",
		"docker ps --filter label=boks.app=bot --format {{.Names}}",
		admitTake("bot"),
		netOwnerQuery("boks-bot"),
		boxesQuery,
		"docker network create --label boks.app=bot boks-bot",
		// The journal entry is opened before the first change on the server, and stopping the
		// running copy is one: a run cut right after the stop must leave a trace.
		"sh -c cat '.boks/bot/journal.jsonl' 2>/dev/null || true",
		"sh -c cat '.boks/bot/current' 2>/dev/null || true",
		"docker stop bot-v1-1",
		// The stop is confirmed by the container's state, not by the command having returned.
		isRunningQuery + "bot-v1-1",
		"docker run -d --name bot-v2-1700000000 --network boks-bot --network-alias bot --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 --restart unless-stopped " +
			"--label boks.app=bot --label boks.version=v2 --label boks.ports=[] --label boks.replace=stop-first " +
			"--env-file .boks/bot/bot-v2-1700000000.env ghcr.io/x/bot:v2",
		"docker inspect --format {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} bot-v2-1700000000",
		// In stop-first the admission lasts until the new copy is up.
		admitGive("bot"),
		"docker inspect --type image --format {{json .RepoDigests}} ghcr.io/x/bot:v2",
		"sh -c ls -1 '.boks/bot/releases' 2>/dev/null || true",
		cronClear("bot"),
		// Recorded: no proxy routes to the app, so the proxy is not left on its network — asked under
		// the lock.
		admitTake("bot"),
		proxyNets,
		admitGive("bot"),
		"docker stop bot-v1-1",
		"docker rm -v bot-v1-1",
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

// Every app makes its own network, and one without routes never boots the proxy: a server that only
// runs such an app (Redis on a small box) has no proxy, and `docker run --network` would fail on the
// very first deploy if nobody made the network.
func TestRoutelessCreatesTheNetworkOnAFreshServer(t *testing.T) {
	f := newFake()
	f.out["docker image inspect"] = `["CMD-SHELL","true"]`
	f.out["docker inspect --format"] = "healthy"
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v1", quick()); err != nil {
		t.Fatal(err)
	}
	created, ran := -1, -1
	for i, c := range f.calls {
		switch {
		case c == "docker network create --label boks.app=bot boks-bot":
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
		if err == nil || !strings.Contains(err.Error(), "HEALTHCHECK") || !strings.Contains(err.Error(), "healthcheck block to boks.yml") {
			t.Fatalf("%q: want a refusal naming both remedies, the config's block and the image's HEALTHCHECK, got %v", declared, err)
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
	if !f.has("docker rm -f -v bot-v2-1700000000") || !f.has("docker start bot-v1-1") {
		t.Errorf("the new copy must go and the old one must come back: %v", f.calls)
	}
}

// If the failed new copy cannot be confirmed gone, bringing the old one back could leave two
// copies running at once: the old one stays stopped and the error says so.
func TestRoutelessKeepsTheOldCopyStoppedWhenTheNewOneWillNotGo(t *testing.T) {
	f := routelessFake("unhealthy")
	f.out["docker ps -a --filter name=^bot-v2-1700000000$"] = "bot-v2-1700000000\tbot\n"
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
	if !f.has("docker stop bot-v2-1700000000") || !f.has("docker rm -f -v bot-v2-1700000000") {
		t.Errorf("the unhealthy new copy must be stopped and removed: %v", f.calls)
	}
	if !f.has("docker start bot-v1-1") {
		t.Errorf("old copy must be restarted: %v", f.calls)
	}
	if f.has("docker rm -v bot-v1-1") {
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
	if !f.has("docker rm -f -v bot-v2-1700000000") || !f.has("docker start bot-v1-1") {
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
	if !ok.has("docker rm -v bot-v0-1") || !ok.has("docker rm -v bot-v1-1") {
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
	legacyLeft = "docker volume ls --quiet --filter name=^demo-data$"
	legacyUse  = "docker ps -a --filter volume=demo-data"
)

// Renaming the volume would hand the app an empty one and lose the data silently, so the deploy
// stops before anything happens and says how to move it — stopping the app first, or the copy
// would miss what it writes until the deploy retires it.
func TestRunRefusesWhenDataStillSitsUnderTheOldVolumeName(t *testing.T) {
	f := newFake()
	f.out[legacyLeft] = "demo-data"
	f.out[legacyUse] = "demo-v1-1\tdemo\n"
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

// Every volume is checked, not only the first: one that is fine says nothing about the next.
func TestRunChecksEveryVolumeForDataUnderTheOldName(t *testing.T) {
	f := newFake()
	f.out[legacyLeft] = "demo-data"
	f.out[legacyUse] = "demo-v1-1\tdemo\n"
	twoVolumes := strings.Replace(onePort, "volumes: [data:/data]", "volumes: [cache:/cache, data:/data]", 1)
	err := Run(context.Background(), f, io.Discard, parse(t, twoVolumes), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "volume demo-data holds this app's data") {
		t.Fatalf("want the refusal for the second volume, got %v", err)
	}
	if !f.has("docker volume ls --quiet --filter name=^demo-cache$") {
		t.Errorf("the first volume must have been checked too: %v", f.calls)
	}
	if f.has("docker pull") || f.has("docker run -d") || f.has("docker network") {
		t.Errorf("nothing may happen before the data is moved: %v", f.calls)
	}
}

// Once the data has been moved the deploy goes ahead. The volume filter is a regular expression,
// so the dot has to be escaped: unescaped, this lookup would not be the one that answers.
func TestRunProceedsOnceTheVolumeWasMoved(t *testing.T) {
	f := newFake()
	f.out[legacyLeft] = "demo-data"
	f.out[legacyUse] = "demo-v1-1\tdemo\n"
	f.out[`docker volume ls --quiet --filter name=^demo\.data$`] = "demo.data"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker run -d --name demo-v2-1700000000") {
		t.Errorf("the deploy must go ahead: %v", f.calls)
	}
}

// A volume the config once dropped has no container left to say whose it is — the old name is
// the ambiguous one. The deploy stops and offers both ways on, rather than start on an empty one.
func TestRunRefusesALegacyVolumeNobodyUses(t *testing.T) {
	f := newFake()
	f.out[legacyLeft] = "demo-data"
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "no container of a boks app uses it") {
		t.Fatalf("want a refusal for a volume nobody uses, got %v", err)
	}
	for _, way := range []string{"-v demo-data:/from -v demo.data:/to", "create the new volume empty"} {
		if !strings.Contains(err.Error(), way) {
			t.Errorf("the refusal must offer %q: %v", way, err)
		}
	}
	if f.has("docker pull") || f.has("docker run -d --name demo-") {
		t.Errorf("nothing may happen: %v", f.calls)
	}
}

// App `a` with volume `b-c` and app `a-b` with volume `c` both called theirs `a-b-c`. Mounted
// only by `a-b`'s container, it is not `a`'s data, and `a` starts on its own new volume.
func TestRunLeavesAnotherAppsLegacyVolumeAlone(t *testing.T) {
	f := newFake()
	f.out["docker volume ls --quiet --filter name=^a-b-c$"] = "a-b-c"
	f.out["docker ps -a --filter volume=a-b-c"] = "a-b-v1-1\ta-b\n"
	cfg := parse(t, "app: a\nimage: ghcr.io/x/a\nservers: [lab]\nvolumes: [b-c:/data]\n"+
		"ports:\n  - {name: web, port: 3000, host: a.example.com}\n")
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if run := f.at("docker run -d --name a-v2-1700000000"); run < 0 || !strings.Contains(f.calls[run], "-v a.b-c:/data") {
		t.Errorf("the deploy must go ahead on a's own new volume: %v", f.calls)
	}
}

// A container without the boks label — a `docker run -v` left behind by hand — is nobody's app
// and says nothing about whose data the volume holds.
func TestRunTreatsAnUnlabeledContainerAsNobody(t *testing.T) {
	f := newFake()
	f.out[legacyLeft] = "demo-data"
	f.out[legacyUse] = "eager_turing\t\n"
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "no container of a boks app uses it") {
		t.Fatalf("want the refusal for a volume no app uses, got %v", err)
	}
}

// The question of who mounts the old volume failing is not an answer either.
func TestRunRefusesWhenTheOwnerCheckFails(t *testing.T) {
	f := newFake()
	f.out[legacyLeft] = "demo-data"
	f.fail[legacyUse] = errors.New("ssh: connection reset")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker pull") || f.has("docker network") || f.has("docker run -d") {
		t.Errorf("nothing may happen: %v", f.calls)
	}
}

// A check that cannot run is not a check that passed: the app would start on an empty volume.
// Each lookup fails on its own, the new name answering first, so neither failure is masked by
// the other one failing earlier.
func TestRunRefusesWhenTheVolumeCheckFails(t *testing.T) {
	for _, failing := range []string{
		"docker volume ls --quiet --filter name=^demo\\.data$",
		legacyLeft,
	} {
		f := newFake()
		f.fail[failing] = errors.New("ssh: connection reset")
		if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
			t.Fatalf("%s failing: want an error", failing)
		}
		if f.has("docker pull") || f.has("docker network") || f.has("docker run -d") {
			t.Errorf("%s failing: nothing may happen: %v", failing, f.calls)
		}
	}
}

// routedFake is a server where demo-v1-1 is the running copy of the app, and the proxy serves it on
// web's host.
func routedFake(t *testing.T) *fake {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\t\n"
	f.out[frags] = fragment(t, "demo", "demo-v1-1", webPort)
	return f
}

// The switch makes the app's routes exactly what the config describes, dialling the new copy: a host
// the config dropped goes with the same reload, before the old container does, so no route is left
// pointing at a container this deploy removed. Other apps' routes ride along untouched.
func TestTheSwitchReplacesTheAppsWholeFragment(t *testing.T) {
	f := routedFake(t)
	f.out[frags] = fragment(t, "demo", "demo-v1-1", webPort, config.Port{Name: "legacy", Port: 3000, Host: "old.example.com"}) + "\n" +
		fragment(t, "other", "other-v1-1", config.Port{Name: "web", Port: 80, Host: "other.example.com"})
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	next := f.uploads[".boks/_proxy/caddy.next.json"]
	if !strings.Contains(next, `"dial": "`+newCopy+`:3000"`) || strings.Contains(next, "old.example.com") ||
		strings.Contains(next, "demo-v1-1") || !strings.Contains(next, `"dial": "other-v1-1:80"`) {
		t.Errorf("want demo's routes on the new copy alone, and other's kept:\n%s", next)
	}
	if strings.Contains(f.fragmentWrite("demo"), "old.example.com") || f.fragmentWrite("other") != "" {
		t.Errorf("want demo's fragment rewritten and other's left alone: %q %q", f.fragmentWrite("demo"), f.fragmentWrite("other"))
	}
	if reloaded, retired := f.at(reloadVia), f.at("docker rm -v demo-v1-1"); reloaded < 0 || retired < reloaded {
		t.Errorf("the reload comes before the old container goes: %v", f.calls)
	}
}

// What the proxy serves for the app is where a failed switch sends the routes back, so a deploy that
// cannot read it does not start.
func TestRunDoesNotStartWithoutTheRoutes(t *testing.T) {
	f := routedFake(t)
	f.fail[frags] = errors.New("boom")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker run -d --name demo-") {
		t.Errorf("nothing may start: %v", f.calls)
	}
}

// A host another app routes is refused before anything of the app changes: found at the switch, it
// would stop a deploy whose new copy already runs.
func TestAHostAnotherAppRoutesIsRefusedBeforeAnyChange(t *testing.T) {
	f := routedFake(t)
	f.out[frags] = fragment(t, "other", "other-v1-1", webPort)
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "is routed by both") {
		t.Fatalf("want the host refused, got %v", err)
	}
	if f.has("docker run") || f.has("docker network create") || len(f.appends) != 0 {
		t.Errorf("nothing of the app may change: %v", f.calls)
	}
}

// The legacy-volume refusal holds on the path without routes too.
func TestRoutelessRefusesWhenDataStillSitsUnderTheOldVolumeName(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker volume ls --quiet --filter name=^bot-data$"] = "bot-data"
	f.out["docker ps -a --filter volume=bot-data"] = "bot-v1-1\tbot\n"
	cfg := parse(t, noPorts+"volumes: [data:/data]\n")
	err := Run(context.Background(), f, io.Discard, cfg, "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "old naming scheme") {
		t.Fatalf("want a refusal naming the old volume, got %v", err)
	}
	if f.has("docker pull") || f.has("docker stop") || f.has("docker run -d") {
		t.Errorf("nothing may happen before the data is moved: %v", f.calls)
	}
}

// botPort is the port bot published before this deploy dropped it.
var botPort = config.Port{Name: "web", Port: 3000, Host: "bot.example.com"}

// A route of a removed port that cannot be dropped keeps the old copy: retiring it would leave
// the route pointing at a removed container. The new copy stays up, the old one is not revived.
func TestRoutelessKeepsTheOldCopyWhenARouteStays(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.out[frags] = fragment(t, "bot", "bot-v1-1", botPort)
	f.fail[reloadVia] = errors.New("boom")
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "bot-v1-1") {
		t.Fatalf("want an error naming the kept container, got %v", err)
	}
	if f.has("docker rm -v bot-v1-1") || f.has("docker start bot-v1-1") || f.has("docker rm -f -v bot-v2") {
		t.Errorf("the old copy is kept stopped and the new one stays: %v", f.calls)
	}
	if journalOpen(f, ".boks/bot/journal.jsonl") == false {
		t.Errorf("the routes are not where the config says, so the operation stays open: %q", f.appends[".boks/bot/journal.jsonl"])
	}
}

// A proxy that is stopped is not reloaded, and not started for an app that does not use it: the
// routes leave the files it loads when it starts, and the deploy goes on.
func TestRoutelessDropsItsRoutesWhileTheProxyIsStopped(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = "exited\tcaddy"
	f.out[frags] = fragment(t, "bot", "bot-v1-1", botPort)
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if f.has("docker exec boks-proxy") || f.has("docker start boks-proxy") {
		t.Errorf("a stopped proxy is neither reloaded nor started: %v", f.calls)
	}
	if !f.has("rm -f .boks/_proxy/routes/bot.json") || strings.Contains(f.uploads[".boks/_proxy/caddy.json"], "bot.example.com") ||
		f.uploads[".boks/_proxy/caddy.json"] == "" {
		t.Errorf("want bot's routes gone from the files the proxy loads: %v %v", f.calls, f.uploads)
	}
	if !f.has("docker rm -v bot-v1-1") {
		t.Errorf("no route reaches the old copy any more, so it goes: %v", f.calls)
	}
}

// An app whose ports were all removed still has the routes it had; left alone they answer with a
// 502 from a container this deploy removes. They go after the new copy is healthy and before the
// old one is retired, with one reload that keeps other apps' routes — without booting the proxy.
func TestRoutelessDropsTheRoutesOfRemovedPorts(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.out[frags] = fragment(t, "bot", "bot-v1-1", botPort, config.Port{Name: "api", Port: 3001, Host: "api.example.com"}) + "\n" +
		fragment(t, "other", "other-v1-1", config.Port{Name: "web", Port: 80, Host: "other.example.com"})
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	healthy, reloaded, retired := f.at("docker inspect --format"), f.at(reloadVia), f.at("docker rm -v bot-v1-1")
	if reloaded < healthy || retired < reloaded {
		t.Errorf("the routes must go after the new copy is healthy and before the old one is retired: %v", f.calls)
	}
	next := f.uploads[".boks/_proxy/caddy.next.json"]
	if strings.Contains(next, "bot.example.com") || strings.Contains(next, "api.example.com") || !strings.Contains(next, "other.example.com") {
		t.Errorf("only this app's routes may go:\n%s", next)
	}
	if !f.has("rm -f .boks/_proxy/routes/bot.json") || f.has("docker start boks-proxy") || f.has("docker network inspect boks") {
		t.Errorf("the fragment goes and the proxy is not booted: %v", f.calls)
	}
}

// A removal a cut run wrote to the fragments but never got into the proxy's config — the fragment
// gone, the applied config still routing the app — is finished by the next deploy, though the app
// has no fragment left to say so.
func TestRoutelessFinishesARemovalACutRunLeft(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	other := fragment(t, "other", "other-v1-1", config.Port{Name: "web", Port: 80, Host: "other.example.com"})
	f.out[frags] = other
	var both []proxy.Fragment
	for _, fr := range []string{fragment(t, "bot", "bot-v1-1", botPort), other} {
		var x proxy.Fragment
		if err := json.Unmarshal([]byte(fr), &x); err != nil {
			t.Fatal(err)
		}
		both = append(both, x)
	}
	stale, _ := proxy.Config(proxy.Policy{}, both)
	f.out[applied] = "present\n" + strings.TrimSuffix(string(stale), "\n")
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	next := f.uploads[".boks/_proxy/caddy.next.json"]
	if !f.has(reloadVia) || strings.Contains(next, "bot.example.com") || !strings.Contains(next, "other.example.com") {
		t.Errorf("want a reload without the app's routes:\n%s\n%v", next, f.calls)
	}
	if f.at(reloadVia) > f.at("docker rm -v bot-v1-1") {
		t.Errorf("the routes go before the old copy: %v", f.calls)
	}
}

// An app that drops its routes on a server still on kamal-proxy is refused before anything of it
// changes: its routes are kamal-proxy's, and retiring the copies they dial would leave them on 502.
func TestRoutelessRefusesToDropKamalRoutes(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running\t"
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t" + `[{"name":"web","port":3000,"host":"bot.example.com"}]` + "\n"
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "boks proxy migrate") || f.has("docker stop") || f.has("docker run") {
		t.Errorf("want the migration asked for and nothing changed: %v %v", err, f.calls)
	}
	// An app that never had routes deploys there as before.
	g := routelessFake("healthy")
	g.out["docker ps -a --filter name=^boks-proxy$"] = "running\t"
	g.out["docker ps -a --filter label=boks.app=bot"] = "bot-v1-1\t[]\n"
	if err := Run(context.Background(), g, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Errorf("a routeless app has nothing on kamal-proxy: %v", err)
	}
}

// An app that never had routes reloads nothing.
func TestRoutelessWithoutRoutesLeavesTheProxyAlone(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.out[frags] = fragment(t, "other", "other-v1-1", config.Port{Name: "web", Port: 80, Host: "other.example.com"})
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if f.has("docker exec boks-proxy") || f.has("rm -f .boks/_proxy") || proxyWrites(f) {
		t.Errorf("nothing of the proxy changes: %v %v", f.calls, f.uploads)
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

// A reload that fails may still have gone through, so the routes are put back on the old copy with a
// forced reload before the new copy goes; the old copy keeps serving, and the outcome is known.
func TestRunKeepsOldWhenSwitchFails(t *testing.T) {
	f := routedFake(t)
	reloads := 0
	f.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, reloadVia) {
			if reloads++; reloads == 1 {
				f.fail[reloadVia] = errors.New("loading new config: connection reset")
			} else {
				delete(f.fail, reloadVia)
			}
		}
	}
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("want the switch error, got %v", err)
	}
	restored, removed := f.at(reloadVia+" --force"), f.at("docker rm -f -v "+newCopy)
	if restored < 0 || removed < restored {
		t.Errorf("want the routes put back, then the new copy removed: %v", f.calls)
	}
	if f.has("docker stop demo-v1-1") || f.has("docker rm -v demo-v1-1") {
		t.Errorf("old container must survive a failed switch, got %v", f.calls)
	}
	if !strings.Contains(f.uploads[".boks/_proxy/caddy.next.json"], `"dial": "demo-v1-1:3000"`) {
		t.Errorf("want the restored config dialling the old copy: %s", f.uploads[".boks/_proxy/caddy.next.json"])
	}
	if journalOpen(f, journal) || !strings.Contains(f.appends[journal], `"result":"failed"`) {
		t.Errorf("the routes are back, so the outcome is known: %q", f.appends[journal])
	}
	if f.calls[len(f.calls)-1] != "rmdir /tmp/boks-demo.lock" {
		t.Errorf("lock must be released on failure, last call %s", f.calls[len(f.calls)-1])
	}
}

// When the routes cannot be put back either, the new copy may be what serves: it stays, the old one
// too, and the operation stays open.
func TestAFailedSwitchThatCannotBePutBackKeepsBothCopies(t *testing.T) {
	f := routedFake(t)
	f.fail[reloadVia] = errors.New("connection reset")
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "putting the routes back failed too") {
		t.Fatalf("want both failures named, got %v", err)
	}
	if f.has("docker rm -f -v "+newCopy) || f.has("docker stop demo-v1-1") || !journalOpen(f, journal) {
		t.Errorf("want both copies kept and the operation open: %v %q", f.calls, f.appends[journal])
	}
}

// A copy that never passes its health check never got the routes: it goes without a reload, the old
// copy keeps serving, and the outcome is known.
func TestAnUnhealthyCopyGetsNoRoute(t *testing.T) {
	f := routedFake(t)
	f.fail[probe] = errors.New("wget: server returned error: HTTP/1.1 503 Service Unavailable")
	cfg := parse(t, onePort+"deploy_timeout: 1ms\n")
	err := Run(context.Background(), f, io.Discard, cfg, "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "did not pass its health check within 1ms, so no route moved") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("want the health check named, got %v", err)
	}
	if f.has(reloadVia) || !f.has("docker rm -f -v "+newCopy) || f.has("docker stop demo-v1-1") {
		t.Errorf("no reload, the new copy removed, the old one kept: %v", f.calls)
	}
	if journalOpen(f, journal) {
		t.Errorf("nothing moved, so the outcome is known: %q", f.appends[journal])
	}
	// deploy_timeout bounds the probes themselves: one that never answers is cut off at it.
	g := routedFake(t)
	g.hang = []string{probe}
	done, hung := make(chan error, 1), parse(t, onePort+"deploy_timeout: 100ms\n")
	go func() { done <- Run(context.Background(), g, io.Discard, hung, "v2", quick()) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "did not pass its health check within 100ms") || g.has(reloadVia) {
			t.Errorf("want the timeout, and no route moved: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hung probe held the deploy past deploy_timeout")
	}
}

// Each port is checked where kamal-proxy checked it: its health_port when set, its path or /up, by the
// name the route will dial; a port that answered is not asked again while another one is waited for.
func TestTheHealthCheckOfEveryPortComesFirst(t *testing.T) {
	f := routedFake(t)
	const ready = probe + "http://" + newCopy + ":3002/ready"
	tries := 0
	f.onRun = func(cmd string) {
		if cmd == probe+"http://"+newCopy+":3000/up"+probeEnd {
			if tries++; tries < 3 {
				f.fail[probe+"http://"+newCopy+":3000/up"] = errors.New("refused")
			} else {
				delete(f.fail, probe+"http://"+newCopy+":3000/up")
			}
		}
	}
	cfg := parse(t, twoPorts+"  - {name: admin, port: 3002, host: admin.example.com, health_path: /ready}\n")
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(f.calls, "\n"), probe+"http://"+newCopy+":3000/up"); n != 4 {
		t.Errorf("web (3000/up) three times, actions (health_port 3000) once: %d probes %v", n, f.calls)
	}
	if n := strings.Count(strings.Join(f.calls, "\n"), ready); n != 1 {
		t.Errorf("admin answered at once and is not asked again: %d probes %v", n, f.calls)
	}
	if last, reload := f.lastAt(probe), f.at(reloadVia); reload < last {
		t.Errorf("the routes move once every port answers: %v", f.calls)
	}
}

// Each port has its own deploy_timeout from when the one before it answered, as kamal-proxy gave each
// route it deployed: two ports that answer 250ms apart pass under a 300ms timeout though together they
// take longer.
func TestEveryPortHasItsOwnDeployTimeout(t *testing.T) {
	f := routedFake(t)
	start := time.Now()
	web, admin := probe+"http://"+newCopy+":3000/up", probe+"http://"+newCopy+":3002/ready"
	f.onRun = func(cmd string) {
		for url, at := range map[string]time.Duration{web: 250 * time.Millisecond, admin: 500 * time.Millisecond} {
			if strings.HasPrefix(cmd, url) {
				if time.Since(start) < at {
					f.fail[url] = errors.New("refused")
				} else {
					delete(f.fail, url)
				}
			}
		}
	}
	cfg := parse(t, onePort+"deploy_timeout: 300ms\n")
	cfg.Ports = append(cfg.Ports, config.Port{Name: "admin", Port: 3002, Host: "admin.example.com", HealthPath: "/ready"})
	opts := quick()
	opts.Poll = 10 * time.Millisecond
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", opts); err != nil {
		t.Fatalf("want both ports through, each within its own budget: %v", err)
	}
}

// The previous copy finishes the requests the proxy still holds for it before it is stopped, within
// drain_timeout; one that never finishes is stopped at the bound, with a warning.
func TestTheOldCopyDrainsBeforeItGoes(t *testing.T) {
	f := routedFake(t)
	asked := 0
	f.onRun = func(cmd string) {
		if cmd == upstreams {
			if asked++; asked < 3 {
				f.out[upstreams] = `[{"address":"demo-v1-1:3000","num_requests":2}]`
			} else {
				f.out[upstreams] = `[{"address":"demo-v1-1:3000","num_requests":0}]`
			}
		}
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if asked != 3 || f.lastAt(upstreams) > f.at("docker stop demo-v1-1") || f.at(upstreams) < f.at(reloadVia) {
		t.Errorf("want the drain between the reload and the stop: %d %v", asked, f.calls)
	}
	g := routedFake(t)
	g.out[upstreams] = `[{"address":"demo-v1-1:3000","num_requests":1}]`
	var log strings.Builder
	if err := Run(context.Background(), g, &log, parse(t, onePort+"drain_timeout: 1ms\n"), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "1 requests to the previous copies still in flight after 1ms") || !g.has("docker stop demo-v1-1") {
		t.Errorf("want the bound to end the drain, with a warning: %q %v", log.String(), g.calls)
	}
	// A proxy that cannot say what it holds is waited out to the bound: stopping early is what the
	// drain exists to prevent.
	q := routedFake(t)
	q.fail[upstreams] = errors.New("connection lost")
	log.Reset()
	start := time.Now()
	if err := Run(context.Background(), q, &log, parse(t, onePort+"drain_timeout: 200ms\n"), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 200*time.Millisecond || !strings.Contains(log.String(), "could not say") || q.at("docker stop demo-v1-1") < q.lastAt(upstreams) {
		t.Errorf("want the bound waited out before the stop, with a warning: %s %q", time.Since(start), log.String())
	}
	// A question the bound cuts off after the proxy said what it holds: the warning reports that.
	k := routedFake(t)
	answered := 0
	k.onRun = func(cmd string) {
		if cmd == upstreams {
			if answered++; answered > 1 {
				k.hang = []string{upstreams}
			}
		}
	}
	k.out[upstreams] = `[{"address":"demo-v1-1:3000","num_requests":1}]`
	log.Reset()
	if err := Run(context.Background(), k, &log, parse(t, onePort+"drain_timeout: 100ms\n"), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "1 requests to the previous copies still in flight after 100ms") {
		t.Errorf("want the proxy's last answer in the warning: %q", log.String())
	}
	// A question that never answers is cut off at the bound, not waited on forever.
	w := routedFake(t)
	w.hang = []string{upstreams}
	done, hung := make(chan error, 1), parse(t, onePort+"drain_timeout: 100ms\n")
	go func() { done <- Run(context.Background(), w, io.Discard, hung, "v2", quick()) }()
	select {
	case err := <-done:
		if err != nil || !w.has("docker stop demo-v1-1") {
			t.Errorf("want the deploy to finish after the bound: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hung drain question held the deploy past drain_timeout")
	}
	// The drain is by container: a fragment a cut run left, naming a copy Caddy never sent anything
	// to, does not let the copy that served go before its requests end.
	c := routedFake(t)
	c.out[frags] = fragment(t, "demo", "demo-cut-1", webPort)
	busy := 0
	c.onRun = func(cmd string) {
		if cmd == upstreams {
			if busy++; busy < 3 {
				c.out[upstreams] = `[{"address":"demo-cut-1:3000","num_requests":0},{"address":"demo-v1-1:3000","num_requests":1}]`
			} else {
				c.out[upstreams] = `[]`
			}
		}
	}
	if err := Run(context.Background(), c, io.Discard, parse(t, onePort), "v2", quick()); err != nil || busy != 3 {
		t.Errorf("want the copy that served drained: %d %v", busy, err)
	}
	// A first deploy has nothing to drain.
	h := routedFake(t)
	h.out[frags] = ""
	h.out["docker ps -a --filter label=boks.app=demo"] = ""
	if err := Run(context.Background(), h, io.Discard, parse(t, onePort), "v2", quick()); err != nil || h.has(upstreams) {
		t.Errorf("nothing to drain: %v %v", err, h.calls)
	}
}

// A health path written without its slash means what kamal-proxy made of it: /up, joined onto the
// copy's address.
func TestARelativeHealthPathIsJoinedOntoTheAddress(t *testing.T) {
	f := routedFake(t)
	cfg := parse(t, strings.Replace(onePort, "health_path: /up", "health_path: up", 1))
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if !f.has(probe + "http://demo-v2-1700000000:3000/up") {
		t.Errorf("want the probe at /up: %v", f.calls)
	}
}

func TestPruneRemovesUntaggedImages(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
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

// No env means no env file.
func TestRunWithoutEnv(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v1", Options{Now: fixed.Now}); err != nil {
		t.Fatal(err)
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

// A commit tag makes the name one DNS label no more, and Docker's resolver answers nothing for it:
// the tag is cut so the name fits, and the time still sets the deploys apart.
func TestContainerNameFitsOneDNSLabel(t *testing.T) {
	sha := "157eb19fd30d085cdb5ec785fdb3574f84cabfda"
	got := ContainerName("glavdoroga-convex", sha, time.Unix(1791336560, 0))
	if len(got) > 63 || got != "glavdoroga-convex-157eb19fd30d085cdb5ec785fdb3574f84-1791336560" {
		t.Errorf("got %s (%d)", got, len(got))
	}
	if a, b := ContainerName("glavdoroga-convex", sha, time.Unix(1, 0)), ContainerName("glavdoroga-convex", sha, time.Unix(2, 0)); a == b {
		t.Errorf("two deploys share %s", a)
	}
	// The cut never leaves a separator at the end of the tag: 34 characters fit, the 34th is a "-".
	if got, want := ContainerName("glavdoroga-convex", strings.Repeat("a", 33)+"-b", time.Unix(1791336560, 0)),
		"glavdoroga-convex-"+strings.Repeat("a", 33)+"-1791336560"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	// The longest app name a config takes leaves no room for the tag: the tag is dropped rather than
	// failing, even an empty one, and the name is still one label.
	long := strings.Repeat("a", config.MaxAppLen)
	for _, tag := range []string{"", "v1"} {
		if got, want := ContainerName(long, tag, time.Unix(1791336560, 0)), long+"--1791336560"; got != want || len(got) > 63 {
			t.Errorf("tag %q: got %s (%d), want %s", tag, got, len(got), want)
		}
	}
}

// The snapshot is what rollback will run, so it has to hold the release rather than point at a
// config that may since have changed.
func TestDeployRecordsWhatItRan(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.out[digests] = `["mirror.example.com/x/y@sha256:other","ghcr.io/x/y@sha256:abc"]`
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	var snap release.Snapshot
	body, ok := f.uploads[".boks/demo/releases/demo-v2-1700000000.json"]
	if !ok {
		t.Fatalf("no snapshot written: %v", f.uploads)
	}
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		t.Fatal(err)
	}
	cfg := parse(t, onePort)
	if snap.Version != release.FormatVersion || snap.ID != "demo-v2-1700000000" || snap.App != "demo" ||
		snap.Image != "ghcr.io/x/y" || snap.Digest != "sha256:abc" || snap.Tag != "v2" ||
		!reflect.DeepEqual(snap.Ports, cfg.Ports) || !reflect.DeepEqual(snap.Volumes, cfg.Volumes) ||
		!reflect.DeepEqual(snap.Networks, []config.Network{{Name: "boks-demo", Aliases: []string{"demo"}}}) || snap.Network != "" || !snap.TLS || !snap.CreatedAt.Equal(time.Unix(1700000000, 0)) ||
		snap.EnvPath != ".boks/demo/demo-v2-1700000000.env" {
		t.Errorf("snapshot does not describe the release: %+v", snap)
	}
	if f.uploads[".boks/demo/current"] != "demo-v2-1700000000\n" {
		t.Errorf("current not moved: %q", f.uploads[".boks/demo/current"])
	}
	if !strings.Contains(f.appends[".boks/demo/journal.jsonl"], `"result":"ok"`) {
		t.Errorf("journal not closed: %q", f.appends[".boks/demo/journal.jsonl"])
	}
}

// A deploy that died between switching routes and retiring the old container leaves no trace in
// docker. The journal is the only place that knows, and the next run has to say so.
func TestDeployWarnsAboutAnOperationThatNeverFinished(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.out["sh -c cat '.boks/demo/journal.jsonl'"] =
		`{"op":"1","action":"deploy","to":"demo-v1-1","started_at":"2026-09-15T10:00:00Z"}`
	var log strings.Builder
	if err := Run(context.Background(), f, &log, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "never finished") {
		t.Errorf("the interrupted deploy must be reported: %q", log.String())
	}
	// Reported once: the entry is closed, or every later deploy would report it again.
	if !strings.Contains(f.appends[".boks/demo/journal.jsonl"], `{"op":"1",`) ||
		!strings.Contains(f.appends[".boks/demo/journal.jsonl"], `"result":"abandoned"}`) {
		t.Errorf("the abandoned entry must be closed: %q", f.appends[".boks/demo/journal.jsonl"])
	}
}

// A switch that returned an error may still have happened on the proxy — the connection can drop
// after kamal-proxy acted. Its outcome is unknown, so the entry stays open: `boks releases` and the
// next deploy are what show it.
func TestFailedSwitchLeavesTheJournalOpen(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.fail[reloadVia] = errors.New("connection reset")
	err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "may be serving") {
		t.Fatalf("want an error saying the new copy may serve, got %v", err)
	}
	opened := f.appends[".boks/demo/journal.jsonl"]
	if !strings.Contains(opened, `"action":"deploy"`) || strings.Contains(opened, `"result"`) {
		t.Fatalf("the entry must stay open: %q", opened)
	}
	// The next deploy reads that journal: it reports the operation and closes it as abandoned.
	next := newFake()
	next.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	next.out["sh -c cat '.boks/demo/journal.jsonl'"] = opened
	var log strings.Builder
	if err := Run(context.Background(), next, &log, parse(t, onePort), "v3", fixed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "never finished") || !strings.Contains(next.appends[".boks/demo/journal.jsonl"], `"result":"abandoned"`) {
		t.Errorf("the next deploy must report the open operation: %q / %q", log.String(), next.appends[".boks/demo/journal.jsonl"])
	}
}

const journal = ".boks/demo/journal.jsonl"

// journalOpen reports a journal with an opened operation and no closing line for it.
func journalOpen(f *fake, path string) bool {
	j := f.appends[path]
	return strings.Contains(j, `"action":"deploy"`) && !strings.Contains(j, `"result"`)
}

func TestFailedStartClosesTheJournalEntry(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	f.fail["docker run"] = errors.New("no such image")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(f.appends[journal], `"result":"failed"`) {
		t.Errorf("a failed start must be recorded as failed: %q", f.appends[journal])
	}
}

// The release is written down before the previous containers go, and in the order that leaves more
// evidence when cut short: snapshot, then current, then the closing line.
func TestDeployRecordsBeforeItRetires(t *testing.T) {
	f := routedFake(t)
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	snap := f.writeIndex(".boks/demo/releases/demo-v2-1700000000.json", "")
	current := f.writeIndex(".boks/demo/current", "")
	closed := f.writeIndex(journal, `"result":"ok"`)
	if snap < 0 || current <= snap || closed <= current {
		t.Errorf("want snapshot, then current, then the closing line; got %d %d %d", snap, current, closed)
	}
	if retired := f.callAt("docker rm -v demo-v1-1"); retired < 0 || retired < f.writeAt(journal, `"result":"ok"`) {
		t.Errorf("the previous container goes only after the release is recorded: %v", f.calls)
	}
}

// If the release cannot be written down, the previous containers are the only trace of what ran
// before it, so they stay and the deploy reports the failure.
func TestUnrecordedReleaseKeepsThePreviousContainers(t *testing.T) {
	t.Run("digest", func(t *testing.T) {
		f := routedFake(t)
		f.fail[digests] = errors.New("connection reset")
		err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
		if err == nil || !strings.Contains(err.Error(), "could not record") || f.has("docker rm -v demo-v1-1") {
			t.Fatalf("a snapshot without its digest is not a record: %v %v", err, f.calls)
		}
	})
	t.Run("routeless", func(t *testing.T) {
		f := routelessFake("healthy")
		f.pipeFail = func(path, _ string) error {
			if path == ".boks/bot/current" {
				return errors.New("disk full")
			}
			return nil
		}
		err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick())
		if err == nil || !strings.Contains(err.Error(), "could not record") || !strings.Contains(err.Error(), "bot-v1-1") {
			t.Fatalf("want an error naming the kept copy, got %v", err)
		}
		if f.has("docker rm -v bot-v1-1") || f.has("docker start bot-v1-1") || f.has("docker rm -f -v bot-v2") {
			t.Errorf("the old copy stays stopped and the new one runs: %v", f.calls)
		}
	})
	for name, fails := range map[string]func(path, content string) bool{
		"snapshot": func(path, _ string) bool { return strings.Contains(path, "/releases/") },
		"current":  func(path, _ string) bool { return path == ".boks/demo/current" },
		"journal":  func(path, content string) bool { return path == journal && strings.Contains(content, `"result":"ok"`) },
	} {
		t.Run(name, func(t *testing.T) {
			f := routedFake(t)
			f.pipeFail = func(path, content string) error {
				if fails(path, content) {
					return errors.New("disk full")
				}
				return nil
			}
			err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed)
			if err == nil || !strings.Contains(err.Error(), "could not record") || !strings.Contains(err.Error(), "demo-v1-1") {
				t.Fatalf("want an error naming the kept container, got %v", err)
			}
			if f.has("docker rm -v demo-v1-1") || f.has("docker stop demo-v1-1") {
				t.Errorf("the previous container must stay: %v", f.calls)
			}
		})
	}
}

// A journal that cannot be opened stops the deploy before anything of the app changes.
func TestDeployDoesNotStartWithoutAJournalEntry(t *testing.T) {
	for cfg, f := range map[string]*fake{onePort: routedFake(t), noPorts: routelessFake("healthy")} {
		f.pipeFail = func(path, content string) error {
			if strings.HasSuffix(path, "journal.jsonl") {
				return errors.New("read-only file system")
			}
			return nil
		}
		if err := Run(context.Background(), f, io.Discard, parse(t, cfg), "v2", quick()); err == nil {
			t.Fatal("want an error")
		}
		if f.has("docker run") || f.has("docker stop") || f.has("docker exec boks-proxy kamal-proxy deploy") {
			t.Errorf("nothing of the app may change: %v", f.calls)
		}
	}
}

// An app without environment gets no env file, so its snapshot must not name one.
func TestSnapshotNamesNoEnvFileWhenThereIsNone(t *testing.T) {
	f := routedFake(t)
	o := fixed
	o.Env = nil
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", o); err != nil {
		t.Fatal(err)
	}
	var snap release.Snapshot
	if err := json.Unmarshal([]byte(f.uploads[".boks/demo/releases/demo-v2-1700000000.json"]), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.EnvPath != "" {
		t.Errorf("no env file was written, got %q", snap.EnvPath)
	}
}

// Hosts covered by a certificate were routed at it; the snapshot keeps which domains those were.
func TestSnapshotKeepsTheCertificateDomains(t *testing.T) {
	f := routedFake(t)
	f.out["docker exec boks-proxy cat /certs/boks/_.example.com.crt"] = "-----BEGIN CERTIFICATE-----"
	cfg := parse(t, onePort+"cert: {domains: [\"*.example.com\"], dns: cloudflare, email: a@example.com}\n")
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", fixed); err != nil {
		t.Fatal(err)
	}
	var snap release.Snapshot
	if err := json.Unmarshal([]byte(f.uploads[".boks/demo/releases/demo-v2-1700000000.json"]), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.CertDomains) != 1 || snap.CertDomains[0] != "*.example.com" {
		t.Errorf("want the certificate's domains, got %v", snap.CertDomains)
	}
}

// The certificate is read through the proxy, so it is checked once the proxy is booted: a deploy
// still brings back a proxy that was stopped or removed, with the certificate on its volume, rather
// than send the operator to issue a certificate that is already there.
func TestTheCertificateIsCheckedOnceTheProxyIsUp(t *testing.T) {
	f := newFake() // no proxy: the deploy boots it
	const crt = "docker exec boks-proxy cat /certs/boks/_.example.com.crt"
	f.fail[crt] = errors.New("Error response from daemon: No such container: boks-proxy")
	f.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, "docker start boks-proxy") {
			delete(f.fail, crt)
			f.out[crt] = "-----BEGIN CERTIFICATE-----"
		}
	}
	cfg := parse(t, onePort+"cert: {domains: [\"*.example.com\"], dns: cloudflare, email: a@example.com}\n")
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if boot, check := f.callAt("docker start boks-proxy"), f.callAt(crt); boot < 0 || check < boot {
		t.Errorf("want the proxy booted before the certificate is read: %d %d", boot, check)
	}
}

const botJournal = ".boks/bot/journal.jsonl"

// Stopping the running copy changes the server, so the entry is open before it.
func TestRoutelessOpensTheJournalBeforeTheStop(t *testing.T) {
	f := routelessFake("healthy")
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	opened, stopped := f.writeAt(botJournal, `"action":"deploy"`), f.callAt("docker stop bot-v1-1")
	if opened < 0 || stopped < 0 || opened > stopped {
		t.Errorf("the entry must be opened before the stop: opened at %d, stop at %d", opened, stopped)
	}
	if !strings.Contains(f.appends[botJournal], `"result":"ok"`) || f.uploads[".boks/bot/current"] != "bot-v2-1700000000\n" {
		t.Errorf("a routeless deploy is recorded too: %q %v", f.appends[botJournal], f.uploads)
	}
}

func TestRoutelessFailedStopClosesTheJournalEntry(t *testing.T) {
	f := routelessFake("healthy")
	f.fail["docker stop bot-v1-1"] = errors.New("connection reset")
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(f.appends[botJournal], `"result":"failed"`) {
		t.Errorf("a refused stop must be recorded as failed: %q", f.appends[botJournal])
	}
}

// The entry closes after the cleanup, so a run cut while the old copy is being brought back stays
// visibly unfinished.
func TestRoutelessFailedStartClosesTheJournalAfterTheCleanup(t *testing.T) {
	for name, f := range map[string]*fake{"unhealthy": routelessFake("unhealthy"), "leftover": routelessFake("unhealthy")} {
		if name == "leftover" {
			f.out["docker ps -a --filter name=^bot-v2-1700000000$"] = "bot-v2-1700000000\tbot\n"
		}
		if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err == nil {
			t.Fatalf("%s: want an error", name)
		}
		closed := f.writeAt(botJournal, `"result":"failed"`)
		cleaned := f.callAt("docker rm -f -v bot-v2-1700000000")
		if name == "unhealthy" {
			cleaned = f.callAt("docker start bot-v1-1")
		}
		if closed < 0 || cleaned < 0 || closed <= cleaned {
			t.Errorf("%s: the entry must close after the cleanup: closed at %d, cleanup at %d", name, closed, cleaned)
		}
	}
}

// A refused deploy changed nothing, so it leaves nothing in the journal either.
func TestRoutelessNameCollisionWritesNoJournal(t *testing.T) {
	f := routelessFake("unhealthy")
	f.out["docker ps -a --filter label=boks.app=bot"] = "bot-v2-1700000000\t\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", quick()); err == nil {
		t.Fatal("want an error")
	}
	if len(f.appends) != 0 {
		t.Errorf("no journal entry for a refused deploy: %v", f.appends)
	}
}

// The opening line names the release being replaced, which is what a later run needs to say what
// was serving; and a current pointer that cannot be read stops the deploy before it changes anything.
func TestJournalNamesTheReleaseBeingReplaced(t *testing.T) {
	f := routedFake(t)
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v1-1\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.appends[journal], `"from":"demo-v1-1","to":"demo-v2-1700000000"`) {
		t.Errorf("want the replaced release in the opening line: %q", f.appends[journal])
	}
	f = routedFake(t)
	f.fail["sh -c cat '.boks/demo/current'"] = errors.New("connection reset")
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err == nil {
		t.Fatal("want an error")
	}
	if f.has("docker run") || len(f.appends) != 0 {
		t.Errorf("nothing may change: %v %v", f.calls, f.appends)
	}
}

// A Docker Hub image configured by its short name is recorded under its canonical repository; the
// digest is still the one to keep, not dropped because the names differ.
func TestSnapshotKeepsTheDigestOfAShortImageName(t *testing.T) {
	f := routedFake(t)
	f.out[digests] = `["docker.io/library/redis@sha256:abc"]`
	cfg := parse(t, strings.Replace(onePort, "image: ghcr.io/x/y", "image: redis", 1))
	if err := Run(context.Background(), f, io.Discard, cfg, "7", fixed); err != nil {
		t.Fatal(err)
	}
	var snap release.Snapshot
	if err := json.Unmarshal([]byte(f.uploads[".boks/demo/releases/demo-7-1700000000.json"]), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Digest != "sha256:abc" {
		t.Errorf("want the canonical repository's digest, got %q", snap.Digest)
	}
}

// A snapshot names the release it was deployed over: that, not deploy order, is where a rollback
// without an id returns once a rollback has happened.
func TestSnapshotNamesTheReleaseItWasDeployedOver(t *testing.T) {
	f := routedFake(t)
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v1-1\n"
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	var snap release.Snapshot
	if err := json.Unmarshal([]byte(f.uploads[".boks/demo/releases/demo-v2-1700000000.json"]), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Previous != "demo-v1-1" {
		t.Errorf("want the release serving before, got %q", snap.Previous)
	}
}

// A stock image with no HEALTHCHECK (postgres, redis) runs without routes once the config gives it
// one: the image is not asked, the container is started with the check, and the release records it.
func TestRoutelessDeploysAStockImageWithAHealthcheckBlock(t *testing.T) {
	f := routelessFake("healthy")
	f.out["docker image inspect"] = ""
	cfg := parse(t, noPorts+"healthcheck: {cmd: pg_isready -U postgres, interval: 1s}\n")
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if f.has("docker image inspect") {
		t.Errorf("with a healthcheck block the image's own HEALTHCHECK does not matter: %v", f.calls)
	}
	run := f.calls[f.callAt("docker run")]
	if !strings.Contains(run, " --health-cmd pg_isready -U postgres --health-interval 1s --health-start-period 2s --health-start-interval 1s ") {
		t.Errorf("the container must be started with the configured check, failures counted only after the deploy's wait: %s", run)
	}
	// The fake joins arguments with spaces, so the command's boundaries are checked on the arguments:
	// docker must get the whole command as the one value of --health-cmd.
	opts := runOptions(cfg, "bot-v2", "v2", "bot:v2", "", nil)
	if i := slices.Index(opts, "--health-cmd"); i < 0 || i+1 >= len(opts) || opts[i+1] != "pg_isready -U postgres" {
		t.Errorf("the health command must be one argument: %q", opts)
	}
	snap := f.uploads[".boks/bot/releases/bot-v2-1700000000.json"]
	if !strings.Contains(snap, `"cmd": "pg_isready -U postgres"`) || !strings.Contains(snap, `"interval": "1s"`) {
		t.Errorf("the release must record the check it ran with: %s", snap)
	}
}

// A release's files go to a directory of their own on the server, readable by the container's user
// whatever it is, and are mounted read-only by their absolute path; the release records them. Every
// one of them: a second file dropped would leave the container on what its image ships there.
func TestDeployMountsTheReleasesFiles(t *testing.T) {
	const dir = ".boks/bot/files/bot-v2-1700000000"
	f := routelessFake("healthy")
	f.out["sh -c cd '"+dir+"' && pwd -P"] = "/home/u/" + dir
	o := quick()
	o.Files = []config.FileContent{
		{Name: "0-site.conf", Target: "/etc/nginx/conf.d/default.conf", Body: []byte("server {}")},
		{Name: "1-mime.types", Target: "/etc/nginx/mime.types", Body: []byte("types {}")},
	}
	if err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", o); err != nil {
		t.Fatal(err)
	}
	chmod, run := f.callAt("chmod 0644 "+dir+"/0-site.conf "+dir+"/1-mime.types"), f.callAt("docker run")
	if chmod < 0 || run < 0 || chmod > run {
		t.Errorf("the files must be made readable before the container starts: %v", f.calls)
	}
	snap := f.uploads[".boks/bot/releases/bot-v2-1700000000.json"]
	for _, c := range o.Files {
		if f.uploads[dir+"/"+c.Name] != string(c.Body) {
			t.Errorf("%s must be written into the release's directory: %v", c.Name, f.uploads)
		}
		// The write leaves the file owner-only, so the mode is set after it, not before.
		if w := f.writeAt(dir+"/"+c.Name, string(c.Body)); w < 0 || w > chmod {
			t.Errorf("%s must be written before its mode is set: write after %d commands, chmod at %d", c.Name, w, chmod)
		}
		if !strings.Contains(f.calls[run], " -v /home/u/"+dir+"/"+c.Name+":"+c.Target+":ro ") {
			t.Errorf("%s must be mounted read-only by its absolute path: %s", c.Name, f.calls[run])
		}
		if !strings.Contains(snap, `"name": "`+c.Name+`"`) || !strings.Contains(snap, `"target": "`+c.Target+`"`) {
			t.Errorf("the release must record %s: %s", c.Name, snap)
		}
	}
}

// Docker reads a relative bind source as a volume name, so a directory that does not resolve to an
// absolute path is a failed start, not a container started without its files.
func TestDeployRefusesAFilesDirectoryItCannotResolve(t *testing.T) {
	f := routelessFake("healthy")
	o := quick()
	o.Files = []config.FileContent{{Name: "0-site.conf", Target: "/etc/site.conf", Body: []byte("x")}}
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "cannot mount") {
		t.Fatalf("want a refusal naming the mount, got %v", err)
	}
	if f.has("docker run") || !f.has("docker start bot-v1-1") {
		t.Errorf("no container may start without its files, and the old copy must come back: %v", f.calls)
	}
}

// A file the container's user may not be able to read is not mounted: a failed chmod fails the start.
func TestDeployRefusesFilesItCouldNotMakeReadable(t *testing.T) {
	f := routelessFake("healthy")
	f.fail["chmod 0644"] = errors.New("Operation not permitted")
	o := quick()
	o.Files = []config.FileContent{{Name: "0-site.conf", Target: "/etc/site.conf", Body: []byte("x")}}
	err := Run(context.Background(), f, io.Discard, parse(t, noPorts), "v2", o)
	if err == nil || !strings.Contains(err.Error(), "readable") {
		t.Fatalf("want a refusal naming the file mode, got %v", err)
	}
	if f.has("docker run") || !f.has("docker start bot-v1-1") {
		t.Errorf("no container may start with unreadable files, and the old copy must come back: %v", f.calls)
	}
}

// The command follows the image on `docker run`, the stop signal goes with the options, and the
// release records both.
func TestDeployRunsTheConfiguredCommandAndStopSignal(t *testing.T) {
	f := routelessFake("healthy")
	cfg := parse(t, noPorts+"command: [redis-server, --appendonly, \"yes\"]\nstop_signal: SIGINT\n")
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", quick()); err != nil {
		t.Fatal(err)
	}
	run := f.calls[f.callAt("docker run")]
	if !strings.HasSuffix(run, " ghcr.io/x/bot:v2 redis-server --appendonly yes") || !strings.Contains(run, " --stop-signal SIGINT ") {
		t.Errorf("want the signal among the options and the command after the image: %s", run)
	}
	snap := f.uploads[".boks/bot/releases/bot-v2-1700000000.json"]
	if !strings.Contains(snap, `"stop_signal": "SIGINT"`) || !strings.Contains(snap, `"--appendonly"`) {
		t.Errorf("the release must record the command and the signal: %s", snap)
	}
	// The fake joins arguments with spaces, so the command's boundaries are checked on the arguments:
	// each element is one argument, a phrase and an empty one included.
	cfg = parse(t, noPorts+"command: [sh, -c, 'exec redis-server --requirepass \"$P\"', \"\"]\n")
	opts := runOptions(cfg, "bot-v2", "v2", "bot:v2", "", nil)
	if want := []string{"bot:v2", "sh", "-c", `exec redis-server --requirepass "$P"`, ""}; len(opts) < len(want) || !slices.Equal(opts[len(opts)-len(want):], want) {
		t.Errorf("each element of the command must be one argument after the image: %q", opts)
	}
}

const withSchedule = noPorts + "schedules:\n  - {name: warm, cron: '*/4 * * * *', command: 'cd /app && ./warm %s'}\n"

// A release with schedules: the server is asked for cron before anything changes, the job's command
// goes under the release's own directory before the snapshot names it, the serving copy is recorded,
// and the app's crontab block points cron at the runner — without the command in the crontab, where
// `%` would end the line.
func TestDeployWithSchedules(t *testing.T) {
	f := routelessFake("healthy")
	f.out["sh -c command -v crontab"] = "yes"
	if err := Run(context.Background(), f, io.Discard, parse(t, withSchedule), "v2", quick()); err != nil {
		t.Fatal(err)
	}
	if cron, stop := f.callAt("sh -c command -v crontab"), f.callAt("docker stop"); cron < 0 || stop < 0 || cron > stop {
		t.Errorf("cron must be checked before the running copy is touched: %v", f.calls)
	}
	if f.uploads[".boks/bot/jobs/bot-v2-1700000000/warm.sh"] != "cd /app && ./warm %s\n" {
		t.Errorf("the job's command must be kept under the release: %v", f.uploads)
	}
	if f.writeIndex(".boks/bot/jobs/bot-v2-1700000000/warm.sh", "warm") > f.writeIndex(".boks/bot/releases/bot-v2-1700000000.json", "") {
		t.Errorf("the command must exist before the snapshot names it")
	}
	if f.uploads[".boks/bot/serving"] != "bot-v2-1700000000 bot-v2-1700000000\n" {
		t.Errorf("the serving release and container must be recorded together: %q", f.uploads[".boks/bot/serving"])
	}
	if f.uploads[".boks/bot/boks-job"] != runner {
		t.Errorf("the runner must be written")
	}
	block := f.uploads[".boks/bot/crontab"]
	if block != "# boks:bot begin\n*/4 * * * * sh $HOME/.boks/bot/boks-job bot warm\n# boks:bot end\n" {
		t.Errorf("unexpected crontab block: %q", block)
	}
	if !f.has("sh -c mkdir -p .boks && exec 9>> .boks/crontab.lock && flock 9 && { crontab -l 2>/dev/null || true; } | sed -e '/^# boks:bot begin$/','/^# boks:bot end$/'d") {
		t.Errorf("the app's block must replace its earlier one in the crontab: %v", f.calls)
	}
	if !strings.Contains(f.uploads[".boks/bot/releases/bot-v2-1700000000.json"], `"name": "warm"`) {
		t.Errorf("the release must record its schedules")
	}
}

// Without cron the jobs would never run, so the deploy is refused while the running copy is still up.
func TestDeployWithSchedulesRefusesAServerWithoutCron(t *testing.T) {
	f := routelessFake("healthy")
	f.out["sh -c command -v crontab"] = "no"
	err := Run(context.Background(), f, io.Discard, parse(t, withSchedule), "v2", quick())
	if err == nil || !strings.Contains(err.Error(), "install cron") {
		t.Fatalf("want a refusal naming cron, got %v", err)
	}
	if f.has("docker stop") || f.has("docker run") || f.has("docker pull") {
		t.Errorf("nothing may change on a server that cannot run the jobs: %v", f.calls)
	}
}

// A port becomes a route the same way for a deploy and a migration: its path, rewrite and headers go
// to the proxy, and a wildcard host under the certificate is served with the certificate's files.
func TestRouteOfCarriesThePortsRouting(t *testing.T) {
	c := &config.Cert{Domains: []string{"*.example.com"}, DNS: "cloudflare", Email: "a@b.c"}
	p := config.Port{Name: "img", Port: 8080, Host: "*.example.com", Path: "/api", PathRewrite: "/img",
		Headers: &config.Headers{Request: map[string]string{"Cookie": ""}, Response: map[string]string{"X-Content-Type-Options": "nosniff"}}}
	rt := routeOf(p, "gw-v1:8080", true, c)
	if rt.Host != "*.example.com" || rt.Path != "/api" || rt.PathRewrite != "/img" || rt.Dial != "gw-v1:8080" || !rt.TLS {
		t.Errorf("unexpected route: %+v", rt)
	}
	if rt.Cert == nil || rt.Headers == nil || !reflect.DeepEqual(rt.Headers.Request, map[string]string{"Cookie": ""}) ||
		rt.Headers.Response["X-Content-Type-Options"] != "nosniff" {
		t.Errorf("want the certificate files and the header rule: %+v", rt)
	}
	if plain := routeOf(config.Port{Host: "a.example.org", StripPath: true, Path: "/x"}, "a:1", false, nil); plain.Cert != nil || !plain.StripPath || plain.Headers != nil {
		t.Errorf("a host outside the certificate keeps automatic HTTPS and only its own rules: %+v", plain)
	}
	// A deploy routes its ports through routeOf: nothing of the port's routing is lost on the way.
	cfg := &config.Config{TLS: true, Cert: c, Ports: []config.Port{p}}
	if got := routesTo(cfg, "gw-v1"); len(got) != 1 || !reflect.DeepEqual(got[0], rt) {
		t.Errorf("want the deploy's route to be the port's: %+v", got)
	}
}
