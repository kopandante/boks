package proxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestDeployArgs(t *testing.T) {
	got := strings.Join(DeployArgs(Service{
		Name: "demo.actions", Target: "demo-v2-1:3211", Host: "actions.example.com",
		TLS: true, HealthPath: "/version", HealthPort: 3210, Timeout: "60s",
	}), " ")
	want := "docker exec boks-proxy kamal-proxy deploy demo.actions --target demo-v2-1:3211 " +
		"--host actions.example.com --forward-headers=false --tls --health-check-path /version --health-check-port 3210 --deploy-timeout 60s"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestDeployArgsWithManualCertificate(t *testing.T) {
	got := strings.Join(DeployArgs(Service{
		Name: "a-web", Target: "a-1:80", Host: "a.example.com", TLS: true,
		CertPath: "/certs/boks/_.example.com.crt", KeyPath: "/certs/boks/_.example.com.key",
	}), " ")
	want := "docker exec boks-proxy kamal-proxy deploy a-web --target a-1:80 --host a.example.com --forward-headers=false --tls " +
		"--tls-certificate-path /certs/boks/_.example.com.crt --tls-private-key-path /certs/boks/_.example.com.key"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestDeployArgsMinimal(t *testing.T) {
	got := strings.Join(DeployArgs(Service{Name: "a-web", Target: "a-1:80", Host: "a.example.com"}), " ")
	if got != "docker exec boks-proxy kamal-proxy deploy a-web --target a-1:80 --host a.example.com --forward-headers=false" {
		t.Errorf("got %s", got)
	}
}

type fake struct {
	calls  []string
	state  string
	silent int               // how many times a just-started proxy does not answer yet
	out    map[string]string // answers by command prefix
	fail   map[string]error  // failures by command prefix
}

func (f *fake) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if strings.HasPrefix(cmd, "docker ps -a") {
		return f.state, nil
	}
	if cmd == answer && f.silent > 0 {
		f.silent--
		return "", errors.New("dial unix /home/kamal-proxy/.config/kamal-proxy/kamal-proxy.sock: connect: no such file or directory")
	}
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
	if cmd == answer+" --json" {
		return "{}", nil // a proxy that holds no routes
	}
	return "", nil
}

const answer = "docker exec boks-proxy kamal-proxy list"

const networksOf = "docker container ls -a --filter name=^boks-proxy$ --format {{.Networks}}"

// at is the position of the first call starting with prefix, or -1.
func at(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func (f *fake) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return f.Run(ctx, args...)
}

func TestBootIdempotent(t *testing.T) {
	f := &fake{state: "running"}
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker run") || strings.HasPrefix(c, "docker start") {
			t.Errorf("running proxy must not be touched, got %s", c)
		}
	}
}

func TestBootStartsMissingProxy(t *testing.T) {
	f := &fake{state: "", out: map[string]string{answer + " --json": "{}"}}
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	started, answered := at(f.calls, "docker run -d --name boks-proxy --restart unless-stopped --network boks "), at(f.calls, answer)
	if started < 0 || !strings.HasSuffix(f.calls[started], " img") || answered != started+1 {
		t.Errorf("expected docker run, then the wait for an answer: %v", f.calls)
	}
}

// A proxy created anew keeps its routes in its config volume but none of its networks: it joins
// those of the containers its routes target — an app's own network, the network apps shared
// before — once each.
func TestANewProxyJoinsTheNetworksItsRoutesNeed(t *testing.T) {
	f := &fake{state: "", out: routes()}
	f.out[networksOf] = "boks" // where a new proxy is started
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(joins(f.calls), "\n"); got != "docker network connect boks-a boks-proxy\ndocker network connect boks-test boks-proxy" {
		t.Errorf("want each target's network joined once, and not its own: %v", f.calls)
	}
	// A target that uses other apps is on their networks too; the proxy joins only its app's own.
	u := &fake{state: "running", out: routes()}
	u.out[inspectOf+"'a-v1-1'"] = "a|boks-a boks-cache boks-convex"
	if err := Boot(context.Background(), u, io.Discard, "img"); err != nil || at(u.calls, "docker network connect boks-cache") >= 0 ||
		at(u.calls, "docker network connect boks-convex") >= 0 || at(u.calls, "docker network connect boks-a") < 0 {
		t.Errorf("want only boks-a joined for a, not the networks it uses: %v %v", err, u.calls)
	}
	// A proxy started by an earlier boks on the shared network is not on boks: a route to a container
	// there makes it join.
	v := &fake{state: "running", out: routes()}
	v.out[networksOf] = "boks-test,boks-a"
	if err := Boot(context.Background(), v, io.Discard, "img"); err != nil || at(v.calls, "docker network connect boks boks-proxy") < 0 {
		t.Errorf("want boks joined for b: %v %v", err, v.calls)
	}
	// A proxy on every network its routes need joins none again.
	g := &fake{state: "running", out: routes()}
	g.out[networksOf] = "boks,boks-a,boks-test"
	if err := Boot(context.Background(), g, io.Discard, "img"); err != nil || len(joins(g.calls)) != 0 {
		t.Errorf("the proxy is on its routes' networks already: %v %v", err, g.calls)
	}
	// A boot cut short after creating the proxy is finished by the next one, which finds it running.
	k := &fake{state: "running", out: routes()}
	k.out[networksOf] = "boks"
	if err := Boot(context.Background(), k, io.Discard, "img"); err != nil || len(joins(k.calls)) != 2 || at(k.calls, "docker run") >= 0 {
		t.Errorf("a running proxy missing its routes' networks joins them: %v %v", err, k.calls)
	}
}

// A route to a container that is gone costs a warning: its app's deploy repairs it. Any other
// failure — a target whose networks cannot be read, a join that fails, the routes or the proxy's own
// networks unread — fails the boot, which would otherwise report a proxy that cannot reach a running
// app as booted.
func TestTheProxyBootFailsOnARouteItCannotReach(t *testing.T) {
	gone := &fake{state: "running", out: routes()}
	gone.out[inspectOf+"'a-v1-1'"] = "<gone>"
	var log strings.Builder
	if err := Boot(context.Background(), gone, &log, "img"); err != nil || !strings.Contains(log.String(), "a-v1-1, which is gone") ||
		at(gone.calls, "docker network connect boks-test") < 0 {
		t.Errorf("a gone target is a warning, the others still joined: %v %q %v", err, log.String(), gone.calls)
	}
	for name, fail := range map[string]map[string]error{
		"a target unread": {inspectOf + "'a-v1-1'": errors.New("connection reset")},
		"a join":          {"docker network connect boks-test": errors.New("network not found")},
		"the routes":      {answer + " --json": errors.New("connection reset")},
		"its networks":    {networksOf: errors.New("connection reset")},
	} {
		f := &fake{state: "running", out: routes(), fail: fail}
		if err := Boot(context.Background(), f, io.Discard, "img"); err == nil {
			t.Errorf("%s: want the boot to fail: %v", name, f.calls)
		}
	}
}

// routes is a proxy holding routes to a-v1-1 (app a, on boks-a, through two ports) and b-v1-1 (started
// by an earlier boks, unlabelled, on the shared boks-test and on boks).
func routes() map[string]string {
	return map[string]string{
		answer + " --json": `{"a.web":{"hosts":["a.example.com"],"targets":["a-v1-1:3000"]},` +
			`"a.api":{"hosts":["api.example.com"],"targets":["a-v1-1:3001"]},"b.web":{"hosts":["b.example.com"],"targets":["b-v1-1:80"]}}`,
		inspectOf + "'a-v1-1'": "a|boks-a",
		// Trimmed, as the SSH runner returns it.
		inspectOf + "'b-v1-1'": "|boks-test boks",
	}
}

func joins(calls []string) []string {
	var j []string
	for _, c := range calls {
		if strings.HasPrefix(c, "docker network connect ") {
			j = append(j, c)
		}
	}
	return j
}

const inspectOf = "sh -c out=$(docker container inspect --format '{{index .Config.Labels \"boks.app\"}}|{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "

// A proxy that was just started is not yet a proxy that answers: the deploy asks it for its
// services right away, so Boot returns only once it does — or says it never did.
func TestBootWaitsForAJustStartedProxyToAnswer(t *testing.T) {
	answerPoll = time.Nanosecond
	f := &fake{state: "", silent: 3}
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	asked := 0
	for _, c := range f.calls {
		if c == answer {
			asked++
		}
	}
	if asked != 4 {
		t.Errorf("want three silent tries and one answer, asked %d times: %v", asked, f.calls)
	}
	answerWait = time.Millisecond
	never := &fake{state: "exited", silent: 1 << 30}
	if err := Boot(context.Background(), never, io.Discard, "img"); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("a proxy that never answers must fail Boot, got %v", err)
	}
}

func TestBootRestartsStoppedProxy(t *testing.T) {
	f := &fake{state: "exited"}
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	if started := at(f.calls, "docker start boks-proxy"); started < 0 || at(f.calls, answer) != started+1 {
		t.Errorf("expected docker start, then the wait for an answer, got %v", f.calls)
	}
}

// late is a proxy that answers, but only after delay, and does not notice cancellation.
type late struct{ delay time.Duration }

func (l late) Run(_ context.Context, args ...string) (string, error) {
	switch cmd := strings.Join(args, " "); {
	case strings.HasPrefix(cmd, "docker ps -a"):
		return "exited", nil
	case cmd == answer:
		time.Sleep(l.delay)
	}
	return "", nil
}

func (l late) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return l.Run(ctx, args...)
}

// The wait is bounded as a whole: an answer that comes after the bound is not one.
func TestBootRejectsAnAnswerAfterTheBound(t *testing.T) {
	answerWait, answerPoll = 5*time.Millisecond, time.Millisecond
	if err := Boot(context.Background(), late{delay: 50 * time.Millisecond}, io.Discard, "img"); err == nil {
		t.Fatal("an answer after the bound must fail Boot")
	}
}

// hung is a proxy whose answer never comes; only the caller's context ends the call.
type hung struct{}

func (hung) Run(ctx context.Context, args ...string) (string, error) {
	switch cmd := strings.Join(args, " "); {
	case strings.HasPrefix(cmd, "docker ps -a"):
		return "exited", nil
	case cmd == answer:
		<-ctx.Done()
		return "", ctx.Err()
	}
	return "", nil
}

func (h hung) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return h.Run(ctx, args...)
}

// The bound reaches the call itself: a call that hangs is cancelled, not waited for.
func TestBootCancelsACallThatHangs(t *testing.T) {
	answerWait, answerPoll = 10*time.Millisecond, time.Millisecond
	done := make(chan error, 1)
	go func() { done <- Boot(context.Background(), hung{}, io.Discard, "img") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a proxy that never answers must fail Boot")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Boot is still waiting on a call past its bound")
	}
}

type said string

func (s said) Run(context.Context, ...string) (string, error)          { return string(s), nil }
func (s said) Pipe(context.Context, []byte, ...string) (string, error) { return string(s), nil }

// What kamal-proxy v0.10.0 prints for `list --json`, verbatim in shape: the deploy decides who
// owns a service and which host it holds from these two fields, so their names are pinned here
// rather than taken from the decoder's own struct tags.
func TestServicesReadsKamalProxysList(t *testing.T) {
	out := said(`{
  "demo-web": {
    "hosts": ["demo.example.com"],
    "path_prefixes": ["/"],
    "tls": true,
    "targets": ["demo-v1-1700000000:3000"],
    "read_targets": [],
    "state": "running",
    "rollout": {"enabled": false, "percentage": 0, "allowlist": [], "targets": [], "read_targets": []}
  },
  "bot.api": {
    "hosts": ["api.example.com"],
    "path_prefixes": ["/"],
    "tls": false,
    "targets": ["bot-v2-1700000001:8080"],
    "read_targets": [],
    "state": "running",
    "rollout": {"enabled": false, "percentage": 0, "allowlist": [], "targets": [], "read_targets": []}
  }
}`)
	services, names, err := Services(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, " ") != "bot.api demo-web" {
		t.Errorf("names %v", names)
	}
	web := services["demo-web"]
	if strings.Join(web.Hosts, ",") != "demo.example.com" || strings.Join(web.Targets, ",") != "demo-v1-1700000000:3000" {
		t.Errorf("demo-web read as %+v", web)
	}
}
