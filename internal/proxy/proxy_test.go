package proxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type fake struct {
	calls  []string
	state  string            // the proxy's Docker state and boks.proxy label, as `docker ps` prints them
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
		return "", errors.New("wget: can't connect to remote host: Connection refused")
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
	switch {
	case cmd == sysctl:
		return "1", nil
	case strings.HasPrefix(cmd, "sh -c if [ -f "):
		return "present\n{}", nil // an applied config is there
	case strings.HasPrefix(cmd, "sh -c cd "):
		return "/home/u/.boks/_proxy", nil
	}
	return "", nil
}

const (
	answer     = "docker exec boks-proxy wget -q -O /dev/null http://127.0.0.1:2019/config/"
	sysctl     = "docker exec boks-proxy cat /proc/sys/net/ipv4/tcp_migrate_req"
	fragments  = "sh -c for f in "
	networksOf = "docker container ls -a --filter name=^boks-proxy$ --format {{.Networks}}"
	running    = "running\tcaddy"
)

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
	f := &fake{state: running}
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker create") || strings.HasPrefix(c, "docker start") {
			t.Errorf("running proxy must not be touched, got %s", c)
		}
	}
}

// A missing proxy is created, put on its routes' networks, started, and only then waited for: the
// names its routes dial resolve from its first request.
func TestBootStartsMissingProxy(t *testing.T) {
	f := &fake{state: "", out: routes()}
	f.out[networksOf] = "boks"
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	created, joined, started := at(f.calls, "docker create --name boks-proxy "), at(f.calls, "docker network connect boks-a"), at(f.calls, "docker start boks-proxy")
	answered, checked := at(f.calls, answer), at(f.calls, sysctl)
	if created < 0 || joined < created || started < joined || answered != started+1 || checked < answered {
		t.Errorf("want create < join < start < answer < sysctl check: %d %d %d %d %d %v", created, joined, started, answered, checked, f.calls)
	}
	if !strings.Contains(f.calls[created], " img caddy run --config /etc/boks/caddy.json") ||
		!strings.Contains(f.calls[created], "/home/u/.boks/_proxy:/etc/boks:ro") {
		t.Errorf("want the image run with the resolved state directory: %s", f.calls[created])
	}
}

// A server that never had a proxy has no config for Caddy to load: one is assembled from the
// fragments — none — before the container is created.
func TestANewProxyGetsAConfigToLoad(t *testing.T) {
	f := &fake{state: "", out: map[string]string{"sh -c if [ -f ": "absent"}}
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	if at(f.calls, "sh -c umask 077") < 0 || at(f.calls, "sh -c umask 077") > at(f.calls, "docker create") {
		t.Errorf("want the config written before the container is created: %v", f.calls)
	}
	empty, _ := Config(nil)
	g := &fake{state: "", out: map[string]string{"sh -c if [ -f ": "present\n" + strings.TrimSuffix(string(empty), "\n")}}
	if err := Boot(context.Background(), g, io.Discard, "img"); err != nil || at(g.calls, "sh -c umask 077") >= 0 {
		t.Errorf("an applied config that is what the fragments make is kept as it is: %v %v", err, g.calls)
	}
	// One a cut run left behind the fragments is replaced before Caddy loads it.
	h := &fake{state: ""}
	if err := Boot(context.Background(), h, io.Discard, "img"); err != nil || at(h.calls, "sh -c umask 077") < 0 ||
		at(h.calls, "sh -c umask 077") > at(h.calls, "docker start") {
		t.Errorf("want the lagging applied config replaced before the start: %v %v", err, h.calls)
	}
}

// A running proxy whose applied config lags the fragments — a run cut after writing its fragment — is
// reloaded with what the fragments make; one that does not lag is left alone.
func TestBootCatchesARunningProxyUp(t *testing.T) {
	f := &fake{state: "running\tcaddy"}
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	if at(f.calls, "docker exec boks-proxy caddy reload --config /etc/boks/caddy.next.json") < 0 {
		t.Errorf("want a reload with the assembled config: %v", f.calls)
	}
	empty, _ := Config(nil)
	g := &fake{state: "running\tcaddy", out: map[string]string{"sh -c if [ -f ": "present\n" + strings.TrimSuffix(string(empty), "\n")}}
	if err := Boot(context.Background(), g, io.Discard, "img"); err != nil || at(g.calls, "docker exec boks-proxy caddy reload") >= 0 {
		t.Errorf("want no reload of a proxy that runs what the fragments make: %v %v", err, g.calls)
	}
	// A catch-up Caddy refuses is a warning, not a failed boot: `boks cert`, which boots first, is what
	// repairs a certificate file a cut run left broken.
	h := &fake{state: "running\tcaddy", fail: map[string]error{"docker exec boks-proxy caddy reload": errors.New("loading new config: tls: failed to find any PEM data in key input")}}
	var log strings.Builder
	if err := Boot(context.Background(), h, &log, "img"); err != nil || !strings.Contains(log.String(), "warning: the proxy runs an older config") {
		t.Errorf("want a warning and a boot: %v %q", err, log.String())
	}
}

// A boks-proxy that is not labelled as Caddy is the kamal-proxy an earlier boks ran: no boot touches
// it, and the refusal names the migration.
func TestBootRefusesKamalProxy(t *testing.T) {
	for _, state := range []string{"running", "running\t", "exited"} {
		f := &fake{state: state}
		err := Boot(context.Background(), f, io.Discard, "img")
		if err == nil || !strings.Contains(err.Error(), "boks proxy migrate") || at(f.calls, "docker start") >= 0 || at(f.calls, "docker create") >= 0 {
			t.Errorf("%q: want the migration named and nothing touched, got %v %v", state, err, f.calls)
		}
	}
}

// Without tcp_migrate_req every reload resets the connections queued on the closing listener
// (measured on boks-lab), and every deploy reloads: a proxy without it is refused, running or just
// started; a kernel that cannot start it with the sysctl is named.
func TestBootRefusesAProxyWithoutMigrateReq(t *testing.T) {
	for _, state := range []string{running, "exited\tcaddy"} {
		f := &fake{state: state, out: map[string]string{sysctl: "0"}}
		if err := Boot(context.Background(), f, io.Discard, "img"); err == nil || !strings.Contains(err.Error(), "tcp_migrate_req=0") {
			t.Errorf("%q: want the sysctl refused, got %v", state, err)
		}
	}
	g := &fake{state: "exited\tcaddy", fail: map[string]error{"docker start": errors.New("sysctl net.ipv4.tcp_migrate_req: invalid argument")}}
	if err := Boot(context.Background(), g, io.Discard, "img"); err == nil || !strings.Contains(err.Error(), "Linux 5.14") {
		t.Errorf("want the kernel named, got %v", err)
	}
}

// A proxy created anew keeps its routes in Dir but none of its networks: it joins those of the
// containers its routes dial — an app's own network, the network apps shared before — once each.
func TestANewProxyJoinsTheNetworksItsRoutesNeed(t *testing.T) {
	f := &fake{state: running, out: routes()}
	f.out[networksOf] = "boks" // where a new proxy is started
	if err := Boot(context.Background(), f, io.Discard, "img"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(joins(f.calls), "\n"); got != "docker network connect boks-a boks-proxy\ndocker network connect boks-test boks-proxy" {
		t.Errorf("want each target's network joined once, and not its own: %v", f.calls)
	}
	// A target that uses other apps is on their networks too; the proxy joins only its app's own.
	u := &fake{state: running, out: routes()}
	u.out[inspectOf+"'a-v1-1'"] = "a|boks-a boks-cache boks-convex"
	if err := Boot(context.Background(), u, io.Discard, "img"); err != nil || at(u.calls, "docker network connect boks-cache") >= 0 ||
		at(u.calls, "docker network connect boks-convex") >= 0 || at(u.calls, "docker network connect boks-a") < 0 {
		t.Errorf("want only boks-a joined for a, not the networks it uses: %v %v", err, u.calls)
	}
	// A proxy started by an earlier boks on the shared network is not on boks: a route to a container
	// there makes it join.
	v := &fake{state: running, out: routes()}
	v.out[networksOf] = "boks-test,boks-a"
	if err := Boot(context.Background(), v, io.Discard, "img"); err != nil || at(v.calls, "docker network connect boks boks-proxy") < 0 {
		t.Errorf("want boks joined for b: %v %v", err, v.calls)
	}
	// A proxy on every network its routes need joins none again.
	g := &fake{state: running, out: routes()}
	g.out[networksOf] = "boks,boks-a,boks-test"
	if err := Boot(context.Background(), g, io.Discard, "img"); err != nil || len(joins(g.calls)) != 0 {
		t.Errorf("the proxy is on its routes' networks already: %v %v", err, g.calls)
	}
	// A boot cut short after creating the proxy is finished by the next one, which finds it running.
	k := &fake{state: running, out: routes()}
	k.out[networksOf] = "boks"
	if err := Boot(context.Background(), k, io.Discard, "img"); err != nil || len(joins(k.calls)) != 2 || at(k.calls, "docker create") >= 0 {
		t.Errorf("a running proxy missing its routes' networks joins them: %v %v", err, k.calls)
	}
}

// A route to a container that is gone costs a warning: its app's deploy repairs it. Any other
// failure — a target whose networks cannot be read, a join that fails, the routes or the proxy's own
// networks unread — fails the boot, which would otherwise report a proxy that cannot reach a running
// app as booted.
func TestTheProxyBootFailsOnARouteItCannotReach(t *testing.T) {
	gone := &fake{state: running, out: routes()}
	gone.out[inspectOf+"'a-v1-1'"] = "<gone>"
	var log strings.Builder
	if err := Boot(context.Background(), gone, &log, "img"); err != nil || !strings.Contains(log.String(), "a-v1-1, which is gone") ||
		at(gone.calls, "docker network connect boks-test") < 0 {
		t.Errorf("a gone target is a warning, the others still joined: %v %q %v", err, log.String(), gone.calls)
	}
	for name, fail := range map[string]map[string]error{
		"a target unread": {inspectOf + "'a-v1-1'": errors.New("connection reset")},
		"a join":          {"docker network connect boks-test": errors.New("network not found")},
		"the routes":      {fragments: errors.New("connection reset")},
		"its networks":    {networksOf: errors.New("connection reset")},
	} {
		f := &fake{state: running, out: routes(), fail: fail}
		if err := Boot(context.Background(), f, io.Discard, "img"); err == nil {
			t.Errorf("%s: want the boot to fail: %v", name, f.calls)
		}
	}
}

// routes is a proxy holding routes to a-v1-1 (app a, on boks-a, through two ports) and b-v1-1 (started
// by an earlier boks, unlabelled, on the shared boks-test and on boks).
func routes() map[string]string {
	return map[string]string{
		fragments: `{"app":"a","routes":[{"host":"a.example.com","dial":"a-v1-1:3000"},{"host":"api.example.com","dial":"a-v1-1:3001"}]}` + "\n" +
			`{"app":"b","routes":[{"host":"b.example.com","dial":"b-v1-1:80"}]}`,
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

// A proxy that was just started is not yet a proxy that answers: the deploy asks it to probe the new
// copy right away, so Boot returns only once it does — or says it never did.
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
	never := &fake{state: "exited\tcaddy", silent: 1 << 30}
	if err := Boot(context.Background(), never, io.Discard, "img"); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("a proxy that never answers must fail Boot, got %v", err)
	}
}

func TestBootRestartsStoppedProxy(t *testing.T) {
	f := &fake{state: "exited\tcaddy"}
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
		return "exited\tcaddy", nil
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
		return "exited\tcaddy", nil
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

// A health check is asked from inside the proxy, by the name and port the route will dial, with a
// bound of its own.
func TestProbe(t *testing.T) {
	const cmd = "docker exec boks-proxy sh -c wget -S -q -O /dev/null -T 5 'http://demo-v2-1:3000/up' 2>&1; true"
	f := &fake{out: map[string]string{cmd: "  HTTP/1.1 200 OK\n  Content-Length: 2"}}
	if err := Probe(context.Background(), f, "demo-v2-1", 3000, "/up"); err != nil {
		t.Fatal(err)
	}
	if at(f.calls, cmd) < 0 {
		t.Errorf("want the probe from the proxy: %v", f.calls)
	}
	// The final status decides, as kamal-proxy's check did: any 2xx after redirects passes, anything
	// else fails — whatever busybox wget's exit status says (what it prints was measured).
	for out, ok := range map[string]bool{
		"  HTTP/1.1 207 Multi-Status\nwget: server returned error: HTTP/1.1 207 Multi-Status": true,
		"  HTTP/1.1 302 Found\n  Content-Length: 0":                                           false,
		"  HTTP/1.1 301 Moved\n  Location: /health\n  HTTP/1.1 204 No Content":                true,
		"  HTTP/1.1 503 Service Unavailable\nwget: server returned error: HTTP/1.1 503":       false,
		"wget: can't connect to remote host: Connection refused":                              false,
	} {
		g := &fake{out: map[string]string{cmd: out}}
		if err := Probe(context.Background(), g, "demo-v2-1", 3000, "/up"); (err == nil) != ok {
			t.Errorf("%q: want pass=%v, got %v", out, ok, err)
		}
	}
}

// Busy counts the requests in flight to the containers asked about, on every port, in the shape Caddy
// 2.11.7 answers /reverse_proxy/upstreams (measured on boks-lab); others are not counted.
func TestBusy(t *testing.T) {
	f := &fake{out: map[string]string{"docker exec boks-proxy wget -q -O - http://127.0.0.1:2019/reverse_proxy/upstreams": `[{"address":"demo-v1-1:3000","num_requests":2,"fails":0},` +
		`{"address":"demo-v1-1:3001","num_requests":1,"fails":0},{"address":"other-v1-1:80","num_requests":7,"fails":0}]`}}
	n, err := Busy(context.Background(), f, []string{"demo-v1-1"})
	if err != nil || n != 3 {
		t.Errorf("want 3 in flight, got %d %v", n, err)
	}
	if _, err := Busy(context.Background(), &fake{}, []string{"x"}); err == nil {
		t.Error("an answer that is no list must not read as nothing in flight")
	}
}
