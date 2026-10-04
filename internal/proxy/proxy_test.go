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
	silent int // how many times a just-started proxy does not answer yet
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
	return "", nil
}

const answer = "docker exec boks-proxy kamal-proxy list"

func (f *fake) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return f.Run(ctx, args...)
}

func TestBootIdempotent(t *testing.T) {
	f := &fake{state: "running"}
	if err := Boot(context.Background(), f, io.Discard, "boks", "img"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker run") || strings.HasPrefix(c, "docker start") {
			t.Errorf("running proxy must not be touched, got %s", c)
		}
	}
}

func TestBootStartsMissingProxy(t *testing.T) {
	f := &fake{state: ""}
	if err := Boot(context.Background(), f, io.Discard, "boks", "img"); err != nil {
		t.Fatal(err)
	}
	started := f.calls[len(f.calls)-2]
	if !strings.HasPrefix(started, "docker run -d --name boks-proxy") || !strings.HasSuffix(started, " img") {
		t.Errorf("expected docker run, got %s", started)
	}
	if f.calls[len(f.calls)-1] != answer {
		t.Errorf("Boot must wait for the proxy to answer: %v", f.calls)
	}
}

// A proxy that was just started is not yet a proxy that answers: the deploy asks it for its
// services right away, so Boot returns only once it does — or says it never did.
func TestBootWaitsForAJustStartedProxyToAnswer(t *testing.T) {
	answerPoll = time.Nanosecond
	f := &fake{state: "", silent: 3}
	if err := Boot(context.Background(), f, io.Discard, "boks", "img"); err != nil {
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
	if err := Boot(context.Background(), never, io.Discard, "boks", "img"); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("a proxy that never answers must fail Boot, got %v", err)
	}
}

func TestBootRestartsStoppedProxy(t *testing.T) {
	f := &fake{state: "exited"}
	if err := Boot(context.Background(), f, io.Discard, "boks", "img"); err != nil {
		t.Fatal(err)
	}
	if f.calls[len(f.calls)-2] != "docker start boks-proxy" || f.calls[len(f.calls)-1] != answer {
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
	if err := Boot(context.Background(), late{delay: 50 * time.Millisecond}, io.Discard, "boks", "img"); err == nil {
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
	go func() { done <- Boot(context.Background(), hung{}, io.Discard, "boks", "img") }()
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
