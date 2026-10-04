package main

import (
	"context"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// recorder is a server that also remembers what it was asked to run.
type recorder struct {
	server
	calls []string
}

func (r *recorder) Run(ctx context.Context, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	return r.server.Run(ctx, args...)
}

func (r *recorder) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return r.Run(ctx, args...)
}

func (r *recorder) ran(prefix string) bool {
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// fleet points the command at fake servers by host and fixes the clock, for the test's duration.
func fleet(t *testing.T, servers map[string]*recorder, clock func() time.Time) {
	t.Helper()
	connect0, now0 := connect, now
	connect = func(host string) remote.Runner { return servers[host] }
	now = clock
	t.Cleanup(func() { connect, now = connect0, now0 })
}

const twoServers = `
app: bot
image: ghcr.io/x/bot
servers: [a, b]
deploy_timeout: 2s
`

func botServer(current, previous string) *recorder {
	s := server{
		"sh -c ls -1":                       "bot-v1-1.json\nbot-v2-2.json\nbot-v3-3.json\n",
		"sh -c cat '.boks/bot/current'":     current + "\n",
		"cat .boks/bot/releases/" + current: `{"id":"` + current + `","previous":"` + previous + `"}`,
		"cat .boks/bot/releases/bot-v1-1":   `{"id":"bot-v1-1","app":"bot","image":"ghcr.io/x/bot","tag":"v1","ports":[]}`,
		"cat .boks/bot/releases/bot-v2-2":   `{"id":"bot-v2-2","app":"bot","image":"ghcr.io/x/bot","tag":"v2","ports":[]}`,
	}
	return &recorder{server: s}
}

func parseConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// After a deploy that reached only server a, a plain rollback would take a back to v2 and the
// healthy b back to v1. Every server is asked first, and nothing is touched on either.
func TestRollbackRefusesWhenServersWouldDiverge(t *testing.T) {
	a, b := botServer("bot-v3-3", "bot-v2-2"), botServer("bot-v2-2", "bot-v1-1")
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	err := dispatch(context.Background(), parseConfig(t, twoServers), []string{"rollback"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "different releases") {
		t.Fatalf("want a refusal naming the divergence, got %v", err)
	}
	for name, s := range map[string]*recorder{"a": a, "b": b} {
		if s.ran("mkdir") || s.ran("docker") {
			t.Errorf("server %s must be left alone: %v", name, s.calls)
		}
	}
}

// A release missing on the second server stops the rollback before the first one changes.
func TestRollbackRefusesWhenAServerLacksTheRelease(t *testing.T) {
	a, b := botServer("bot-v3-3", "bot-v2-2"), botServer("bot-v3-3", "bot-v2-2")
	delete(b.server, "cat .boks/bot/releases/bot-v1-1")
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	err := dispatch(context.Background(), parseConfig(t, twoServers), []string{"rollback", "bot-v1-1"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no server was rolled back") {
		t.Fatalf("want a refusal before anything changed, got %v", err)
	}
	if a.ran("mkdir") || a.ran("docker") {
		t.Errorf("server a must be left alone: %v", a.calls)
	}
}

// One deploy is one release id on every server, however long the first server takes: the clock
// moves on between them, the stamp does not.
func TestDeployNamesTheReleaseOnceForAllServers(t *testing.T) {
	a := &recorder{server: server{"docker inspect --type image": "[]", "docker image inspect": `["CMD","true"]`, "docker inspect --format": "healthy"}}
	b := &recorder{server: server{"docker inspect --type image": "[]", "docker image inspect": `["CMD","true"]`, "docker inspect --format": "healthy"}}
	tick := time.Unix(1600000000, 0)
	fleet(t, map[string]*recorder{"a": a, "b": b}, func() time.Time { tick = tick.Add(5 * time.Second); return tick })
	if err := dispatch(context.Background(), parseConfig(t, twoServers), []string{"deploy", "v4"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*recorder{"a": a, "b": b} {
		if !s.ran("docker run -d --name bot-v4-1600000005 ") {
			t.Errorf("server %s: want the release named by the command's one stamp: %v", name, s.calls)
		}
	}
}

// The first interrupt cancels the run's context — so its cleanup runs — instead of killing it.
func TestAnInterruptCancelsTheRun(t *testing.T) {
	ctx, stop := interruptible(context.Background())
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the interrupt did not cancel the context")
	}
}
