package main

import (
	"context"
	"io"
	"strings"
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

// noNetwork is the check of the app's network, answered as docker does for one not made yet.
const noNetwork = "sh -c out=$(docker network inspect"

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
		noNetwork:                           "absent",
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
	a := &recorder{server: server{"docker inspect --type image": "[]", "docker image inspect": `["CMD","true"]`, "docker inspect --format": "healthy", noNetwork: "absent"}}
	b := &recorder{server: server{"docker inspect --type image": "[]", "docker image inspect": `["CMD","true"]`, "docker inspect --format": "healthy", noNetwork: "absent"}}
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

// `boks proxy boot` changes what every app on the server shares — the proxy and its networks — so it
// takes the server's admission lock around the boot, under a holder no deploy mistakes for its own.
func TestProxyBootTakesTheAdmissionLock(t *testing.T) {
	a := &recorder{server: server{"docker ps -a --filter name=^boks-proxy$": "running", "docker exec boks-proxy kamal-proxy list --json": "{}"}}
	fleet(t, map[string]*recorder{"a": a}, time.Now)
	if err := dispatch(context.Background(), parseConfig(t, "app: bot\nimage: x\nservers: [a]\n"), []string{"proxy", "boot"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	took, booted, gave := -1, -1, -1
	for i, c := range a.calls {
		switch {
		case strings.HasPrefix(c, "ln -sn _proxy.") && took < 0:
			took = i
		case strings.HasPrefix(c, "docker ps -a --filter name=^boks-proxy$") && booted < 0:
			booted = i
		case strings.HasPrefix(c, "sh -c [ \"$(readlink /tmp/boks.admit.lock)\" = '_proxy."):
			gave = i
		}
	}
	if took < 0 || booted < took || gave < booted {
		t.Errorf("want the lock taken, the proxy booted, the lock given back: %d %d %d %v", took, booted, gave, a.calls)
	}
}

// A token the config declares and the environment lacks refuses deploy and rollback before any
// server is reached (E6): not one command runs, not even the lock.
func TestAMissingRegistryTokenReachesNoServer(t *testing.T) {
	a, b := &recorder{server: server{}}, &recorder{server: server{}}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	lookup0 := lookupEnv
	lookupEnv = func(string) (string, bool) { return "", false }
	t.Cleanup(func() { lookupEnv = lookup0 })
	cfg := parseConfig(t, "app: bot\nimage: registry.depot.dev/p\nservers: [a, b]\n"+
		"registry: {host: registry.depot.dev, token_env: DEPOT_TOKEN}\n")
	for _, args := range [][]string{{"deploy", "v2"}, {"rollback"}} {
		err := dispatch(context.Background(), cfg, args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "DEPOT_TOKEN is not set") {
			t.Errorf("%v: want the missing token named, got %v", args, err)
		}
	}
	if len(a.calls)+len(b.calls) != 0 {
		t.Errorf("no server is reached: %v %v", a.calls, b.calls)
	}
}
