package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	stdin []string // what each piped command was given, in order
}

func (r *recorder) Run(ctx context.Context, args ...string) (string, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	return r.server.Run(ctx, args...)
}

func (r *recorder) Pipe(ctx context.Context, stdin []byte, args ...string) (string, error) {
	r.stdin = append(r.stdin, string(stdin))
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

// A release whose files are gone on the second server stops the rollback before the first one changes.
func TestRollbackRefusesWhenAServerLacksTheReleasesFiles(t *testing.T) {
	const v2 = `{"version":6,"id":"bot-v2-2","app":"bot","image":"ghcr.io/x/bot","tag":"v2","ports":[],"networks":[{"name":"boks-bot","aliases":["bot"]}],"files":[{"name":"0-site.conf","target":"/etc/site.conf"}]}`
	a, b := botServer("bot-v3-3", "bot-v2-2"), botServer("bot-v3-3", "bot-v2-2")
	a.server["cat .boks/bot/releases/bot-v2-2"], b.server["cat .boks/bot/releases/bot-v2-2"] = v2, v2
	a.server["sh -c for f in"], b.server["sh -c for f in"] = "present", ".boks/bot/files/bot-v2-2/0-site.conf"
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	err := dispatch(context.Background(), parseConfig(t, twoServers), []string{"rollback"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no server was rolled back") || !strings.Contains(err.Error(), "0-site.conf") {
		t.Fatalf("want a refusal naming the missing file before anything changed, got %v", err)
	}
	if a.ran("mkdir") || a.ran("docker") {
		t.Errorf("server a must be left alone: %v", a.calls)
	}
}

// The files are read from beside boks.yml and go to every server; one that cannot be read refuses
// the deploy before any server is reached.
func TestDeployCarriesTheFilesOfTheConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "site.conf"), []byte("server {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	newServer := func() *recorder {
		return &recorder{server: server{"docker inspect --type image": "[]", "docker image inspect": `["CMD","true"]`,
			"docker inspect --format": "healthy", noNetwork: "absent", "sh -c cd": "/home/u/.boks/bot/files/x"}}
	}
	a, b := newServer(), newServer()
	fleet(t, map[string]*recorder{"a": a, "b": b}, func() time.Time { return time.Unix(1600000000, 0) })
	cfg := parseConfig(t, twoServers+"files: [site.conf:/etc/site.conf]\n")
	cfg.Dir = dir
	if err := dispatch(context.Background(), cfg, []string{"deploy", "v4"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*recorder{"a": a, "b": b} {
		if !slices.Contains(s.stdin, "server {}") || !s.ran("docker run -d --name bot-v4-1600000000 ") {
			t.Errorf("server %s must get the file and start the release: %v", name, s.calls)
		}
	}

	c := newServer()
	fleet(t, map[string]*recorder{"a": c, "b": c}, time.Now)
	cfg.Files = []string{"missing.conf:/etc/site.conf"}
	if err := dispatch(context.Background(), cfg, []string{"deploy", "v5"}, io.Discard); err == nil || !strings.Contains(err.Error(), "missing.conf") {
		t.Fatalf("want a refusal naming the file, got %v", err)
	}
	if len(c.calls) != 0 {
		t.Errorf("no server may be reached before the files are read: %v", c.calls)
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

// The token the environment holds is what deploy and rollback hand to the login on the server:
// through dispatch, not only through a test that builds the options itself.
func TestTheRegistryTokenReachesTheLogin(t *testing.T) {
	const login = "sh -c conf=${DOCKER_CONFIG:-$HOME/.docker}"
	registry := map[string]string{
		"docker info --format":             `{"InsecureRegistryCIDRs":["127.0.0.0/8"],"IndexConfigs":{}}`,
		"getent ahosts":                    "34.1.2.3 STREAM registry.depot.dev",
		"sh -c out=$(docker image inspect": "absent",
	}
	a := botServer("bot-v2-2", "bot-v1-1")
	for k, v := range registry {
		a.server[k] = v
	}
	a.server["cat .boks/bot/releases/bot-v1-1"] = `{"id":"bot-v1-1","app":"bot","image":"registry.depot.dev/p","tag":"v1","ports":[]}`
	fleet(t, map[string]*recorder{"a": a}, func() time.Time { return time.Unix(1700000000, 0) })
	lookup0 := lookupEnv
	lookupEnv = func(k string) (string, bool) { return "tok", k == "DEPOT_TOKEN" }
	t.Cleanup(func() { lookupEnv = lookup0 })
	cfg := parseConfig(t, "app: bot\nimage: registry.depot.dev/p\nservers: [a]\ndeploy_timeout: 2s\n"+
		"registry: {host: registry.depot.dev, token_env: DEPOT_TOKEN}\n")
	for _, args := range [][]string{{"deploy", "v2"}, {"rollback"}} {
		a.calls, a.stdin = nil, nil
		_ = dispatch(context.Background(), cfg, args, io.Discard) // how the rest of the run goes is not the question
		if !slices.Contains(a.stdin, "tok") || !a.ran(login) {
			t.Errorf("%v: the token must reach the login script: %q %v", args, a.stdin, a.calls)
		}
		if a.ran("docker pull") {
			t.Errorf("%v: no pull goes around the login: %v", args, a.calls)
		}
	}
}

// The environment is read once, before any server is reached: an env_file that is not there
// refuses the deploy with every server untouched, not after the first one was deployed.
func TestAMissingEnvFileReachesNoServer(t *testing.T) {
	a, b := &recorder{server: server{}}, &recorder{server: server{}}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	cfg := parseConfig(t, twoServers+"env_file: missing.env\n")
	cfg.Dir = t.TempDir()
	if err := dispatch(context.Background(), cfg, []string{"deploy", "v2"}, io.Discard); err == nil || !strings.Contains(err.Error(), "missing.env") {
		t.Errorf("want the missing env file named, got %v", err)
	}
	if len(a.calls)+len(b.calls) != 0 {
		t.Errorf("no server is reached: %v %v", a.calls, b.calls)
	}
}
