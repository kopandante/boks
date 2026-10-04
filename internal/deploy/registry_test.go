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

	"github.com/kopandante/boks/internal/config"
)

const (
	loginCall    = "sh -c exec 9>>/tmp/boks.registry.lock"
	registryInfo = "docker info --format {{json .RegistryConfig}}"
	resolveHost  = "sh -c getent ahosts"
	depotToken   = "depot-secret-token"
	// secureInfo is docker's answer on a server with the default settings: loopback is insecure, and
	// nothing else.
	secureInfo = `{"InsecureRegistryCIDRs":["127.0.0.0/8","::1/128"],"IndexConfigs":{"docker.io":{"Name":"docker.io","Secure":true}}}`
)

// depotPort is onePort with its image on Depot's registry.
var depotPort = strings.Replace(onePort, "image: ghcr.io/x/y",
	"image: registry.depot.dev/p\nregistry: {host: registry.depot.dev, token_env: DEPOT_TOKEN}", 1)

func depotOptions(t *testing.T, cfg *config.Config) Options {
	t.Helper()
	l, err := NewLogin(cfg, func(k string) (string, bool) { return depotToken, k == "DEPOT_TOKEN" })
	if err != nil {
		t.Fatal(err)
	}
	o := fixed
	o.Login = l
	return o
}

func depotFake() *fake {
	f := newFake()
	f.out[registryInfo] = secureInfo
	f.out[resolveHost] = "34.1.2.3"
	return f
}

// The pull of an image on the private registry is one script on the server: the token on its
// stdin and in no command line, the logout armed before the login, and all of it before the proxy is
// booted. The container is started with --pull never, so nothing fetches the image but that script.
func TestDeployPullsLoggedInBeforeTheProxy(t *testing.T) {
	f := depotFake()
	cfg := parse(t, depotPort)
	if err := Run(context.Background(), f, io.Discard, cfg, "v2", depotOptions(t, cfg)); err != nil {
		t.Fatal(err)
	}
	at := f.callAt(loginCall)
	if at < 0 {
		t.Fatalf("no login: %v", f.calls)
	}
	script := f.calls[at]
	if f.stdin[script] != depotToken {
		t.Errorf("the token goes on stdin: %q", f.stdin[script])
	}
	for _, c := range f.calls {
		if strings.Contains(c, depotToken) {
			t.Errorf("the token is in a command line: %s", c)
		}
	}
	lock, trap, login, pull := strings.Index(script, "flock"), strings.Index(script, "trap logout EXIT"),
		strings.Index(script, "docker login 'registry.depot.dev' -u 'x-token' --password-stdin"),
		strings.Index(script, "docker pull 'registry.depot.dev/p:v2' </dev/null")
	if lock < 0 || trap < lock || login < trap || pull < login {
		t.Errorf("want lock, then the logout armed, then login, then pull:\n%s", script)
	}
	if f.has("docker pull") {
		t.Errorf("no pull goes around the login: %v", f.calls)
	}
	if info, boot := f.callAt(registryInfo), f.callAt("docker ps -a --filter name=^boks-proxy$"); info > at || at > boot {
		t.Errorf("want the HTTPS check, then the login, then the proxy boot: %d %d %d", info, at, boot)
	}
	if run := f.calls[f.callAt("docker run -d --name demo-")]; !strings.HasSuffix(run, " --pull never registry.depot.dev/p:v2") {
		t.Errorf("the container must not fetch the image itself: %s", run)
	}
}

// A token the registry refuses stops the deploy before anything on the server changes, the proxy
// included, and says which variable held it.
func TestARefusedLoginChangesNothing(t *testing.T) {
	f := depotFake()
	f.fail[loginCall] = errors.New("sh: exit status 1: Error response from daemon: unauthorized\n" + loginRefused)
	cfg := parse(t, depotPort)
	err := Run(context.Background(), f, io.Discard, cfg, "v2", depotOptions(t, cfg))
	if err == nil || !strings.Contains(err.Error(), "refused the login as x-token with the token in DEPOT_TOKEN") ||
		!strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("want the refused login named, got %v", err)
	}
	if !changedNothing(f) || f.has(admitTake("demo")) {
		t.Errorf("nothing may change: %v", f.calls)
	}
	if !f.has("rmdir /tmp/boks-demo.lock") {
		t.Errorf("the app's lock is given back: %v", f.calls)
	}
}

// Depot takes any token at the login and turns it down at the pull: that too is named as the token,
// and changes nothing.
func TestATokenRefusedAtThePullIsNamed(t *testing.T) {
	f := depotFake()
	f.fail[loginCall] = errors.New("sh: exit status 1: Error response from daemon: unknown: failed to resolve reference " +
		`"registry.depot.dev/p:v2": unexpected status from HEAD request to https://registry.depot.dev/v2/p/manifests/v2: 401 Unauthorized`)
	cfg := parse(t, depotPort)
	err := Run(context.Background(), f, io.Discard, cfg, "v2", depotOptions(t, cfg))
	if err == nil || !strings.Contains(err.Error(), "refused the pull of registry.depot.dev/p:v2 with the token in DEPOT_TOKEN") ||
		!strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("want the token named, got %v", err)
	}
	if !changedNothing(f) || f.has(admitTake("demo")) {
		t.Errorf("nothing may change: %v", f.calls)
	}
	// Any other failure of the pull is said as it is.
	g := depotFake()
	g.fail[loginCall] = errors.New("sh: exit status 1: write /var/lib/docker/x: permission denied")
	if err := Run(context.Background(), g, io.Discard, cfg, "v2", depotOptions(t, cfg)); err == nil ||
		strings.Contains(err.Error(), "token") || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("want the failure as it is, got %v", err)
	}
}

// A registry the server's docker would reach over plain HTTP gets no token: listed by name in
// insecure-registries, resolving into an insecure range, or impossible to check.
func TestAnInsecureRegistryGetsNoToken(t *testing.T) {
	cases := map[string]func(f *fake){
		"listed as insecure": func(f *fake) {
			f.out[registryInfo] = `{"InsecureRegistryCIDRs":[],"IndexConfigs":{"registry.depot.dev":{"Secure":false}}}`
		},
		"in an insecure range": func(f *fake) {
			f.out[registryInfo] = `{"InsecureRegistryCIDRs":["127.0.0.0/8","10.0.0.0/8"],"IndexConfigs":{}}`
			f.out[resolveHost] = "34.1.2.3\n10.1.2.3"
		},
		"docker cannot say": func(f *fake) { f.fail[registryInfo] = errors.New("connection reset") },
		"not resolved":      func(f *fake) { f.out[resolveHost] = "" },
	}
	for name, setup := range cases {
		f := depotFake()
		setup(f)
		cfg := parse(t, depotPort)
		if err := Run(context.Background(), f, io.Discard, cfg, "v2", depotOptions(t, cfg)); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
		if f.has(loginCall) || !changedNothing(f) {
			t.Errorf("%s: no token is sent and nothing changes: %v", name, f.calls)
		}
	}
	// A host given as an address is checked as it is, without a lookup.
	f := depotFake()
	f.out[registryInfo] = `{"InsecureRegistryCIDRs":["10.0.0.0/8"],"IndexConfigs":{}}`
	if err := checkSecure(context.Background(), f, "10.1.2.3:5000"); err == nil || f.has(resolveHost) {
		t.Errorf("an address in the range is refused without a lookup: %v %v", err, f.calls)
	}
}

// A rollback that has to fetch its image fetches it the way a deploy does; a release recorded
// before the image moved to the registry is fetched as it was then, without a login.
func TestRollbackFetchesThroughTheSameLogin(t *testing.T) {
	cfg := parse(t, depotPort)
	depotRelease := strings.Replace(v1Release, `"image":"ghcr.io/x/y"`, `"image":"registry.depot.dev/p"`, 1)
	f := demoReleases(t, `{`+depotRelease+`,"digest":"sha256:old"}`)
	f.out[registryInfo] = secureInfo
	f.out[resolveHost] = "34.1.2.3"
	f.out["sh -c out=$(docker image inspect"] = "absent"
	if err := Rollback(context.Background(), f, io.Discard, cfg, "", depotOptions(t, cfg)); err != nil {
		t.Fatal(err)
	}
	if at := f.callAt(loginCall); at < 0 || !strings.Contains(f.calls[at], "docker pull 'registry.depot.dev/p@sha256:old'") ||
		f.stdin[f.calls[at]] != depotToken {
		t.Errorf("want the pull of the digest through the login: %v", f.calls)
	}
	if run := f.calls[f.callAt("docker run -d")]; !strings.Contains(run, " --pull never ") {
		t.Errorf("the container must not fetch the image itself: %s", run)
	}

	g := demoReleases(t, `{`+v1Release+`,"digest":"sha256:old"}`)
	g.out["sh -c out=$(docker image inspect"] = "absent"
	if err := Rollback(context.Background(), g, io.Discard, cfg, "", depotOptions(t, cfg)); err != nil {
		t.Fatal(err)
	}
	if !g.has("docker pull ghcr.io/x/y@sha256:old") || g.has(loginCall) || g.has(registryInfo) {
		t.Errorf("an image elsewhere is pulled without the login: %v", g.calls)
	}
	if run := g.calls[g.callAt("docker run -d")]; strings.Contains(run, "--pull") {
		t.Errorf("an image elsewhere is run as before: %s", run)
	}
}

// A config without a registry has no login, and a declared token missing from the environment is
// a refusal before the command reaches any server.
func TestNewLogin(t *testing.T) {
	none := func(string) (string, bool) { return "", false }
	if l, err := NewLogin(parse(t, onePort), none); l != nil || err != nil {
		t.Errorf("a public image needs no token: %v %v", l, err)
	}
	_, err := NewLogin(parse(t, depotPort), none)
	if err == nil || !strings.Contains(err.Error(), "DEPOT_TOKEN is not set") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Errorf("want the missing token named: %v", err)
	}
}

// The script itself, run by a real shell against a stand-in docker: the logout runs however the
// pull ends, the token reaches `docker login` on its stdin and nothing else, and the script's
// status is the pull's.
func TestTheLoginScriptLogsOutWhateverHappens(t *testing.T) {
	dir := t.TempDir()
	fakeDocker := `#!/bin/sh
echo "$1" >> "$DIR/log"
case "$1" in
login) cat > "$DIR/login-stdin"; echo "WARNING! stored unencrypted" >&2; [ "$LOGIN" = ok ] || exit 1 ;;
pull) cat > "$DIR/pull-stdin"
  case "$PULL" in fail) exit 3 ;; term) kill -TERM $PPID; sleep 1 ;; esac ;;
logout) [ "$LOGOUT" = ok ] || exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flock"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	l := &Login{Registry: &config.Registry{Host: "registry.depot.dev", User: "x-token", TokenEnv: "T"}, Token: depotToken}
	// Ubuntu's sh is dash, whose traps differ from bash's in the details this script leans on.
	shells := []string{"sh"}
	if _, err := exec.LookPath("dash"); err == nil {
		shells = append(shells, "dash")
	}
	for _, shell := range shells {
		t.Run(shell, func(t *testing.T) { runLoginScript(t, shell, dir, l) })
	}
}

func runLoginScript(t *testing.T, shell, dir string, l *Login) {
	for _, c := range []struct {
		login, pull, logout string
		status              int
		log                 string
	}{
		{"ok", "ok", "ok", 0, "login pull logout"},
		{"no", "ok", "ok", 1, "login logout"},
		{"ok", "fail", "ok", 3, "login pull logout"},
		{"ok", "term", "ok", 143, "login pull logout"},
		// A logout that fails fails the script, and a failed pull keeps its own status.
		{"ok", "ok", "fail", 1, "login pull logout"},
		{"ok", "fail", "fail", 3, "login pull logout"},
	} {
		os.Remove(filepath.Join(dir, "log"))
		os.Remove(filepath.Join(dir, "pull-stdin"))
		cmd := exec.Command(shell, "-c", loginPull(l, "registry.depot.dev/p:v1"))
		cmd.Stdin = bytes.NewReader([]byte(l.Token))
		cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "DIR=" + dir, "LOGIN=" + c.login, "PULL=" + c.pull, "LOGOUT=" + c.logout}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		_ = cmd.Run()
		if got := cmd.ProcessState.ExitCode(); got != c.status {
			t.Errorf("login %s, pull %s, logout %s: exit %d, want %d (%s)", c.login, c.pull, c.logout, got, c.status, stderr.String())
		}
		if c.logout != "ok" && !strings.Contains(stderr.String(), "docker logout registry.depot.dev failed") {
			t.Errorf("a failed logout is said: %q", stderr.String())
		}
		log, _ := os.ReadFile(filepath.Join(dir, "log"))
		if got := strings.Join(strings.Fields(string(log)), " "); got != c.log {
			t.Errorf("login %s, pull %s: docker ran %q, want %q", c.login, c.pull, got, c.log)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "login-stdin")); string(got) != depotToken {
			t.Errorf("login %s, pull %s: login read %q from stdin", c.login, c.pull, got)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "pull-stdin")); len(got) != 0 {
			t.Errorf("login %s, pull %s: the pull read %q from stdin", c.login, c.pull, got)
		}
		if c.login != "ok" && (!strings.Contains(stderr.String(), loginRefused) || !strings.Contains(stderr.String(), "WARNING")) {
			t.Errorf("a refused login is said as such, with what docker said: %q", stderr.String())
		}
		if c.login == "ok" && strings.Contains(stderr.String(), "WARNING") {
			t.Errorf("what a successful login says is not passed on: %q", stderr.String())
		}
	}
}
