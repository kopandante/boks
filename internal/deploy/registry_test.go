package deploy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
)

const (
	loginCall    = "sh -c conf=${DOCKER_CONFIG:-$HOME/.docker}"
	registryInfo = "docker info --format {{json .RegistryConfig}}"
	resolveHost  = "getent ahosts registry.depot.dev"
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
	f.out[resolveHost] = "34.1.2.3        STREAM registry.depot.dev\n34.1.2.3        DGRAM"
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
			f.out[resolveHost] = "34.1.2.3        STREAM registry.depot.dev\n10.1.2.3        STREAM"
		},
		"docker cannot say": func(f *fake) { f.fail[registryInfo] = errors.New("connection reset") },
		"not resolved":      func(f *fake) { f.fail[resolveHost] = errors.New("getent: exit status 2: ") },
		"no address":        func(f *fake) { f.out[resolveHost] = "" },
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
	f.out[resolveHost] = "34.1.2.3        STREAM registry.depot.dev\n34.1.2.3        DGRAM"
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
echo "$*" >> "$DIR/log"
case "$1" in
login) cat > "$DIR/login-stdin"; echo "WARNING! stored unencrypted" >&2; [ "$LOGIN" = ok ] || exit 1 ;;
pull) cat > "$DIR/pull-stdin"
  case "$PULL" in fail) exit 3 ;; term) kill -TERM $PPID; sleep 1 ;; hang) echo $$ > "$DIR/pull-pid"; exec sleep 30 ;; esac ;;
logout) [ "$LOGOUT" = ok ] || exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flock"), []byte("#!/bin/sh\necho \"$*\" > \"$DIR/flock-args\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	l := &Login{Registry: &config.Registry{Host: "registry.depot.dev", User: "x-token", TokenEnv: "T"}, Token: depotToken}
	// Ubuntu's sh is dash, whose traps differ from bash's in the details this script leans on.
	shells := []string{"sh"}
	if _, err := exec.LookPath("dash"); err == nil {
		shells = append(shells, "dash")
	}
	for _, shell := range shells {
		t.Run(shell, func(t *testing.T) {
			runLoginScript(t, shell, dir, l)
			runLoginScriptCut(t, shell, dir, l)
			runLoginScriptTerm(t, shell, dir, l)
		})
	}
}

const (
	wantLogin  = "login registry.depot.dev -u x-token --password-stdin"
	wantPull   = "pull registry.depot.dev/p:v1"
	wantLogout = "logout registry.depot.dev"
)

func loginScript(shell, dir string, l *Login, login, pull, logout string) *exec.Cmd {
	os.Remove(filepath.Join(dir, "log"))
	os.Remove(filepath.Join(dir, "pull-stdin"))
	os.Remove(filepath.Join(dir, "flock-args"))
	os.Remove(filepath.Join(dir, "pull-pid"))
	cmd := exec.Command(shell, "-c", loginPull(l, "registry.depot.dev/p:v1"))
	cmd.Stdin = bytes.NewReader([]byte(l.Token))
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "HOME=" + dir, "DIR=" + dir, "LOGIN=" + login, "PULL=" + pull, "LOGOUT=" + logout}
	return cmd
}

// dockerRan is what the stand-in docker was asked, one command per element.
func dockerRan(dir string) []string {
	log, _ := os.ReadFile(filepath.Join(dir, "log"))
	return strings.Split(strings.TrimSpace(string(log)), "\n")
}

func runLoginScript(t *testing.T, shell, dir string, l *Login) {
	for _, c := range []struct {
		login, pull, logout string
		status              int
		ran                 []string
	}{
		{"ok", "ok", "ok", 0, []string{wantLogin, wantPull, wantLogout}},
		{"no", "ok", "ok", 1, []string{wantLogin, wantLogout}},
		{"ok", "fail", "ok", 3, []string{wantLogin, wantPull, wantLogout}},
		{"ok", "term", "ok", 143, []string{wantLogin, wantPull, wantLogout}},
		// A logout that fails fails the script, and a failed pull keeps its own status.
		{"ok", "ok", "fail", 1, []string{wantLogin, wantPull, wantLogout}},
		{"ok", "fail", "fail", 3, []string{wantLogin, wantPull, wantLogout}},
	} {
		cmd := loginScript(shell, dir, l, c.login, c.pull, c.logout)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		_ = cmd.Run()
		name := "login " + c.login + ", pull " + c.pull + ", logout " + c.logout
		if got := cmd.ProcessState.ExitCode(); got != c.status {
			t.Errorf("%s: exit %d, want %d (%s)", name, got, c.status, stderr.String())
		}
		if c.logout != "ok" && !strings.Contains(stderr.String(), "docker logout registry.depot.dev failed") {
			t.Errorf("%s: a failed logout is said: %q", name, stderr.String())
		}
		if got := dockerRan(dir); strings.Join(got, "|") != strings.Join(c.ran, "|") {
			t.Errorf("%s: docker ran %q, want %q", name, got, c.ran)
		}
		// Waiting, and for long enough to outlast another pull: an flock without -w, or with -u,
		// would not serialize anything.
		if got, _ := os.ReadFile(filepath.Join(dir, "flock-args")); strings.TrimSpace(string(got)) != "-w 600 9" {
			t.Errorf("%s: flock ran with %q", name, got)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "login-stdin")); string(got) != depotToken {
			t.Errorf("%s: login read %q from stdin", name, got)
		}
		// The lock is the docker config's, beside the credentials it guards.
		if _, err := os.Stat(filepath.Join(dir, ".docker", registryLock)); err != nil {
			t.Errorf("%s: no lock in the docker config: %v", name, err)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "pull-stdin")); len(got) != 0 {
			t.Errorf("%s: the pull read %q from stdin", name, got)
		}
		if c.login != "ok" && (!strings.Contains(stderr.String(), loginRefused) || !strings.Contains(stderr.String(), "WARNING")) {
			t.Errorf("%s: a refused login is said as such, with what docker said: %q", name, stderr.String())
		}
		if c.login == "ok" && strings.Contains(stderr.String(), "WARNING") {
			t.Errorf("%s: what a successful login says is not passed on: %q", name, stderr.String())
		}
	}
}

// boks going away — a cancelled run, a CI job killed — closes the connection the script writes to.
// A pull that sits silent would never notice; the watcher does, stops the pull and the script logs
// out within seconds rather than when the pull would have ended.
func runLoginScriptCut(t *testing.T, shell, dir string, l *Login) {
	cmd := loginScript(shell, dir, l, "ok", "hang", "ok")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && !slices.Contains(dockerRan(dir), wantPull); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	start := time.Now()
	out.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("the script outlived the connection by 15s: docker ran %q", dockerRan(dir))
	}
	if cmd.ProcessState.ExitCode() == 0 {
		t.Error("a pull cut short is not a success")
	}
	if got := dockerRan(dir); strings.Join(got, "|") != strings.Join([]string{wantLogin, wantPull, wantLogout}, "|") {
		t.Errorf("docker ran %q, want the logout after the cut pull", got)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the logout came %s after the connection closed", d)
	}
	pullGone(t, dir)
}

// A signal to the script — the server's own shutdown, an operator's kill — stops a silent pull at
// once and logs out, rather than after the pull would have ended.
func runLoginScriptTerm(t *testing.T, shell, dir string, l *Login) {
	cmd := loginScript(shell, dir, l, "ok", "hang", "ok")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(dir, "pull-pid")); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("the script outlived SIGTERM by 10s: docker ran %q", dockerRan(dir))
	}
	if got := cmd.ProcessState.ExitCode(); got != 143 {
		t.Errorf("exit %d after SIGTERM, want 143", got)
	}
	if got := dockerRan(dir); strings.Join(got, "|") != strings.Join([]string{wantLogin, wantPull, wantLogout}, "|") {
		t.Errorf("docker ran %q, want the logout after the signal", got)
	}
	pullGone(t, dir)
}

// pullGone checks that the stand-in pull the script started is no longer running.
func pullGone(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "pull-pid"))
	if err != nil {
		t.Fatalf("the pull never started: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for i := 0; i < 40; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	syscall.Kill(pid, syscall.SIGKILL)
	t.Errorf("the pull (pid %d) was left running", pid)
}
