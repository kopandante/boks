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
	f.fail[loginCall] = errors.New("sh: exit status 1: Error response from daemon: Get \"https://registry.depot.dev/v2/\": unauthorized: authentication required\n" + loginRefused)
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
	// A login that fails on the way to the registry is not blamed on the token.
	g := depotFake()
	g.fail[loginCall] = errors.New("sh: exit status 1: Error response from daemon: Get \"https://registry.depot.dev/v2/\": dial tcp: i/o timeout\n" + loginRefused)
	err = Run(context.Background(), g, io.Discard, cfg, "v2", depotOptions(t, cfg))
	if err == nil || strings.Contains(err.Error(), "token") || !strings.Contains(err.Error(), "docker login to registry.depot.dev on this server failed") {
		t.Errorf("want the failed login said as it is, got %v", err)
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

// The script itself, run by a real shell against stand-in docker and flock, once per outcome: the
// logout runs wherever the login may have happened and nowhere else, the token reaches `docker
// login` on its stdin, a silent pull is stopped by a signal or a cut connection,
// and the script's status is the pull's. Under sh and dash: Ubuntu's sh is dash, whose traps differ
// from bash's in the details the script leans on.
func TestTheLoginScriptLogsOutWhateverHappens(t *testing.T) {
	all := []string{wantLogin, wantPull, wantLogout}
	cases := []scriptCase{
		{name: "pulled", status: 0, ran: all},
		// A run that never took the lock touches nothing: its logout would end another pull's login.
		{name: "lock not taken", flock: "fail", status: 1, says: "another pull has held the registry login"},
		{name: "login refused", login: "fail", status: 1, ran: []string{wantLogin, wantLogout}, says: loginRefused},
		{name: "pull failed", pull: "fail", status: 3, ran: all},
		// A logout that fails leaves the token behind, so it fails the script; a failed pull keeps its status.
		{name: "logout failed", logout: "fail", status: 1, ran: all, says: "docker logout registry.depot.dev failed"},
		{name: "pull and logout failed", pull: "fail", logout: "fail", status: 3, ran: all, says: "docker logout registry.depot.dev failed"},
		// boks going away closes the connection; nothing else would make a silent pull notice.
		{name: "connection cut", pull: "hang", act: "cut", status: -1, ran: all},
		{name: "SIGTERM", pull: "hang", act: "term", status: 143, ran: all},
		// A user whose docker keeps its config elsewhere has the lock there, beside the credentials.
		{name: "own docker config", dockerConfig: "conf", status: 0, ran: all},
	}
	shells := []string{"sh"}
	if _, err := exec.LookPath("dash"); err == nil {
		shells = append(shells, "dash")
	}
	for _, shell := range shells {
		for _, c := range cases {
			t.Run(shell+"/"+c.name, func(t *testing.T) { runScript(t, shell, c) })
		}
	}
}

const (
	wantLogin  = "login registry.depot.dev -u x-token --password-stdin"
	wantPull   = "pull registry.depot.dev/p:v1"
	wantLogout = "logout registry.depot.dev"
)

// scriptCase is one outcome of the login script. The stand-ins succeed unless told "fail"; a pull
// told "hang" sits silent until stopped, and act is what then happens to the script: "cut" closes
// its connection, "term" signals it.
type scriptCase struct {
	name                       string
	flock, login, pull, logout string
	act                        string
	dockerConfig               string   // DOCKER_CONFIG, under the case's directory; "" leaves it unset
	status                     int      // the exit status; -1 is any but 0
	ran                        []string // what docker was asked, in order, in full
	says                       string   // what the script must say on stderr
}

const fakeDocker = `#!/bin/sh
echo "$*" >> "$DIR/log"
case "$1" in
login) cat > "$DIR/login-stdin"; echo "WARNING! stored unencrypted" >&2; [ "$LOGIN" != fail ] ;;
pull) echo $$ > "$DIR/pull-pid"
  case "$PULL" in fail) exit 3 ;; hang) exec sleep 30 ;; esac ;;
logout) [ "$LOGOUT" != fail ] ;;
esac
`

const fakeFlock = `#!/bin/sh
echo "$*" > "$DIR/flock-args"
[ "$FLOCK" != fail ]
`

func runScript(t *testing.T, shell string, c scriptCase) {
	dir := t.TempDir()
	for name, body := range map[string]string{"docker": fakeDocker, "flock": fakeFlock} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) string { b, _ := os.ReadFile(filepath.Join(dir, name)); return string(b) }
	l := &Login{Registry: &config.Registry{Host: "registry.depot.dev", User: "x-token", TokenEnv: "T"}, Token: depotToken}
	cmd := exec.Command(shell, "-c", loginPull(l, "registry.depot.dev/p:v1"))
	cmd.Stdin = strings.NewReader(l.Token)
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "HOME=" + dir, "DIR=" + dir,
		"FLOCK=" + c.flock, "LOGIN=" + c.login, "PULL=" + c.pull, "LOGOUT=" + c.logout}
	conf := filepath.Join(dir, ".docker")
	if c.dockerConfig != "" {
		conf = filepath.Join(dir, c.dockerConfig)
		cmd.Env = append(cmd.Env, "DOCKER_CONFIG="+conf)
	}
	// Its own process group, so whatever the script leaves behind can be stopped after a failure.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	var conn io.Closer
	if c.act == "cut" {
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		conn = out
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	deadline := time.Now().Add(10 * time.Second)
	if c.act != "" {
		for read("pull-pid") == "" {
			if time.Now().After(deadline) {
				t.Fatalf("the pull never started; docker ran %q", read("log"))
			}
			time.Sleep(20 * time.Millisecond)
		}
		switch c.act {
		case "cut":
			conn.Close()
		case "term":
			cmd.Process.Signal(syscall.SIGTERM)
		}
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Until(deadline)):
		t.Fatalf("the script was still running after 10s; docker ran %q", read("log"))
	}

	if got := cmd.ProcessState.ExitCode(); got != c.status && !(c.status == -1 && got != 0) {
		t.Errorf("exit %d, want %d; stderr %q", got, c.status, stderr.String())
	}
	if got := strings.FieldsFunc(read("log"), func(r rune) bool { return r == '\n' }); !slices.Equal(got, c.ran) {
		t.Errorf("docker ran %q, want %q", got, c.ran)
	}
	if c.says != "" && !strings.Contains(stderr.String(), c.says) {
		t.Errorf("stderr %q, want it to say %q", stderr.String(), c.says)
	}
	// What a successful login says (that the credentials are stored unencrypted) is noise after the
	// pull; a refused one is passed on with docker's own words.
	if warned := strings.Contains(stderr.String(), "WARNING"); warned != (c.login == "fail") {
		t.Errorf("docker login's warning passed on: %v; stderr %q", warned, stderr.String())
	}
	// Waiting, and for long enough to outlast another pull: an flock without -w, or with -u, would not
	// serialize anything. The lock is the docker config's, beside the credentials it guards.
	if got := strings.TrimSpace(read("flock-args")); got != "-w 600 9" {
		t.Errorf("flock ran with %q", got)
	}
	if _, err := os.Stat(filepath.Join(conf, registryLock)); err != nil {
		t.Errorf("no lock in the docker config %s: %v", conf, err)
	}
	if c.dockerConfig != "" {
		if _, err := os.Stat(filepath.Join(dir, ".docker")); err == nil {
			t.Errorf("a lock beside ~/.docker, not the docker config %s", conf)
		}
	}
	if slices.Contains(c.ran, wantLogin) && read("login-stdin") != depotToken {
		t.Errorf("login read %q from stdin", read("login-stdin"))
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(read("pull-pid"))); err == nil {
		for i := 0; syscall.Kill(pid, 0) == nil; i++ {
			if i == 50 {
				t.Errorf("the pull (pid %d) was left running", pid)
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
