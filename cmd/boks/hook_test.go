package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/deploy"
	"github.com/kopandante/boks/internal/remote"
)

// hooked is what deploy-hook ran: the deploy it asked for, if any.
type hooked struct {
	called bool
	cfg    *config.Config
	tag    string
	o      deploy.Options
}

// hookHome is a server's home where `server apply` wrote shop, and deploy-hook's deploy recorded in h;
// sent is what the client sent as SSH_ORIGINAL_COMMAND.
func hookHome(t *testing.T, sent string, h *hooked) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".boks/_server/apps/shop")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"boks.yml":       "app: shop\nimage: ghcr.io/x/shop\nservers: [a]\nregistry: {host: ghcr.io, token_env: SHOP_TOKEN}\n",
		"env":            "A=1\n",
		"registry.token": "t0ken\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wasLookup, wasDeploy, wasLocal := lookupEnv, hookDeploy, local
	lookupEnv = func(k string) (string, bool) {
		if k == "SSH_ORIGINAL_COMMAND" {
			return sent, true
		}
		return "from the hook's own environment", true
	}
	hookDeploy = func(_ context.Context, _ remote.Runner, _ io.Writer, cfg *config.Config, tag string, o deploy.Options) error {
		h.called, h.cfg, h.tag, h.o = true, cfg, tag, o
		return nil
	}
	local = func(string) remote.Runner {
		t.Error("the server was asked something")
		return nil
	}
	t.Cleanup(func() { lookupEnv, hookDeploy, local = wasLookup, wasDeploy, wasLocal })
	return home
}

// The client sends the tag alone; anything else is refused before the server is asked anything (#154,
// stage 3).
func TestDeployHookRefusesAnythingButATag(t *testing.T) {
	for _, sent := range []string{"", "v1; id", "$(id)", "`id`", "v1 v2", "v1\nid", " v1", "-v1", ".v1", strings.Repeat("a", 129), "v1|sh", "../v1"} {
		var h hooked
		hookHome(t, sent, &h)
		var errw strings.Builder
		if code := run([]string{"deploy-hook", "shop"}, io.Discard, &errw); code != 1 || !strings.Contains(errw.String(), "send the image's tag alone") || h.called {
			t.Errorf("%q: %d %q, deployed %v", sent, code, errw.String(), h.called)
		}
	}
}

// A tag deploys the app with what apply wrote on the server: its boks.yml, its env and the token file —
// nothing of the hook's own environment.
func TestDeployHookDeploysFromTheServersFiles(t *testing.T) {
	var h hooked
	home := hookHome(t, "v1.2.3_rc-4", &h)
	local = func(dir string) remote.Runner {
		if dir != home {
			t.Errorf("runner from %s, want the home", dir)
		}
		return remote.Local{Dir: dir}
	}
	var errw strings.Builder
	if code := run([]string{"deploy-hook", "shop"}, io.Discard, &errw); code != 0 {
		t.Fatalf("%d %q", code, errw.String())
	}
	if !h.called || h.cfg.App != "shop" || h.tag != "v1.2.3_rc-4" || string(h.o.Env) != "A=1\n" || h.o.Login == nil || h.o.Login.Token != "t0ken" {
		t.Errorf("%+v", h)
	}
}

// A client gone mid-deploy does not cut the deploy short: the hook, its stdout a pipe no one reads any
// more, prints on and the deploy runs to its end, where it unlocks; Go's SIGPIPE would end it on its
// first line instead (#154, stage 3). The hook runs in a child process, as sshd starts it.
func TestDeployHookOutlivesItsClient(t *testing.T) {
	if done := os.Getenv("BOKS_TEST_HOOK_DONE"); done != "" {
		var h hooked
		hookHome(t, "v1", &h)
		hookDeploy = func(_ context.Context, _ remote.Runner, out io.Writer, _ *config.Config, _ string, _ deploy.Options) error {
			for i := range 3 {
				fmt.Fprintf(out, "step %d\n", i)
			}
			return os.WriteFile(done, []byte("unlocked"), 0o600)
		}
		run([]string{"deploy-hook", "shop"}, os.Stdout, io.Discard)
		return
	}
	done := filepath.Join(t.TempDir(), "done")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close() // the client is gone before the hook prints anything
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeployHookOutlivesItsClient$")
	cmd.Env = append(os.Environ(), "BOKS_TEST_HOOK_DONE="+done)
	cmd.Stdout = w
	runErr := cmd.Run()
	w.Close()
	if b, err := os.ReadFile(done); err != nil || string(b) != "unlocked" {
		t.Errorf("the deploy did not run to its end: %v (hook: %v)", err, runErr)
	}
}

// An app apply never wrote, or not an app name, is refused before anything runs.
func TestDeployHookRefusesAnAppNotKept(t *testing.T) {
	for _, app := range []string{"blog", "../shop", "Shop", "bin"} {
		var h hooked
		hookHome(t, "v1", &h)
		var errw strings.Builder
		if code := run([]string{"deploy-hook", app}, io.Discard, &errw); code != 1 || h.called {
			t.Errorf("%s: %d %q", app, code, errw.String())
		}
	}
}

// A boks.yml under one app's directory that names another is refused: the key is bound to the directory.
func TestDeployHookRefusesAnotherAppsConfig(t *testing.T) {
	var h hooked
	home := hookHome(t, "v1", &h)
	if err := os.WriteFile(filepath.Join(home, ".boks/_server/apps/shop/boks.yml"), []byte("app: blog\nimage: x\nservers: [a]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errw strings.Builder
	if code := run([]string{"deploy-hook", "shop"}, io.Discard, &errw); code != 1 || !strings.Contains(errw.String(), "names the app blog") || h.called {
		t.Errorf("%d %q", code, errw.String())
	}
}

// A rollback of the policy neither reads the apps of server.yml nor touches their files on the server:
// one whose boks.yml is gone does not stop it (infra-pm, 01.11).
func TestServerRollbackLeavesTheApps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(path, []byte("servers: [a]\nrevision: 5\nboks:\n  commit: "+strings.Repeat("a", 40)+
		"\n  sha256: {amd64: "+strings.Repeat("b", 64)+"}\napps: {shop: gone/boks.yml}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hist := "sh -c if [ -f '.boks/_server/history/4.json' ]"
	a := &recorder{server: server{policyRead: "present\n{\"revision\":5,\"floor\":5}", hist: "present\n{\"revision\":4}"}}
	fleet(t, map[string]*recorder{"a": a}, time.Now)
	var errw strings.Builder
	run([]string{"server", "rollback", path, "4"}, io.Discard, &errw)
	if strings.Contains(errw.String(), "apps") {
		t.Errorf("rollback refused for the apps: %q", errw.String())
	}
	for _, c := range a.calls {
		if strings.Contains(c, "_server/apps") || strings.Contains(c, "authorized_keys") {
			t.Errorf("rollback touched %s", c)
		}
	}
	if !strings.Contains(strings.Join(a.stdin, "\n"), `"action":"server rollback"`) {
		t.Errorf("the rollback did not run: %q %v", errw.String(), a.calls)
	}
}

// apply writes the deploy keys after the apps and before the policy, on the servers their app goes on.
func TestApplyWritesTheDeployKeysAfterTheApps(t *testing.T) {
	build := []byte("a build")
	sum := sha256Hex(build)
	was := fetchBoks
	fetchBoks = func(context.Context, string) ([]byte, error) { return build, nil }
	t.Cleanup(func() { fetchBoks = was })
	dir := t.TempDir()
	shop := "app: shop\nimage: ghcr.io/x/shop:v1\nservers: [a]\n"
	if err := os.WriteFile(filepath.Join(dir, "shop.yml"), []byte(shop), 0o600); err != nil {
		t.Fatal(err)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN2dRDHyVokdan3Hc3xKeeo0b3EHb7NRJDfT/T3dozGa"
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte("servers: [a, b]\nrevision: 2\nboks:\n  commit: "+strings.Repeat("a", 40)+
		"\n  sha256: {amd64: "+sum+"}\napps: {shop: shop.yml}\ndeploy_keys: {shop: \""+key+" ci\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := "present\n{\"revision\":1,\"floor\":1}"
	a := &recorder{server: server{policyRead: pol, "uname -m": "x86_64", keysRead: "absent"}}
	b := &recorder{server: server{policyRead: pol, "uname -m": "x86_64", keysRead: "absent"}}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	run([]string{"server", "apply", path}, io.Discard, io.Discard)
	app, keys, policy := -1, -1, -1
	line := deploy.HookLine("shop", key)
	for i, in := range a.stdin {
		switch {
		case in == shop:
			app = i
		case strings.Contains(in, line):
			keys = i
		case strings.Contains(in, `"action":"server apply"`) && policy < 0:
			policy = i
		}
	}
	if app < 0 || keys < app || policy < keys {
		t.Errorf("boks.yml at %d, keys at %d, the policy at %d", app, keys, policy)
	}
	for _, in := range b.stdin {
		if strings.Contains(in, "deploy-hook") {
			t.Errorf("b got shop's deploy key: %q", in)
		}
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
