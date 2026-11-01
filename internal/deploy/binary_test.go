package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

// home runs commands with sh in a directory standing for the server's home, as ssh would: the install's
// script is shell, and its checks are what a test has to see run. sha256sum is the coreutils one on a
// server; where it is not (macOS), a shim gives the same output.
type home struct {
	dir, path string
	calls     []string
}

func newHome(t *testing.T) *home {
	t.Helper()
	h := &home{dir: t.TempDir()}
	bin := t.TempDir()
	if _, err := exec.LookPath("sha256sum"); err != nil {
		shim := "#!/bin/sh\nexec shasum -a 256 \"$@\"\n"
		if err := os.WriteFile(filepath.Join(bin, "sha256sum"), []byte(shim), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	return h
}

func (h *home) Run(ctx context.Context, args ...string) (string, error) {
	return h.Pipe(ctx, nil, args...)
}

func (h *home) Pipe(ctx context.Context, stdin []byte, args ...string) (string, error) {
	h.calls = append(h.calls, strings.Join(args, " "))
	if args[0] == "uname" {
		return "x86_64", nil
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir, cmd.Env = h.dir, append(os.Environ(), "PATH="+h.path)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", errors.New(err.Error() + ": " + errb.String())
	}
	return strings.TrimSpace(out.String()), nil
}

// build is a stand-in for boks's build of commit: a script that says commit to `version`.
func build(says string) []byte { return []byte("#!/bin/sh\necho " + says + "\n") }

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (h *home) link(t *testing.T) string {
	t.Helper()
	l, err := os.Readlink(filepath.Join(h.dir, binLink))
	if err != nil {
		return ""
	}
	return l
}

const (
	commitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	commitB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	commitC = "cccccccccccccccccccccccccccccccccccccccc"
)

func served(body []byte, fetched *[]string) Fetch {
	return func(_ context.Context, url string) ([]byte, error) {
		*fetched = append(*fetched, url)
		return body, nil
	}
}

// The build is fetched for the server's architecture, checked, written, checked there, and only then
// named by the link; a second install of the same is left alone; a third commit keeps the one it
// replaced and removes older ones (#154).
func TestInstallBoks(t *testing.T) {
	h := newHome(t)
	var fetched []string
	ctx := context.Background()
	for i, c := range []string{commitA, commitB, commitB, commitC} {
		b := build(c)
		var log strings.Builder
		if err := InstallBoks(ctx, h, &log, &config.ServerBoks{Commit: c, SHA256: map[string]string{"amd64": sum(b)}}, served(b, &fetched)); err != nil {
			t.Fatalf("%d %s: %v", i, c[:4], err)
		}
		if got := h.link(t); got != "../_server/bin/boks-"+c {
			t.Errorf("%d: the link names %q", i, got)
		}
		if got, _ := RunningBoks(ctx, h); got != c {
			t.Errorf("%d: running %q", i, got)
		}
		if i == 2 && (len(fetched) != 2 || !strings.Contains(log.String(), "already")) {
			t.Errorf("the same build again was fetched: %v %s", fetched, log.String())
		}
	}
	if fetched[0] != "https://github.com/kopandante/boks/releases/download/bin-"+commitA+"/boks-linux-amd64" {
		t.Errorf("fetched %s", fetched[0])
	}
	left, _ := filepath.Glob(filepath.Join(h.dir, binDir, "boks-*"))
	var names []string
	for _, f := range left {
		names = append(names, filepath.Base(f))
	}
	if strings.Join(names, " ") != "boks-"+commitB+" boks-"+commitC {
		t.Errorf("builds kept: %v", names)
	}
	if fi, err := os.Stat(filepath.Join(h.dir, binDir, "boks-"+commitC)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("mode: %v %v", fi, err)
	}
}

// A build whose sum is not server.yml's, one that says another commit, and an architecture server.yml
// writes no sum for are refused, and the boks that ran stays named.
func TestInstallBoksRefuses(t *testing.T) {
	h := newHome(t)
	ctx := context.Background()
	var fetched []string
	good := build(commitA)
	if err := InstallBoks(ctx, h, &strings.Builder{}, &config.ServerBoks{Commit: commitA, SHA256: map[string]string{"amd64": sum(good)}}, served(good, &fetched)); err != nil {
		t.Fatal(err)
	}
	liar := build(commitC)
	for name, c := range map[string]struct {
		b    *config.ServerBoks
		body []byte
		want string
	}{
		"another sum":     {&config.ServerBoks{Commit: commitB, SHA256: map[string]string{"amd64": sum(good)}}, build(commitB), "has sha256"},
		"another commit":  {&config.ServerBoks{Commit: commitB, SHA256: map[string]string{"amd64": sum(liar)}}, liar, "says it is " + commitC},
		"no sum for arch": {&config.ServerBoks{Commit: commitB, SHA256: map[string]string{"arm64": sum(liar)}}, liar, "no sha256 for amd64"},
	} {
		err := InstallBoks(ctx, h, &strings.Builder{}, c.b, served(c.body, &fetched))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if got := h.link(t); got != "../_server/bin/boks-"+commitA {
			t.Errorf("%s: the link names %q", name, got)
		}
		if _, err := os.Stat(filepath.Join(h.dir, binDir, "boks-"+commitB)); err == nil {
			t.Errorf("%s: the refused build is left on the server", name)
		}
	}
}

// A link that does not switch is a failed install, not "runs": the script's last line succeeds whatever
// came before it, so the swap has to stop the script itself.
func TestInstallBoksLinkNotSwitched(t *testing.T) {
	h := newHome(t)
	ctx := context.Background()
	var fetched []string
	a, b := build(commitA), build(commitB)
	if err := InstallBoks(ctx, h, &strings.Builder{}, &config.ServerBoks{Commit: commitA, SHA256: map[string]string{"amd64": sum(a)}}, served(a, &fetched)); err != nil {
		t.Fatal(err)
	}
	// A directory where the new link is made: ln puts the link inside it, and mv cannot put a directory
	// over the link, as root too.
	if err := os.MkdirAll(filepath.Join(h.dir, binLink+".new", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	err := InstallBoks(ctx, h, &log, &config.ServerBoks{Commit: commitB, SHA256: map[string]string{"amd64": sum(b)}}, served(b, &fetched))
	if err == nil || !strings.Contains(err.Error(), "not switched") {
		t.Errorf("err %v, log %s", err, log.String())
	}
	if got := h.link(t); got != "../_server/bin/boks-"+commitA {
		t.Errorf("the link names %q", got)
	}
}

// corrupting writes other bytes than it is given: what a write gone wrong on the way would leave.
type corrupting struct{ *home }

func (c corrupting) Pipe(ctx context.Context, stdin []byte, args ...string) (string, error) {
	if stdin != nil {
		stdin = append([]byte(nil), stdin...)
		stdin[len(stdin)-2] ^= 1
	}
	return c.home.Pipe(ctx, stdin, args...)
}

func (c corrupting) Run(ctx context.Context, args ...string) (string, error) {
	return c.Pipe(ctx, nil, args...)
}

// The sum is checked again on the server, on the bytes written there: a build that arrives otherwise is
// refused and removed, and the boks that ran stays named.
func TestInstallBoksChecksTheSumOnTheServer(t *testing.T) {
	h := newHome(t)
	ctx := context.Background()
	var fetched []string
	a, b := build(commitA), build(commitB)
	if err := InstallBoks(ctx, h, &strings.Builder{}, &config.ServerBoks{Commit: commitA, SHA256: map[string]string{"amd64": sum(a)}}, served(a, &fetched)); err != nil {
		t.Fatal(err)
	}
	err := InstallBoks(ctx, corrupting{h}, &strings.Builder{}, &config.ServerBoks{Commit: commitB, SHA256: map[string]string{"amd64": sum(b)}}, served(b, &fetched))
	if err == nil || !strings.Contains(err.Error(), "differs from the one fetched") {
		t.Errorf("err %v", err)
	}
	if got := h.link(t); got != "../_server/bin/boks-"+commitA {
		t.Errorf("the link names %q", got)
	}
	if _, err := os.Stat(filepath.Join(h.dir, binDir, "boks-"+commitB)); err == nil {
		t.Error("the refused build is left on the server")
	}
}

// CheckBoks refuses what InstallBoks would on this side, with nothing written, and with Remember the
// install after it fetches nothing again; a server that runs the build already is not fetched for.
func TestCheckBoks(t *testing.T) {
	h := newHome(t)
	ctx := context.Background()
	var fetched []string
	a := build(commitA)
	ok := &config.ServerBoks{Commit: commitA, SHA256: map[string]string{"amd64": sum(a)}}
	for name, c := range map[string]struct {
		b    *config.ServerBoks
		want string
	}{
		"no sum for arch": {&config.ServerBoks{Commit: commitA, SHA256: map[string]string{"arm64": sum(a)}}, "no sha256 for amd64"},
		"another sum":     {&config.ServerBoks{Commit: commitA, SHA256: map[string]string{"amd64": sum(build(commitB))}}, "has sha256"},
	} {
		if err := CheckBoks(ctx, h, &strings.Builder{}, c.b, served(a, &fetched)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".boks")); err == nil {
		t.Error("a check wrote to the server")
	}
	fetched = nil
	fetch := Remember(served(a, &fetched), io.Discard)
	if err := CheckBoks(ctx, h, &strings.Builder{}, ok, fetch); err != nil {
		t.Fatal(err)
	}
	if err := InstallBoks(ctx, h, &strings.Builder{}, ok, fetch); err != nil {
		t.Fatal(err)
	}
	if err := CheckBoks(ctx, h, &strings.Builder{}, ok, served(a, &fetched)); err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 1 {
		t.Errorf("fetched %v", fetched)
	}
}

// The link names a build of the commit whose file is not of the sum: the install writes the new bytes
// beside it, and a refusal removes those alone — the boks that ran is still there, named (#159).
func TestInstallBoksOverItsOwnCommitRefused(t *testing.T) {
	h := newHome(t)
	ctx := context.Background()
	var fetched []string
	a := build(commitA)
	ok := &config.ServerBoks{Commit: commitA, SHA256: map[string]string{"amd64": sum(a)}}
	if err := InstallBoks(ctx, h, &strings.Builder{}, ok, served(a, &fetched)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(h.dir, binDir, "boks-"+commitA)
	if err := os.WriteFile(file, append(build(commitA), '#'), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := InstallBoks(ctx, corrupting{h}, &strings.Builder{}, ok, served(a, &fetched)); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Errorf("err %v", err)
	}
	if got := h.link(t); got != "../_server/bin/boks-"+commitA {
		t.Errorf("the link names %q", got)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the build the link names is gone: %v", err)
	}
	if err := InstallBoks(ctx, h, &strings.Builder{}, ok, served(a, &fetched)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(file); string(got) != string(a) {
		t.Errorf("the build is %q", got)
	}
}

// Another install holding the lock refuses this one before anything is checked or switched.
func TestInstallBoksWaitsForTheLock(t *testing.T) {
	h := newHome(t)
	shim := strings.SplitN(h.path, string(os.PathListSeparator), 2)[0]
	if err := os.WriteFile(filepath.Join(shim, "flock"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var fetched []string
	a := build(commitA)
	err := InstallBoks(context.Background(), h, &strings.Builder{}, &config.ServerBoks{Commit: commitA, SHA256: map[string]string{"amd64": sum(a)}}, served(a, &fetched))
	if err == nil || !strings.Contains(err.Error(), "another install holds the lock") {
		t.Errorf("err %v", err)
	}
	if got := h.link(t); got != "" {
		t.Errorf("the link names %q", got)
	}
}
