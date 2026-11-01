package deploy

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

// locked is a home whose admission lock is recorded rather than taken: the lock lives in /tmp, which a
// test must not touch.
type locked struct{ *home }

func (l locked) Run(ctx context.Context, args ...string) (string, error) {
	return l.Pipe(ctx, nil, args...)
}

func (l locked) Pipe(ctx context.Context, stdin []byte, args ...string) (string, error) {
	if c := strings.Join(args, " "); strings.Contains(c, admitLock) {
		l.calls = append(l.calls, "lock: "+c)
		return "", nil
	}
	return l.home.Pipe(ctx, stdin, args...)
}

var shopApp = config.ServerApp{Name: "shop", Config: []byte("app: shop\n"), Env: []byte("A=1\n"), Token: "t0ken"}

func read(t *testing.T, h *home, p string) (string, os.FileMode) {
	t.Helper()
	fi, err := os.Stat(filepath.Join(h.dir, p))
	if err != nil {
		return "", 0
	}
	b, _ := os.ReadFile(filepath.Join(h.dir, p))
	return string(b), fi.Mode().Perm()
}

// apply writes each app's boks.yml, environment and token, 0600, under the admission lock; a public
// image's token is removed, and an app server.yml no longer names goes (#154, stage 2).
func TestPutApps(t *testing.T) {
	h := newHome(t)
	l := locked{h}
	blog := config.ServerApp{Name: "blog", Config: []byte("app: blog\n"), Env: []byte("")}
	if err := PutApps(context.Background(), l, io.Discard, []config.ServerApp{shopApp, blog}, fixed); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		".boks/_server/apps/shop/boks.yml": "app: shop\n", ".boks/_server/apps/shop/env": "A=1\n",
		".boks/_server/apps/shop/registry.token": "t0ken\n", ".boks/_server/apps/blog/env": "",
	} {
		if got, mode := read(t, h, p); got != want || mode != 0o600 {
			t.Errorf("%s: %q %o, want %q 600", p, got, mode, want)
		}
	}
	if _, mode := read(t, h, ".boks/_server/apps/blog/registry.token"); mode != 0 {
		t.Errorf("a public image's app has a token")
	}
	if i := slices.IndexFunc(h.calls, func(c string) bool { return strings.HasPrefix(c, "lock: ln -sn") }); i != 0 {
		t.Errorf("the lock is not taken first: %v", h.calls)
	}
	// boks.yml goes last: a run cut before it leaves the old one, and status names it as differing.
	at := func(f string) int {
		return slices.IndexFunc(h.calls, func(c string) bool { return strings.Contains(c, "apps/shop/"+f+".tmp") })
	}
	if cfg, env, token := at("boks.yml"), at("env"), at("registry.token"); env < 0 || token < 0 || cfg < env || cfg < token {
		t.Errorf("boks.yml at %d, env at %d, the token at %d: %v", cfg, env, token, h.calls)
	}
	// ... and released last, after every write: the server's boks never reads a half-written app.
	if last := h.calls[len(h.calls)-1]; !strings.HasPrefix(last, "lock: sh -c [ \"$(readlink") {
		t.Errorf("the lock is not released last: %v", h.calls)
	}
	// shop goes public, blog is no longer named.
	public := shopApp
	public.Token = ""
	if err := PutApps(context.Background(), l, io.Discard, []config.ServerApp{public}, fixed); err != nil {
		t.Fatal(err)
	}
	if _, mode := read(t, h, ".boks/_server/apps/shop/registry.token"); mode != 0 {
		t.Errorf("the token of an image now public is kept")
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".boks/_server/apps/blog")); !os.IsNotExist(err) {
		t.Errorf("blog's files are kept: %v", err)
	}
}

// status names an app missing from the server, one whose boks.yml differs or has no environment, and
// one server.yml no longer names.
func TestAppsDrift(t *testing.T) {
	h := newHome(t)
	if err := PutApps(context.Background(), locked{h}, io.Discard, []config.ServerApp{shopApp}, fixed); err != nil {
		t.Fatal(err)
	}
	if d, err := AppsDrift(context.Background(), h, []config.ServerApp{shopApp}); err != nil || len(d) != 0 {
		t.Errorf("as written: %v %v", d, err)
	}
	changed := shopApp
	changed.Config = []byte("app: shop\nkeep: 3\n")
	blog := config.ServerApp{Name: "blog", Config: []byte("app: blog\n")}
	if err := os.Remove(filepath.Join(h.dir, ".boks/_server/apps/shop/env")); err != nil {
		t.Fatal(err)
	}
	d, err := AppsDrift(context.Background(), h, []config.ServerApp{changed, blog})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(d, "\n")
	for _, want := range []string{"app blog: not on the server", "app shop: its boks.yml on the server differs", "app shop: no environment"} {
		if !strings.Contains(got, want) {
			t.Errorf("drift %q, want %q", got, want)
		}
	}
	if d, _ := AppsDrift(context.Background(), h, nil); len(d) != 1 || !strings.Contains(d[0], "server.yml does not name it") {
		t.Errorf("extra: %v", d)
	}
}
