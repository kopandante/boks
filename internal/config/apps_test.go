package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commitSum = "boks:\n  commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  sha256: {amd64: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}\n"

// apps: names each app's boks.yml; the server's own boks deploys them, so boks: is required, and a name
// is an app's name (#154, stage 2).
func TestServerApps(t *testing.T) {
	s, err := ParseServer([]byte("servers: [a]\n" + commitSum + "apps: {shop: apps/shop/boks.yml}\n"))
	if err != nil || s.Apps["shop"] != "apps/shop/boks.yml" {
		t.Fatalf("%+v %v", s, err)
	}
	for doc, want := range map[string]string{
		"apps: {shop: apps/shop/boks.yml}\n": "boks: is required",
		commitSum + "apps: {Shop: a.yml}\n":  "must match",
		commitSum + "apps: {bin: a.yml}\n":   "not be bin",
		commitSum + "apps: {shop: \" \"}\n":  "path of its boks.yml",
	} {
		if _, err := ParseServer([]byte("servers: [a]\n" + doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", doc, err, want)
		}
	}
}

// serverWith is a server.yml in a directory of its own, with boks.yml files beside it.
func serverWith(t *testing.T, doc string, files map[string]string) *Server {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadServer(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func none(string) (string, bool) { return "", false }

// An app goes on the servers of server.yml its boks.yml names, in server.yml's order, with its boks.yml
// as written, the environment its deploy would send and the registry's token.
func TestLoadApps(t *testing.T) {
	shop := "app: shop\nimage: ghcr.io/x/shop:v1\nservers: [c, a]\nenv: {B: \"2\", A: \"1\"}\nregistry: {host: ghcr.io, token_env: SHOP_TOKEN}\n"
	s := serverWith(t, "servers: [a, b, c]\n"+commitSum+"apps: {shop: apps/shop.yml}\n", map[string]string{"apps/shop.yml": shop})
	lookup := func(k string) (string, bool) { return " t0ken\n", k == "SHOP_TOKEN" }
	apps, err := s.LoadApps(lookup, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 {
		t.Fatalf("%+v", apps)
	}
	a := apps[0]
	if a.Name != "shop" || strings.Join(a.Servers, ",") != "a,c" || string(a.Config) != shop || string(a.Env) != "A=1\nB=2\n" || a.Token != "t0ken" {
		t.Errorf("%+v (env %q)", a, a.Env)
	}
	if on := AppsOn(apps, "b"); len(on) != 0 {
		t.Errorf("b: %+v", on)
	}
	// Without secrets: the config alone, and no token is asked for.
	apps, err = s.LoadApps(none, false)
	if err != nil || apps[0].Env != nil || apps[0].Token != "" || string(apps[0].Config) != shop {
		t.Errorf("without secrets: %+v %v", apps, err)
	}
	// With them, a token not set is refused before any server is asked.
	if _, err := s.LoadApps(none, true); err == nil || !strings.Contains(err.Error(), "apps: shop: registry.token_env: SHOP_TOKEN") {
		t.Errorf("no token: %v", err)
	}
}

func TestLoadAppsRefuses(t *testing.T) {
	for want, body := range map[string]string{
		"names the app blog":          "app: blog\nimage: x\nservers: [a]\n",
		"none of the servers":         "app: shop\nimage: x\nservers: [z]\n",
		"files and cert are not kept": "app: shop\nimage: x\nservers: [a]\nfiles: [\"nginx.conf:/etc/nginx/nginx.conf\"]\n",
		"no such file":                "",
	} {
		files := map[string]string{"shop.yml": body}
		if body == "" {
			files = nil
		}
		s := serverWith(t, "servers: [a]\n"+commitSum+"apps: {shop: shop.yml}\n", files)
		if _, err := s.LoadApps(none, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", want, err)
		}
	}
}
