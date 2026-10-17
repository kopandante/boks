package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeBWS replaces the BWS call for one test and counts how often it ran.
func fakeBWS(t *testing.T, list []bwsSecret, err error) *int {
	t.Helper()
	calls := 0
	orig := bwsList
	bwsList = func() ([]bwsSecret, error) { calls++; return list, err }
	bwsOnce, bwsSnapshot, bwsErr = sync.Once{}, nil, nil
	t.Cleanup(func() { bwsList = orig; bwsOnce, bwsSnapshot, bwsErr = sync.Once{}, nil, nil })
	return &calls
}

func TestEnvContentBWS(t *testing.T) {
	fakeBWS(t, []bwsSecret{
		{Key: "shop__TOKEN", Value: "t1"},
		{Key: "shop__API_KEY", Value: "k1"},
		{Key: "shop-dev__TOKEN", Value: "other app"}, // a longer app name with the same start
		{Key: "UNPREFIXED", Value: "x"},
	}, nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Dir: dir, EnvFile: ".env", EnvBWS: "shop", Env: map[string]string{"C": "3"}}
	got, err := cfg.EnvContent()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "A=1\nAPI_KEY=k1\nTOKEN=t1\nC=3\n" {
		t.Errorf("got %q", got)
	}
}

// Every env_bws lookup of one boks process shares a single request to BWS, whatever the app.
func TestEnvBWSOneRequestPerProcess(t *testing.T) {
	calls := fakeBWS(t, []bwsSecret{{Key: "a__X", Value: "1"}, {Key: "b__Y", Value: "2"}}, nil)
	for _, app := range []string{"a", "b", "a"} {
		if _, err := (&Config{EnvBWS: app}).EnvContent(); err != nil {
			t.Fatal(err)
		}
	}
	if *calls != 1 {
		t.Errorf("want 1 request to BWS, got %d", *calls)
	}
}

func TestEnvBWSRefuses(t *testing.T) {
	dir := t.TempDir()
	envFiles := map[string][]byte{
		".env": []byte("# c\nexport TOKEN=file\n"),
		// docker drops a UTF-8 BOM before the first name and reads a bare NAME from the server's env.
		"bom.env":  append([]byte{0xEF, 0xBB, 0xBF}, "TOKEN=file\n"...),
		"bare.env": []byte("A=1\n  TOKEN\n"),
	}
	for name, data := range envFiles {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	token := []bwsSecret{{Key: "s__TOKEN", Value: "sv-token"}}
	cases := []struct {
		name string
		list []bwsSecret
		err  error
		cfg  Config
		want string
	}{
		{"set by env_file too", token, nil, Config{Dir: dir, EnvFile: ".env", EnvBWS: "s"}, "set by env_file too"},
		{"env_file with a BOM", token, nil, Config{Dir: dir, EnvFile: "bom.env", EnvBWS: "s"}, "set by env_file too"},
		{"bare name in env_file", token, nil, Config{Dir: dir, EnvFile: "bare.env", EnvBWS: "s"}, "set by env_file too"},
		{"set by env too", token, nil,
			Config{EnvBWS: "s", Env: map[string]string{"TOKEN": "inline"}}, "set by env too"},
		{"env key with a leading space", token, nil,
			Config{EnvBWS: "s", Env: map[string]string{" TOKEN": "inline"}}, "set by env too"},
		{"env value carrying a line", token, nil,
			Config{EnvBWS: "s", Env: map[string]string{"A": "x\nTOKEN=inline"}}, "set by env too"},
		{"twice in BWS", []bwsSecret{{Key: "s__T", Value: "sv-one"}, {Key: "s__T", Value: "sv-two"}}, nil,
			Config{EnvBWS: "s"}, "in BWS twice"},
		{"name with a space", []bwsSecret{{Key: "s__ TOKEN", Value: "sv-space"}}, nil,
			Config{Dir: dir, EnvFile: ".env", EnvBWS: "s"}, "is not a variable name"},
		{"empty name", []bwsSecret{{Key: "s__", Value: "sv-empty"}}, nil,
			Config{EnvBWS: "s"}, "is not a variable name"},
		{"multi-line", []bwsSecret{{Key: "s__PEM", Value: "sv-first\nsv-second"}}, nil,
			Config{EnvBWS: "s"}, "spans several lines"},
		{"nothing for the app", []bwsSecret{{Key: "other__T", Value: "sv-other"}}, nil,
			Config{EnvBWS: "s"}, "no secrets named s__*"},
		{"bws failed", nil, errors.New("env_bws: bws secret list: 429"), Config{EnvBWS: "s"}, "429"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeBWS(t, c.list, c.err)
			cfg := c.cfg
			got, err := cfg.EnvContent()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error %q, got %v (env %q)", c.want, err, got)
			}
			// A refused env carries no secret value, nor any line of one, into the error.
			for _, s := range c.list {
				for _, part := range strings.Split(s.Value, "\n") {
					if strings.Contains(err.Error(), part) {
						t.Errorf("error leaks a value: %v", err)
					}
				}
			}
		})
	}
}

// Without env_bws nothing asks BWS: configs that do not use it deploy as before, without a token.
func TestEnvContentWithoutBWSNoRequest(t *testing.T) {
	calls := fakeBWS(t, nil, errors.New("must not be called"))
	if _, err := (&Config{Env: map[string]string{"A": "1"}}).EnvContent(); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Errorf("BWS asked %d times without env_bws", *calls)
	}
}

func TestParseEnvBWS(t *testing.T) {
	cfg, err := Parse([]byte("app: shop\nimage: x\nservers: [s1]\nenv_bws: shop-prod\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnvBWS != "shop-prod" {
		t.Errorf("env_bws not parsed: %q", cfg.EnvBWS)
	}
}

// fakeBin puts executables named after the keys, with the given shell bodies, first on PATH.
func fakeBin(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// The real bwsList hands the token to bws in its environment and decodes the JSON list.
func TestBWSListRunsCLI(t *testing.T) {
	dir := fakeBin(t, map[string]string{
		"bws": `echo "$BWS_ACCESS_TOKEN $*" > "$(dirname "$0")/seen"
echo '[{"key":"shop__A","value":"1","id":"x"}]'`,
	})
	t.Setenv("BWS_ACCESS_TOKEN", "tok-env")
	list, err := bwsList()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0] != (bwsSecret{Key: "shop__A", Value: "1"}) {
		t.Errorf("list %+v", list)
	}
	seen, _ := os.ReadFile(filepath.Join(dir, "seen"))
	if strings.TrimSpace(string(seen)) != "tok-env --output json secret list" {
		t.Errorf("bws saw %q", seen)
	}
}

// A failed bws is reported by the server's line, and the token never reaches the error.
func TestBWSListFailure(t *testing.T) {
	fakeBin(t, map[string]string{
		"bws": `echo "Error: 
  0: Received error message from server: [429 Too Many Requests] Slow down
Backtrace omitted. Run with RUST_BACKTRACE=1 to display it. $BWS_ACCESS_TOKEN" >&2
exit 1`,
	})
	t.Setenv("BWS_ACCESS_TOKEN", "tok-secret")
	_, err := bwsList()
	if err == nil || !strings.Contains(err.Error(), "Slow down") || strings.Contains(err.Error(), "tok-secret") {
		t.Fatalf("got %v", err)
	}
}

// On macOS a shell without BWS_ACCESS_TOKEN takes the token from the keychain item bws-claude-token.
func TestBWSListKeychainToken(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain fallback is macOS only")
	}
	dir := fakeBin(t, map[string]string{
		"security": `[ "$*" = "find-generic-password -s bws-claude-token -w" ] || exit 44
echo tok-keychain`,
		"bws": `echo "$BWS_ACCESS_TOKEN" > "$(dirname "$0")/seen"; echo '[]'`,
	})
	t.Setenv("BWS_ACCESS_TOKEN", "")
	if _, err := bwsList(); err != nil {
		t.Fatal(err)
	}
	if seen, _ := os.ReadFile(filepath.Join(dir, "seen")); strings.TrimSpace(string(seen)) != "tok-keychain" {
		t.Errorf("bws saw token %q", seen)
	}
}

// Neither the environment nor the keychain has a token: refused before bws runs.
func TestBWSListNoToken(t *testing.T) {
	fakeBin(t, map[string]string{"security": "exit 44", "bws": "exit 99"})
	t.Setenv("BWS_ACCESS_TOKEN", "")
	if _, err := bwsList(); err == nil || !strings.Contains(err.Error(), "BWS_ACCESS_TOKEN is not set") {
		t.Fatalf("got %v", err)
	}
}
