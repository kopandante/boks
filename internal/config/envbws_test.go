package config

import (
	"errors"
	"os"
	"path/filepath"
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

// A fleet deploy builds the env of many apps in one process: one request to BWS, not one per app.
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
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("# c\nexport TOKEN=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		list []bwsSecret
		err  error
		cfg  Config
		want string
	}{
		{"set by env_file too", []bwsSecret{{Key: "s__TOKEN", Value: "v"}}, nil,
			Config{Dir: dir, EnvFile: ".env", EnvBWS: "s"}, "set by env_file too"},
		{"set by env too", []bwsSecret{{Key: "s__TOKEN", Value: "v"}}, nil,
			Config{EnvBWS: "s", Env: map[string]string{"TOKEN": "inline"}}, "set by env too"},
		{"twice in BWS", []bwsSecret{{Key: "s__T", Value: "1"}, {Key: "s__T", Value: "2"}}, nil,
			Config{EnvBWS: "s"}, "in BWS twice"},
		{"multi-line", []bwsSecret{{Key: "s__PEM", Value: "a\nb"}}, nil,
			Config{EnvBWS: "s"}, "spans several lines"},
		{"nothing for the app", []bwsSecret{{Key: "other__T", Value: "1"}}, nil,
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
			// A refused env carries no secret value into the error.
			for _, s := range c.list {
				if strings.Contains(err.Error(), "="+s.Value) {
					t.Errorf("error leaks a value: %v", err)
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
