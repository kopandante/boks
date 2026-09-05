package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimal = `
app: demo
image: ghcr.io/x/y
servers: [lab]
ports:
  - {name: web, port: 3000, host: demo.example.com}
`

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != DefaultNetwork || cfg.ProxyImage != DefaultProxyImage ||
		cfg.Keep != DefaultKeep || cfg.DeployTimeout != DefaultDeployTimeout {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"app: Demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]":                       "app:",
		"app: demo\nservers: [a]\nports: [{name: w, port: 1, host: h}]":                                 "image",
		"app: demo\nimage: x\nports: [{name: w, port: 1, host: h}]":                                     "servers",
		"app: demo\nimage: x\nservers: [a]":                                                             "ports",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 70000, host: h}]":                   "out of range",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1}]":                                "host is required",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\nvolumes: [data]":      "volumes",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\ndeploy_timeout: soon": "deploy_timeout",
	}
	for in, want := range cases {
		_, err := Parse([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", in, want, err)
		}
	}
}

func TestEnvContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Dir: dir, EnvFile: ".env", Env: map[string]string{"C": "3", "B": "2"}}
	got, err := cfg.EnvContent()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "A=1\nB=2\nC=3\n" {
		t.Errorf("got %q", got)
	}
}

func TestEnvContentEmpty(t *testing.T) {
	got, err := (&Config{}).EnvContent()
	if err != nil || len(got) != 0 {
		t.Errorf("want empty, got %q %v", got, err)
	}
}
