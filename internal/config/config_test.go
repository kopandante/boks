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
		"app: Demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]":                              "app:",
		"app: demo\nservers: [a]\nports: [{name: w, port: 1, host: h}]":                                        "image",
		"app: demo\nimage: x\nports: [{name: w, port: 1, host: h}]":                                            "servers",
		"app: demo\nimage: x\nservers: [a]":                                                                    "ports",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 70000, host: h}]":                          "out of range",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1}]":                                       "host is required",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\nvolumes: [data]":             "volumes",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\ndeploy_timeout: soon":        "deploy_timeout",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: a}, {name: w, port: 2, host: b}]": "duplicate name",
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: a}, {name: v, port: 2, host: a}]": "duplicate host",
	}
	for in, want := range cases {
		_, err := Parse([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", in, want, err)
		}
	}
}

func TestCertCovers(t *testing.T) {
	c := &Cert{Domains: []string{"*.lab.example.com", "plain.example.com"}}
	covered := []string{"api.lab.example.com", "actions.lab.example.com", "plain.example.com"}
	for _, h := range covered {
		if !c.Covers(h) {
			t.Errorf("%s must be covered", h)
		}
	}
	// A wildcard matches exactly one label: the bare domain and a deeper name are not covered,
	// and neither is an unrelated host — those keep kamal-proxy's autocert.
	for _, h := range []string{"lab.example.com", "a.b.lab.example.com", "other.example.com", ""} {
		if c.Covers(h) {
			t.Errorf("%q must not be covered", h)
		}
	}
	if (*Cert)(nil).Covers("anything") {
		t.Error("no cert block covers nothing")
	}
}

func TestCertSlug(t *testing.T) {
	if got := (&Cert{Domains: []string{"*.lab.example.com"}}).Slug(); got != "_.lab.example.com" {
		t.Errorf("got %s, want lego's own naming", got)
	}
}

func TestCertRejects(t *testing.T) {
	base := "app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\ncert:\n"
	cases := map[string]string{
		"  dns: cloudflare\n  email: a@b.c\n":                                "cert.domains",
		"  domains: ['*.x.y']\n  email: a@b.c\n":                             "cert.dns",
		"  domains: ['*.x.y']\n  dns: cloudflare\n":                          "cert.email",
		"  domains: ['*.x.y']\n  dns: c\n  email: a@b.c\n  renew_days: -1\n": "renew_days",
	}
	for tail, want := range cases {
		if _, err := Parse([]byte(base + tail)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", tail, want, err)
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
