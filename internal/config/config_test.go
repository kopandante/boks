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
	if cfg.Network != nil || cfg.ProxyImage != DefaultProxyImage ||
		cfg.Keep != DefaultKeep || cfg.DeployTimeout != DefaultDeployTimeout {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"app: Demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]":                              "app:",
		"app: demo\nservers: [a]\nports: [{name: w, port: 1, host: h}]":                                        "image",
		"app: demo\nimage: x\nports: [{name: w, port: 1, host: h}]":                                            "servers",
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

// Every app has its own network now, so a `network` key would go on saying something that is no
// longer so: it is refused by name, empty or not, rather than left to mean nothing.
func TestParseRefusesTheNetworkKey(t *testing.T) {
	for _, v := range []string{"boks-test", `""`} {
		_, err := Parse([]byte("app: demo\nimage: x\nservers: [a]\nnetwork: " + v + "\n"))
		if err == nil || !strings.Contains(err.Error(), "own network boks-demo") {
			t.Errorf("network: %s: want the refusal naming the app's network, got %v", v, err)
		}
	}
}

// The app's containers start on boks-<app> under the app's name; a recorded release's networks,
// when a rollback sets them, are what they join instead.
func TestNetworksAreTheAppsOwnUnlessRecorded(t *testing.T) {
	cfg, err := Parse([]byte("app: demo\nimage: x\nservers: [a]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n := cfg.Networks(); len(n) != 1 || n[0].Name != "boks-demo" || len(n[0].Aliases) != 1 || n[0].Aliases[0] != "demo" {
		t.Errorf("want boks-demo with the alias demo, got %v", n)
	}
	cfg.Attach = []Network{{Name: "boks-demo", Aliases: []string{"api"}}}
	if n := cfg.Networks(); len(n) != 1 || n[0].Aliases[0] != "api" {
		t.Errorf("want the recorded networks, got %v", n)
	}
}

// An app that publishes nothing (a bot, a worker) is a valid shape: it is judged by the image's
// own HEALTHCHECK instead of by a route.
func TestParseAcceptsAnAppWithoutPorts(t *testing.T) {
	cfg, err := Parse([]byte("app: bot\nimage: ghcr.io/x/bot\nservers: [lab]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ports) != 0 {
		t.Errorf("want no ports, got %v", cfg.Ports)
	}
}

func TestParseIsStrict(t *testing.T) {
	cases := map[string]string{
		minimal + "volums: [data:/x]\n":  "volums",
		minimal + "---\n" + minimal:      "more than one",
		minimal + "---\nfoo: 1\n":        "more than one",
		minimal + "---\nfoo\n":           "more than one",
		minimal + "---\n---\n" + minimal: "more than one",
		minimal + "---\n: [\n":           "after the first",
		"":                               "empty",
	}
	for in, want := range cases {
		_, err := Parse([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", in, want, err)
		}
	}
}

// A trailing `---` is an empty document, not a second app: nothing in it goes unread, and such
// files parsed before strict decoding.
func TestParseAcceptsEmptyTrailingDocument(t *testing.T) {
	for _, tail := range []string{"---\n", "---\n# end\n", "---\n~\n", "...\n---\n"} {
		if _, err := Parse([]byte(minimal + tail)); err != nil {
			t.Errorf("%q: %v", tail, err)
		}
	}
}

// The shipped example has to keep parsing: strict decoding turns any drift between it and the
// schema into a failure here rather than into a surprise on someone's first deploy.
func TestExampleParses(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "examples", "convex-lab", "boks.yml")); err != nil {
		t.Fatal(err)
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

// memory is docker's format narrowed to what cannot be misread, and replace names one of two modes;
// an app without routes has no handover to overlap, so saying it would is a mistake in the config.
func TestParseResources(t *testing.T) {
	const routed = "app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\n"
	const bot = "app: bot\nimage: x\nservers: [a]\n"
	rejects := map[string]string{
		routed + "memory: 512":          "not a memory size", // docker would read bytes
		routed + "memory: 512mb":        "not a memory size", // a suffix that means different things to different parsers
		routed + "memory: 1.5g":         "not a memory size", // fractions
		routed + "memory: -1g":          "not a memory size",
		routed + "memory: 0m":           "not a memory size",
		routed + "memory: 5m":           "below docker's minimum",
		routed + "memory: 99999999999g": "too large",
		routed + "replace: rolling":     "replace:",
		bot + "replace: overlap":        "always replaced stop-first",
	}
	for in, want := range rejects {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", in, want, err)
		}
	}
	accepts := map[string]int64{"6m": 6 << 20, "512m": 512 << 20, "1g": 1 << 30, "2G": 2 << 30, "65536k": 64 << 20, "8388608b": 8 << 20}
	for in, bytes := range accepts {
		cfg, err := Parse([]byte(routed + "memory: " + in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if n, _ := MemoryBytes(cfg.Memory); n != bytes {
			t.Errorf("%s: want %d bytes, got %d", in, bytes, n)
		}
	}
}

func TestReplaceMode(t *testing.T) {
	cases := map[string]string{
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\n":                      ReplaceOverlap,
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\nreplace: overlap\n":    ReplaceOverlap,
		"app: demo\nimage: x\nservers: [a]\nports: [{name: w, port: 1, host: h}]\nreplace: stop-first\n": ReplaceStopFirst,
		"app: bot\nimage: x\nservers: [a]\n":                                                             ReplaceStopFirst,
		"app: bot\nimage: x\nservers: [a]\nreplace: stop-first\n":                                        ReplaceStopFirst,
	}
	for in, want := range cases {
		cfg, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := cfg.ReplaceMode(); got != want {
			t.Errorf("%q: want %s, got %s", in, want, got)
		}
	}
}

// The shipped example is what people copy: it must parse, and Convex on SQLite in it is replaced
// stop-first.
func TestTheExampleParses(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "examples", "convex-lab", "boks.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReplaceMode() != ReplaceStopFirst {
		t.Errorf("convex-lab keeps SQLite on its volume: want stop-first, got %s", cfg.ReplaceMode())
	}
}
