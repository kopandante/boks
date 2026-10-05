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
	if cfg.Network.Kind != 0 || cfg.ProxyImage != DefaultProxyImage ||
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
	for _, v := range []string{"boks-test", `""`, "", "~"} {
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

// `uses` names apps: an invalid name, the app itself or a name twice is refused; the apps it names
// add their networks after the app's own, in order, without an alias.
func TestUsesNamesOtherApps(t *testing.T) {
	for v, want := range map[string]string{"[Cache]": "must be an app name", "[demo]": "is this app", "[cache, cache]": "named twice"} {
		if _, err := Parse([]byte("app: demo\nimage: x\nservers: [a]\nuses: " + v + "\n")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("uses: %s: want %q, got %v", v, want, err)
		}
	}
	cfg, err := Parse([]byte("app: demo\nimage: x\nservers: [a]\nuses: [convex, cache]\n"))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.Networks()
	if len(n) != 3 || n[1].Name != "boks-convex" || n[2].Name != "boks-cache" || len(n[1].Aliases) != 0 {
		t.Errorf("want the app's own network, then boks-convex and boks-cache without aliases: %v", n)
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

const depot = "app: demo\nimage: registry.depot.dev/nfj4ttf4bx\nservers: [a]\n"

func TestParseRegistry(t *testing.T) {
	cfg, err := Parse([]byte(depot + "registry: {host: registry.depot.dev, token_env: DEPOT_TOKEN}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r := cfg.Registry; r == nil || r.Host != "registry.depot.dev" || r.TokenEnv != "DEPOT_TOKEN" || r.User != DefaultRegistryUser {
		t.Errorf("registry: %+v", cfg.Registry)
	}
	cfg, err = Parse([]byte("app: demo\nimage: ghcr.io/me/app\nservers: [a]\nregistry: {host: ghcr.io, user: me, token_env: GHCR_TOKEN}\n"))
	if err != nil || cfg.Registry.User != "me" {
		t.Errorf("an explicit user is kept: %+v, %v", cfg.Registry, err)
	}
	// Docker Hub files its login under another key than its logout looks for: the token would stay.
	for _, hub := range []string{"docker.io", "index.docker.io", "registry-1.docker.io"} {
		_, err := Parse([]byte("app: demo\nimage: " + hub + "/myorg/private\nservers: [a]\nregistry: {host: " + hub + ", token_env: HUB_TOKEN}\n"))
		if err == nil || !strings.Contains(err.Error(), "is Docker Hub") {
			t.Errorf("%s: want Docker Hub refused, got %v", hub, err)
		}
	}
	if cfg, err := Parse([]byte(depot)); err != nil || cfg.Registry != nil {
		t.Errorf("without the block the image is public: %+v, %v", cfg, err)
	}
}

func TestParseRejectsRegistry(t *testing.T) {
	cases := map[string]string{
		"registry:\n":    "the block is empty",
		"registry: ~\n":  "the block is empty",
		"registry: {}\n": "registry.host is required",
		"registry: {host: http://registry.depot.dev, token_env: T}\n":                                            "HTTP registries are not supported",
		"registry: {host: HTTP://registry.depot.dev, token_env: T}\n":                                            "HTTP registries are not supported",
		"registry: {host: https://registry.depot.dev, token_env: T}\n":                                           "write the host alone",
		"registry: {host: registry.depot.dev/nfj4ttf4bx, token_env: T}\n":                                        "without a path",
		"registry: {host: Registry.Depot.dev, token_env: T}\n":                                                   "is not a registry host",
		"registry: {host: depot, token_env: T}\n":                                                                "is not a registry host",
		"registry: {host: 127.0.0.1:5000, token_env: T}\n":                                                       "loopback",
		"registry: {host: registry.depot.dev}\n":                                                                 "registry.token_env",
		"registry: {host: registry.depot.dev, token_env: depot_token}\n":                                         "registry.token_env",
		"registry: {host: registry.depot.dev, token_env: \"$DEPOT_TOKEN\"}\n":                                    "registry.token_env",
		"registry: {host: registry.depot.dev, token_env: T, user: \"a b\"}\n":                                    "registry.user",
		"registry: {host: registry.depot.dev, token_env: T, token: abc}\n":                                       "field token not found",
		"registry: {host: ghcr.io, token_env: T}\n":                                                              "not on registry.host ghcr.io",
		"registry: {host: registry.depot.dev, token_env: T}\nproxy_image: registry.depot.dev/nfj4ttf4bx:proxy\n": "proxy_image",
	}
	for in, want := range cases {
		_, err := Parse([]byte(depot + in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", in, want, err)
		}
	}
	// localhost has no dot and fails the host form before the loopback check; either way it is refused.
	if _, err := Parse([]byte("app: demo\nimage: localhost:5000/x\nservers: [a]\nregistry: {host: localhost:5000, token_env: T}\n")); err == nil {
		t.Error("a registry on localhost must be refused")
	}
}

func TestRegistryToken(t *testing.T) {
	r := &Registry{Host: "registry.depot.dev", TokenEnv: "DEPOT_TOKEN"}
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	if _, err := r.Token(env(nil)); err == nil || !strings.Contains(err.Error(), "DEPOT_TOKEN is not set") {
		t.Errorf("unset: %v", err)
	}
	if _, err := r.Token(env(map[string]string{"DEPOT_TOKEN": " \n"})); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("blank: %v", err)
	}
	// A space or \r pasted with the token would reach the registry and read as a wrong token.
	if v, err := r.Token(env(map[string]string{"DEPOT_TOKEN": " tok\r\n"})); err != nil || v != "tok" {
		t.Errorf("set: %q, %v", v, err)
	}
}

func TestImageHost(t *testing.T) {
	for ref, want := range map[string]string{
		"registry.depot.dev/nfj4ttf4bx:v1":        "registry.depot.dev",
		"registry.depot.dev/nfj4ttf4bx@sha256:ab": "registry.depot.dev",
		"ghcr.io/x/y":                  "ghcr.io",
		"10.0.0.5:5000/app":            "10.0.0.5:5000",
		"localhost/app":                "localhost",
		"basecamp/kamal-proxy:v0.10.0": "docker.io",
		"redis:8":                      "docker.io",
	} {
		if got := ImageHost(ref); got != want {
			t.Errorf("ImageHost(%q) = %q, want %q", ref, got, want)
		}
	}
	r := &Registry{Host: "registry.depot.dev"}
	if !r.Logs("registry.depot.dev/p:v1") || r.Logs("ghcr.io/x/y:v1") || (*Registry)(nil).Logs("registry.depot.dev/p:v1") {
		t.Error("Logs must hold for images on the host only, and never without a registry")
	}
}

// healthcheck gives a stock image the health check an app without routes is judged by. The interval
// is filled in, so a release records what it ran with; one the deploy could never wait out is refused.
func TestParseHealthcheck(t *testing.T) {
	const bot = "app: bot\nimage: postgres\nservers: [a]\n"
	cfg, err := Parse([]byte(bot + "healthcheck: {cmd: pg_isready -U postgres}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h := cfg.Healthcheck; h == nil || h.Cmd != "pg_isready -U postgres" || h.Interval != "5s" {
		t.Errorf("want the command and the default interval, got %+v", h)
	}
	rejects := map[string]string{
		bot + "healthcheck:\n":                                              "the block is empty",
		bot + "healthcheck: {interval: 5s}\n":                               "healthcheck.cmd is required",
		bot + "healthcheck: {cmd: \"  \"}\n":                                "healthcheck.cmd is required",
		bot + "healthcheck: {cmd: x, interval: 5}\n":                        "at least 1ms",
		bot + "healthcheck: {cmd: x, interval: 0s}\n":                       "at least 1ms",
		bot + "healthcheck: {cmd: x, interval: -1s}\n":                      "at least 1ms",
		bot + "healthcheck: {cmd: x, interval: 500us}\n":                    "at least 1ms", // docker's minimum
		bot + "healthcheck: {cmd: x, interval: 60s}\n":                      "not shorter than deploy_timeout",
		bot + "deploy_timeout: 10s\nhealthcheck: {cmd: x, interval: 30s}\n": "not shorter than deploy_timeout",
		bot + "healthcheck: {cmd: x, test: y}\n":                            "test", // strict inside the block too
	}
	for in, want := range rejects {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", in, want, err)
		}
	}
}

// files mount a file of the repository at a path in the container: the path goes to `docker run -v`,
// so it is clean and absolute, without the colon -v splits on, and no two files share it.
func TestParseFiles(t *testing.T) {
	const bot = "app: bot\nimage: nginx\nservers: [a]\nports: [{name: w, port: 80, host: h}]\n"
	if _, err := Parse([]byte(bot + "files: [nginx.conf:/etc/nginx/conf.d/default.conf]\n")); err != nil {
		t.Fatal(err)
	}
	rejects := map[string]string{
		bot + "files: [nginx.conf]\n":         "must be local/path:/absolute",
		bot + "files: [\":/etc/x\"]\n":        "must be local/path:/absolute",
		bot + "files: [a:etc/x]\n":            "clean absolute path",
		bot + "files: [a:/]\n":                "clean absolute path",
		bot + "files: [a:/etc/../x]\n":        "clean absolute path",
		bot + "files: [a:/etc/x/]\n":          "clean absolute path",
		bot + "files: [\"a:/etc/x:ro\"]\n":    "cannot contain a colon",
		bot + "files: [a:/etc/x, b:/etc/x]\n": "target of two files",
	}
	for in, want := range rejects {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", in, want, err)
		}
	}
}

// The files are read from beside boks.yml, and two sources with one base name stay apart on the server.
func TestFileContents(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"a/site.conf": "A", "b/site.conf": "B"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{Dir: dir, Files: []string{"a/site.conf:/etc/a.conf", "b/site.conf:/etc/b.conf"}}
	got, err := cfg.FileContents()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name == got[1].Name || string(got[0].Body) != "A" || got[1].Target != "/etc/b.conf" {
		t.Errorf("want two files under distinct names, got %+v", got)
	}
	cfg.Files = []string{"missing.conf:/etc/m.conf"}
	if _, err := cfg.FileContents(); err == nil || !strings.Contains(err.Error(), "missing.conf") {
		t.Errorf("a file that cannot be read must refuse the deploy, got %v", err)
	}
}
