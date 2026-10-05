package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultProxyImage is pinned: a proxy that changes under a moving tag changes every app's routing.
	// 2.11.7 was the newest Caddy on Docker Hub on 2026-10-06, and the one boks-lab was measured with.
	DefaultProxyImage    = "caddy:2.11.7-alpine"
	DefaultKeep          = 3
	DefaultDeployTimeout = "60s"
	// DefaultDrainTimeout is kamal-proxy's: how long the previous copy may go on finishing the requests
	// it holds once the routes have moved, before it is stopped.
	DefaultDrainTimeout = "30s"
	// DefaultHealthInterval is shorter than docker's 30s on purpose: docker runs the first check only
	// after one interval, and a deploy without routes waits on that answer — at 30s a 60s deploy_timeout
	// would see two checks at most.
	DefaultHealthInterval = "5s"

	// ReplaceOverlap starts the new copy beside the old one and moves the routes once it is healthy:
	// no downtime, but for a moment two copies run, on the same volumes.
	ReplaceOverlap = "overlap"
	// ReplaceStopFirst stops the old copy before the new one starts, for storage that takes one
	// writer at a time (SQLite): two copies on one volume could corrupt it. The app is down for the
	// length of the swap.
	ReplaceStopFirst = "stop-first"
)

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	// memoryRe is docker's own format narrowed to what cannot be misread: a whole number and a unit.
	// Docker takes a bare number as bytes, so `memory: 512` would be a 512-byte limit no container
	// survives; fractions and suffixes like `MB` or `GiB` are left out because they read as one thing
	// and mean another depending on who parses them.
	memoryRe = regexp.MustCompile(`^([1-9][0-9]*)([bkmgBKMG])$`)
	// registryHostRe is a registry as docker names it in an image reference: a lowercase DNS name with
	// at least one dot, or an IPv4 address, and an optional port. No scheme and no path — the
	// repository belongs in image.
	registryHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$`)
	envNameRe      = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	// signalRe is a signal as docker names it, written the one way that cannot be misread.
	signalRe       = regexp.MustCompile(`^SIG[A-Z0-9]+$`)
	registryUserRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*$`)
)

// DefaultRegistryUser is the user name Depot's registry takes with a token as the password.
const DefaultRegistryUser = "x-token"

// minMemory is the smallest limit docker accepts; below it `docker run` refuses, and it is better
// to hear that from the config than from a half-done deploy.
const minMemory = 6 << 20

// Port is one published port of the app, routed by the proxy under its own host.
// The json tags are load-bearing, not decoration: a deploy stores this spec verbatim in the
// container's `boks.ports` label and in the release snapshot a rollback reads back, so the
// field names must survive a rename of the Go fields.
type Port struct {
	Name       string `yaml:"name" json:"name"`
	Port       int    `yaml:"port" json:"port"`
	Host       string `yaml:"host" json:"host"`
	HealthPath string `yaml:"health_path" json:"health_path"`
	HealthPort int    `yaml:"health_port" json:"health_port"`
}

// Network is a Docker network a container of the app joins, with the aliases it answers to there.
// The json tags are load-bearing: a release snapshot stores the networks verbatim, and a rollback
// reads them back to put the container where that release had it.
type Network struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// AppNetwork is the network an app's containers are started on. The app's name is their alias in
// it, so whoever shares the network reaches the app by name across deploys, while the container's
// own name changes with every one.
func AppNetwork(app string) string { return "boks-" + app }

// Networks are the networks a container of the app joins, the one it is started on first. Attach,
// when a rollback sets it, is what the release recorded; otherwise it is the app's own network,
// with the app's name as the alias, then the network of each app it uses, without an alias: the
// container reaches them there, and none of them reaches it.
func (c *Config) Networks() []Network {
	if len(c.Attach) > 0 {
		return c.Attach
	}
	nets := []Network{{Name: AppNetwork(c.App), Aliases: []string{c.App}}}
	for _, dep := range c.Uses {
		nets = append(nets, Network{Name: AppNetwork(dep)})
	}
	return nets
}

// Healthcheck is the container's health check when the config gives one: it sets the image's
// HEALTHCHECK or replaces it, so a stock image that declares none (postgres, redis) can still run
// without routes or be used by another app. The json tags are load-bearing: a release snapshot
// stores it verbatim, and a rollback starts the restored copy with it.
type Healthcheck struct {
	// Cmd is run by `sh -c` inside the container, as docker's CMD-SHELL; exit 0 is healthy.
	Cmd      string `yaml:"cmd" json:"cmd"`
	Interval string `yaml:"interval" json:"interval"`
}

// Schedule is a shell command run on a cron schedule inside the copy of the app that serves at that
// moment — what Dokploy calls an application schedule. The json tags are load-bearing: a release
// snapshot stores the schedules verbatim, and a rollback brings back the ones that release had.
type Schedule struct {
	Name string `yaml:"name" json:"name"`
	// Cron is five fields — minute, hour, day of month, month, day of week — in the server's cron,
	// which runs in UTC on our servers.
	Cron string `yaml:"cron" json:"cron"`
	// Command is run by `sh` inside the container, as its default user and in its working directory.
	Command string `yaml:"command" json:"command"`
}

// Cert describes a certificate obtained by lego over DNS-01 — the case the proxy's automatic HTTPS
// cannot serve, because a wildcard has no HTTP-01 challenge. Hosts not covered by it keep using
// automatic HTTPS, so an app can mix both.
type Cert struct {
	Domains   []string `yaml:"domains"`
	DNS       string   `yaml:"dns"`   // lego provider name, e.g. "cloudflare"
	Email     string   `yaml:"email"` // ACME account
	Path      string   `yaml:"path"`  // local lego state, relative to boks.yml
	Staging   bool     `yaml:"staging"`
	RenewDays int      `yaml:"renew_days"` // 0 = lego's own schedule (a third of the lifetime)
}

// Config is the parsed boks.yml of one app.
type Config struct {
	Cert    *Cert    `yaml:"cert"`
	App     string   `yaml:"app"`
	Image   string   `yaml:"image"`
	Servers []string `yaml:"servers"`
	// Network is read only to refuse it: every app now has its own network, AppNetwork. A key that
	// went on being accepted would keep meaning something it no longer does. A node rather than a
	// string, because only a node tells a key written with no value (`network:`) from no key at all.
	Network       yaml.Node         `yaml:"network"`
	ProxyImage    string            `yaml:"proxy_image"`
	EnvFile       string            `yaml:"env_file"`
	Env           map[string]string `yaml:"env"`
	Volumes       []string          `yaml:"volumes"`
	Ports         []Port            `yaml:"ports"`
	TLS           bool              `yaml:"tls"`
	Keep          int               `yaml:"keep"`
	DeployTimeout string            `yaml:"deploy_timeout"`
	// DrainTimeout bounds the wait for the previous copy's requests in flight after a switch.
	DrainTimeout string `yaml:"drain_timeout"`
	// Memory is the container's hard memory limit in docker's format (512m, 1g); empty means none.
	Memory string `yaml:"memory"`
	// Healthcheck is the container's health check; nil leaves the image's HEALTHCHECK, if any.
	Healthcheck *Healthcheck `yaml:"healthcheck"`
	// Command replaces the image's CMD, in exec form: the program, then its arguments, passed as they
	// are. There is no shell, so `$VAR` is not expanded; an app that needs a variable writes the shell
	// itself — ["sh", "-c", "exec redis-server --requirepass \"$REDIS_PASSWORD\""], `exec` so that the
	// stop signal reaches the program rather than the shell — and the secret stays in the environment
	// file rather than in boks.yml. The image's ENTRYPOINT, if any, still runs and receives these as its
	// arguments. Empty leaves the image's CMD.
	Command []string `yaml:"command"`
	// StopSignal is what `docker stop` sends in place of the image's STOPSIGNAL (SIGTERM unless the
	// image says otherwise): self-hosted Convex shuts down cleanly on SIGINT.
	StopSignal string `yaml:"stop_signal"`
	// Schedules are commands cron runs inside the serving copy of the app.
	Schedules []Schedule `yaml:"schedules"`
	// Files are files of the app's repository the container reads, each `local:/container/path`,
	// the local path relative to boks.yml. Every release gets its own copy on the server, mounted
	// read-only, so a rollback reads the files it ran with.
	Files []string `yaml:"files"`
	// Replace is how a new version takes over from the old one: ReplaceOverlap or ReplaceStopFirst.
	// Empty means the default for the app's shape, which ReplaceMode tells.
	Replace string `yaml:"replace"`
	// Uses names the apps this one reaches. Its containers join their networks and reach each by the
	// app's name, its alias there. It is membership, not access control: two apps that use one
	// dependency share its network and see each other.
	Uses []string `yaml:"uses"`
	// Registry is the private registry the image is pulled from: boks logs in to it on the server for
	// each pull and logs out once the pull is over. Nil means the image is public and pulled without a
	// login, as before.
	Registry *Registry `yaml:"registry"`
	// Attach overrides Networks with what a recorded release joined; never read from boks.yml.
	Attach []Network `yaml:"-"`
	Dir    string    `yaml:"-"`
}

// Registry is a private registry reached over HTTPS with a token (E2). The token itself is never in
// boks.yml and never kept on a server: boks reads it from the environment it runs in — the
// operator's shell or CI — under the name TokenEnv, and hands it to `docker login` on stdin.
type Registry struct {
	Host     string `yaml:"host"`      // registry.depot.dev; the image must live on this host
	User     string `yaml:"user"`      // DefaultRegistryUser when empty
	TokenEnv string `yaml:"token_env"` // the environment variable holding the token, e.g. DEPOT_TOKEN
}

// Token reads the registry's token from the environment through lookup (os.LookupEnv outside
// tests). A token the config declares and the environment does not hold is a refusal (E6), and one
// that is set but blank is the same thing: a login without a password would fail on the server, and
// only after the deploy had begun. Whitespace around it is dropped: no token has any, and a space or
// \r pasted along with one would reach the registry, which turns it down as a wrong token.
func (r *Registry) Token(lookup func(string) (string, bool)) (string, error) {
	v, ok := lookup(r.TokenEnv)
	if !ok {
		return "", fmt.Errorf("registry.token_env: %s is not set in the environment boks runs in; "+
			"export the token of %s under that name", r.TokenEnv, r.Host)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("registry.token_env: %s is set but empty; it must hold the token of %s", r.TokenEnv, r.Host)
	}
	return v, nil
}

// ImageHost is the registry an image reference names, by docker's rule: the part before the first
// slash when it has a dot or a colon in it or is localhost, and Docker Hub otherwise.
func ImageHost(ref string) string {
	first, _, ok := strings.Cut(ref, "/")
	if ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first
	}
	return "docker.io"
}

// Logs reports whether pulling ref goes through the login to r. A release recorded before the image
// moved to the registry names another host, and is pulled as it was then, without a login.
func (r *Registry) Logs(ref string) bool {
	return r != nil && ImageHost(ref) == r.Host
}

// ReplaceMode is how this app's versions take turns. An app without routes has no traffic to hand
// over, and two copies of a worker would drain one queue twice, so it is always stop-first; an app
// with routes overlaps unless the config says otherwise.
func (c *Config) ReplaceMode() string {
	if len(c.Ports) == 0 || c.Replace == ReplaceStopFirst {
		return ReplaceStopFirst
	}
	return ReplaceOverlap
}

// MemoryBytes reads a limit written in the format Memory accepts. Empty is no limit, and 0.
func MemoryBytes(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	m := memoryRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("%q is not a memory size such as 512m or 1g", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is too large", s)
	}
	shift := map[string]uint{"b": 0, "k": 10, "m": 20, "g": 30}[strings.ToLower(m[2])]
	if n > math.MaxInt64>>shift {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return n << shift, nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Dir = filepath.Dir(path)
	return cfg, nil
}

func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Strict about unknown keys, because the alternative is silence: a misspelled `volums:` used
	// to leave the app running with no volumes and say nothing. It matters more once two versions
	// of boks exist — an old binary would otherwise accept a config written for the new format and
	// drop every field it does not know.
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the file is empty")
		}
		return nil, err
	}
	// A block key with nothing after it decodes to no block at all. `registry:` would then pull the
	// image without a login — which fails on the server, after the deploy began, and reads as a
	// registry outage rather than as the half-written block it is; `healthcheck:` would leave the
	// image's own check, or none, in force.
	var probe struct {
		Registry    yaml.Node `yaml:"registry"`
		Healthcheck yaml.Node `yaml:"healthcheck"`
		Command     yaml.Node `yaml:"command"`
	}
	if yaml.Unmarshal(data, &probe) == nil {
		if cfg.Registry == nil && probe.Registry.Kind != 0 {
			return nil, errors.New("registry: the block is empty; give host and token_env, or remove the key for a public image")
		}
		// A null element (`~`, or a bare `-`) decodes to nothing rather than to "": `[redis-server, --save, ~]`
		// would run without the argument and shift the ones after it. An empty argument is written "".
		// An alias (`command: *cmd`) is decoded through to the list it names, and so is checked there.
		seq := &probe.Command
		for seq.Kind == yaml.AliasNode && seq.Alias != nil {
			seq = seq.Alias
		}
		if seq.Kind == yaml.SequenceNode && len(seq.Content) != len(cfg.Command) {
			return nil, errors.New(`command: an element is null; write "" for an empty argument`)
		}
		// `command:` or `command: []` would start the image's own CMD while the config looks as if it set one.
		if len(cfg.Command) == 0 && probe.Command.Kind != 0 {
			return nil, errors.New("command: give the program and its arguments, or remove the key to keep the image's CMD")
		}
		if cfg.Healthcheck == nil && probe.Healthcheck.Kind != 0 {
			return nil, errors.New("healthcheck: the block is empty; give cmd, or remove the key to keep the image's HEALTHCHECK")
		}
	}
	// Anything past the first document would be read by nobody, so refuse the file rather than
	// apply half of it. An empty document holds nothing that could go unread: a trailing `---`
	// (with or without a comment after it) parsed on earlier versions and still does.
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("YAML document after the first: %w", err)
		}
		if !isEmptyDocument(&doc) {
			return nil, errors.New("more than one YAML document: boks reads one app per file")
		}
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// isEmptyDocument reports whether a decoded YAML document carries no value: nothing at all, or
// a bare null (what `---` with nothing after it decodes to).
func isEmptyDocument(doc *yaml.Node) bool {
	for _, n := range doc.Content {
		if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!null" {
			return false
		}
	}
	return true
}

func (c *Config) applyDefaults() {
	if c.ProxyImage == "" {
		c.ProxyImage = DefaultProxyImage
	}
	if c.Keep == 0 {
		c.Keep = DefaultKeep
	}
	if c.DeployTimeout == "" {
		c.DeployTimeout = DefaultDeployTimeout
	}
	if c.DrainTimeout == "" {
		c.DrainTimeout = DefaultDrainTimeout
	}
	if c.Registry != nil && c.Registry.User == "" {
		c.Registry.User = DefaultRegistryUser
	}
	// Filled in here rather than at `docker run`, so a release snapshot records the interval it ran
	// with and a rollback keeps it even if the default changes.
	if c.Healthcheck != nil && c.Healthcheck.Interval == "" {
		c.Healthcheck.Interval = DefaultHealthInterval
	}
}

func (c *Config) validate() error {
	if !nameRe.MatchString(c.App) {
		return fmt.Errorf("app: %q must match %s", c.App, nameRe)
	}
	if c.Image == "" {
		return fmt.Errorf("image is required")
	}
	if len(c.Servers) == 0 {
		return fmt.Errorf("servers: at least one is required")
	}
	if c.Network.Kind != 0 {
		return fmt.Errorf("network: no longer set per app — each app runs on its own network %s, and the proxy joins it; "+
			"remove the key", AppNetwork(c.App))
	}
	if c.Keep < 1 {
		return fmt.Errorf("keep: must be at least 1")
	}
	if _, err := time.ParseDuration(c.DeployTimeout); err != nil {
		return fmt.Errorf("deploy_timeout: %q is not a duration such as 60s or 2m", c.DeployTimeout)
	}
	if d, err := time.ParseDuration(c.DrainTimeout); err != nil || d < 0 {
		return fmt.Errorf("drain_timeout: %q is not a duration such as 30s", c.DrainTimeout)
	}
	if err := c.validateResources(); err != nil {
		return err
	}
	if err := c.validateHealthcheck(); err != nil {
		return err
	}
	if len(c.Command) > 0 && strings.TrimSpace(c.Command[0]) == "" {
		return errors.New("command: the first element is the program to run and cannot be empty")
	}
	if c.StopSignal != "" && !signalRe.MatchString(c.StopSignal) {
		return fmt.Errorf("stop_signal: %q must be a signal name such as SIGINT or SIGQUIT", c.StopSignal)
	}
	if err := c.Cert.validate(); err != nil {
		return err
	}
	if err := c.validateRegistry(); err != nil {
		return err
	}
	return c.validateLists()
}

func (c *Config) validateResources() error {
	n, err := MemoryBytes(c.Memory)
	if err != nil {
		return fmt.Errorf("memory: %w", err)
	}
	if c.Memory != "" && n < minMemory {
		return fmt.Errorf("memory: %q is below docker's minimum of 6m", c.Memory)
	}
	switch c.Replace {
	case "", ReplaceStopFirst:
	case ReplaceOverlap:
		// Said explicitly, it would promise a handover that cannot happen: without a route there is
		// no traffic to move, and the old copy is always stopped first.
		if len(c.Ports) == 0 {
			return errors.New("replace: overlap needs ports; an app without routes is always replaced stop-first")
		}
	default:
		return fmt.Errorf("replace: %q must be %s or %s", c.Replace, ReplaceOverlap, ReplaceStopFirst)
	}
	return nil
}

func (c *Config) validateHealthcheck() error {
	h := c.Healthcheck
	if h == nil {
		return nil
	}
	if strings.TrimSpace(h.Cmd) == "" {
		return errors.New("healthcheck.cmd is required: a shell command run in the container, exit 0 meaning healthy, e.g. `pg_isready -U postgres`")
	}
	// Docker refuses an interval under a millisecond, and only at `docker run` — after stop-first has
	// already taken the running copy down.
	interval, err := time.ParseDuration(h.Interval)
	if err != nil || interval < time.Millisecond {
		return fmt.Errorf("healthcheck.interval: %q is not a duration of at least 1ms, such as 5s", h.Interval)
	}
	// Docker runs the first check one interval after the start, so a deploy that waits less than
	// that never sees an answer and always fails.
	if timeout, _ := time.ParseDuration(c.DeployTimeout); interval >= timeout {
		return fmt.Errorf("healthcheck.interval: %s is not shorter than deploy_timeout %s, so the deploy would end before the first check",
			h.Interval, c.DeployTimeout)
	}
	return nil
}

func (c *Config) validateRegistry() error {
	r := c.Registry
	if r == nil {
		return nil
	}
	switch {
	case r.Host == "":
		return errors.New("registry.host is required, e.g. registry.depot.dev")
	case strings.HasPrefix(strings.ToLower(r.Host), "http://"):
		return fmt.Errorf("registry.host: %q is plain HTTP, and HTTP registries are not supported: the token would cross the network in clear", r.Host)
	case strings.Contains(r.Host, "://"):
		return fmt.Errorf("registry.host: %q — write the host alone (registry.depot.dev); boks only speaks HTTPS to it", r.Host)
	case strings.Contains(r.Host, "/"):
		return fmt.Errorf("registry.host: %q — the host alone, without a path; the repository goes in image", r.Host)
	case !registryHostRe.MatchString(r.Host):
		return fmt.Errorf("registry.host: %q is not a registry host such as registry.depot.dev (lowercase, no scheme, optional :port)", r.Host)
	}
	// Docker talks plain HTTP to a registry on a loopback address unless told otherwise, so a token
	// sent there would cross in clear — the case E2 rules out. localhost never gets here: it has no
	// dot, and the form above refuses it.
	name, _, _ := strings.Cut(r.Host, ":")
	if ip := net.ParseIP(name); ip != nil && ip.IsLoopback() {
		return fmt.Errorf("registry.host: %q is a loopback address, which docker reaches over plain HTTP; HTTP registries are not supported", r.Host)
	}
	// Docker files a Docker Hub login under https://index.docker.io/v1/ and looks for another key on
	// `docker logout docker.io`, which then finds nothing, succeeds, and leaves the token on the
	// server. Until that is handled, Docker Hub is no private registry boks logs in to.
	switch name {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return fmt.Errorf("registry.host: %q is Docker Hub, whose logout by host name leaves the token on the server; "+
			"boks does not log in to it — use a registry such as registry.depot.dev", r.Host)
	}
	if !envNameRe.MatchString(r.TokenEnv) {
		return fmt.Errorf("registry.token_env: %q must name an environment variable (%s), e.g. DEPOT_TOKEN — the token itself never goes in boks.yml",
			r.TokenEnv, envNameRe)
	}
	if !registryUserRe.MatchString(r.User) {
		return fmt.Errorf("registry.user: %q must match %s", r.User, registryUserRe)
	}
	// The login is to one host; an image elsewhere would be pulled without it and fail on the server.
	if h := ImageHost(c.Image); h != r.Host {
		return fmt.Errorf("image: %s is on %s, not on registry.host %s; boks logs in to %s only", c.Image, h, r.Host, r.Host)
	}
	// The proxy is booted by `docker run`, which pulls without the login.
	if r.Logs(c.ProxyImage) {
		return fmt.Errorf("proxy_image: %s is on the private registry %s, and the proxy is pulled without a login; use a public proxy image",
			c.ProxyImage, r.Host)
	}
	return nil
}

func (c *Cert) validate() error {
	if c == nil {
		return nil
	}
	if len(c.Domains) == 0 {
		return fmt.Errorf("cert.domains: at least one is required")
	}
	if c.DNS == "" {
		return fmt.Errorf("cert.dns: lego provider name is required (see `lego dnshelp`)")
	}
	if c.Email == "" {
		return fmt.Errorf("cert.email: required for the ACME account")
	}
	if c.RenewDays < 0 {
		return fmt.Errorf("cert.renew_days: must not be negative")
	}
	return nil
}

// Covers reports whether host is served by this certificate. A wildcard matches exactly one
// label, as in RFC 6125: `*.example.com` covers `api.example.com` but neither `example.com`
// nor `a.b.example.com`.
func (c *Cert) Covers(host string) bool {
	if c == nil {
		return false
	}
	for _, d := range c.Domains {
		if d == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(d, "*."); ok {
			if rest, found := strings.CutSuffix(host, "."+suffix); found && rest != "" &&
				!strings.Contains(rest, ".") {
				return true
			}
		}
	}
	return false
}

// Slug names the certificate files. lego writes one SAN certificate for the whole domain list,
// named after the first entry with `*` replaced by `_`.
func (c *Cert) Slug() string {
	if c == nil || len(c.Domains) == 0 {
		return ""
	}
	return strings.ReplaceAll(c.Domains[0], "*", "_")
}

// LegoPath is the local lego state directory, resolved against the config's own directory.
func (c *Config) LegoPath() string {
	p := ".lego"
	if c.Cert != nil && c.Cert.Path != "" {
		p = c.Cert.Path
	}
	return c.resolve(p)
}

func (c *Config) validateLists() error {
	// No ports is a real shape, not an oversight: a bot or a background worker publishes nothing
	// and is judged by its container's health check — the image's HEALTHCHECK or the config's
	// healthcheck block — instead of by a route.
	seenName, seenHost := map[string]bool{}, map[string]bool{}
	for _, p := range c.Ports {
		if err := p.validate(); err != nil {
			return err
		}
		if seenName[p.Name] {
			return fmt.Errorf("ports: duplicate name %q", p.Name)
		}
		// Two ports on one host would be two routes for one host: the proxy would send it to the
		// first and never to the second.
		if seenHost[p.Host] {
			return fmt.Errorf("ports: duplicate host %q", p.Host)
		}
		seenName[p.Name], seenHost[p.Host] = true, true
	}
	for _, v := range c.Volumes {
		if err := validateVolume(v); err != nil {
			return err
		}
	}
	// Each server's cron runs the jobs in that server's copy, so an app on several servers would run
	// every job once per server, at the same moment. Until one of them is chosen to run them, an app
	// with schedules lives on one server.
	if len(c.Schedules) > 0 && len(c.Servers) > 1 {
		return fmt.Errorf("schedules: %s is on %d servers, and each would run every job; an app with schedules must be on one server", c.App, len(c.Servers))
	}
	jobs := map[string]bool{}
	for _, s := range c.Schedules {
		if err := s.validate(); err != nil {
			return err
		}
		if jobs[s.Name] {
			return fmt.Errorf("schedules: %s is named twice", s.Name)
		}
		jobs[s.Name] = true
	}
	targets := map[string]bool{}
	for _, f := range c.Files {
		_, target, err := splitFile(f)
		if err != nil {
			return err
		}
		// Two files at one path: docker would mount both, and which one the container reads depends on
		// the order of the mounts.
		if targets[target] {
			return fmt.Errorf("files: %s is the target of two files", target)
		}
		targets[target] = true
	}
	seen := map[string]bool{}
	for _, dep := range c.Uses {
		switch {
		case !nameRe.MatchString(dep):
			return fmt.Errorf("uses: %q must be an app name matching %s", dep, nameRe)
		case dep == c.App:
			return fmt.Errorf("uses: %s is this app; an app reaches itself on its own network", dep)
		case seen[dep]:
			return fmt.Errorf("uses: %s is named twice", dep)
		}
		seen[dep] = true
	}
	return nil
}

func (p Port) validate() error {
	if !nameRe.MatchString(p.Name) {
		return fmt.Errorf("ports: name %q must match %s", p.Name, nameRe)
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("ports[%s]: port %d out of range", p.Name, p.Port)
	}
	if p.Host == "" {
		return fmt.Errorf("ports[%s]: host is required", p.Name)
	}
	return nil
}

func validateVolume(v string) error {
	name, path, ok := strings.Cut(v, ":")
	if !ok || !nameRe.MatchString(name) || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("volumes: %q must be name:/absolute/path", v)
	}
	return nil
}

func (s Schedule) validate() error {
	if !nameRe.MatchString(s.Name) {
		return fmt.Errorf("schedules: name %q must match %s", s.Name, nameRe)
	}
	fields := strings.Fields(s.Cron)
	if len(fields) != 5 {
		return fmt.Errorf("schedules[%s]: cron %q must have five fields: minute hour day-of-month month day-of-week", s.Name, s.Cron)
	}
	for i, f := range fields {
		if err := cronField(f, cronBounds[i]); err != nil {
			return fmt.Errorf("schedules[%s]: cron field %q (%s): %w", s.Name, f, cronBounds[i].name, err)
		}
	}
	if strings.TrimSpace(s.Command) == "" {
		return fmt.Errorf("schedules[%s]: command is required", s.Name)
	}
	return nil
}

// cronBounds are the five cron fields in order, with the values each accepts (7 is Sunday, as 0).
type cronBound struct {
	name   string
	lo, hi int
}

var cronBounds = [5]cronBound{{"minute", 0, 59}, {"hour", 0, 23}, {"day of month", 1, 31}, {"month", 1, 12}, {"day of week", 0, 7}}

// cronField checks one field in the form every cron reads alike: a list of `*`, a number or a range
// `a-b`, the star and the range optionally stepped `/n`. Names (MON, JAN) and @-shortcuts vary between
// cron implementations, so they are left out. The crontab is installed after the release already
// serves, so a field the server's cron would refuse is refused here, before anything changes.
func cronField(f string, b cronBound) error {
	num := func(v string) (int, error) {
		if v == "" || strings.Trim(v, "0123456789") != "" {
			return 0, fmt.Errorf("must use numbers, *, ranges, lists and steps only")
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < b.lo || n > b.hi {
			return 0, fmt.Errorf("%s must be within %d-%d", v, b.lo, b.hi)
		}
		return n, nil
	}
	for _, item := range strings.Split(f, ",") {
		base, step, stepped := strings.Cut(item, "/")
		if stepped {
			if strings.Trim(step, "0123456789") != "" || step == "" {
				return fmt.Errorf("must use numbers, *, ranges, lists and steps only")
			}
			if n, err := strconv.Atoi(step); err != nil || n < 1 || n > b.hi-b.lo+1 {
				return fmt.Errorf("step %s must be within 1-%d", step, b.hi-b.lo+1)
			}
		}
		if base == "*" {
			continue
		}
		lo, hi, ranged := strings.Cut(base, "-")
		if !ranged {
			if stepped {
				return fmt.Errorf("a step follows * or a range, not a single number")
			}
			if _, err := num(base); err != nil {
				return err
			}
			continue
		}
		a, err := num(lo)
		if err != nil {
			return err
		}
		z, err := num(hi)
		if err != nil {
			return err
		}
		if a > z {
			return fmt.Errorf("range %s runs backwards", base)
		}
	}
	return nil
}

// splitFile reads one `files` entry. The target goes to `docker run -v host:target:ro`, so it is a
// clean absolute path without the colon that separates the parts there.
func splitFile(v string) (source, target string, err error) {
	source, target, ok := strings.Cut(v, ":")
	switch {
	case !ok || source == "":
		return "", "", fmt.Errorf("files: %q must be local/path:/absolute/path/in/container", v)
	case !strings.HasPrefix(target, "/") || target == "/" || path.Clean(target) != target:
		return "", "", fmt.Errorf("files: %q — the container path must be a clean absolute path to a file, such as /etc/nginx/conf.d/default.conf", v)
	case strings.Contains(target, ":"):
		return "", "", fmt.Errorf("files: %q — the container path cannot contain a colon", v)
	}
	return source, target, nil
}

// FileContent is one file of `files` as it goes to the server: Name is its file name in the
// release's directory there, unique even when two sources share a base name.
type FileContent struct {
	Name   string
	Target string
	Body   []byte
}

// FileContents reads the files the config names, from the paths relative to boks.yml. A file that
// cannot be read refuses the deploy before any server is reached.
func (c *Config) FileContents() ([]FileContent, error) {
	var out []FileContent
	for i, f := range c.Files {
		source, target, err := splitFile(f)
		if err != nil {
			return nil, err
		}
		body, err := os.ReadFile(c.resolve(source))
		if err != nil {
			return nil, fmt.Errorf("files: %w", err)
		}
		out = append(out, FileContent{Name: fmt.Sprintf("%d-%s", i, filepath.Base(source)), Target: target, Body: body})
	}
	return out, nil
}

// EnvContent is the env-file body sent to the server: env_file contents (if any) followed by
// inline env entries, sorted by key so the output is stable.
func (c *Config) EnvContent() ([]byte, error) {
	var b strings.Builder
	if c.EnvFile != "" {
		data, err := os.ReadFile(c.resolve(c.EnvFile))
		if err != nil {
			return nil, err
		}
		b.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	keys := make([]string, 0, len(c.Env))
	for k := range c.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, c.Env[k])
	}
	return []byte(b.String()), nil
}

func (c *Config) resolve(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Dir, p)
}
