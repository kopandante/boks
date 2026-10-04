package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultProxyImage    = "basecamp/kamal-proxy:v0.10.0"
	DefaultKeep          = 3
	DefaultDeployTimeout = "60s"

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
)

// minMemory is the smallest limit docker accepts; below it `docker run` refuses, and it is better
// to hear that from the config than from a half-done deploy.
const minMemory = 6 << 20

// Port is one published port of the app, routed by kamal-proxy under its own host.
// The json tags are load-bearing, not decoration: a deploy stores this spec verbatim in the
// container's `boks.ports` label and a later deploy reads it back to revert a route, so the
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

// Cert describes a certificate obtained by lego over DNS-01 — the case kamal-proxy's built-in
// autocert cannot serve, because a wildcard has no HTTP-01 challenge. Hosts not covered by it
// keep using autocert, so an app can mix both.
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
	// Memory is the container's hard memory limit in docker's format (512m, 1g); empty means none.
	Memory string `yaml:"memory"`
	// Replace is how a new version takes over from the old one: ReplaceOverlap or ReplaceStopFirst.
	// Empty means the default for the app's shape, which ReplaceMode tells.
	Replace string `yaml:"replace"`
	// Uses names the apps this one reaches. Its containers join their networks and reach each by the
	// app's name, its alias there. It is membership, not access control: two apps that use one
	// dependency share its network and see each other.
	Uses []string `yaml:"uses"`
	// Attach overrides Networks with what a recorded release joined; never read from boks.yml.
	Attach []Network `yaml:"-"`
	Dir    string    `yaml:"-"`
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
	if err := c.validateResources(); err != nil {
		return err
	}
	if err := c.Cert.validate(); err != nil {
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
	// and is judged by the image's own HEALTHCHECK instead of by a route.
	seenName, seenHost := map[string]bool{}, map[string]bool{}
	for _, p := range c.Ports {
		if err := p.validate(); err != nil {
			return err
		}
		if seenName[p.Name] {
			return fmt.Errorf("ports: duplicate name %q", p.Name)
		}
		// Two ports on one host would fight over the same proxy service: kamal-proxy allows
		// one service per host and the second deploy would take the route from the first.
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
