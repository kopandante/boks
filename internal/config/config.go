package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultNetwork       = "boks"
	DefaultProxyImage    = "basecamp/kamal-proxy:v0.10.0"
	DefaultKeep          = 3
	DefaultDeployTimeout = "60s"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

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
	Cert          *Cert             `yaml:"cert"`
	App           string            `yaml:"app"`
	Image         string            `yaml:"image"`
	Servers       []string          `yaml:"servers"`
	Network       string            `yaml:"network"`
	ProxyImage    string            `yaml:"proxy_image"`
	EnvFile       string            `yaml:"env_file"`
	Env           map[string]string `yaml:"env"`
	Volumes       []string          `yaml:"volumes"`
	Ports         []Port            `yaml:"ports"`
	TLS           bool              `yaml:"tls"`
	Keep          int               `yaml:"keep"`
	DeployTimeout string            `yaml:"deploy_timeout"`
	Dir           string            `yaml:"-"`
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
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Network == "" {
		c.Network = DefaultNetwork
	}
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
	if c.Keep < 1 {
		return fmt.Errorf("keep: must be at least 1")
	}
	if _, err := time.ParseDuration(c.DeployTimeout); err != nil {
		return fmt.Errorf("deploy_timeout: %q is not a duration such as 60s or 2m", c.DeployTimeout)
	}
	if err := c.Cert.validate(); err != nil {
		return err
	}
	return c.validateLists()
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
	if len(c.Ports) == 0 {
		return fmt.Errorf("ports: at least one is required")
	}
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
