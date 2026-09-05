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
type Port struct {
	Name       string `yaml:"name"`
	Port       int    `yaml:"port"`
	Host       string `yaml:"host"`
	HealthPath string `yaml:"health_path"`
	HealthPort int    `yaml:"health_port"`
}

// Config is the parsed boks.yml of one app.
type Config struct {
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
	return c.validateLists()
}

func (c *Config) validateLists() error {
	if len(c.Ports) == 0 {
		return fmt.Errorf("ports: at least one is required")
	}
	for _, p := range c.Ports {
		if err := p.validate(); err != nil {
			return err
		}
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
