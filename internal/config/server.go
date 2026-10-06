package config

// server.yml: what belongs to a server rather than to any app on it — the bot filter the proxy
// applies to every host. It lives in the infrastructure repository and is applied with `boks server
// apply`; a deploy reads the policy already applied and changes only its own app's routes.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Server is a parsed server.yml.
type Server struct {
	Servers []string `yaml:"servers"`
	// Revision grows by one with every edit, as a DNS zone's serial does: a server takes the revision
	// after the highest it ever applied, so a stale CI run or a concurrent edit made from the same
	// revision cannot put back what another one replaced.
	Revision int  `yaml:"revision"`
	Bots     Bots `yaml:"bots"`
}

// Bots is the filter by User-Agent the proxy applies before any app's route: a request one of Block
// matches gets 403, unless one of Allow matches it — Allow wins over every rule.
type Bots struct {
	Allow []BotAllow `yaml:"allow"`
	Block []BotBlock `yaml:"block"`
}

// BotBlock refuses a User-Agent matching UserAgent on Domains — each domain and every host under it,
// at any depth — or on every host the proxy serves when Domains is empty.
type BotBlock struct {
	Name      string   `yaml:"name"`
	Domains   []string `yaml:"domains"`
	UserAgent string   `yaml:"user_agent"`
}

// BotAllow lets through what a rule would refuse: every field it gives must match. Host is one exact
// host; Paths are prefixes, each the path itself and everything below it.
type BotAllow struct {
	Host      string   `yaml:"host"`
	Paths     []string `yaml:"paths"`
	UserAgent string   `yaml:"user_agent"`
}

// domainRe is a lowercase DNS name of two labels or more, without a wildcard.
var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// LoadServer reads and checks a server.yml.
func LoadServer(path string) (*Server, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ParseServer(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ParseServer is LoadServer on bytes: strict about unknown keys and about a second document, for the
// same reason as Parse.
func ParseServer(data []byte) (*Server, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Server
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the file is empty")
		}
		return nil, err
	}
	if err := restIsEmpty(dec, "server.yml is read as one"); err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Server) validate() error {
	if len(s.Servers) == 0 {
		return errors.New("servers: at least one is required")
	}
	if s.Revision < 1 {
		return errors.New("revision: required, a whole number from 1 that grows by one with every edit")
	}
	names := map[string]bool{}
	for i, b := range s.Bots.Block {
		if !nameRe.MatchString(b.Name) {
			return fmt.Errorf("bots.block[%d]: name %q must match %s", i, b.Name, nameRe)
		}
		if names[b.Name] {
			return fmt.Errorf("bots.block[%s]: the name is used twice", b.Name)
		}
		names[b.Name] = true
		for _, d := range b.Domains {
			if !domainRe.MatchString(d) {
				return fmt.Errorf("bots.block[%s]: domains: %q must be a lowercase domain such as example.com — it covers every host under it", b.Name, d)
			}
		}
		if b.UserAgent == "" {
			return fmt.Errorf("bots.block[%s]: user_agent is required — without it the rule would refuse every visitor", b.Name)
		}
		if err := checkUserAgent(b.UserAgent); err != nil {
			return fmt.Errorf("bots.block[%s]: %w", b.Name, err)
		}
	}
	for i, a := range s.Bots.Allow {
		if a.Host == "" && len(a.Paths) == 0 && a.UserAgent == "" {
			return fmt.Errorf("bots.allow[%d] gives nothing to match, and would let every bot through", i)
		}
		if a.Host != "" && !domainRe.MatchString(a.Host) {
			return fmt.Errorf("bots.allow[%d]: host %q must be one lowercase host such as img.example.com", i, a.Host)
		}
		for _, p := range a.Paths {
			if !pathRe.MatchString(p) {
				return fmt.Errorf("bots.allow[%d]: path %q must be an absolute prefix without a trailing slash, such as /pics", i, p)
			}
		}
		if a.UserAgent != "" {
			if err := checkUserAgent(a.UserAgent); err != nil {
				return fmt.Errorf("bots.allow[%d]: %w", i, err)
			}
		}
	}
	return nil
}

// checkUserAgent compiles a pattern as Caddy will: both are Go's RE2, so what compiles here compiles there.
func checkUserAgent(p string) error {
	if _, err := regexp.Compile(p); err != nil {
		return fmt.Errorf("user_agent %q is not a regular expression: %w", p, err)
	}
	return nil
}
