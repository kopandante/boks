package config

// server.yml: what belongs to a server rather than to any app on it — the bot filter the proxy
// applies to every host. It lives in the infrastructure repository and is applied with `boks server
// apply`; a deploy reads the policy already applied and changes only its own app's routes.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"

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
	// Egress, when given, has the server's proxy carry outgoing requests too: a service elsewhere sends
	// them through it to leave from this server's address, as it did through a tinyproxy beside boks.
	Egress *Egress `yaml:"egress"`
}

// Egress is the forward proxy the server's Caddy runs on a port of its own.
type Egress struct {
	// Port is where it listens, 3128 when not given — tinyproxy's and squid's port, so clients keep
	// their proxy URL.
	Port int `yaml:"port"`
	// Allow is who may use it: addresses or CIDR ranges of the clients. Required — a forward proxy open
	// to everyone is a relay for anyone's traffic from this server's address.
	Allow []string `yaml:"allow"`
	// User and PasswordEnv add a login: the password is read from the environment boks runs in, under
	// that name, and never goes in server.yml.
	User        string `yaml:"user"`
	PasswordEnv string `yaml:"password_env"`
	// Ports are the ports it lets a client reach, 443 when not given.
	Ports []int `yaml:"ports"`
	// HostsFile is a hosts file of the server the proxy resolves names through — pins a job on the
	// server keeps current.
	HostsFile string `yaml:"hosts_file"`
}

// DefaultEgressPort is the port of an egress block without one.
const DefaultEgressPort = 3128

// Prefixes are Allow as CIDR ranges, an address alone as the range of that one address.
func (e *Egress) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range e.Allow {
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p.Masked())
		} else if ip, err := netip.ParseAddr(a); err == nil {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return out
}

// Password reads the login's password from the environment; "" without a login.
func (e *Egress) Password() (string, error) {
	if e.User == "" {
		return "", nil
	}
	v, ok := os.LookupEnv(e.PasswordEnv)
	if !ok {
		return "", fmt.Errorf("egress.password_env: %s is not set in the environment boks runs in", e.PasswordEnv)
	}
	if v == "" {
		return "", fmt.Errorf("egress.password_env: %s is set but empty", e.PasswordEnv)
	}
	// The server keeps it in a file whose reading trims the ends: a space there would be lost, and
	// every client refused. A newline would break the file.
	if strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("egress.password_env: %s starts or ends with whitespace, or holds a line break; use a password without", e.PasswordEnv)
	}
	return v, nil
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
	// A file of servers alone — what `boks server install` reads — has no policy to number. One with a
	// policy needs its revision, and `boks server apply` asks for one either way.
	if s.Revision < 1 && (s.Revision != 0 || len(s.Bots.Block) > 0 || len(s.Bots.Allow) > 0 || s.Egress != nil) {
		return errors.New("revision: required, a whole number from 1 that grows by one with every edit")
	}
	if s.Egress != nil {
		if err := s.Egress.validate(); err != nil {
			return fmt.Errorf("egress: %w", err)
		}
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

func (e *Egress) validate() error {
	if e.Port == 0 {
		e.Port = DefaultEgressPort
	}
	switch {
	case e.Port < 1 || e.Port > 65535:
		return fmt.Errorf("port %d is not a TCP port", e.Port)
	case e.Port == 80 || e.Port == 443 || e.Port == 2019:
		return fmt.Errorf("port %d is the proxy's own (80 and 443 serve the apps, 2019 is Caddy's admin API)", e.Port)
	}
	if len(e.Allow) == 0 {
		return errors.New("allow: the clients that may use it are required — open to everyone, it relays anyone's traffic from this server's address")
	}
	for _, a := range e.Allow {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			ip, aerr := netip.ParseAddr(a)
			if aerr != nil {
				return fmt.Errorf("allow: %q is neither an address nor a CIDR range", a)
			}
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		if p.Bits() == 0 {
			return fmt.Errorf("allow: %q lets every address in; name the clients", a)
		}
	}
	if (e.User == "") != (e.PasswordEnv == "") {
		return errors.New("user and password_env go together: a login needs both, and none is no login")
	}
	if e.User != "" && !egressUserRe.MatchString(e.User) {
		return fmt.Errorf("user %q must be letters, digits, '.', '_' or '-'", e.User)
	}
	if e.PasswordEnv != "" && !envNameRe.MatchString(e.PasswordEnv) {
		return fmt.Errorf("password_env: %q must name an environment variable (%s) — the password itself never goes in server.yml", e.PasswordEnv, envNameRe)
	}
	if len(e.Ports) == 0 {
		e.Ports = []int{443}
	}
	for _, p := range e.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("ports: %d is not a TCP port", p)
		}
	}
	if e.HostsFile != "" {
		if !path.IsAbs(e.HostsFile) {
			return fmt.Errorf("hosts_file: %q must be an absolute path on the server", e.HostsFile)
		}
		// As docker records the mount's source: written otherwise, the proxy would never look like the
		// container the policy needs, and every apply would create it again.
		e.HostsFile = path.Clean(e.HostsFile)
	}
	return nil
}

var egressUserRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// checkUserAgent compiles a pattern as Caddy will: both are Go's RE2, so what compiles here compiles there.
func checkUserAgent(p string) error {
	if _, err := regexp.Compile(p); err != nil {
		return fmt.Errorf("user_agent %q is not a regular expression: %w", p, err)
	}
	return nil
}
