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
	"time"

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
	// TrustedProxies are the addresses or CIDR ranges of a proxy standing in front of boks — a CDN, a
	// load balancer, another server's proxy on the way in: a request from one of them keeps the
	// X-Forwarded-For it brings, with the proxy's address added after it. Without any, boks trusts no
	// one, and every app sees the address of the connection (#48).
	TrustedProxies []string `yaml:"trusted_proxies"`
	// Ban, when given, has the proxy refuse an address that sends too many requests: 403 on every host
	// of the server for a while, without the request reaching any app.
	Ban *Ban `yaml:"ban"`
}

// Ban is the ban by request rate. An address that sends more than Limit requests within Window — on
// all the server's hosts together — gets 403 for Duration. Not counted: loopback and the private
// networks, what bots.allow lets through, Next.js's /_next/, a page's images, media, fonts, styles
// and scripts by Sec-Fetch-Dest, ACME's challenge, and ExemptPaths and ExemptRanges.
type Ban struct {
	// Limit is 300 when not given.
	Limit int `yaml:"limit"`
	// Window is 1m when not given; Duration 24h. Go durations, in whole seconds.
	Window   string `yaml:"window"`
	Duration string `yaml:"duration"`
	// ExemptPaths are regular expressions on the request's path, such as ^/api/[a-z]+/pics.
	ExemptPaths []string `yaml:"exempt_paths"`
	// ExemptRanges are addresses or CIDR ranges, such as a client's office.
	ExemptRanges []string `yaml:"exempt_ranges"`
}

// The ban's defaults and bounds. A window past an hour or a ban past 30 days is a typo more often
// than a policy, and both are memory the proxy holds per address.
const (
	DefaultBanLimit    = 300
	DefaultBanWindow   = "1m"
	DefaultBanDuration = "24h"
	maxBanWindow       = time.Hour
	maxBanDuration     = 30 * 24 * time.Hour
)

// ExemptPrefixes are ExemptRanges as CIDR ranges, as Prefixes are an egress's Allow.
func (b *Ban) ExemptPrefixes() []netip.Prefix { return prefixes(b.ExemptRanges) }

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
func (e *Egress) Prefixes() []netip.Prefix { return prefixes(e.Allow) }

// TrustedPrefixes are TrustedProxies as CIDR ranges, as Prefixes are Allow.
func (s *Server) TrustedPrefixes() []netip.Prefix { return prefixes(s.TrustedProxies) }

// rangeOf is an address or a CIDR range as a range, an address alone the range of that one address;
// the bits past the prefix stay as written.
func rangeOf(a string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(a); err == nil {
		return p, true
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		return netip.PrefixFrom(ip, ip.BitLen()), true
	}
	return netip.Prefix{}, false
}

func prefixes(list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range list {
		if p, ok := rangeOf(a); ok {
			out = append(out, p.Masked())
		}
	}
	return out
}

// checkRanges refuses an entry of list that is not an address or a CIDR range, and one that covers
// every address.
func checkRanges(list []string, whom string) error {
	for _, a := range list {
		p, ok := rangeOf(a)
		if !ok {
			return fmt.Errorf("%q is neither an address nor a CIDR range", a)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("%q lets every address in; name the %s", a, whom)
		}
	}
	return nil
}

// checkWrittenAsIPv4 refuses an IPv4 address written as IPv6 (::ffff:a.b.c.d): an IPv4 client
// connects as an IPv4 address, and Caddy compares it with IPv4 ranges only, so the entry would be
// applied and match no one. Told by the address as written: masked to a short prefix, it would lose
// the ::ffff.
func checkWrittenAsIPv4(list []string) error {
	for _, a := range list {
		if p, _ := rangeOf(a); p.Addr().Is4In6() {
			return fmt.Errorf("%q is an IPv4 address written as IPv6; write it as IPv4", a)
		}
	}
	return nil
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
	if s.Revision < 1 && (s.Revision != 0 || len(s.Bots.Block) > 0 || len(s.Bots.Allow) > 0 || s.Egress != nil || len(s.TrustedProxies) > 0 || s.Ban != nil) {
		return errors.New("revision: required, a whole number from 1 that grows by one with every edit")
	}
	if s.Egress != nil {
		if err := s.Egress.validate(); err != nil {
			return fmt.Errorf("egress: %w", err)
		}
	}
	if s.Ban != nil {
		if err := s.Ban.validate(); err != nil {
			return fmt.Errorf("ban: %w", err)
		}
	}
	// Trusting everyone hands every app the address a visitor writes into X-Forwarded-For.
	if err := checkRanges(s.TrustedProxies, "proxies in front of boks"); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	if err := checkWrittenAsIPv4(s.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
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
	if err := checkRanges(e.Allow, "clients"); err != nil {
		return fmt.Errorf("allow: %w", err)
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

// validate fills in the defaults and writes the durations one way, so the same ban is the same
// policy whatever its file wrote (60s and 1m).
func (b *Ban) validate() error {
	if b.Limit == 0 {
		b.Limit = DefaultBanLimit
	}
	if b.Window == "" {
		b.Window = DefaultBanWindow
	}
	if b.Duration == "" {
		b.Duration = DefaultBanDuration
	}
	if b.Limit < 1 {
		return fmt.Errorf("limit %d: must be at least 1", b.Limit)
	}
	window, err := banDuration("window", b.Window, maxBanWindow)
	if err != nil {
		return err
	}
	duration, err := banDuration("duration", b.Duration, maxBanDuration)
	if err != nil {
		return err
	}
	b.Window, b.Duration = formatDuration(window), formatDuration(duration)
	for _, p := range b.ExemptPaths {
		if p == "" {
			return errors.New("exempt_paths: an empty pattern matches every path, and would turn the ban off")
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("exempt_paths: %q is not a regular expression: %w", p, err)
		}
	}
	if err := checkRanges(b.ExemptRanges, "addresses to leave uncounted"); err != nil {
		return fmt.Errorf("exempt_ranges: %w", err)
	}
	if err := checkWrittenAsIPv4(b.ExemptRanges); err != nil {
		return fmt.Errorf("exempt_ranges: %w", err)
	}
	return nil
}

// banDuration reads a ban's duration: whole seconds, from one second to max.
func banDuration(key, s string, max time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	switch {
	case err != nil:
		return 0, fmt.Errorf("%s: %q is not a duration such as 1m or 24h", key, s)
	case d < time.Second || d%time.Second != 0:
		return 0, fmt.Errorf("%s: %s must be whole seconds, at least 1s", key, s)
	case d > max:
		return 0, fmt.Errorf("%s: %s is longer than %s", key, s, formatDuration(max))
	}
	return d, nil
}

// formatDuration is d as Go writes it, without the zero units it ends in: 1m, 24h, 1h30m.
func formatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// checkUserAgent compiles a pattern as Caddy will: both are Go's RE2, so what compiles here compiles there.
func checkUserAgent(p string) error {
	if _, err := regexp.Compile(p); err != nil {
		return fmt.Errorf("user_agent %q is not a regular expression: %w", p, err)
	}
	return nil
}
