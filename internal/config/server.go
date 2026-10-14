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

// Ban is the ban by request rate. An address that sends more than a rule's Limit requests within its
// Window — on all the server's hosts together — gets 403 for Duration. Not counted by any rule:
// loopback and the private networks, what bots.allow lets through, Next.js's /_next/, ACME's
// challenge, and ExemptPaths and ExemptRanges; a page's images, media, fonts, styles and scripts by
// Sec-Fetch-Dest are left out of the rules of class all and page only.
type Ban struct {
	// Limit and Window are the ban written before rules: one rule, default, of class all. They go
	// without Rules; 300 and 1m when neither they nor Rules are given. validate turns them into that
	// rule and clears them, so a policy holds rules alone.
	Limit  int    `yaml:"limit"`
	Window string `yaml:"window"`
	// Duration is 24h when not given. Go durations, in whole seconds.
	Duration string `yaml:"duration"`
	// Rules each count on their own; the first one an address goes past bans it.
	Rules []BanRule `yaml:"rules"`
	// Heuristics, when given and not off, look for requests a browser would not send.
	Heuristics *BanHeuristics `yaml:"heuristics"`
	// ExemptPaths are regular expressions on the request's path, such as ^/api/[a-z]+/pics.
	ExemptPaths []string `yaml:"exempt_paths"`
	// ExemptRanges are addresses or CIDR ranges, such as a client's office.
	ExemptRanges []string `yaml:"exempt_ranges"`
}

// BanRule counts the requests of an address its selector takes: those of Class and, when Paths are
// given, on a path one of them matches.
type BanRule struct {
	Name   string `yaml:"name"`
	Limit  int    `yaml:"limit"`
	Window string `yaml:"window"`
	// Class is all — every request counted — when not given; page is a GET outside /api/ that is not
	// Next.js's prefetch; api is a request under /api/.
	Class string `yaml:"class"`
	// Paths are regular expressions on the cleaned path.
	Paths []string `yaml:"paths"`
}

// BanHeuristics flag requests whose headers no browser sends together, and the clusters of addresses
// that send them with one fingerprint. Mode is off, log — the journal only — or ban: 403 to the
// cluster's requests for the ban's duration.
type BanHeuristics struct {
	Mode    string     `yaml:"mode"`
	Cluster BanCluster `yaml:"cluster"`
}

// BanCluster is a fingerprint sending more than Limit flagged requests within Window from at least
// MinAddresses addresses.
type BanCluster struct {
	Limit        int    `yaml:"limit"`
	Window       string `yaml:"window"`
	MinAddresses int    `yaml:"min_addresses"`
}

// The ban's defaults and bounds. A window past an hour or a ban past 30 days is a typo more often
// than a policy, and both are memory the proxy holds per address; so is a rule past the 16th. The
// cluster's defaults are the plan's for hb-sites: the storm on dbauto sent some 1 200 flagged requests
// in 10 minutes from 72 addresses. Its addresses are held per fingerprint up to MinAddresses, so 100
// bounds that memory.
const (
	DefaultBanLimit         = 300
	DefaultBanWindow        = "1m"
	DefaultBanDuration      = "24h"
	DefaultBanRule          = "default"
	DefaultClusterLimit     = 300
	DefaultClusterWindow    = "10m"
	DefaultClusterAddresses = 10
	maxBanWindow            = time.Hour
	maxBanDuration          = 30 * 24 * time.Hour
	maxBanRules             = 16
	maxClusterAddresses     = 100
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
	// `ban:` with nothing under it — its keys commented out — decodes as no ban at all: applied, it
	// would lift the server's ban without a word.
	var keys struct {
		Ban yaml.Node `yaml:"ban"`
	}
	if s.Ban == nil && yaml.Unmarshal(data, &keys) == nil && keys.Ban.Kind != 0 {
		return nil, errors.New("ban: empty; write `ban: {}` for the defaults (300 requests in 1m ban for 24h), or remove the key for no ban")
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
// policy whatever its file wrote (60s and 1m, no class and all, limit and window and their rule).
func (b *Ban) validate() error {
	if b.Rules != nil && (b.Limit != 0 || b.Window != "") {
		return errors.New("limit and window go without rules: write the limit as a rule of its own")
	}
	if b.Rules == nil {
		b.Rules = []BanRule{{Name: DefaultBanRule, Limit: b.Limit, Window: b.Window}}
		if b.Rules[0].Limit == 0 {
			b.Rules[0].Limit = DefaultBanLimit
		}
		if b.Rules[0].Window == "" {
			b.Rules[0].Window = DefaultBanWindow
		}
		// Checked as the rule, but named as the file wrote them.
		if err := b.Rules[0].validate(); err != nil {
			return errors.New(strings.TrimPrefix(err.Error(), "rules[default]: "))
		}
		b.Limit, b.Window = 0, ""
	}
	if b.Duration == "" {
		b.Duration = DefaultBanDuration
	}
	switch n := len(b.Rules); {
	case n == 0:
		return errors.New("rules: empty, and would count nothing; remove the key for the default rule")
	case n > maxBanRules:
		return fmt.Errorf("rules: %d of them, more than %d", n, maxBanRules)
	}
	names := map[string]bool{}
	for i := range b.Rules {
		r := &b.Rules[i]
		if !nameRe.MatchString(r.Name) {
			return fmt.Errorf("rules[%d]: name %q must match %s", i, r.Name, nameRe)
		}
		if names[r.Name] {
			return fmt.Errorf("rules[%s]: the name is used twice", r.Name)
		}
		names[r.Name] = true
		if err := r.validate(); err != nil {
			return err
		}
	}
	duration, err := banDuration("duration", b.Duration, maxBanDuration)
	if err != nil {
		return err
	}
	b.Duration = formatDuration(duration)
	if b.Heuristics != nil {
		if err := b.Heuristics.validate(); err != nil {
			return fmt.Errorf("heuristics: %w", err)
		}
		if b.Heuristics.Mode == "off" {
			b.Heuristics = nil
		}
	}
	if err := checkPatterns(b.ExemptPaths, "turn the ban off"); err != nil {
		return fmt.Errorf("exempt_paths: %w", err)
	}
	if err := checkRanges(b.ExemptRanges, "addresses to leave uncounted"); err != nil {
		return fmt.Errorf("exempt_ranges: %w", err)
	}
	if err := checkWrittenAsIPv4(b.ExemptRanges); err != nil {
		return fmt.Errorf("exempt_ranges: %w", err)
	}
	return nil
}

func (r *BanRule) validate() error {
	if r.Class == "" {
		r.Class = "all"
	}
	if r.Limit < 1 {
		return fmt.Errorf("rules[%s]: limit %d: must be at least 1", r.Name, r.Limit)
	}
	window, err := banDuration("window", r.Window, maxBanWindow)
	if err != nil {
		return fmt.Errorf("rules[%s]: %w", r.Name, err)
	}
	r.Window = formatDuration(window)
	if r.Class != "all" && r.Class != "page" && r.Class != "api" {
		return fmt.Errorf("rules[%s]: class %q must be all, page or api", r.Name, r.Class)
	}
	if err := checkPatterns(r.Paths, "count every path, which is what no paths say"); err != nil {
		return fmt.Errorf("rules[%s]: paths: %w", r.Name, err)
	}
	return nil
}

// validate fills in the cluster's defaults, whatever the mode: off keeps the numbers the next mode
// would use, though the policy drops them with it.
func (h *BanHeuristics) validate() error {
	if h.Mode == "" {
		h.Mode = "off"
	}
	if h.Mode != "off" && h.Mode != "log" && h.Mode != "ban" {
		return fmt.Errorf("mode %q must be off, log or ban", h.Mode)
	}
	c := &h.Cluster
	if c.Limit == 0 {
		c.Limit = DefaultClusterLimit
	}
	if c.Window == "" {
		c.Window = DefaultClusterWindow
	}
	if c.MinAddresses == 0 {
		c.MinAddresses = DefaultClusterAddresses
	}
	if c.Limit < 1 {
		return fmt.Errorf("cluster: limit %d: must be at least 1", c.Limit)
	}
	window, err := banDuration("window", c.Window, maxBanWindow)
	if err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	c.Window = formatDuration(window)
	// One address is the address's own rules' business; past the bound, the memory of every fingerprint grows.
	if c.MinAddresses < 2 || c.MinAddresses > maxClusterAddresses {
		return fmt.Errorf("cluster: min_addresses %d: must be from 2 to %d", c.MinAddresses, maxClusterAddresses)
	}
	return nil
}

// checkPatterns refuses an empty pattern, which matches everything — what would turns says — and one
// that does not compile as Caddy's Go RE2 compiles it.
func checkPatterns(list []string, would string) error {
	for _, p := range list {
		if p == "" {
			return fmt.Errorf("an empty pattern matches every path, and would %s", would)
		}
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("%q is not a regular expression: %w", p, err)
		}
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
