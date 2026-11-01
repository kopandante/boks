package config

// server.yml: what belongs to a server rather than to any app on it — the bot filter the proxy
// applies to every host. It lives in the infrastructure repository and is applied with `boks server
// apply`; a deploy reads the policy already applied and changes only its own app's routes.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"path/filepath"
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
	// load balancer, another server's proxy on the way in: the client of a request from one of them is
	// read from the X-Forwarded-For it brings, from the right, the first address outside them, and the
	// app gets that one address as X-Forwarded-For (#136). Without any, boks trusts no one, and every
	// app sees the address of the connection (#48).
	TrustedProxies []string `yaml:"trusted_proxies"`
	// TrustedProxiesCA, when given, is the PEM of the CA certificates a trusted proxy's client
	// certificate must chain to — Cloudflare's Authenticated Origin Pulls. A TLS connection from a
	// trusted proxy without such a certificate is refused at the handshake; plain HTTP, which can carry
	// none, has its forwarded headers no longer trusted. Visitors from other addresses are not asked for
	// a certificate.
	TrustedProxiesCA string `yaml:"trusted_proxies_ca"`
	// Ban, when given, has the proxy refuse an address that sends too many requests: 403 on every host
	// of the server for a while, without the request reaching any app.
	Ban *Ban `yaml:"ban"`
	// Gate, when given, has the proxy check the sites' API token on the hosts of the apps it names, in
	// place of each site (gate.go).
	Gate *Gate `yaml:"gate"`
	// RangeSets are named sets of addresses — a country's, from its registry's delegations — that a gate
	// signature's `ranges` names (#140): a list of addresses and CIDR ranges, or a file of them beside
	// server.yml, one on a line, # for comments. A file is read when server.yml is, and what it held goes
	// into the policy, in the groups whose signatures name the set: a revision holds the list it was
	// applied with, a rollback puts that list back, and an edit of the file changes nothing until applied.
	RangeSets map[string]RangeSet `yaml:"range_sets"`
}

// RangeSet is one of range_sets: Ranges as written, or read from File.
type RangeSet struct {
	File   string
	Ranges []string
}

// maxRangeSet bounds a set: Japan's delegations merged are some thousands of ranges.
const maxRangeSet = 50_000

func (r *RangeSet) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&r.File)
	}
	return n.Decode(&r.Ranges)
}

// readRangeFile is a file of range_sets: an address or a CIDR range on a line, blank lines and what
// follows # left out.
func readRangeFile(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// readRangeSets reads every set given as a file, relative to dir, into its Ranges.
func (s *Server) readRangeSets(dir string) error {
	for name, rs := range s.RangeSets {
		if rs.File == "" {
			continue
		}
		f := rs.File
		if !filepath.IsAbs(f) {
			f = filepath.Join(dir, f)
		}
		list, err := readRangeFile(f)
		if err != nil {
			return fmt.Errorf("range_sets.%s: %w", name, err)
		}
		rs.Ranges = list
		s.RangeSets[name] = rs
	}
	return nil
}

// validateRangeSets checks every set: a name, addresses and CIDR ranges alone, none of every address.
func (s *Server) validateRangeSets() error {
	for name, rs := range s.RangeSets {
		switch {
		case !nameRe.MatchString(name):
			return fmt.Errorf("range_sets: name %q must match %s", name, nameRe)
		case len(rs.Ranges) == 0:
			return fmt.Errorf("range_sets.%s: empty; a signature on it would match no one", name)
		case len(rs.Ranges) > maxRangeSet:
			return fmt.Errorf("range_sets.%s: %d ranges, more than %d", name, len(rs.Ranges), maxRangeSet)
		}
		if err := checkRanges(rs.Ranges, "holds every address; a signature on it would ignore the address"); err != nil {
			return fmt.Errorf("range_sets.%s: %w", name, err)
		}
		if err := checkWrittenAsIPv4(rs.Ranges); err != nil {
			return fmt.Errorf("range_sets.%s: %w", name, err)
		}
	}
	return nil
}

// RangePrefixes are a set's ranges as masked CIDR ranges, as TrustedPrefixes are TrustedProxies.
func (r RangeSet) RangePrefixes() []string {
	var out []string
	for _, p := range prefixes(r.Ranges) {
		out = append(out, p.String())
	}
	return out
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
	// DenyRanges are addresses or CIDR ranges the proxy refuses whatever they send: 403 on every host,
	// before ExemptRanges, bots.allow, the rules and the gate are asked.
	DenyRanges []string `yaml:"deny_ranges"`
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

// DenyPrefixes are DenyRanges as CIDR ranges, as ExemptPrefixes are ExemptRanges.
func (b *Ban) DenyPrefixes() []netip.Prefix { return prefixes(b.DenyRanges) }

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

// TrustedPrefixes are TrustedProxies as CIDR ranges, as Prefixes are Allow, less WorkerClientIP: a
// range that holds it is written as the ranges around it.
func (s *Server) TrustedPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range prefixes(s.TrustedProxies) {
		out = append(out, without(p, WorkerClientIP)...)
	}
	return out
}

// WorkerClientIP is the address Cloudflare writes for the client of a Worker's request to another
// zone (Cloudflare's HTTP headers, CF-Connecting-IP in Worker subrequests): inside its own ranges, and
// so, trusted, an address Caddy would read past to the one the Worker wrote before it. Never trusted,
// it is the client of such a request — the Worker, not whom it names. The documentation names this one
// address and no range.
var WorkerClientIP = netip.MustParseAddr("2a06:98c0:3600::103")

// without is p less the address a: p itself when it does not hold a, none when it is a alone, else the
// halves of p down to a's own, each but the one holding a — 128 less p's bits ranges for IPv6.
func without(p netip.Prefix, a netip.Addr) []netip.Prefix {
	if !p.Contains(a) {
		return []netip.Prefix{p}
	}
	var out []netip.Prefix
	for bits := p.Bits(); bits < a.BitLen(); bits++ {
		// The half of the range at bits+1 that does not hold a: a with bit bits flipped, masked.
		b := a.As16()
		i := bits
		if a.Is4() {
			i += 96
		}
		b[i/8] ^= 0x80 >> (i % 8)
		other := netip.AddrFrom16(b)
		if a.Is4() {
			other = other.Unmap()
		}
		out = append(out, netip.PrefixFrom(other, bits+1).Masked())
	}
	return out
}

// TrustedProxiesCerts are TrustedProxiesCA as DER certificates, in the order written; none without it.
// A validated server.yml parses.
func (s *Server) TrustedProxiesCerts() [][]byte {
	certs, _ := parseCAs(s.TrustedProxiesCA)
	return certs
}

// parseCAs reads the certificates of pem: CERTIFICATE blocks and nothing else, at least one. Text around
// or between the blocks is refused, and so is a block pem.Decode would skip as broken: whatever else was
// pasted there — a key, half a certificate — is not a CA. Their term is judged by apply and rollback
// (proxy.CheckCATerm), not here: an expired CA must not lock every `boks server` command — status, the
// rollback to a revision without it — out of the server it took down.
func parseCAs(data string) ([][]byte, error) {
	junk := errors.New("want one or more PEM certificates (-----BEGIN CERTIFICATE-----) and nothing else")
	var certs [][]byte
	rest := bytes.TrimSpace([]byte(data))
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, junk
		}
		b, next := pem.Decode(rest)
		if b == nil || bytes.Count(rest[:len(rest)-len(next)], []byte("-----BEGIN ")) != 1 {
			return nil, junk
		}
		rest = bytes.TrimSpace(next)
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("a %s block; only CERTIFICATE blocks go here — never a key", b.Type)
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(certs)+1, err)
		}
		if err := CheckOwnCA(b.Bytes); err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(certs)+1, err)
		}
		certs = append(certs, b.Bytes)
	}
	if len(certs) == 0 {
		return nil, junk
	}
	return certs, nil
}

// sharedOriginPullCA is the SHA-256 of Cloudflare's own origin-pull CA (CN origin-pull.cloudflare.net,
// 2019–2029; developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem), the CA of global
// Authenticated Origin Pulls.
const sharedOriginPullCA = "9a1ac2b4be15f9f27eee20a734cba4e9898f61001b3bd7c84b69b56a3e25a2b9"

// CheckOwnCA refuses Cloudflare's shared origin-pull CA: every zone of every account that turns global
// Authenticated Origin Pulls on presents a certificate of it, so with it a Worker of anyone's account
// passes the check, its zone set up the same. Only a zone's own client certificate, uploaded for
// zone-level pulls, proves the request came through that zone.
func CheckOwnCA(der []byte) error {
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) == sharedOriginPullCA {
		return errors.New("Cloudflare's shared origin-pull CA (origin-pull.cloudflare.net) proves only that a request came through some " +
			"Cloudflare zone, anyone's; upload a client certificate of your own for zone-level Authenticated Origin Pulls and put its CA here")
	}
	return nil
}

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
// every address, saying what such an entry would do: every, after the entry.
func checkRanges(list []string, every string) error {
	for _, a := range list {
		p, ok := rangeOf(a)
		if !ok {
			return fmt.Errorf("%q is neither an address nor a CIDR range", a)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("%q %s", a, every)
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
// host; Domains, in its place, each domain and every host under it, as a block's; Paths are prefixes,
// each the path itself and everything below it.
//
// Header makes the allow one of an API sold by key — X-Cars-Key, Authorization — on the hosts it names:
// a request bringing the header, with any value but blanks, is refused by no block, whatever its
// User-Agent, as a partner's server or bot is most often an HTTP library a block refuses by name. Its
// presence is enough because the app checks the key itself and answers 401 without a valid one: a
// scraper writing the header gets past the blocks to that refusal. So such an allow spares the blocks
// alone, never the ban, which would otherwise spare any client writing the header; and it names its
// hosts, Host or Domains — without them it would open every host of the server to anyone.
type BotAllow struct {
	Host      string   `yaml:"host"`
	Domains   []string `yaml:"domains"`
	Paths     []string `yaml:"paths"`
	UserAgent string   `yaml:"user_agent"`
	Header    string   `yaml:"header"`
}

// validate checks an allow: something to match, its hosts, its header with the hosts it is for, its
// paths and its User-Agent.
func (a BotAllow) validate() error {
	if a.Host == "" && len(a.Domains) == 0 && len(a.Paths) == 0 && a.UserAgent == "" && a.Header == "" {
		return errors.New("nothing to match: it would let every bot through")
	}
	if err := a.validateHosts(); err != nil {
		return err
	}
	if err := a.validateHeader(); err != nil {
		return err
	}
	return a.validatePaths()
}

// validateHosts checks an allow's host or its domains.
func (a BotAllow) validateHosts() error {
	if a.Host != "" && !domainRe.MatchString(a.Host) {
		return fmt.Errorf("host %q must be one lowercase host such as img.example.com", a.Host)
	}
	if a.Host != "" && len(a.Domains) > 0 {
		return errors.New("host and domains: one or the other")
	}
	for _, d := range a.Domains {
		if !domainRe.MatchString(d) {
			return fmt.Errorf("domains: %q must be a lowercase domain such as example.com — it covers every host under it", d)
		}
	}
	return nil
}

// validateHeader checks an allow's header: a key's name, on the hosts it names.
func (a BotAllow) validateHeader() error {
	switch {
	case a.Header == "":
		return nil
	case a.Host == "" && len(a.Domains) == 0:
		return fmt.Errorf("header %s needs host or domains: without them anyone writing it would get past every block on every host of the server", a.Header)
	case !headerRe.MatchString(a.Header):
		return fmt.Errorf("header %q must be a header's name such as X-Cars-Key", a.Header)
	case strings.EqualFold(a.Header, "Host") || strings.EqualFold(a.Header, "User-Agent"):
		return fmt.Errorf("header %s: every request brings it; the allow is for a key's header", a.Header)
	}
	return nil
}

// validatePaths checks an allow's paths and its User-Agent.
func (a BotAllow) validatePaths() error {
	for _, p := range a.Paths {
		if !pathRe.MatchString(p) {
			return fmt.Errorf("path %q must be an absolute prefix without a trailing slash, such as /pics", p)
		}
	}
	if a.UserAgent != "" {
		return checkUserAgent(a.UserAgent)
	}
	return nil
}

// domainRe is a lowercase DNS name of two labels or more, without a wildcard.
var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// LoadServer reads and checks a server.yml.
func LoadServer(path string) (*Server, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := parseServerIn(data, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ParseServer is LoadServer on bytes, its range_sets files read relative to the working directory.
func ParseServer(data []byte) (*Server, error) { return parseServerIn(data, ".") }

// parseServerIn is LoadServer on bytes, its range_sets files read relative to dir: strict about
// unknown keys and about a second document, for the same reason as Parse.
func parseServerIn(data []byte, dir string) (*Server, error) {
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
		Ban  yaml.Node `yaml:"ban"`
		Gate yaml.Node `yaml:"gate"`
		CA   yaml.Node `yaml:"trusted_proxies_ca"`
	}
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	// And for the CA: an empty one — its certificate taken out while changing it — would trust the
	// headers of every connection from the proxies' addresses again.
	if strings.TrimSpace(s.TrustedProxiesCA) == "" && keys.CA.Kind != 0 {
		return nil, errors.New("trusted_proxies_ca: empty; write the CA's certificate, or remove the key to trust the proxies by address alone")
	}
	if s.Ban == nil && keys.Ban.Kind != 0 {
		return nil, errors.New("ban: empty; write `ban: {}` for the defaults (300 requests in 1m ban for 24h), or remove the key for no ban")
	}
	// The same for the gate: applied, an empty one would lift it from every group.
	if s.Gate == nil && keys.Gate.Kind != 0 {
		return nil, errors.New("gate: empty; remove the key for no gate")
	}
	if err := s.readRangeSets(dir); err != nil {
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
	if s.Revision < 1 && (s.Revision != 0 || len(s.Bots.Block) > 0 || len(s.Bots.Allow) > 0 || s.Egress != nil || len(s.TrustedProxies) > 0 || s.TrustedProxiesCA != "" || len(s.RangeSets) > 0 || s.Ban != nil || s.Gate != nil) {
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
	if err := s.validateRangeSets(); err != nil {
		return err
	}
	if s.Gate != nil {
		if err := s.Gate.validate(); err != nil {
			return fmt.Errorf("gate: %w", err)
		}
		if err := s.Gate.withRangeSets(s.RangeSets); err != nil {
			return fmt.Errorf("gate: %w", err)
		}
	}
	// Trusting everyone hands every app the address a visitor writes into X-Forwarded-For.
	if err := checkRanges(s.TrustedProxies, "lets every address in; name the proxies in front of boks"); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	if err := checkWrittenAsIPv4(s.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	// The Worker's address alone is cut to nothing (TrustedPrefixes): applied, nothing would be trusted
	// and a CA beside it dropped without a word.
	if len(s.TrustedProxies) > 0 && len(s.TrustedPrefixes()) == 0 {
		return fmt.Errorf("trusted_proxies: only %s, Cloudflare's client address of a Worker, which boks never trusts; name the proxies in front of boks", WorkerClientIP)
	}
	if err := s.validateCA(); err != nil {
		return fmt.Errorf("trusted_proxies_ca: %w", err)
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
		if err := a.validate(); err != nil {
			return fmt.Errorf("bots.allow[%d]: %w", i, err)
		}
	}
	return nil
}

// validateCA checks the trusted proxies' CA: certificates alone, beside the proxies they are asked of.
func (s *Server) validateCA() error {
	if s.TrustedProxiesCA == "" {
		return nil
	}
	if len(s.TrustedProxies) == 0 {
		return errors.New("no trusted_proxies to ask a certificate of")
	}
	_, err := parseCAs(s.TrustedProxiesCA)
	return err
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
	if err := checkRanges(e.Allow, "lets every address in; name the clients"); err != nil {
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
	if err := checkRanges(b.ExemptRanges, "lets every address in; name the addresses to leave uncounted"); err != nil {
		return fmt.Errorf("exempt_ranges: %w", err)
	}
	if err := checkWrittenAsIPv4(b.ExemptRanges); err != nil {
		return fmt.Errorf("exempt_ranges: %w", err)
	}
	if err := checkRanges(b.DenyRanges, "refuses every address; name the addresses to refuse"); err != nil {
		return fmt.Errorf("deny_ranges: %w", err)
	}
	if err := checkWrittenAsIPv4(b.DenyRanges); err != nil {
		return fmt.Errorf("deny_ranges: %w", err)
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
