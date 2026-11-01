package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// habsida is the bot policy Habsida ran as hand-written Traefik files (bot-policy.yml,
// telegram-images-allow.yml), as server.yml says it.
const habsida = `
servers: [habsida]
revision: 1
bots:
  allow:
    - host: backends-encar.v1.backend.dev.habsidev.com
      paths: [/pics, /pics_i]
      user_agent: "(?i)telegrambot"
  block:
    - name: infra
      domains: [habsidev.com]
      user_agent: "(?i)(bot|crawler|spider|scrape|slurp|yeti|daumoa|omgili|googleother|anthropic-ai|claude-|cohere-|meta-external|externalhit)"
    - name: crawlers
      user_agent: "(?i)(bingbot|duckduckbot|applebot|gptbot|claudebot|ahrefsbot|semrushbot|petalbot)"
`

func TestParseServer(t *testing.T) {
	s, err := ParseServer([]byte(habsida))
	if err != nil {
		t.Fatal(err)
	}
	if s.Revision != 1 || len(s.Bots.Block) != 2 || s.Bots.Block[0].Domains[0] != "habsidev.com" ||
		len(s.Bots.Allow) != 1 || s.Bots.Allow[0].Paths[1] != "/pics_i" {
		t.Errorf("parsed wrong: %+v", s)
	}
}

// An allow by a header names its hosts by host or by domains, as the pool's gateway on hb-poolapi sells
// its API by X-Cars-Key.
func TestParseServerAllowByHeader(t *testing.T) {
	s, err := ParseServer([]byte("servers: [hb-poolapi]\nrevision: 1\nbots:\n  allow:\n" +
		"    - {domains: [v1.backend.dev.habsidev.com], header: X-Cars-Key}\n" +
		"    - {host: translate.habsidev.com, paths: [/api], header: X-Cars-Key}\n"))
	if err != nil {
		t.Fatal(err)
	}
	a := s.Bots.Allow
	if len(a) != 2 || a[0].Domains[0] != "v1.backend.dev.habsidev.com" || a[0].Header != "X-Cars-Key" || a[1].Host != "translate.habsidev.com" {
		t.Errorf("parsed wrong: %+v", a)
	}
}

// A server.yml that only lists servers is what `boks server install` reads: it applies no policy, so
// it needs no revision.
func TestParseServerWithServersOnly(t *testing.T) {
	s, err := ParseServer([]byte("servers: [lab]\n"))
	if err != nil || s.Revision != 0 || len(s.Servers) != 1 {
		t.Errorf("got %+v, %v", s, err)
	}
}

func TestParseServerRejects(t *testing.T) {
	block := func(rule string) string {
		return "servers: [lab]\nrevision: 1\nbots:\n  block:\n    - " + rule + "\n"
	}
	allow := func(entry string) string {
		return "servers: [lab]\nrevision: 1\nbots:\n  allow:\n    - " + entry + "\n"
	}
	cases := map[string]string{
		"servers":                     "revision: 1\n",
		"revision":                    "servers: [lab]\nbots:\n  block:\n    - {name: a, user_agent: gptbot}\n",
		"from 1":                      "servers: [lab]\nrevision: -1\n",
		"field bot not found":         "servers: [lab]\nrevision: 1\nbot: {}\n",
		"more than one YAML document": "servers: [lab]\nrevision: 1\n---\nservers: [x]\n",
		// An empty document hides nothing after it.
		"read as one": "servers: [lab]\nrevision: 1\n---\n---\nbots:\n  block:\n    - {name: a, user_agent: gptbot}\n",
		"name":        block(`{name: Infra, user_agent: bot}`),
		"used twice":  "servers: [lab]\nrevision: 1\nbots:\n  block:\n    - {name: a, user_agent: x}\n    - {name: a, user_agent: y}\n",
		// A domain covers every host under it; a wildcard would say something else.
		"lowercase domain":       block(`{name: a, domains: ["*.habsidev.com"], user_agent: bot}`),
		"user_agent is required": block(`{name: a, domains: [habsidev.com]}`),
		"not a regular":          block(`{name: a, user_agent: "(?i)(bot"}`),
		"nothing to match":       allow(`{}`),
		"one lowercase host":     allow(`{host: "*.habsidev.com"}`),
		"absolute prefix":        allow(`{paths: [pics]}`),
		// An allow by a header without its hosts would open every host of the server to anyone writing it.
		"needs host or domains":               allow(`{header: X-Cars-Key}`),
		"needs host or domains: without them": allow(`{header: X-Cars-Key, paths: [/api], user_agent: bot}`),
		"a header's name":                     allow(`{host: translate.habsidev.com, header: "X Cars Key"}`),
		"every request brings it":             allow(`{host: translate.habsidev.com, header: user-agent}`),
		"one or the other":                    allow(`{host: translate.habsidev.com, domains: [habsidev.com], header: X-Cars-Key}`),
		"domains: \"*.habsidev.com\"":         allow(`{domains: ["*.habsidev.com"], header: X-Cars-Key}`),
	}
	for want, doc := range cases {
		if _, err := ParseServer([]byte(doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an error containing %q, got %v", strings.TrimSpace(doc), want, err)
		}
	}
}

// encarPool is the egress the tinyproxy of the encar pool ran, as server.yml says it.
const encarPool = `
servers: [egress1]
revision: 1
egress:
  allow: [203.0.113.10, 198.51.100.0/24]
  user: encar
  password_env: ENCAR_EGRESS_PROXY_PASSWORD
  ports: [443, 80]
  hosts_file: /etc/hosts
`

func TestParseServerEgress(t *testing.T) {
	s, err := ParseServer([]byte(encarPool))
	if err != nil {
		t.Fatal(err)
	}
	e := s.Egress
	if e == nil || e.Port != DefaultEgressPort || e.User != "encar" || len(e.Ports) != 2 || e.HostsFile != "/etc/hosts" {
		t.Fatalf("parsed wrong: %+v", e)
	}
	if p := e.Prefixes(); len(p) != 2 || p[0].String() != "203.0.113.10/32" || p[1].String() != "198.51.100.0/24" {
		t.Errorf("prefixes: %v", p)
	}
	s, err = ParseServer([]byte("servers: [a]\nrevision: 1\negress: {allow: [10.0.0.0/8]}\n"))
	if err != nil || len(s.Egress.Ports) != 1 || s.Egress.Ports[0] != 443 || s.Egress.User != "" {
		t.Errorf("defaults: %+v, %v", s.Egress, err)
	}
	// As docker records a mount's source, or the proxy would never look like the one the policy needs.
	if s, err := ParseServer([]byte("servers: [a]\nrevision: 1\negress: {allow: [10.0.0.1], hosts_file: /etc//hosts/}\n")); err != nil || s.Egress.HostsFile != "/etc/hosts" {
		t.Errorf("hosts_file not cleaned: %+v, %v", s, err)
	}
	t.Setenv("ENCAR_EGRESS_PROXY_PASSWORD", "")
	if _, err := e.Password(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty password: %v", err)
	}
	t.Setenv("ENCAR_EGRESS_PROXY_PASSWORD", "s3cret")
	if p, err := e.Password(); err != nil || p != "s3cret" {
		t.Errorf("password: %q, %v", p, err)
	}
}

func TestParseServerEgressRejects(t *testing.T) {
	egress := func(body string) string { return "servers: [a]\nrevision: 1\negress: " + body + "\n" }
	for want, doc := range map[string]string{
		"revision":                "servers: [a]\negress: {allow: [10.0.0.1]}\n",
		"clients that may use it": egress(`{port: 3128}`),
		"lets every address in":   egress(`{allow: [0.0.0.0/0]}`),
		"neither an address":      egress(`{allow: [habsida]}`),
		"proxy's own":             egress(`{port: 443, allow: [10.0.0.1]}`),
		"not a TCP port":          egress(`{port: 70000, allow: [10.0.0.1]}`),
		"go together":             egress(`{allow: [10.0.0.1], user: encar}`),
		"never goes in":           egress(`{allow: [10.0.0.1], user: encar, password_env: "pass word"}`),
		"letters, digits":         egress(`{allow: [10.0.0.1], user: "en:car", password_env: P}`),
		"ports: 0":                egress(`{allow: [10.0.0.1], ports: [0]}`),
		"absolute path":           egress(`{allow: [10.0.0.1], hosts_file: etc/hosts}`),
	} {
		if _, err := ParseServer([]byte(doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an error containing %q, got %v", strings.TrimSpace(doc), want, err)
		}
	}
}

// The server keeps the password in a file whose reading trims the ends: one with spaces there, or a
// line break, is refused before anything changes rather than every client being refused after.
func TestEgressPasswordWithoutWhitespaceAtTheEnds(t *testing.T) {
	e := &Egress{User: "encar", PasswordEnv: "EG_PASS"}
	for _, bad := range []string{"s3cret ", " s3cret", "s3c\nret"} {
		t.Setenv("EG_PASS", bad)
		if _, err := e.Password(); err == nil || !strings.Contains(err.Error(), "whitespace") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	t.Setenv("EG_PASS", "s3 cret")
	if p, err := e.Password(); err != nil || p != "s3 cret" {
		t.Errorf("a space inside: %q, %v", p, err)
	}
}

// A proxy in front of boks is trusted by address or range; a file without one trusts no one.
func TestParseServerTrustedProxies(t *testing.T) {
	s, err := ParseServer([]byte("servers: [a]\nrevision: 1\ntrusted_proxies: [87.228.113.239, 10.1.2.3/16, \"2001:db8::1/48\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range s.TrustedPrefixes() {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "87.228.113.239/32 10.1.0.0/16 2001:db8::/48" {
		t.Errorf("prefixes: %v", got)
	}
	s, err = ParseServer([]byte(habsida))
	if err != nil || s.TrustedProxies != nil || s.TrustedPrefixes() != nil {
		t.Errorf("want no trusted proxies without the field: %v, %v", s.TrustedProxies, err)
	}
}

func TestParseServerTrustedProxiesRejects(t *testing.T) {
	trusted := func(list string) string { return "servers: [a]\nrevision: 1\ntrusted_proxies: " + list + "\n" }
	for _, c := range []struct{ doc, want string }{
		{"servers: [a]\ntrusted_proxies: [10.0.0.1]\n", "revision"},
		{trusted(`[0.0.0.0/0]`), "trusted_proxies: \"0.0.0.0/0\" lets every address in"},
		{trusted(`["::/0"]`), "lets every address in"},
		{trusted(`[traefik]`), "trusted_proxies: \"traefik\" is neither an address nor a CIDR range"},
		{trusted(`[10.0.0.1/33]`), "neither an address"},
		{trusted(`[""]`), "neither an address"},
		{trusted(`["::ffff:87.228.113.239"]`), "trusted_proxies: \"::ffff:87.228.113.239\" is an IPv4 address written as IPv6"},
		{trusted(`["::ffff:10.0.0.0/104"]`), "written as IPv6"},
		// Masked to /80, the address would be ::, an IPv6 range that never holds the proxy.
		{trusted(`["::ffff:87.228.113.239/80"]`), "written as IPv6"},
	} {
		if _, err := ParseServer([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", strings.TrimSpace(c.doc), c.want, err)
		}
	}
}

// A ban without fields is one rule, default: 300 requests a minute bans for a day; durations are
// written one way, ranges as given.
func TestParseServerBan(t *testing.T) {
	s, err := ParseServer([]byte("servers: [a]\nrevision: 1\nban: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if b := s.Ban; !reflect.DeepEqual(b.Rules, []BanRule{{Name: "default", Limit: 300, Window: "1m", Class: "all"}}) ||
		b.Limit != 0 || b.Window != "" || b.Duration != "24h" || b.Heuristics != nil || b.ExemptPaths != nil || b.ExemptPrefixes() != nil {
		t.Errorf("defaults: %+v", b)
	}
	s, err = ParseServer([]byte(`servers: [a]
revision: 2
ban:
  limit: 120
  window: 60s
  duration: 1440m
  exempt_paths: ["^/api/[a-z]+/pics", "^/api/auctions/[^/]+/(image|video)"]
  exempt_ranges: [203.0.113.7, 198.51.100.9/24]
  deny_ranges: [89.167.100.21, 2001:db8::7/32]
`))
	if err != nil {
		t.Fatal(err)
	}
	b := s.Ban
	var ranges, deny []string
	for _, p := range b.ExemptPrefixes() {
		ranges = append(ranges, p.String())
	}
	for _, p := range b.DenyPrefixes() {
		deny = append(deny, p.String())
	}
	if strings.Join(deny, " ") != "89.167.100.21/32 2001:db8::/32" {
		t.Errorf("deny: %v", deny)
	}
	if !reflect.DeepEqual(b.Rules, []BanRule{{Name: "default", Limit: 120, Window: "1m", Class: "all"}}) || b.Duration != "24h" ||
		len(b.ExemptPaths) != 2 || strings.Join(ranges, " ") != "203.0.113.7/32 198.51.100.0/24" {
		t.Errorf("ban: %+v, ranges %v", b, ranges)
	}
	for in, want := range map[string]string{"90s": "1m30s", "1h": "1h", "5400s": "1h30m", "720h": "720h", "1h0m1s": "1h0m1s"} {
		s, err := ParseServer([]byte("servers: [a]\nrevision: 1\nban: {duration: " + in + "}\n"))
		if err != nil || s.Ban.Duration != want {
			t.Errorf("duration %s: want %s, got %v %v", in, want, s, err)
		}
	}
	if s, err := ParseServer([]byte(habsida)); err != nil || s.Ban != nil {
		t.Errorf("want no ban without the key: %v", err)
	}
}

// hbSites is the ban the plan sets for hb-sites: two windows over everything, one over pages, and
// the heuristics in the journal only.
const hbSites = `servers: [hb-sites]
revision: 3
ban:
  duration: 24h
  rules:
    - {name: all-1m, limit: 1500, window: 60s}
    - {name: all-10m, limit: 2500, window: 10m, class: all}
    - {name: pages, limit: 120, window: 1m, class: page}
    - {name: report, limit: 30, window: 1m, class: api, paths: ["^/api/[a-z]+/report$"]}
  heuristics:
    mode: log
    cluster: {limit: 300, window: 600s, min_addresses: 10}
`

// Rules are taken as written, their class and windows written one way; the heuristics fill in the
// cluster's defaults and `mode: off` is no heuristics at all.
func TestParseServerBanRules(t *testing.T) {
	s, err := ParseServer([]byte(hbSites))
	if err != nil {
		t.Fatal(err)
	}
	b := s.Ban
	want := []BanRule{
		{Name: "all-1m", Limit: 1500, Window: "1m", Class: "all"},
		{Name: "all-10m", Limit: 2500, Window: "10m", Class: "all"},
		{Name: "pages", Limit: 120, Window: "1m", Class: "page"},
		{Name: "report", Limit: 30, Window: "1m", Class: "api", Paths: []string{"^/api/[a-z]+/report$"}},
	}
	if !reflect.DeepEqual(b.Rules, want) || b.Limit != 0 || b.Window != "" {
		t.Errorf("rules: %+v", b)
	}
	if h := b.Heuristics; h == nil || *h != (BanHeuristics{Mode: "log", Cluster: BanCluster{Limit: 300, Window: "10m", MinAddresses: 10}}) {
		t.Errorf("heuristics: %+v", h)
	}
	s, err = ParseServer([]byte("servers: [a]\nrevision: 1\nban:\n  heuristics: {mode: ban}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h := s.Ban.Heuristics; h == nil || *h != (BanHeuristics{Mode: "ban", Cluster: BanCluster{Limit: 300, Window: "10m", MinAddresses: 10}}) {
		t.Errorf("cluster defaults: %+v", h)
	}
	for _, off := range []string{"{}", "{mode: off}", "{mode: off, cluster: {limit: 5}}"} {
		s, err := ParseServer([]byte("servers: [a]\nrevision: 1\nban:\n  heuristics: " + off + "\n"))
		if err != nil || s.Ban.Heuristics != nil {
			t.Errorf("%s: want no heuristics, got %+v %v", off, s, err)
		}
	}
}

func TestParseServerBanRejects(t *testing.T) {
	ban := func(body string) string { return "servers: [a]\nrevision: 1\nban: " + body + "\n" }
	rules := func(list string) string { return ban(`{rules: ` + list + `}`) }
	var seventeen []string
	for i := range 17 {
		seventeen = append(seventeen, fmt.Sprintf("{name: r%d, limit: 1, window: 1m}", i))
	}
	for _, c := range []struct{ doc, want string }{
		{"servers: [a]\nban: {}\n", "revision"},
		{ban(`{limit: -1}`), "ban: limit -1: must be at least 1"},
		{ban(`{window: 1x}`), `ban: window: "1x" is not a duration`},
		{ban(`{window: 500ms}`), "whole seconds, at least 1s"},
		{ban(`{window: 1500ms}`), "whole seconds"},
		{ban(`{window: -1m}`), "at least 1s"},
		{ban(`{window: 2h}`), "window: 2h is longer than 1h"},
		{ban(`{duration: 721h}`), "duration: 721h is longer than 720h"},
		{ban(`{exempt_paths: ["("]}`), `exempt_paths: "(" is not a regular expression`},
		{ban(`{exempt_paths: [""]}`), "turn the ban off"},
		{ban(`{exempt_ranges: [office]}`), `exempt_ranges: "office" is neither an address nor a CIDR range`},
		{ban(`{exempt_ranges: [0.0.0.0/0]}`), "lets every address in"},
		{ban(`{exempt_ranges: ["::ffff:203.0.113.7"]}`), "written as IPv6"},
		{ban(`{deny_ranges: [n8n]}`), `deny_ranges: "n8n" is neither an address nor a CIDR range`},
		{ban(`{deny_ranges: ["::/0"]}`), "deny_ranges: \"::/0\" refuses every address"},
		{ban(`{deny_ranges: ["::ffff:89.167.100.21"]}`), "deny_ranges: \"::ffff:89.167.100.21\" is an IPv4 address written as IPv6"},
		{ban(`{limt: 3}`), "field limt not found"},
		{ban(""), "ban: empty; write `ban: {}`"},
		{"servers: [a]\nrevision: 1\nban:\n  # limit: 300\n", "ban: empty"},
		{ban("~"), "ban: empty"},
		// Rules replace limit and window: both at once would leave which one counts to a guess.
		{ban(`{limit: 300, rules: [{name: a, limit: 1, window: 1m}]}`), "ban: limit and window go without rules"},
		{ban(`{window: 1m, rules: [{name: a, limit: 1, window: 1m}]}`), "go without rules"},
		{rules(`[]`), "ban: rules: empty"},
		{rules("[" + strings.Join(seventeen, ", ") + "]"), "ban: rules: 17 of them, more than 16"},
		{rules(`[{limit: 1, window: 1m}]`), `ban: rules[0]: name "" must match`},
		{rules(`[{name: All, limit: 1, window: 1m}]`), "must match"},
		{rules(`[{name: a, limit: 1, window: 1m}, {name: a, limit: 2, window: 10m}]`), "ban: rules[a]: the name is used twice"},
		{rules(`[{name: a, window: 1m}]`), "ban: rules[a]: limit 0: must be at least 1"},
		{rules(`[{name: a, limit: 1}]`), `ban: rules[a]: window: "" is not a duration`},
		{rules(`[{name: a, limit: 1, window: 2h}]`), "ban: rules[a]: window: 2h is longer than 1h"},
		{rules(`[{name: a, limit: 1, window: 1m, class: pages}]`), `ban: rules[a]: class "pages" must be all, page or api`},
		{rules(`[{name: a, limit: 1, window: 1m, paths: [""]}]`), "ban: rules[a]: paths: an empty pattern"},
		{rules(`[{name: a, limit: 1, window: 1m, paths: ["("]}]`), `ban: rules[a]: paths: "(" is not a regular expression`},
		{rules(`[{name: a, limit: 1, window: 1m, path: [x]}]`), "field path not found"},
		{ban(`{heuristics: {mode: block}}`), `ban: heuristics: mode "block" must be off, log or ban`},
		{ban(`{heuristics: {mode: log, cluster: {limit: -1}}}`), "ban: heuristics: cluster: limit -1: must be at least 1"},
		{ban(`{heuristics: {mode: log, cluster: {window: 2h}}}`), "ban: heuristics: cluster: window: 2h is longer than 1h"},
		{ban(`{heuristics: {mode: log, cluster: {min_addresses: 1}}}`), "ban: heuristics: cluster: min_addresses 1: must be from 2 to 100"},
		{ban(`{heuristics: {mode: log, cluster: {min_addresses: 101}}}`), "must be from 2 to 100"},
	} {
		if _, err := ParseServer([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", strings.TrimSpace(c.doc), c.want, err)
		}
	}
}

// caPEM is a file of the live test of the origin pull (proxy/gate), indented under trusted_proxies_ca.
func caPEM(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../proxy/gate/testdata/originpull/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return "trusted_proxies_ca: |\n  " + strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", "\n  ") + "\n"
}

// The trusted proxies' CA is read as its certificates, DER; without it there are none.
func TestParseServerTrustedProxiesCA(t *testing.T) {
	both := "servers: [a]\nrevision: 1\ntrusted_proxies: [173.245.48.0/20]\n" + caPEM(t, "ca.pem") + "  " + strings.TrimPrefix(caPEM(t, "other-ca.pem"), "trusted_proxies_ca: |\n  ")
	s, err := ParseServer([]byte(both))
	if err != nil {
		t.Fatal(err)
	}
	certs := s.TrustedProxiesCerts()
	if len(certs) != 2 {
		t.Fatalf("want both certificates, got %d", len(certs))
	}
	if c, err := x509.ParseCertificate(certs[0]); err != nil || c.Subject.CommonName != "boks test origin-pull CA" {
		t.Errorf("first certificate: %v %v", c, err)
	}
	s, err = ParseServer([]byte("servers: [a]\nrevision: 1\ntrusted_proxies: [173.245.48.0/20]\n"))
	if err != nil || s.TrustedProxiesCerts() != nil {
		t.Errorf("want none without the field: %v", err)
	}
}

// A CA without proxies to ask, a key, anything but certificates, and an empty one are refused.
func TestParseServerTrustedProxiesCARejects(t *testing.T) {
	trusted := "servers: [a]\nrevision: 1\ntrusted_proxies: [173.245.48.0/20]\n"
	for _, c := range []struct{ doc, want string }{
		{"servers: [a]\n" + caPEM(t, "ca.pem"), "revision"},
		{"servers: [a]\nrevision: 1\n" + caPEM(t, "ca.pem"), "trusted_proxies_ca: no trusted_proxies to ask a certificate of"},
		{trusted + caPEM(t, "client.key"), "trusted_proxies_ca: a EC PRIVATE KEY block; only CERTIFICATE blocks go here"},
		{trusted + "trusted_proxies_ca: cloudflare\n", "trusted_proxies_ca: want one or more PEM certificates"},
		// The key left with its certificate taken out would trust the proxies by address again.
		{trusted + "trusted_proxies_ca:\n", "trusted_proxies_ca: empty"},
		{trusted + "trusted_proxies_ca: |\nban: {}\n", "trusted_proxies_ca: empty"},
		{trusted + "trusted_proxies_ca: \"\"\n", "trusted_proxies_ca: empty"},
		{trusted + caPEM(t, "ca.pem") + "  trailing\n", "want one or more PEM certificates"},
		{trusted + strings.Replace(caPEM(t, "ca.pem"), "|\n  ", "|\n  subject=CN boks\n  ", 1), "want one or more PEM certificates"},
		{trusted + caPEM(t, "ca.pem") + "  between\n  " + strings.TrimPrefix(caPEM(t, "other-ca.pem"), "trusted_proxies_ca: |\n  "), "want one or more PEM certificates"},
		// A key whose base64 is broken, which pem.Decode skips for the certificate after it.
		{trusted + "trusted_proxies_ca: |\n  -----BEGIN EC PRIVATE KEY-----\n  !!!!\n  -----END EC PRIVATE KEY-----\n  " +
			strings.TrimPrefix(caPEM(t, "ca.pem"), "trusted_proxies_ca: |\n  "), "want one or more PEM certificates"},
		{trusted + "trusted_proxies_ca: |\n  -----BEGIN CERTIFICATE-----\n  AAAA\n  -----END CERTIFICATE-----\n", "trusted_proxies_ca: certificate 1:"},
	} {
		if _, err := ParseServer([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", strings.TrimSpace(c.doc)[:40], c.want, err)
		}
	}
	// The term is apply's and rollback's to judge (proxy.CheckCATerm): an expired CA is still read, so
	// status and a rollback away from it run.
	doc := trusted + "trusted_proxies_ca: |\n  " + strings.ReplaceAll(strings.TrimSpace(expiredCAPEM(t)), "\n", "\n  ") + "\n"
	if sc, err := ParseServer([]byte(doc)); err != nil || len(sc.TrustedProxiesCerts()) != 1 {
		t.Errorf("want an expired CA read: %v", err)
	}
}

// expiredCAPEM is a CA certificate that ran out in 2001, as PEM.
func expiredCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "expired CA"},
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Cloudflare's shared origin-pull CA is refused, alone or beside a CA of one's own: any zone with
// global pulls on presents it.
func TestParseServerRefusesTheSharedOriginPullCA(t *testing.T) {
	trusted := "servers: [a]\nrevision: 1\ntrusted_proxies: [173.245.48.0/20]\n"
	own := caPEM(t, "ca.pem")
	shared := caPEM(t, "cloudflare-shared-ca.pem")
	for _, doc := range []string{trusted + shared, trusted + own + "  " + strings.TrimPrefix(shared, "trusted_proxies_ca: |\n  ")} {
		_, err := ParseServer([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), "Cloudflare's shared origin-pull CA") || !strings.Contains(err.Error(), "zone-level") {
			t.Errorf("want the shared CA refused, got %v", err)
		}
	}
	if _, err := ParseServer([]byte(trusted + own)); err != nil {
		t.Errorf("a CA of one's own: %v", err)
	}
}

// The Worker's client address is cut out of a trusted range that holds it: the ranges around it cover
// the rest of the range and nothing else; a range without it stays as written; the address alone goes.
func TestTrustedPrefixesLeaveTheWorkerOut(t *testing.T) {
	s, err := ParseServer([]byte("servers: [a]\nrevision: 1\ntrusted_proxies: [173.245.48.0/20, \"2a06:98c0::/29\", \"2400:cb00::/32\", \"2a06:98c0:3600::103\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := s.TrustedPrefixes()
	if got[0].String() != "173.245.48.0/20" || got[len(got)-1].String() != "2400:cb00::/32" {
		t.Errorf("ranges without the address changed: %v … %v", got[0], got[len(got)-1])
	}
	cut := got[1 : len(got)-1]
	if len(cut) != 128-29 {
		t.Fatalf("want %d ranges around the address, got %d", 128-29, len(cut))
	}
	whole := netip.MustParsePrefix("2a06:98c0::/29")
	for _, p := range cut {
		if p.Contains(WorkerClientIP) || !whole.Contains(p.Addr()) || p.Bits() < 30 {
			t.Errorf("%v: holds the address or lies outside the range", p)
		}
	}
	// Disjoint, one range per length, so together they are the range less one address.
	seen := map[int]bool{}
	for _, p := range cut {
		if seen[p.Bits()] {
			t.Errorf("two ranges of /%d", p.Bits())
		}
		seen[p.Bits()] = true
	}
	for _, a := range []string{"2a06:98c0:3600::102", "2a06:98c0:3600::104", "2a06:98c0::1", "2a06:98c7:ffff:ffff:ffff:ffff:ffff:ffff", "2a06:98c0:3600::"} {
		if n := countHolding(cut, netip.MustParseAddr(a)); n != 1 {
			t.Errorf("%s: held by %d ranges, want 1", a, n)
		}
	}
	if countHolding(got, WorkerClientIP) != 0 {
		t.Errorf("the Worker's address is still trusted")
	}
	// IPv4 the same way: 10.0.0.0/30 less 10.0.0.1.
	if v4 := without(netip.MustParsePrefix("10.0.0.0/30"), netip.MustParseAddr("10.0.0.1")); fmt.Sprint(v4) != "[10.0.0.2/31 10.0.0.0/32]" {
		t.Errorf("IPv4: %v", v4)
	}
}

func countHolding(ps []netip.Prefix, a netip.Addr) int {
	n := 0
	for _, p := range ps {
		if p.Contains(a) {
			n++
		}
	}
	return n
}

// workerGolden is the trusted ranges a proxy at 127.0.0.1 and Cloudflare's 2a06:98c0::/29 become, which
// the live test of the Worker's address loads into Caddy (proxy/gate, TestWorkerIsTheClientThroughCaddy).
const workerGolden = "../../proxy/gate/testdata/worker/trusted.json"

func TestWorkerGolden(t *testing.T) {
	s, err := ParseServer([]byte("servers: [a]\nrevision: 1\ntrusted_proxies: [127.0.0.1, \"2a06:98c0::/29\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	var rs []string
	for _, p := range s.TrustedPrefixes() {
		rs = append(rs, p.String())
	}
	got, _ := json.Marshal(rs)
	got = append(got, '\n')
	if os.Getenv("BOKS_UPDATE") == "1" {
		if err := os.WriteFile(workerGolden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(workerGolden)
	if err != nil || string(got) != string(want) {
		t.Errorf("trusted ranges\n%s\nwant (%s, BOKS_UPDATE=1 to rewrite)\n%s %v", got, workerGolden, want, err)
	}
}
