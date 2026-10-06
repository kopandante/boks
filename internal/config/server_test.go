package config

import (
	"strings"
	"testing"
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
