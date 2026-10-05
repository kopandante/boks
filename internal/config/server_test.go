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

func TestParseServerRejects(t *testing.T) {
	block := func(rule string) string {
		return "servers: [lab]\nrevision: 1\nbots:\n  block:\n    - " + rule + "\n"
	}
	allow := func(entry string) string {
		return "servers: [lab]\nrevision: 1\nbots:\n  allow:\n    - " + entry + "\n"
	}
	cases := map[string]string{
		"servers":                     "revision: 1\n",
		"revision":                    "servers: [lab]\n",
		"field bot not found":         "servers: [lab]\nrevision: 1\nbot: {}\n",
		"more than one YAML document": "servers: [lab]\nrevision: 1\n---\nservers: [x]\n",
		"name":                        block(`{name: Infra, user_agent: bot}`),
		"used twice":                  "servers: [lab]\nrevision: 1\nbots:\n  block:\n    - {name: a, user_agent: x}\n    - {name: a, user_agent: y}\n",
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
