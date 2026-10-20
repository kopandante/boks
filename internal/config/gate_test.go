package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// gated is the gate of the plan's revision 16 of hb-sites, two of its groups: the template's and
// glavdoroga's partner Bearer.
const gated = `servers: [hb-sites]
revision: 16
gate:
  groups:
    - name: koreaautotrade
      app: koreaautotrade
      secret_env: KOREAAUTOTRADE_GATE_SECRET
      mode: log
      site_gate: on
      skip_fp: [/api/encar/pics]
    - name: glavdoroga
      app: glavdoroga
      secret_env: GLAVDOROGA_GATE_SECRET
      mode: enforce
      skip_fp: [/api/encar/pics]
      exempt: [{prefix: /api/encar/}, {exact: /api/hook, methods: [POST]}]
      bearer: {paths: ['^/api/encar(/|$)'], methods: [GET, HEAD], digests_env: GLAVDOROGA_BEARER_DIGESTS}
`

// boks reads of a group the fields it acts on itself; the rest goes to the proxy's handler as written,
// as JSON, whose schema Caddy checks.
func TestParseServerGate(t *testing.T) {
	s, err := ParseServer([]byte(gated))
	if err != nil {
		t.Fatal(err)
	}
	g := s.Gate
	if len(g.Groups) != 2 || g.Groups[0].App != "koreaautotrade" || g.Groups[0].SiteGate != "on" || g.Groups[1].SiteGate != "on" ||
		g.Groups[1].Mode != "enforce" || g.Groups[1].Bearer == nil || g.Groups[1].Bearer.DigestsEnv != "GLAVDOROGA_BEARER_DIGESTS" {
		t.Errorf("groups: %+v", g.Groups)
	}
	var back struct {
		Groups []map[string]any `json:"groups"`
	}
	if err := json.Unmarshal(g.JSON, &back); err != nil {
		t.Fatal(err)
	}
	if back.Groups[1]["exempt"].([]any)[1].(map[string]any)["methods"].([]any)[0] != "POST" || back.Groups[0]["site_gate"] != "on" {
		t.Errorf("json: %s", g.JSON)
	}
	if s, err := ParseServer([]byte(habsida)); err != nil || s.Gate != nil {
		t.Errorf("no gate without the key: %v", err)
	}
}

func TestParseServerGateRejects(t *testing.T) {
	group := func(g string) string { return "servers: [a]\nrevision: 1\ngate:\n  groups:\n    - " + g + "\n" }
	ok := "{name: a, app: a, mode: log, secret_env: A_SECRET"
	cases := map[string]string{
		"gate: empty":                     "servers: [a]\nrevision: 1\ngate:\n",
		"empty; remove the key":           "servers: [a]\nrevision: 1\nban: {}\ngate:\n#  groups:\n",
		"groups: at least one":            "servers: [a]\nrevision: 1\ngate: {groups: []}\n",
		"gate: only groups":               "servers: [a]\nrevision: 1\ngate: {groups: [" + ok + "}], mode: log}\n",
		"name":                            group("{app: a, mode: log, secret_env: A_SECRET}"),
		"app: required":                   group("{name: a, mode: log, secret_env: A_SECRET}"),
		"mode":                            group("{name: a, app: a, mode: ban, secret_env: A_SECRET}"),
		"secret_env":                      group("{name: a, app: a, mode: log}"),
		"site_gate":                       group(ok + ", site_gate: maybe}"),
		"site_gate off goes with enforce": group(ok + ", site_gate: off}"),
		"secret never goes in server.yml": group(ok + ", secrets: [x]}"),
		"digests never go":                group(ok + ", bearer: {paths: [x], digests: [x], digests_env: D}}"),
		"digests_env":                     group(ok + ", bearer: {paths: [x]}}"),
		"boks writes it":                  group(ok + ", hosts: [a.example.com]}"),
		`"Secrets": keys are written in lowercase`: group(ok + ", Secrets: [x]}"),
		`"Digests": keys are written in lowercase`: group(ok + ", bearer: {paths: [x], Digests: [x], digests_env: D}}"),
		`"Mode": keys are written in lowercase`:    group(ok + ", Mode: enforce}"),
		`"Prefix": keys are written in lowercase`:  group(ok + ", exempt: [{prefix: /a, Prefix: /b}]}"),
		`"ſecrets": keys are written in lowercase`: group(ok + ", ſecrets: [x]}"),
		"is a secret_env and a bearer.digests_env": group(ok + ", bearer: {paths: [x], digests_env: A_SECRET}}"),
		"is a previous secret and a secret_env":    "servers: [a]\nrevision: 1\ngate:\n  groups:\n    - " + ok + "}\n    - {name: b, app: b, mode: log, secret_env: A_SECRET_PREVIOUS}\n",
		"app: a string; quote it":                  group("{name: a, app: 2048, mode: log, secret_env: A_SECRET}"),
		"revision: required":                       "servers: [a]\ngate:\n  groups:\n    - " + ok + "}\n",
		"the name is used twice":                   "servers: [a]\nrevision: 1\ngate:\n  groups:\n    - " + ok + "}\n    - {name: a, app: b, mode: log, secret_env: B}\n",
		"in two groups":                            "servers: [a]\nrevision: 1\ngate:\n  groups:\n    - " + ok + "}\n    - {name: b, app: a, mode: log, secret_env: B}\n",
		"token_ttl goes with site_gate off":        group(ok + ", token_ttl: 12h}"),
		`token_ttl "soon": a duration`:             group("{name: a, app: a, mode: enforce, site_gate: off, secret_env: A_SECRET, token_ttl: soon}"),
		"token_ttl 1m0s must be from":              group("{name: a, app: a, mode: enforce, site_gate: off, secret_env: A_SECRET, token_ttl: 1m}"),
		"token_ttl 48h0m0s must be from":           group("{name: a, app: a, mode: enforce, site_gate: off, secret_env: A_SECRET, token_ttl: 48h}"),
		"token_ttl: a string; quote it":            group("{name: a, app: a, mode: enforce, site_gate: off, secret_env: A_SECRET, token_ttl: 3600}"),
	}
	for want, file := range cases {
		_, err := ParseServer([]byte(file))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want an error with %q, got %v", want, err)
		}
	}
}

// The secrets come from the environment boks runs in, never the file: the current one and, while it is
// rotated out, NAME_PREVIOUS; the Bearer digests a comma list. One not set is left to what the server
// keeps; one set wrong stops the apply before any server is asked.
func TestGateSecrets(t *testing.T) {
	s, err := ParseServer([]byte(gated))
	if err != nil {
		t.Fatal(err)
	}
	cur, prev := strings.Repeat("c", 32), strings.Repeat("p", 32)
	d1, d2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	t.Setenv("KOREAAUTOTRADE_GATE_SECRET", cur)
	t.Setenv("KOREAAUTOTRADE_GATE_SECRET_PREVIOUS", prev)
	t.Setenv("GLAVDOROGA_BEARER_DIGESTS", d1+", "+d2)
	got, err := s.Gate.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got["KOREAAUTOTRADE_GATE_SECRET"], " ") != cur+" "+prev || strings.Join(got["GLAVDOROGA_BEARER_DIGESTS"], " ") != d1+" "+d2 {
		t.Errorf("secrets %v", got)
	}
	if _, set := got["GLAVDOROGA_GATE_SECRET"]; set {
		t.Errorf("a secret not in the environment is left to the server: %v", got)
	}
	for name, value := range map[string]string{
		"KOREAAUTOTRADE_GATE_SECRET": "short",
		"GLAVDOROGA_GATE_SECRET":     " " + cur,
		"GLAVDOROGA_BEARER_DIGESTS":  d1 + ",nothex",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			if _, err := s.Gate.Secrets(); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s=%q: %v", name, value, err)
			}
		})
	}
}

// A previous secret alone would leave the server's pair in place: refused. A digest set wrong is named
// by its place, never printed — it may be the token itself.
func TestGateSecretsRefuseHalfAPairAndKeepDigestsOut(t *testing.T) {
	s, err := ParseServer([]byte(gated))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range s.Gate.Groups {
		os.Unsetenv(g.SecretEnv)
		if g.Bearer != nil {
			os.Unsetenv(g.Bearer.DigestsEnv)
		}
	}
	g := s.Gate.Groups[0]
	t.Setenv(g.SecretEnv+"_PREVIOUS", strings.Repeat("p", 32))
	if _, err := s.Gate.Secrets(); err == nil || !strings.Contains(err.Error(), "_PREVIOUS is set without") {
		t.Errorf("want half a pair refused, got %v", err)
	}
	// An empty previous one is none: the current one alone.
	t.Setenv(g.SecretEnv, strings.Repeat("c", 32))
	t.Setenv(g.SecretEnv+"_PREVIOUS", "")
	if got, err := s.Gate.Secrets(); err != nil || len(got[g.SecretEnv]) != 1 {
		t.Errorf("want the current secret alone: %v %v", got[g.SecretEnv], err)
	}
	os.Unsetenv(g.SecretEnv)
	os.Unsetenv(g.SecretEnv + "_PREVIOUS")
	for _, g := range s.Gate.Groups {
		if g.Bearer == nil {
			continue
		}
		token := "a-bearer-token-put-here-by-mistake"
		t.Setenv(g.Bearer.DigestsEnv, token)
		if _, err := s.Gate.Secrets(); err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "entry 1") {
			t.Errorf("want the entry named, not printed: %v", err)
		}
		// The digest the handler compares is lowercase hex: one in capitals would never match.
		t.Setenv(g.Bearer.DigestsEnv, strings.Repeat("A", 64))
		if _, err := s.Gate.Secrets(); err == nil || !strings.Contains(err.Error(), "entry 1") {
			t.Errorf("want a digest in capitals refused, got %v", err)
		}
	}
}

// token_ttl of a site that checks nothing itself goes to the handler as written.
func TestParseServerGateTokenTTL(t *testing.T) {
	s, err := ParseServer([]byte("servers: [a]\nrevision: 1\ngate:\n  groups:\n    - {name: e, app: e, mode: enforce, site_gate: off, secret_env: E_SECRET, skip_fp: [/api/], token_ttl: 12h}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Gate.Groups[0].TokenTTL != "12h" || !strings.Contains(string(s.Gate.JSON), `"token_ttl":"12h"`) {
		t.Errorf("%+v %s", s.Gate.Groups[0], s.Gate.JSON)
	}
}
