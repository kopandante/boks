package config

import (
	"encoding/json"
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
		"the name is used twice":          "servers: [a]\nrevision: 1\ngate:\n  groups:\n    - " + ok + "}\n    - {name: a, app: b, mode: log, secret_env: B}\n",
		"in two groups":                   "servers: [a]\nrevision: 1\ngate:\n  groups:\n    - " + ok + "}\n    - {name: b, app: a, mode: log, secret_env: B}\n",
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
