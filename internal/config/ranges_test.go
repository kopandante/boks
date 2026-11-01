package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rangedGate is a server.yml with the set jp and two groups: dbauto, whose signature names it, and
// shop, whose names none.
func rangedGate(sets string) string {
	return "servers: [a]\nrevision: 1\n" + sets + `gate:
  groups:
    - name: dbauto
      app: dbauto
      mode: enforce
      secret_env: DBAUTO_SECRET
      signatures:
        - {name: node-chrome-jp, mode: enforce, ranges: jp, headers: [{name: accept-encoding, pattern: "^br, gzip, deflate$"}]}
    - name: shop
      app: shop
      mode: log
      secret_env: SHOP_SECRET
`
}

// groupSets are the range_sets boks wrote into each group of s's gate, by the group's name.
func groupSets(t *testing.T, s *Server) map[string]any {
	t.Helper()
	var top struct {
		Groups []map[string]any `json:"groups"`
	}
	if err := json.Unmarshal(s.Gate.JSON, &top); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	for _, g := range top.Groups {
		out[g["name"].(string)] = g["range_sets"]
	}
	return out
}

// The set a signature names goes into its group, as masked ranges; a group naming none gets nothing.
func TestRangeSetsGoIntoTheGroupThatNamesThem(t *testing.T) {
	s, err := ParseServer([]byte(rangedGate("range_sets:\n  jp: [126.1.2.3/8, 1.0.16.0/20, \"2400:4050::/32\", 133.0.0.1]\n  kr: [1.11.0.0/16]\n")))
	if err != nil {
		t.Fatal(err)
	}
	sets := groupSets(t, s)
	if got, _ := json.Marshal(sets["dbauto"]); string(got) != `{"jp":["126.0.0.0/8","1.0.16.0/20","2400:4050::/32","133.0.0.1/32"]}` {
		t.Errorf("dbauto: %s", got)
	}
	if sets["shop"] != nil {
		t.Errorf("shop names no set and got %v", sets["shop"])
	}
}

// A gate without a set named keeps the bytes it had: a server.yml without range_sets applies as before.
func TestNoRangesKeepTheGateAsWritten(t *testing.T) {
	doc := strings.Replace(rangedGate(""), "ranges: jp, ", "", 1)
	s, err := ParseServer([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(s.Gate.JSON), "range_sets") {
		t.Errorf("range_sets written without a set named: %s", s.Gate.JSON)
	}
}

// A set is read from a file beside server.yml, comments and blank lines left out, into the group whose
// signature names it (that a revision keeps its list is TestRangeSetRollsBackWithItsRevision's).
func TestRangeSetFromAFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "ranges"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ranges", "jp.txt"), []byte("# APNIC, JP\n126.0.0.0/8\n\n2400:4050::/32  # NTT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	yml := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(yml, []byte(rangedGate("range_sets:\n  jp: ranges/jp.txt\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadServer(yml)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(groupSets(t, s)["dbauto"]); string(got) != `{"jp":["126.0.0.0/8","2400:4050::/32"]}` {
		t.Errorf("from the file: %s", got)
	}
}

// A signature naming a set there is not, a set that is no list of ranges, a group writing range_sets
// itself, and a missing file are refused before any server is asked.
func TestRangeSetsRefused(t *testing.T) {
	for _, c := range []struct{ sets, want string }{
		{"", `gate: groups[0].signatures[0]: ranges: no set "jp" in range_sets`},
		{"range_sets:\n  kr: [1.11.0.0/16]\n", `no set "jp" in range_sets`},
		{"range_sets:\n  jp: []\n", "range_sets.jp: empty"},
		{"range_sets:\n  jp: [japan]\n", `range_sets.jp: "japan" is neither an address nor a CIDR range`},
		{"range_sets:\n  jp: [0.0.0.0/0]\n", `range_sets.jp: "0.0.0.0/0" holds every address`},
		{"range_sets:\n  jp: [\"::ffff:126.0.0.0/104\"]\n", "written as IPv6"},
		{"range_sets:\n  JP: [126.0.0.0/8]\n", `range_sets: name "JP" must match`},
		{"range_sets:\n  jp: ranges/none.txt\n", "range_sets.jp: open"},
	} {
		if _, err := ParseServer([]byte(rangedGate(c.sets))); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: want %q, got %v", c.sets, c.want, err)
		}
	}
	written := strings.Replace(rangedGate("range_sets:\n  jp: [126.0.0.0/8]\n"), "      secret_env: SHOP_SECRET\n", "      secret_env: SHOP_SECRET\n      range_sets: {jp: [1.0.0.0/8]}\n", 1)
	if _, err := ParseServer([]byte(written)); err == nil || !strings.Contains(err.Error(), "range_sets: boks writes") {
		t.Errorf("a group writing range_sets: %v", err)
	}
	if _, err := ParseServer([]byte("servers: [a]\nrange_sets:\n  jp: [126.0.0.0/8]\n")); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Errorf("range_sets without a revision: %v", err)
	}
}

// The fleet's load (rollback, status) reads no set file: with ranges/jp.txt gone it loads, the sets left
// out, while apply's load refuses it. The rest of server.yml is still checked.
func TestFleetLoadReadsNoSetFile(t *testing.T) {
	dir := t.TempDir()
	yml := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(yml, []byte(rangedGate("range_sets:\n  jp: ranges/jp.txt\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(yml); err == nil || !strings.Contains(err.Error(), "range_sets.jp: open") {
		t.Errorf("apply's load with the file gone: %v", err)
	}
	s, err := LoadServerForFleet(yml)
	if err != nil {
		t.Fatalf("fleet load with the file gone: %v", err)
	}
	if s.RangeSets != nil || strings.Contains(string(s.Gate.JSON), "range_sets") {
		t.Errorf("fleet load read sets: %v %s", s.RangeSets, s.Gate.JSON)
	}
	bad := strings.Replace(rangedGate("range_sets:\n  jp: ranges/jp.txt\n"), "revision: 1\n", "", 1)
	if err := os.WriteFile(yml, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerForFleet(yml); err == nil {
		t.Error("fleet load took a server.yml without revision")
	}
}
