package proxy

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

// rangedPolicy is revision rev of a server.yml whose shop group's signature names the set jp, as list.
func rangedPolicy(t *testing.T, rev int, list string) Policy {
	t.Helper()
	sc, err := config.ParseServer([]byte(`servers: [a]
revision: 1
range_sets:
  jp: ` + list + `
gate:
  groups:
    - name: shop
      app: shop
      mode: enforce
      secret_env: SHOP_SECRET
      signatures:
        - {name: node-chrome-jp, mode: enforce, ranges: jp, headers: [{name: accept-encoding, pattern: "^br, gzip, deflate$"}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	return Policy{Revision: rev, Floor: rev, Gate: sc.Gate.JSON, GateSecrets: map[string][]string{"SHOP_SECRET": {siteSecret}}}
}

// handlerSets are the range_sets of the gate's handler in the config b, as JSON.
func handlerSets(t *testing.T, b []byte) string {
	t.Helper()
	var found any
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if v["handler"] == "boks_gate" {
				found = v["range_sets"]
				return
			}
			for _, sub := range v {
				walk(sub)
			}
		case []any:
			for _, sub := range v {
				walk(sub)
			}
		}
	}
	walk(decoded(t, b))
	s, _ := json.Marshal(found)
	return string(s)
}

// The set goes with the revision (#140): a rollback to an earlier revision puts back the list that
// revision was applied with, and the config assembled from it hands the gate that list. The marker
// stays the gate's: a set needs no newer boks, every boks hands the group to the handler as written.
func TestRangeSetRollsBackWithItsRevision(t *testing.T) {
	ctx := context.Background()
	d := newDisk()
	if _, err := SetRoutes(ctx, d, io.Discard, "shop", []Route{{Host: "shop.example.com", Dial: "shop:1", TLS: true}}); err != nil {
		t.Fatal(err)
	}
	first, second := rangedPolicy(t, 1, "[126.0.0.0/8]"), rangedPolicy(t, 2, "[133.0.0.0/8, 126.0.0.0/8]")
	for _, p := range []Policy{first, second} {
		if err := SetPolicy(ctx, d, io.Discard, p); err != nil {
			t.Fatal(err)
		}
	}
	if marker := d.files[Dir+"/routes/_server.json"]; marker != "8\n" {
		t.Errorf("want the gate's marker 8 with a set: %q", marker)
	}
	if got := handlerSets(t, []byte(d.files[appliedPath()])); got != `{"jp":["133.0.0.0/8","126.0.0.0/8"]}` {
		t.Errorf("revision 2 runs %s", got)
	}
	old, ok, err := History(ctx, d, 1)
	if err != nil || !ok {
		t.Fatalf("revision 1 in the history: %v %v", ok, err)
	}
	old.GateSecrets = first.GateSecrets
	b, err := Config(old, []Fragment{{App: "shop", Routes: []Route{{Host: "shop.example.com", Dial: "shop:1", TLS: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := handlerSets(t, b); got != `{"jp":["126.0.0.0/8"]}` {
		t.Errorf("rolled back to revision 1, the gate gets %s", got)
	}
}
