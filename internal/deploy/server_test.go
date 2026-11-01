package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
)

const (
	policyRead = "sh -c if [ -f '.boks/_server/policy.json' ]"
	policyFile = ".boks/_server/policy.json"
	serverLog  = ".boks/_server/journal.jsonl"
)

var crawlers = []proxy.BotBlock{{Name: "crawlers", UserAgent: "(?i)gptbot"}}

// serverFake is a server applying cur, with the proxy running and no routes.
func serverFake(t *testing.T, cur proxy.Policy) *fake {
	t.Helper()
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = caddyUp
	if cur.Revision > 0 {
		b, _ := json.Marshal(cur)
		f.out[policyRead] = "present\n" + string(b)
	}
	return f
}

func TestCheckRevision(t *testing.T) {
	cur := proxy.Policy{Revision: 3, Floor: 5, Block: crawlers}
	for _, c := range []struct {
		next proxy.Policy
		want string
	}{
		{proxy.Policy{Revision: 6}, ""},                            // the one after the highest applied
		{proxy.Policy{Revision: 3, Block: crawlers}, ""},           // the one it runs, again: a run to repeat
		{proxy.Policy{Revision: 3}, "older file"},                  // the same revision with another policy
		{proxy.Policy{Revision: 5, Block: crawlers}, "older file"}, // undone by a rollback, not taken back
		{proxy.Policy{Revision: 4}, "older file"},
		{proxy.Policy{Revision: 7}, "takes 6 next"},
	} {
		err := CheckRevision(cur, c.next)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("revision %d: want %q, got %v", c.next.Revision, c.want, err)
		}
	}
	// The same revision with any one field changed is another policy, not a repeat.
	full := proxy.Policy{Revision: 3, Floor: 5,
		Allow: []proxy.BotAllow{{Host: "img.example.com", Paths: []string{"/pics"}, UserAgent: "(?i)telegrambot"}},
		Block: []proxy.BotBlock{{Name: "infra", Domains: []string{"example.com"}, UserAgent: "(?i)bot"}}}
	if err := CheckRevision(full, proxy.Policy{Revision: 3, Allow: full.Allow, Block: full.Block}); err != nil {
		t.Errorf("the same policy with allows, again: %v", err)
	}
	for name, edit := range map[string]func(p *proxy.Policy){
		"user_agent": func(p *proxy.Policy) {
			p.Block = []proxy.BotBlock{{Name: "infra", Domains: []string{"example.com"}, UserAgent: "(?i)crawler"}}
		},
		"domains": func(p *proxy.Policy) {
			p.Block = []proxy.BotBlock{{Name: "infra", Domains: []string{"example.org"}, UserAgent: "(?i)bot"}}
		},
		"allow path": func(p *proxy.Policy) {
			p.Allow = []proxy.BotAllow{{Host: "img.example.com", Paths: []string{"/img"}, UserAgent: "(?i)telegrambot"}}
		},
		"allow host": func(p *proxy.Policy) {
			p.Allow = []proxy.BotAllow{{Host: "x.example.com", Paths: []string{"/pics"}, UserAgent: "(?i)telegrambot"}}
		},
	} {
		next := proxy.Policy{Revision: 3, Allow: full.Allow, Block: full.Block}
		edit(&next)
		if err := CheckRevision(full, next); err == nil || !strings.Contains(err.Error(), "older file") {
			t.Errorf("%s changed at the same revision: want a refusal, got %v", name, err)
		}
	}
	// The revision a boks of format 6 applied, from its unchanged server.yml: the same ban, now its rule.
	legacy := proxy.Policy{Revision: 7, Floor: 7, Ban: &proxy.Ban{Limit: 1500, Window: "1m", Duration: "24h"}}
	again := proxy.Policy{Revision: 7, Ban: &proxy.Ban{Duration: "24h", Rules: []proxy.BanRule{{Name: "default", Limit: 1500, Window: "1m", Class: "all"}}}}
	if err := CheckRevision(legacy, again); err != nil {
		t.Errorf("the revision a boks of format 6 applied, again: %v", err)
	}
	// A server that never applied a policy takes whatever revision the fleet is at.
	if err := CheckRevision(proxy.Policy{}, proxy.Policy{Revision: 9}); err != nil {
		t.Errorf("a new server: %v", err)
	}
}

// An apply records the floor, journals the run from the old revision to the new, and holds the
// admission lock while the proxy reloads.
func TestApplyServerRecordsAndJournals(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 3, Floor: 3})
	err := ApplyServer(context.Background(), f, io.Discard, proxy.Policy{Revision: 4, Block: crawlers}, fixed)
	if err != nil {
		t.Fatal(err)
	}
	var got proxy.Policy
	if err := json.Unmarshal([]byte(f.uploads[policyFile]), &got); err != nil || got.Revision != 4 || got.Floor != 4 {
		t.Errorf("want revision 4 with floor 4 recorded: %s", f.uploads[policyFile])
	}
	if j := f.appends[serverLog]; !strings.Contains(j, `"action":"server apply","from":"3","to":"4"`) || !strings.Contains(j, `"result":"ok"`) {
		t.Errorf("want the run journaled and closed: %s", j)
	}
	lock, reload, unlock := f.at("ln -sn _proxy."), f.at(reloadVia), f.at("sh -c [ \"$(readlink /tmp/boks.admit.lock)\" = '_proxy.")
	if lock < 0 || reload < lock || unlock < reload {
		t.Errorf("want the reload under the admission lock: %v", f.calls)
	}
}

// Repeating the revision a rollback went back to keeps the floor: the revisions it undid stay refused.
func TestApplyServerRepeatedAfterARollbackKeepsTheFloor(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 3, Floor: 5, Block: crawlers})
	if err := ApplyServer(context.Background(), f, io.Discard, proxy.Policy{Revision: 3, Block: crawlers}, fixed); err != nil {
		t.Fatal(err)
	}
	var got proxy.Policy
	if err := json.Unmarshal([]byte(f.uploads[policyFile]), &got); err != nil || got.Revision != 3 || got.Floor != 5 {
		t.Errorf("want revision 3 with floor 5 still: %s", f.uploads[policyFile])
	}
}

// A refused revision changes nothing and gives the lock back.
func TestApplyServerRefusesBeforeAnythingChanges(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 4, Floor: 4, Block: crawlers})
	err := ApplyServer(context.Background(), f, io.Discard, proxy.Policy{Revision: 4}, fixed)
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 || f.has("docker exec boks-proxy caddy") {
		t.Errorf("want nothing written: %v %v", f.uploads, f.appends)
	}
	if !f.has("sh -c [ \"$(readlink /tmp/boks.admit.lock)\" = '_proxy.") {
		t.Errorf("want the lock given back")
	}
}

// A rollback puts back a revision from the history and keeps the floor, so the undone file stays refused.
func TestRollbackServerKeepsTheFloor(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 5, Floor: 5})
	old, _ := json.Marshal(proxy.Policy{Revision: 3, Block: crawlers})
	f.out["sh -c if [ -f '.boks/_server/history/3.json' ]"] = "present\n" + string(old)
	if err := RollbackServer(context.Background(), f, io.Discard, 3, fixed); err != nil {
		t.Fatal(err)
	}
	var got proxy.Policy
	if err := json.Unmarshal([]byte(f.uploads[policyFile]), &got); err != nil || got.Revision != 3 || got.Floor != 5 || len(got.Block) != 1 {
		t.Errorf("want revision 3 back with floor 5: %s", f.uploads[policyFile])
	}
}

func TestRollbackServerRefusesARevisionNeverApplied(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 5, Floor: 5})
	err := RollbackServer(context.Background(), f, io.Discard, 2, fixed)
	if err == nil || !strings.Contains(err.Error(), "never applied revision 2") || len(f.uploads) > 0 {
		t.Errorf("want a refusal before any write, got %v %v", err, f.uploads)
	}
}

// A server whose boks-proxy is still kamal-proxy refuses a policy before anything changes: written for
// a Caddy that is not there, it would be reported applied while no request is filtered.
func TestApplyServerRefusesKamalProxy(t *testing.T) {
	f := serverFake(t, proxy.Policy{})
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running\t"
	err := ApplyServer(context.Background(), f, io.Discard, proxy.Policy{Revision: 1, Block: crawlers}, fixed)
	if err == nil || !strings.Contains(err.Error(), "boks proxy migrate") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("want the kamal-proxy refusal, got %v", err)
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 {
		t.Errorf("want nothing written: %v %v", f.uploads, f.appends)
	}
	if err := CheckApply(context.Background(), f, proxy.Policy{Revision: 1}, false); err == nil {
		t.Errorf("want the check before any server changes to refuse it too")
	}
	if err := CheckServerRollback(context.Background(), f, 1, false); err == nil {
		t.Errorf("want the rollback check to refuse it too")
	}
}

// Where no proxy runs yet the policy is written for Caddy to load when it starts, and the run says
// that nothing is filtered until then.
func TestApplyServerSaysWhenNoProxyRuns(t *testing.T) {
	f := serverFake(t, proxy.Policy{})
	f.out["docker ps -a --filter name=^boks-proxy$"] = ""
	var log strings.Builder
	if err := ApplyServer(context.Background(), f, &log, proxy.Policy{Revision: 1, Block: crawlers}, fixed); err != nil {
		t.Fatal(err)
	}
	if f.uploads[policyFile] == "" || !strings.Contains(log.String(), "nothing is filtered until it starts") {
		t.Errorf("want the policy written and the run to say it is not served yet: %s", log.String())
	}
	g := serverFake(t, proxy.Policy{})
	log.Reset()
	if err := ApplyServer(context.Background(), g, &log, proxy.Policy{Revision: 1, Block: crawlers}, fixed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "not running") {
		t.Errorf("a running proxy is not reported as stopped: %s", log.String())
	}
}

// The check before any server changes refuses a rollback to a revision the server never applied.
func TestCheckServerRollback(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 5, Floor: 5})
	if err := CheckServerRollback(context.Background(), f, 3, false); err == nil || !strings.Contains(err.Error(), "never applied revision 3") {
		t.Errorf("want a refusal, got %v", err)
	}
	old, _ := json.Marshal(proxy.Policy{Revision: 3, Block: crawlers})
	f.out["sh -c if [ -f '.boks/_server/history/3.json' ]"] = "present\n" + string(old)
	if err := CheckServerRollback(context.Background(), f, 3, false); err != nil {
		t.Errorf("want revision 3 taken: %v", err)
	}
}

// A rollback to a revision whose trusted proxies' CA has run out is refused before any server changes:
// the proxies in front would be refused at the handshake.
func TestCheckServerRollbackRefusesAnExpiredCA(t *testing.T) {
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
	f := serverFake(t, proxy.Policy{Revision: 5, Floor: 5})
	old, _ := json.Marshal(proxy.Policy{Revision: 3, TrustedProxies: []string{"173.245.48.0/20"}, TrustedProxiesCA: [][]byte{der}})
	f.out["sh -c if [ -f '.boks/_server/history/3.json' ]"] = "present\n" + string(old)
	if err := CheckServerRollback(context.Background(), f, 3, false); err == nil || !strings.Contains(err.Error(), "revision 3: trusted_proxies_ca: certificate 1 (CN=expired CA) is valid from") {
		t.Errorf("want the rollback refused, got %v", err)
	}
}

// upgradeFake is a server whose Caddy runs caddy:old with no routes.
func upgradeFake() *fake {
	f := newFake()
	f.out[proxyState] = caddyUp
	f.out[proxyImage] = "caddy:old"
	return f
}

// An upgrade journals the swap alone, under the admission lock: what refuses before the stop opens
// nothing, a swap that fails closes failed, and an entry a cut run left open is closed as abandoned
// rather than named by `boks server status` forever.
func TestUpgradeProxyJournalsTheSwapAlone(t *testing.T) {
	f := upgradeFake()
	if err := UpgradeProxy(context.Background(), f, io.Discard, "caddy:new", fixed); err != nil {
		t.Fatal(err)
	}
	if j := f.appends[serverLog]; !strings.Contains(j, `"action":"proxy upgrade","from":"caddy:old","to":"caddy:new"`) || !strings.Contains(j, `"result":"ok"`) {
		t.Errorf("want the swap journaled and closed: %s", j)
	}
	lock, stop, unlock := f.at(admitTake(proxyHolder)), f.at("docker stop boks-proxy"), f.at(admitGive(proxyHolder))
	if lock < 0 || stop < lock || unlock < stop {
		t.Errorf("want the swap under the admission lock: %v", f.calls)
	}

	for name, setup := range map[string]func(*fake){
		"refuses the proxy's config": func(f *fake) { f.fail["docker run --rm"] = errors.New("unknown field") },
		// A swap cut after the new proxy was made: its image is the one asked for, and still the cut
		// swap is named rather than "already runs".
		"left from an upgrade": func(f *fake) {
			f.out[proxyImage] = "caddy:new"
			f.out[`docker ps -a --filter name=^boks-proxy\.old$`] = "boks-proxy.old"
		},
	} {
		f := upgradeFake()
		setup(f)
		err := UpgradeProxy(context.Background(), f, io.Discard, "caddy:new", fixed)
		if err == nil || !strings.Contains(err.Error(), name) || f.appends[serverLog] != "" || f.has("docker stop") {
			t.Errorf("%s: want a refusal with nothing journaled or stopped, got %v %q", name, err, f.appends[serverLog])
		}
		if !f.has(admitGive(proxyHolder)) {
			t.Errorf("%s: the admission lock was kept", name)
		}
	}

	f = upgradeFake()
	f.fail["docker create --name boks-proxy"] = errors.New("no space left")
	if err := UpgradeProxy(context.Background(), f, io.Discard, "caddy:new", fixed); err == nil || !strings.Contains(f.appends[serverLog], `"result":"failed"`) {
		t.Errorf("a failed swap: want it journaled failed, got %v %s", err, f.appends[serverLog])
	}

	// A run cut after the new proxy answered, before its entry closed: the retry finds the image in
	// place and closes that upgrade, and only that one.
	for open, want := range map[string]bool{
		`{"op":"1","action":"proxy upgrade","from":"caddy:old","to":"caddy:new","started_at":"2026-01-01T00:00:00Z"}`: true,
		`{"op":"1","action":"proxy upgrade","from":"caddy:new","to":"caddy:old","started_at":"2026-01-01T00:00:00Z"}`: false,
		`{"op":"1","action":"server apply","from":"3","to":"4","started_at":"2026-01-01T00:00:00Z"}`:                  false,
	} {
		f = upgradeFake()
		f.out[proxyImage] = "caddy:new"
		f.out["sh -c cat '.boks/_server/journal.jsonl'"] = open
		err := UpgradeProxy(context.Background(), f, io.Discard, "caddy:new", fixed)
		j := f.appends[serverLog]
		closed := strings.Contains(j, `{"op":"1","finished_at":`) && strings.HasSuffix(strings.TrimSpace(j), `"result":"ok"}`)
		if err != nil || closed != want || strings.Contains(j, `{"op":"1"`) != want || f.has("docker stop") ||
			strings.Contains(f.appends[serverLog], `"started_at"`) {
			t.Errorf("already runs, open %s: want closed=%v and nothing begun, got %v %s", open, want, err, f.appends[serverLog])
		}
	}

	f = upgradeFake()
	f.out["sh -c cat '.boks/_server/journal.jsonl'"] = `{"op":"1","action":"proxy upgrade","from":"a","to":"b","started_at":"2026-01-01T00:00:00Z"}`
	if err := UpgradeProxy(context.Background(), f, io.Discard, "caddy:new", fixed); err != nil || !strings.Contains(f.appends[serverLog], `{"op":"1","finished_at":`) ||
		!strings.Contains(f.appends[serverLog], `"result":"abandoned"`) {
		t.Errorf("want the open entry closed as abandoned: %v %s", err, f.appends[serverLog])
	}
}

// An egress policy publishes its port before it is applied: the proxy is made again, with the image it
// runs, and only then does the policy that listens on the port go in.
func TestApplyServerMakesTheProxyForEgressFirst(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 1, Floor: 1})
	f.out["docker inspect -f {{range"] = "443/tcp 80/tcp |"
	f.out["docker exec boks-proxy caddy list-modules"] = "http.handlers.forward_proxy"
	f.out[proxyImage] = config.DefaultProxyImage
	next := proxy.Policy{Revision: 2, Egress: &proxy.Egress{Port: 3128, Allow: []string{"203.0.113.10/32"}, Ports: []int{443}}}
	var log strings.Builder
	if err := ApplyServer(context.Background(), f, &log, next, fixed); err != nil {
		t.Fatal(err)
	}
	create, policy := f.callAt("docker create --name boks-proxy"), f.writeAt(policyFile, `"egress"`)
	if create < 0 || policy < 0 || policy < create || !strings.Contains(f.calls[create], "-p 3128:3128") {
		t.Errorf("want the proxy made with the port (call %d) before the policy (%d): %v", create, policy, f.calls)
	}
	if !strings.Contains(log.String(), "egress proxy on port 3128 for 203.0.113.10/32") {
		t.Errorf("log: %s", log.String())
	}
}

// An egress the server cannot run is refused when every server of the file is asked, before any changes:
// found only by the swap, it would leave the servers before it on the new policy.
func TestCheckApplyRefusesAnEgressTheProxyCannotRun(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 1, Floor: 1})
	f.out["docker exec boks-proxy caddy list-modules"] = "http.handlers.reverse_proxy"
	f.out[proxyImage] = "caddy:2.11.7-alpine"
	next := proxy.Policy{Revision: 2, Egress: &proxy.Egress{Port: 3128, Allow: []string{"203.0.113.10/32"}, Ports: []int{443}}}
	if err := CheckApply(context.Background(), f, next, false); err == nil || !strings.Contains(err.Error(), "no forward proxy") {
		t.Errorf("want the stock image refused: %v", err)
	}
}

// A ban the proxy's image cannot run is refused before any changes, on apply and on rollback: Caddy
// would refuse the config, and every deploy's reload after it. The image is asked with a config that
// has every field of the ban this boks writes — Caddy decodes a module strictly, so a handler of an
// older image refuses the fields it does not know — whether the proxy runs or is stopped.
func TestCheckApplyRefusesABanTheProxyCannotRun(t *testing.T) {
	const old, current = "ghcr.io/kopandante/boks-caddy:2.11.7-fp0aab84d-ban3", "ghcr.io/kopandante/boks-caddy:2.11.7-fp0aab84d-ban8"
	validate := func(image string) string {
		return "docker run --rm -i --network none --entrypoint caddy " + image + " validate --config /dev/stdin"
	}
	unknown := errors.New(`exit status 1: loading module 'boks_ban': decoding module config: http.handlers.boks_ban: json: unknown field "heuristics"`)
	ban := &proxy.Ban{Rules: []proxy.BanRule{{Name: "default", Limit: 300, Window: "1m", Class: "all"}}, Duration: "24h"}

	f := serverFake(t, proxy.Policy{Revision: 1, Floor: 1})
	f.out[proxyImage] = old
	f.fail[validate(old)] = unknown
	if err := CheckApply(context.Background(), f, proxy.Policy{Revision: 2, Ban: ban}, false); err == nil || !strings.Contains(err.Error(), "the proxy runs "+old) ||
		!strings.Contains(err.Error(), "rules and heuristics") || !strings.Contains(err.Error(), `unknown field "heuristics"`) ||
		!strings.Contains(err.Error(), "boks proxy upgrade") {
		t.Errorf("want the image without the new fields refused: %v", err)
	}
	probe := f.stdin[validate(old)]
	for _, field := range []string{`"handler":"boks_ban"`, `"rules":[`, `"class":"api"`, `"paths":[`, `"heuristics":{"mode":"log"`, `"min_addresses":`} {
		if !strings.Contains(probe, field) {
			t.Errorf("want the probe to carry %s: %s", field, probe)
		}
	}
	f.out[proxyImage] = current
	if err := CheckApply(context.Background(), f, proxy.Policy{Revision: 2, Ban: ban}, false); err != nil {
		t.Errorf("want the image that takes the probe taken: %v", err)
	}
	// No ban, nothing asked.
	n := len(f.calls)
	if err := CheckApply(context.Background(), f, proxy.Policy{Revision: 2}, false); err != nil || slices.ContainsFunc(f.calls[n:], func(c string) bool { return strings.HasPrefix(c, "docker run") }) {
		t.Errorf("want a policy without a ban to ask no image: %v %v", err, f.calls[n:])
	}

	g := serverFake(t, proxy.Policy{Revision: 5, Floor: 5})
	hist, _ := json.Marshal(proxy.Policy{Revision: 3, Ban: ban})
	g.out["sh -c if [ -f '.boks/_server/history/3.json' ]"] = "present\n" + string(hist)
	g.out[proxyImage] = old
	g.fail[validate(old)] = unknown
	if err := CheckServerRollback(context.Background(), g, 3, false); err == nil || !strings.Contains(err.Error(), "rules and heuristics") {
		t.Errorf("want a rollback to a ban refused on the image without the fields: %v", err)
	}
	if len(g.uploads) > 0 || len(g.appends) > 0 {
		t.Errorf("want nothing written: %v %v", g.uploads, g.appends)
	}
	g.out[proxyImage] = current
	if err := CheckServerRollback(context.Background(), g, 3, false); err != nil {
		t.Errorf("want the rollback taken on the image with the fields: %v", err)
	}

	// A stopped proxy is asked through its image too: the boot after the apply starts it as it is.
	h := serverFake(t, proxy.Policy{Revision: 1, Floor: 1})
	h.out["docker ps -a --filter name=^boks-proxy$"] = "exited\tcaddy"
	h.out[proxyImage] = old
	h.fail[validate(old)] = unknown
	if err := CheckApply(context.Background(), h, proxy.Policy{Revision: 2, Ban: ban}, false); err == nil || !strings.Contains(err.Error(), "rules and heuristics") ||
		!strings.Contains(err.Error(), "stopped container") {
		t.Errorf("want a stopped proxy whose image lacks the fields refused: %v", err)
	}
	h.out[proxyImage] = current
	if err := CheckApply(context.Background(), h, proxy.Policy{Revision: 2, Ban: ban}, false); err != nil {
		t.Errorf("want a stopped proxy whose image has the fields taken: %v", err)
	}
	if slices.ContainsFunc(h.calls, func(c string) bool { return strings.HasPrefix(c, "docker exec") }) {
		t.Errorf("want a stopped proxy asked through its image alone: %v", h.calls)
	}
}

// Status reports the policy even when the running proxy cannot be compared with it.
func TestServerStatusSaysWhatItCannotCompare(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 2, Floor: 2, Egress: &proxy.Egress{Port: 3128, Allow: []string{"203.0.113.10/32"}, Ports: []int{443}}})
	f.fail["docker inspect -f {{range"] = errors.New("Cannot connect to the Docker daemon")
	p, _, drift, err := ServerStatus(context.Background(), f)
	if err != nil || p.Revision != 2 || len(drift) != 1 || !strings.Contains(drift[0], "could not compare") {
		t.Errorf("policy %+v, drift %v, err %v", p, drift, err)
	}
}

// A server whose own boks does not read the policy refuses it before anything changes (#154): found
// only by the load after the swap, it would leave the proxy made for the new egress port serving the
// policy put back, which does not listen there.
func TestApplyServerAsksTheServersBoksBeforeTheSwap(t *testing.T) {
	f := serverFake(t, proxy.Policy{Revision: 1, Floor: 1})
	f.out["docker inspect -f {{range"] = "443/tcp 80/tcp |"
	f.out["docker exec boks-proxy caddy list-modules"] = "http.handlers.forward_proxy"
	f.out[proxyImage] = config.DefaultProxyImage
	f.out[ownBoks] = "yes"
	check := proxy.ServerBoks + " " + proxy.AssembleCommand + " " + proxy.CheckArg
	f.fail[check] = errors.New(`json: unknown field "egress"`)
	next := proxy.Policy{Revision: 2, Egress: &proxy.Egress{Port: 3128, Allow: []string{"203.0.113.10/32"}, Ports: []int{443}}}
	err := ApplyServer(context.Background(), f, io.Discard, next, fixed)
	if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "the policy and the proxy were not changed") {
		t.Fatalf("want the server's boks's refusal, got %v", err)
	}
	if f.has("docker create --name boks-proxy") || f.has("docker stop") || len(f.uploads) > 0 || len(f.appends) > 0 {
		t.Errorf("want nothing changed: %v %v %v", f.calls, f.uploads, f.appends)
	}
	// It was asked about the bytes SetPolicy would write.
	var asked proxy.Policy
	if err := json.Unmarshal([]byte(f.stdin[check]), &asked); err != nil || asked.Revision != 2 || asked.Floor != 2 || asked.Egress == nil {
		t.Errorf("asked about %q (%v), want next with its floor", f.stdin[check], err)
	}
}
