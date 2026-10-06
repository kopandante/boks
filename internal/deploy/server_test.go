package deploy

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

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
	if err := CheckApply(context.Background(), f, proxy.Policy{Revision: 1}); err == nil {
		t.Errorf("want the check before any server changes to refuse it too")
	}
	if err := CheckServerRollback(context.Background(), f, 1); err == nil {
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
	if err := CheckServerRollback(context.Background(), f, 3); err == nil || !strings.Contains(err.Error(), "never applied revision 3") {
		t.Errorf("want a refusal, got %v", err)
	}
	old, _ := json.Marshal(proxy.Policy{Revision: 3, Block: crawlers})
	f.out["sh -c if [ -f '.boks/_server/history/3.json' ]"] = "present\n" + string(old)
	if err := CheckServerRollback(context.Background(), f, 3); err != nil {
		t.Errorf("want revision 3 taken: %v", err)
	}
}
