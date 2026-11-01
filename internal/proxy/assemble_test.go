package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/remote"
)

// owned is a server with a boks of its own (#154): it answers the question of whether there is one,
// and its boks answers proxy-config with config, or fails with err. Everything else goes to the fake.
type owned struct {
	*fake
	config string
	err    error
	piped  []byte
}

func (o *owned) Run(ctx context.Context, args ...string) (string, error) {
	if strings.HasPrefix(strings.Join(args, " "), "sh -c if [ -x "+ServerBoks+" ]") {
		o.calls = append(o.calls, "own boks?")
		return "yes", nil
	}
	return o.fake.Run(ctx, args...)
}

func (o *owned) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	switch strings.Join(args, " ") {
	case ServerBoks + " " + AssembleCommand:
		o.calls = append(o.calls, "assemble")
		o.piped = content
		return o.config, o.err
	case ServerBoks + " " + AssembleCommand + " " + CheckArg:
		o.calls = append(o.calls, "check")
		o.piped = content
		return o.config, o.err
	}
	return o.fake.Pipe(ctx, content, args...)
}

var site = []Fragment{{App: "web", Routes: web}}

// On a server with its own boks the config is the one it assembles from the routes it is sent: the
// policy is not read here at all, so a boks older than the policy has nothing to drop.
func TestAssembleAsksTheServersBoks(t *testing.T) {
	o := &owned{fake: &fake{}, config: `{"from":"the server"}`}
	body, err := assemble(context.Background(), o, site)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"from":"the server"}`+"\n" {
		t.Errorf("config %q, want the server's answer with its newline", body)
	}
	var sent []Fragment
	if err := json.Unmarshal(o.piped, &sent); err != nil || len(sent) != 1 || sent[0].App != "web" || len(sent[0].Routes) != len(web) {
		t.Errorf("sent %s, want the routes given (%v)", o.piped, err)
	}
	if at(o.calls, "sh -c if [ -f '.boks/_server/policy.json'") >= 0 {
		t.Errorf("the policy was read here: %v", o.calls)
	}
}

// Its refusal is a refusal: assembling here instead would let this boks's idea of the policy through.
func TestAssembleRefusesWhatTheServersBoksRefuses(t *testing.T) {
	o := &owned{fake: &fake{}, err: errors.New("unknown field")}
	_, err := assemble(context.Background(), o, site)
	if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "server apply") {
		t.Fatalf("err = %v, want the server's refusal and what to do", err)
	}
	if at(o.calls, "sh -c if [ -f '.boks/_server/policy.json'") >= 0 {
		t.Errorf("assembled here after the refusal: %v", o.calls)
	}
}

// Without its own boks the server's config is assembled here, from its policy, as before.
func TestAssembleHereWithoutTheServersBoks(t *testing.T) {
	f := &fake{out: map[string]string{"sh -c if [ -f '.boks/_server/policy.json'": "absent"}}
	body, err := assemble(context.Background(), f, site)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Config(Policy{}, site)
	if string(body) != string(want) {
		t.Errorf("config differs from Config's")
	}
}

// A reload goes with the config the server's boks assembled: converge, Validate and Lags all take it.
func TestConvergeLoadsTheServersConfig(t *testing.T) {
	o := &owned{fake: &fake{state: running}, config: `{"from":"the server"}`}
	if _, err := converge(context.Background(), o, io.Discard, site, false, "test"); err != nil {
		t.Fatal(err)
	}
	if at(o.calls, "assemble") < 0 {
		t.Errorf("converge did not ask the server's boks: %v", o.calls)
	}
	o.calls = nil
	if err := Validate(context.Background(), o, "web", web); err != nil {
		t.Fatal(err)
	}
	if at(o.calls, "assemble") < 0 {
		t.Errorf("Validate did not ask the server's boks: %v", o.calls)
	}
	o.calls = nil
	if _, err := Lags(context.Background(), o, site); err != nil {
		t.Fatal(err)
	}
	if at(o.calls, "assemble") < 0 {
		t.Errorf("Lags did not ask the server's boks: %v", o.calls)
	}
}

// home is a server's home with the policy p written as boks writes it, and the egress secret.
func home(t *testing.T, policy string) remote.Local {
	t.Helper()
	h := t.TempDir()
	if policy != "" {
		if err := os.MkdirAll(filepath.Join(h, ServerDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h, policyPath()), []byte(policy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return remote.Local{Dir: h}
}

// The server's boks assembles what Config does from the policy on its disk, secrets included.
func TestServerConfigIsConfigOfThePolicyOnDisk(t *testing.T) {
	p := Policy{Revision: 3, Block: []BotBlock{{Name: "crawlers", UserAgent: "(?i)gptbot"}}, Egress: encar}
	l := home(t, string(marshal(p)))
	if err := os.WriteFile(filepath.Join(l.Dir, egressSecretPath()), []byte("encar:s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(site)
	got, err := ServerConfig(context.Background(), l, in)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Config(p, site)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("the server's config differs from Config of its policy")
	}
}

// A server that never had a policy assembles with none, as here.
func TestServerConfigWithoutAPolicy(t *testing.T) {
	in, _ := json.Marshal(site)
	got, err := ServerConfig(context.Background(), home(t, ""), in)
	want, _ := Config(Policy{}, site)
	if err != nil || string(got) != string(want) {
		t.Errorf("err = %v; config differs from Config with no policy", err)
	}
}

// A field this boks does not know is a newer boks's: refused, never assembled without.
func TestServerConfigRefusesWhatItDoesNotKnow(t *testing.T) {
	in, _ := json.Marshal(site)
	_, err := ServerConfig(context.Background(), home(t, `{"revision": 4, "shiny_new_filter": {"on": true}}`), in)
	if err == nil || !strings.Contains(err.Error(), "shiny_new_filter") || !strings.Contains(err.Error(), "newer boks") {
		t.Errorf("policy: err = %v, want a refusal naming the field", err)
	}
	_, err = ServerConfig(context.Background(), home(t, ""), []byte(`[{"app":"web","routes":[{"host":"a.example.com","dial":"web:80","tls":true,"mirror":"x"}]}]`))
	if err == nil || !strings.Contains(err.Error(), "mirror") {
		t.Errorf("routes: err = %v, want a refusal naming the field", err)
	}
}

// The server's boks is asked for the config of the policy as SetPolicy writes it, with the secrets it
// never records and the server's routes; its refusal is a refusal that changed neither the policy nor
// the proxy; a server without one is not asked.
func TestCheckServerBoks(t *testing.T) {
	p := Policy{Revision: 3, Floor: 3, Block: []BotBlock{{Name: "crawlers", UserAgent: "(?i)gptbot"}}, Egress: encar}
	o := &owned{fake: &fake{}, config: "{}"}
	if err := CheckServerBoks(context.Background(), o, p); err != nil {
		t.Fatal(err)
	}
	var c candidate
	if err := strict(o.piped, &c); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(c.Policy, marshal(p)) || c.EgressPassword != "s3cret" {
		t.Errorf("asked about %s with password %q, want the bytes SetPolicy writes and the password", c.Policy, c.EgressPassword)
	}
	o = &owned{fake: &fake{}, err: errors.New(`json: unknown field "egress"`)}
	err := CheckServerBoks(context.Background(), o, p)
	if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "the policy and the proxy were not changed") {
		t.Fatalf("err = %v, want the server's refusal", err)
	}
	// A build that answers with nothing does not pass: the check would otherwise have validated no config.
	o = &owned{fake: &fake{}}
	if err := CheckServerBoks(context.Background(), o, p); err == nil || !strings.Contains(err.Error(), "no config") {
		t.Errorf("err = %v, want an empty answer refused", err)
	}
	f := &fake{}
	if err := CheckServerBoks(context.Background(), f, p); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, AssembleCommand) {
			t.Errorf("asked a server without its own boks: %v", f.calls)
		}
	}
}

// What a check before any change validates is the config the server's boks assembles, not this boks's.
func TestValidateChecksTheServersConfig(t *testing.T) {
	o := &owned{fake: &fake{state: running}, config: `{"from":"the server"}`}
	if err := validate(context.Background(), o, Policy{Revision: 2}, site); err != nil {
		t.Fatal(err)
	}
	if at(o.calls, "check") < 0 {
		t.Errorf("validate did not ask the server's boks: %v", o.calls)
	}
}

// A server's boks that is there and does not run is an error, never a config assembled here.
func TestABrokenServerBoksIsAnError(t *testing.T) {
	f := &fake{out: map[string]string{"sh -c if [ -x " + ServerBoks + " ]": "broken"}}
	if _, err := assemble(context.Background(), f, site); err == nil || !strings.Contains(err.Error(), "does not run") {
		t.Errorf("assemble: err = %v", err)
	}
	if at(f.calls, "sh -c if [ -f '.boks/_server/policy.json'") >= 0 {
		t.Errorf("assembled here: %v", f.calls)
	}
	if _, err := assembleOf(context.Background(), f, Policy{}, site); err == nil {
		t.Errorf("assembleOf: no error")
	}
}

// CandidateConfig is Config of the policy it is sent, read strictly, with the secrets it brings and
// for the rest those the server keeps.
func TestCandidateConfig(t *testing.T) {
	p := Policy{Revision: 4, Block: []BotBlock{{Name: "a", UserAgent: "b"}}, Egress: encar}
	in, _ := json.Marshal(candidate{Policy: marshal(p), Fragments: site, EgressPassword: "s3cret"})
	got, err := CandidateConfig(context.Background(), home(t, ""), in)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Config(p, site)
	if string(got) != string(want) {
		t.Errorf("config differs from Config of the policy sent")
	}
	// Without the password it brings, the one the server keeps.
	l := home(t, "")
	if err := os.MkdirAll(filepath.Join(l.Dir, ServerDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.Dir, egressSecretPath()), []byte("encar:s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, _ = json.Marshal(candidate{Policy: marshal(p), Fragments: site})
	if got, err := CandidateConfig(context.Background(), l, in); err != nil || string(got) != string(want) {
		t.Errorf("with the server's password: err = %v, or config differs", err)
	}
	in, _ = json.Marshal(candidate{Policy: []byte(`{"revision": 2, "floor": 2, "newer_filter": {"on": true}}`)})
	if _, err := CandidateConfig(context.Background(), home(t, ""), in); err == nil || !strings.Contains(err.Error(), "newer_filter") ||
		!strings.Contains(err.Error(), "server apply") {
		t.Errorf("err = %v, want the unknown field refused with what to do", err)
	}
	if _, err := CandidateConfig(context.Background(), home(t, ""), []byte(`{"policy": {}, "newer": 1}`)); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("err = %v, want an unknown field of the request refused", err)
	}
}

// The gate's secrets a candidate brings are the ones its config holds: without them, a server that
// keeps none would refuse the check, and one that keeps old ones would validate their config instead.
func TestCandidateConfigTakesTheGatesSecrets(t *testing.T) {
	p := gated()
	in, _ := json.Marshal(candidate{Policy: marshal(p), Fragments: shopAndBlog, GateSecrets: p.GateSecrets})
	got, err := CandidateConfig(context.Background(), home(t, ""), in)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Config(p, shopAndBlog)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("config differs from Config of the gated policy")
	}
}
