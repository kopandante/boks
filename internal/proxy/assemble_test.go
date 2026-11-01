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
	if strings.Join(args, " ") == "sh -c [ -x "+ServerBoks+" ] && echo yes; true" {
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
		return "", o.err
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

// The server's boks is asked about the policy as SetPolicy writes it, and its refusal is a refusal that
// changed nothing; a server without one is not asked.
func TestCheckServerBoks(t *testing.T) {
	p := Policy{Revision: 3, Floor: 3, Block: []BotBlock{{Name: "crawlers", UserAgent: "(?i)gptbot"}}}
	o := &owned{fake: &fake{}}
	if err := CheckServerBoks(context.Background(), o, p); err != nil {
		t.Fatal(err)
	}
	if string(o.piped) != string(marshal(p)) {
		t.Errorf("asked about %s, want the bytes SetPolicy writes", o.piped)
	}
	o = &owned{fake: &fake{}, err: errors.New(`json: unknown field "egress"`)}
	err := CheckServerBoks(context.Background(), o, p)
	if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("err = %v, want the server's refusal", err)
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

// CheckPolicy reads a policy as ServerConfig reads the one on the disk: a field this boks does not know
// is refused, one it knows is taken.
func TestCheckPolicyIsStrict(t *testing.T) {
	if err := CheckPolicy(marshal(Policy{Revision: 2, Block: []BotBlock{{Name: "a", UserAgent: "b"}}})); err != nil {
		t.Errorf("a policy of this boks refused: %v", err)
	}
	err := CheckPolicy([]byte(`{"revision": 2, "floor": 2, "newer_filter": {"on": true}}`))
	if err == nil || !strings.Contains(err.Error(), "newer_filter") || !strings.Contains(err.Error(), "server apply") {
		t.Errorf("err = %v, want the unknown field refused with what to do", err)
	}
}
