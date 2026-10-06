package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// encar is the egress the encar pool's tinyproxy served: three clients, a login, 443 and 80.
var encar = &Egress{Port: 3128, Allow: []string{"203.0.113.10/32", "198.51.100.0/24"}, User: "encar", Ports: []int{443, 80}, Password: "s3cret"}

// egressOf is the egress server of the config p and the web routes make.
func egressOf(t *testing.T, p Policy) map[string]any {
	t.Helper()
	body, err := Config(p, []Fragment{{App: "web", Routes: web}})
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]map[string]any `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c.Apps.HTTP.Servers["egress"]
}

// The forward proxy is a server of its own on its port: only the allowed clients reach the handler,
// with the login as the plugin compares it — base64 of user:password, which JSON writes in base64 once
// more — and everyone else gets 403. No logs, no automatic HTTPS, no bot filter or 404 of the sites.
func TestConfigEgress(t *testing.T) {
	s := egressOf(t, Policy{Revision: 1, Block: []BotBlock{{Name: "crawlers", UserAgent: "(?i)gptbot"}}, Egress: encar})
	if s == nil {
		t.Fatal("no egress server")
	}
	b, _ := json.Marshal(s)
	got := string(b)
	for _, want := range []string{`"listen":[":3128"]`, `"automatic_https":{"disable":true}`,
		`"remote_ip":{"ranges":["203.0.113.10/32","198.51.100.0/24"]}`, `"handler":"forward_proxy"`,
		`"hide_ip":true`, `"hide_via":true`, `"allowed_ports":[443,80]`, `"status_code":403`} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in %s", want, got)
		}
	}
	if strings.Contains(got, `"logs"`) || strings.Contains(got, "User-Agent") || strings.Contains(got, `"status_code":404`) {
		t.Errorf("the sites' logs, filter or 404 on the egress server: %s", got)
	}
	creds := s["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["auth_credentials"].([]any)[0].(string)
	inner, err := base64.StdEncoding.DecodeString(creds)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := base64.StdEncoding.DecodeString(string(inner)); err != nil || string(plain) != "encar:s3cret" {
		t.Errorf("want base64(base64(encar:s3cret)), got %s → %s", creds, inner)
	}
	if s := egressOf(t, Policy{Revision: 1}); s != nil {
		t.Errorf("an egress server without egress: %v", s)
	}
	noLogin := *encar
	noLogin.User, noLogin.Password = "", ""
	if b, _ := json.Marshal(egressOf(t, Policy{Revision: 1, Egress: &noLogin})); strings.Contains(string(b), "auth_credentials") {
		t.Errorf("a login without one: %s", b)
	}
	lost := *encar
	lost.Password = ""
	if _, err := Config(Policy{Revision: 1, Egress: &lost}, nil); err == nil || !strings.Contains(err.Error(), "no password") {
		t.Errorf("a login without its password: %v", err)
	}
}

// The policy never records the password; SamePolicy does not see it either, so a new password is
// applied by applying the same revision again.
func TestPolicyKeepsNoPassword(t *testing.T) {
	b := marshal(Policy{Revision: 1, Egress: encar})
	if strings.Contains(string(b), "s3cret") {
		t.Errorf("the password in the policy: %s", b)
	}
	other := *encar
	other.Password = "new"
	if !SamePolicy(Policy{Revision: 1, Egress: encar}, Policy{Revision: 1, Egress: &other}) {
		t.Errorf("a new password made another policy")
	}
}

func TestCreateArgsShape(t *testing.T) {
	got := strings.Join(CreateArgs(oldImage, "/home/u/.boks/_proxy", Shape{EgressPort: 3128, HostsFile: "/etc/hosts"}), " ")
	if !strings.Contains(got, "-p 80:80 -p 443:443 -p 3128:3128 --mount type=bind,source=/etc/hosts,target=/etc/hosts,readonly -v ") {
		t.Errorf("got %s", got)
	}
	if got := ShapeOf(Policy{Egress: encar}); got != (Shape{EgressPort: 3128}) {
		t.Errorf("shape: %+v", got)
	}
}

// SetPolicy keeps the password in a file of its own, before the policy, and assembles the config with
// it; applied again without the password — a rollback — it uses the one the server keeps for that
// user, and refuses another user's.
func TestSetPolicyKeepsTheEgressSecret(t *testing.T) {
	d := newDisk()
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 1, Egress: encar}); err != nil {
		t.Fatal(err)
	}
	if d.files[ServerDir+"/egress.secret"] != "encar:s3cret\n" || strings.Contains(d.files[ServerDir+"/policy.json"], "s3cret") {
		t.Errorf("secret %q, policy %s", d.files[ServerDir+"/egress.secret"], d.files[ServerDir+"/policy.json"])
	}
	if sec, pol := index(d.calls, "upload "+ServerDir+"/egress.secret"), index(d.calls, "upload "+ServerDir+"/policy.json"); sec < 0 || pol < sec {
		t.Errorf("want the secret before the policy: %v", d.calls)
	}
	if !strings.Contains(d.files[Dir+"/caddy.json"], "auth_credentials") {
		t.Errorf("config without the login: %s", d.files[Dir+"/caddy.json"])
	}
	again := *encar
	again.Password = ""
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 2, Egress: &again}); err != nil || again.Password != "" {
		t.Errorf("applied again without the password: %v; the caller's policy got %q", err, again.Password)
	}
	other := again
	other.User = "bravo"
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 3, Egress: &other}); err == nil || !strings.Contains(err.Error(), "no password for the egress login bravo") {
		t.Errorf("another user's login without a password: %v", err)
	}
}

// reshapeServer is a swap server whose proxy runs boks's image, published on 80 and 443 only.
func reshapeServer() *swap {
	s := newSwap(oldImage)
	s.out["docker inspect -f {{range"] = "443/tcp 80/tcp |"
	s.out["docker exec "+Container+" caddy list-modules"] = "http.handlers.reverse_proxy\nhttp.handlers.forward_proxy"
	return s
}

var openEgress = Policy{Revision: 1, Egress: &Egress{Port: 3128, Allow: []string{"203.0.113.10/32"}, Ports: []int{443}}}

// A policy that needs another container makes it again with the image the proxy runs — after the
// forward proxy and the config are asked of the running Caddy, before anything stops.
func TestReshapePublishesTheEgressPort(t *testing.T) {
	s := reshapeServer()
	if err := Reshape(context.Background(), s, io.Discard, openEgress); err != nil {
		t.Fatal(err)
	}
	mods, valid, stop, create := s.at("docker exec "+Container+" caddy list-modules"), s.at("docker exec "+Container+" caddy validate"),
		s.at("docker stop "+Container), s.at("docker create --name "+Container)
	if mods < 0 || valid < mods || stop < valid || create < stop {
		t.Errorf("order: modules %d validate %d stop %d create %d\n%v", mods, valid, stop, create, s.calls)
	}
	if c := s.calls[create]; !strings.Contains(c, "-p 3128:3128") || !strings.Contains(c, " "+oldImage+" caddy run") {
		t.Errorf("want the proxy made again with its own image and the port: %s", c)
	}
	if b := s.boxes[Container]; b.state != "running" || len(s.boxes) != 1 {
		t.Errorf("boxes: %v", s.boxes)
	}
}

func TestReshapeLeavesAProxyInShapeAlone(t *testing.T) {
	s := reshapeServer()
	s.out["docker inspect -f {{range"] = "3128/tcp 443/tcp 80/tcp |"
	if err := Reshape(context.Background(), s, io.Discard, openEgress); err != nil || s.at("docker stop") >= 0 {
		t.Errorf("err %v, calls %v", err, s.calls)
	}
	// Not running: the boot that starts it makes it in the applied shape.
	s = reshapeServer()
	s.boxes[Container] = box{"exited", oldImage, Kind}
	if err := Reshape(context.Background(), s, io.Discard, openEgress); err != nil || s.at("docker stop") >= 0 {
		t.Errorf("a stopped proxy: err %v, calls %v", err, s.calls)
	}
}

// Every refusal comes before the stop: an image without the forward proxy, a config the running Caddy
// refuses, a deploy in progress, a swap left cut.
func TestReshapeRefusesBeforeTheStop(t *testing.T) {
	for want, setup := range map[string]func(s *swap){
		"no forward proxy": func(s *swap) { s.out["docker exec "+Container+" caddy list-modules"] = "http.handlers.reverse_proxy" },
		"refuses the config": func(s *swap) {
			s.fail["docker exec "+Container+" caddy validate"] = errors.New("unknown module")
		},
		"deploy is in progress": func(s *swap) { s.out["sh -c for d in /tmp/boks-*.lock"] = "/tmp/boks-web.lock" },
		"cut short":             func(s *swap) { s.boxes[asideName] = box{"exited", oldImage, Kind} },
	} {
		s := reshapeServer()
		setup(s)
		err := Reshape(context.Background(), s, io.Discard, openEgress)
		if err == nil || !strings.Contains(err.Error(), want) || s.at("docker stop") >= 0 {
			t.Errorf("%s: err %v, calls %v", want, err, s.calls)
		}
	}
}

// A new proxy that does not answer is removed and the old one, with the config it ran, serves again.
func TestReshapePutsTheOldProxyBack(t *testing.T) {
	s := reshapeServer()
	// The new container comes up without the sysctl; the old one is only asked to answer.
	s.fail["docker exec "+Container+" cat /proc/sys/"] = errors.New("no such file")
	err := Reshape(context.Background(), s, io.Discard, openEgress)
	if err == nil || !strings.Contains(err.Error(), "serves again") {
		t.Fatalf("got %v", err)
	}
	if b := s.boxes[Container]; b.state != "running" || len(s.boxes) != 1 {
		t.Errorf("boxes: %v\n%v", s.boxes, s.calls)
	}
}

// Boot creates a missing proxy in the shape of the policy on the server, and makes a stopped one in
// another shape again rather than start it without the egress port.
func TestBootCreatesTheProxyInTheAppliedShape(t *testing.T) {
	pol, _ := json.Marshal(openEgress)
	for _, state := range []string{"", "exited"} {
		s := newSwap(oldImage)
		if state == "" {
			delete(s.boxes, Container)
		} else {
			s.boxes[Container] = box{state, oldImage, Kind}
		}
		s.out["sh -c if [ -f '.boks/_server/policy.json' ]"] = "present\n" + string(pol)
		s.out["docker inspect -f {{range"] = "443/tcp 80/tcp |"
		s.out["docker network inspect"] = "{}"
		if err := Boot(context.Background(), s, io.Discard, oldImage); err != nil {
			t.Fatalf("%q: %v", state, err)
		}
		create := s.at("docker create --name " + Container)
		if create < 0 || !strings.Contains(s.calls[create], "-p 3128:3128") {
			t.Errorf("%q: want the proxy created with the egress port: %v", state, s.calls)
		}
	}
}
