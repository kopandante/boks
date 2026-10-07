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
	// A target that does not answer is 502, not the 403 of a refusal.
	if !strings.Contains(got, `"errors":{"routes":[{"handle":[{"body":"egress: no address of the target answered\n","handler":"static_response","status_code":502}]`) ||
		!strings.Contains(got, `"expression":"{http.error.status_code} == 403 \u0026\u0026 {http.error.message}.startsWith('no allowed IP addresses')"`) {
		t.Errorf("want the unanswered target answered 502: %s", got)
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

// A policy whose ports were lost is refused rather than given to the plugin, which reads no ports as
// every port.
func TestConfigEgressRefusesNoPorts(t *testing.T) {
	noPorts := *encar
	noPorts.Ports = nil
	if _, err := Config(Policy{Revision: 1, Egress: &noPorts}, nil); err == nil || !strings.Contains(err.Error(), "no ports") {
		t.Errorf("no ports: %v", err)
	}
}

// A policy that failed to apply takes the previous password back with it: a rotation that did not go
// through leaves the login the proxy still runs.
func TestSetPolicyPutsTheSecretBack(t *testing.T) {
	d := newDisk()
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 1, Egress: encar}); err != nil {
		t.Fatal(err)
	}
	rotated := *encar
	rotated.Password = "n3w"
	d.fail[reloadNext] = errors.New("refused")
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 1, Egress: &rotated}); err == nil {
		t.Fatal("want the failed reload reported")
	}
	if got := d.files[ServerDir+"/egress.secret"]; got != "encar:s3cret\n" {
		t.Errorf("want the previous secret back, got %q", got)
	}
}

// A policy without egress makes the proxy again without the port and the hosts file — and asks the
// image for no forward proxy it no longer needs.
func TestReshapeDropsTheEgress(t *testing.T) {
	s := reshapeServer()
	s.out["docker inspect -f {{range"] = "3128/tcp 443/tcp 80/tcp |/etc/hosts"
	if err := Reshape(context.Background(), s, io.Discard, Policy{Revision: 2}); err != nil {
		t.Fatal(err)
	}
	create := s.at("docker create --name " + Container)
	if create < 0 || strings.Contains(s.calls[create], "3128") || strings.Contains(s.calls[create], "--mount") {
		t.Errorf("want the proxy made again without egress: %v", s.calls)
	}
	if s.at("docker exec "+Container+" caddy list-modules") >= 0 {
		t.Errorf("asked for the forward proxy without egress: %v", s.calls)
	}
}

// An upgrade to the image the proxy runs already still makes it again when its shape is not the one
// the policy needs; in that shape, it changes nothing.
func TestUpgradeMakesTheProxyInTheAppliedShape(t *testing.T) {
	pol, _ := json.Marshal(openEgress)
	s := newSwap(newImage)
	s.out["sh -c if [ -f '.boks/_server/policy.json'"] = "present\n" + string(pol)
	s.out["docker inspect -f {{range"] = "443/tcp 80/tcp |"
	if _, err := s.upgrade(t); err != nil {
		t.Fatal(err)
	}
	create := s.at("docker create --name " + Container)
	if create < 0 || !strings.Contains(s.calls[create], "-p 3128:3128") || !strings.Contains(s.calls[create], " "+newImage+" caddy run") {
		t.Errorf("want the proxy made again with the egress port: %v", s.calls)
	}
	s = newSwap(newImage)
	s.out["sh -c if [ -f '.boks/_server/policy.json'"] = "present\n" + string(pol)
	s.out["docker inspect -f {{range"] = "3128/tcp 443/tcp 80/tcp |"
	if out, err := s.upgrade(t); err != nil || s.at("docker stop") >= 0 || !strings.Contains(out, "already runs") {
		t.Errorf("in shape: err %v, log %s, calls %v", err, out, s.calls)
	}
}

// CheckEgress refuses what would fail only after the proxy stopped, or after another server of the file
// changed: a hosts file that is not there, a login without its password, an image without the plugin.
func TestCheckEgress(t *testing.T) {
	withHosts := Policy{Revision: 1, Egress: &Egress{Port: 3128, Allow: []string{"203.0.113.10/32"}, Ports: []int{443}, HostsFile: "/etc/hosts"}}
	noPass := *encar
	noPass.Password = ""
	for want, c := range map[string]struct {
		p     Policy
		setup func(s *swap)
	}{
		"not a file":                       {withHosts, func(s *swap) {}},
		"no password for the egress login": {Policy{Revision: 1, Egress: &noPass}, func(s *swap) {}},
		"no forward proxy":                 {openEgress, func(s *swap) { s.out["docker exec "+Container+" caddy list-modules"] = "http.handlers.reverse_proxy" }},
		"":                                 {withHosts, func(s *swap) { s.out["sh -c [ -f '/etc/hosts' ]"] = "file" }},
		"stopped: the boot makes it anew": {openEgress, func(s *swap) {
			s.boxes[Container] = box{"exited", oldImage, Kind}
			s.out["docker exec "+Container+" caddy list-modules"] = ""
		}},
	} {
		s := reshapeServer()
		c.setup(s)
		err := CheckEgress(context.Background(), s, c.p)
		if strings.Contains(want, ":") || want == "" {
			if err != nil {
				t.Errorf("%q: %v", want, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
		if s.at("docker stop") >= 0 || s.at("docker create") >= 0 {
			t.Errorf("%q: changed the proxy: %v", want, s.calls)
		}
	}
	if err := CheckEgress(context.Background(), reshapeServer(), Policy{Revision: 1}); err != nil {
		t.Errorf("no egress: %v", err)
	}
}

// Drift names a proxy in another shape than the policy, and a hosts file replaced under its mount.
func TestDrift(t *testing.T) {
	withHosts := Policy{Revision: 1, Egress: &Egress{Port: 3128, Allow: []string{"203.0.113.10/32"}, Ports: []int{443}, HostsFile: "/etc/hosts"}}
	s := reshapeServer()
	if d, err := Drift(context.Background(), s, withHosts); err != nil || len(d) != 1 || !strings.Contains(d[0], "proxy upgrade") {
		t.Errorf("another shape: %v %v", d, err)
	}
	s = reshapeServer()
	s.out["docker inspect -f {{range"] = "3128/tcp 443/tcp 80/tcp |/etc/hosts"
	s.out["stat -c %i /etc/hosts"] = "1041"
	s.out["docker exec "+Container+" stat -c %i /etc/hosts"] = "1041"
	if d, err := Drift(context.Background(), s, withHosts); err != nil || len(d) != 0 {
		t.Errorf("in shape, same file: %v %v", d, err)
	}
	s.out["stat -c %i /etc/hosts"] = "2077"
	if d, err := Drift(context.Background(), s, withHosts); err != nil || len(d) != 1 || !strings.Contains(d[0], "replaced, not written in place") {
		t.Errorf("a replaced hosts file: %v %v", d, err)
	}
	s = reshapeServer()
	s.boxes[Container] = box{"exited", oldImage, Kind}
	if d, err := Drift(context.Background(), s, withHosts); err != nil || len(d) != 0 {
		t.Errorf("a stopped proxy: %v %v", d, err)
	}
}

// A secret whose write answered with an error — the answer lost after the file was replaced — is put
// back at once: the policy stays the old one, and the next deploy must not load the new password.
func TestSetPolicyPutsTheSecretBackWhenItsOwnWriteIsLost(t *testing.T) {
	d := newDisk()
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 1, Egress: encar}); err != nil {
		t.Fatal(err)
	}
	rotated := *encar
	rotated.Password = "n3w"
	d.lost["upload "+ServerDir+"/egress.secret"] = errors.New("connection reset")
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 1, Egress: &rotated}); err == nil {
		t.Fatal("want the lost write reported")
	}
	if got := d.files[ServerDir+"/egress.secret"]; got != "encar:s3cret\n" {
		t.Errorf("want the previous secret back, got %q", got)
	}
}

// The first policy with a login that fails leaves no secret behind, and the marker goes before it.
func TestSetPolicyRemovesASecretItWroteFirst(t *testing.T) {
	d := newDisk()
	d.fail[reloadNext] = errors.New("refused")
	if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 1, Egress: encar}); err == nil {
		t.Fatal("want the failed reload reported")
	}
	if _, left := d.files[ServerDir+"/egress.secret"]; left {
		t.Errorf("a secret left without its policy: %v", d.calls)
	}
	if mark, sec := index(d.calls, "upload "+Dir+"/routes/_server.json"), index(d.calls, "upload "+ServerDir+"/egress.secret"); mark < 0 || sec < mark {
		t.Errorf("want the marker before the secret: %v", d.calls)
	}
}

// uploadFault answers every atomic upload to path from the nth on with an error: before it acts, or
// — lost — after it acted. The others go through to the disk.
type uploadFault struct {
	*disk
	path       string
	from, seen int
	lost       bool
}

func (f *uploadFault) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	if strings.HasSuffix(args[len(args)-1], " '"+f.path+"'") {
		if f.seen++; f.seen >= f.from {
			if f.lost {
				f.disk.Pipe(ctx, content, args...)
			}
			return "", errors.New("connection reset")
		}
	}
	return f.disk.Pipe(ctx, content, args...)
}

// The secret follows the policy on disk when the policy cannot be put back by the book: a new policy
// left in place keeps the secret it needs, and a previous one still there — the new never got there,
// or the undo's answer was lost — gets its own back.
func TestSetPolicyKeepsTheSecretWithThePolicyOnDisk(t *testing.T) {
	open := *encar
	open.User, open.Password = "", ""
	rotated := *encar
	rotated.Password = "n3w"
	for _, c := range []struct {
		name     string
		prev     *Egress
		fault    uploadFault
		revision string
		secret   string
	}{
		{"the undo refused, the new policy stays", &open, uploadFault{from: 2}, `"revision": 2,`, "encar:s3cret\n"},
		{"neither write acted", encar, uploadFault{from: 1}, `"revision": 1,`, "encar:s3cret\n"},
		{"the undo's answer lost", encar, uploadFault{from: 2, lost: true}, `"revision": 1,`, "encar:s3cret\n"},
	} {
		d := newDisk()
		if err := SetPolicy(context.Background(), d, io.Discard, Policy{Revision: 1, Egress: c.prev}); err != nil {
			t.Fatal(err)
		}
		d.fail[reloadNext] = errors.New("refused")
		next := encar
		if c.prev == encar {
			next = &rotated
		}
		f := c.fault
		f.disk, f.path = d, policyPath()
		if err := SetPolicy(context.Background(), &f, io.Discard, Policy{Revision: 2, Egress: next}); err == nil {
			t.Fatalf("%s: want the failure reported", c.name)
		}
		if !strings.Contains(d.files[policyPath()], c.revision) {
			t.Errorf("%s: want %s on disk: %q", c.name, c.revision, d.files[policyPath()])
		}
		if got := d.files[egressSecretPath()]; got != c.secret {
			t.Errorf("%s: want the secret %q, got %q: %v", c.name, c.secret, got, d.calls)
		}
	}
}
