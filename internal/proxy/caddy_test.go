package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
)

// disk is a server as far as the proxy's state goes: files under Dir, the proxy container's state
// and label, and what it was asked to run.
type disk struct {
	files map[string]string
	ps    string // what `docker ps` prints for the proxy: "<state>\t<label>"
	fail  map[string]error
	calls []string
}

func newDisk() *disk {
	return &disk{files: map[string]string{}, ps: "running\tcaddy", fail: map[string]error{}}
}

func (d *disk) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	d.calls = append(d.calls, cmd)
	for prefix, err := range d.fail {
		if strings.HasPrefix(cmd, prefix) {
			return "", err
		}
	}
	switch {
	case strings.HasPrefix(cmd, "docker ps -a --filter name=^boks-proxy$"):
		return d.ps, nil
	case strings.HasPrefix(cmd, "sh -c for f in "):
		var names []string
		for p := range d.files {
			if strings.HasPrefix(p, Dir+"/routes/") {
				names = append(names, p)
			}
		}
		sort.Strings(names)
		var out []string
		for _, p := range names {
			out = append(out, d.files[p])
		}
		return strings.TrimSpace(strings.Join(out, "")), nil
	case strings.HasPrefix(cmd, "sh -c if [ -f "):
		p := strings.Trim(strings.Fields(cmd)[5], "'")
		if body, ok := d.files[p]; ok {
			return strings.TrimSpace("present\n" + body), nil
		}
		return "absent", nil
	case args[0] == "mv":
		d.files[args[2]] = d.files[args[1]]
		delete(d.files, args[1])
	case args[0] == "rm":
		delete(d.files, args[2])
	}
	return "", nil
}

// Pipe takes an atomic upload: the destination is the last quoted token after `mv`.
func (d *disk) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	for prefix, err := range d.fail {
		if strings.HasPrefix("upload "+cmd, prefix) {
			return "", err
		}
	}
	_, tail, _ := strings.Cut(args[2], " && mv ")
	_, dest, _ := strings.Cut(tail, "' '")
	d.files[strings.Trim(dest, "'")] = string(content)
	d.calls = append(d.calls, "upload "+strings.Trim(dest, "'"))
	return "", nil
}

func (d *disk) ran(prefix string) bool {
	for _, c := range d.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

const reloadNext = "docker exec boks-proxy caddy reload --config /etc/boks/caddy.next.json"

var web = []Route{{Host: "demo.example.com", Dial: "demo:3000", TLS: true}}

// decoded is a config read back as generic JSON, to look into it the way Caddy will.
func decoded(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func dig(m any, keys ...string) any {
	for _, k := range keys {
		mm, ok := m.(map[string]any)
		if !ok {
			return nil
		}
		m = mm[k]
	}
	return m
}

// The bytes are the comparison that decides a reload, so the same routes make the same config
// whatever order the fragments were read in.
func TestConfigIsTheSameForTheSameRoutes(t *testing.T) {
	a := Fragment{App: "a", Routes: []Route{{Host: "z.example.com", Dial: "a:1", TLS: true}, {Host: "b.example.com", Dial: "a:2"}}}
	b := Fragment{App: "b", Routes: []Route{{Host: "m.example.com", Dial: "b:1", TLS: true}}}
	one, err := Config([]Fragment{a, b})
	if err != nil {
		t.Fatal(err)
	}
	two, _ := Config([]Fragment{b, a})
	if string(one) != string(two) {
		t.Errorf("same routes, different bytes:\n%s\n%s", one, two)
	}
	hosts := dig(decoded(t, one), "apps", "http", "servers", "https", "routes").([]any)
	if first := hosts[0].(map[string]any)["match"].([]any)[0].(map[string]any)["host"].([]any)[0]; first != "m.example.com" {
		t.Errorf("routes go by host: %v", first)
	}
}

// Caddy would give a host claimed twice to the first route and drop the second without a word.
func TestConfigRefusesAHostRoutedTwice(t *testing.T) {
	_, err := Config([]Fragment{{App: "a", Routes: web}, {App: "b", Routes: []Route{{Host: "Demo.Example.com", Dial: "b:1"}}}})
	if err == nil || !strings.Contains(err.Error(), "routed by both a and b") {
		t.Errorf("want the host refused, got %v", err)
	}
}

// TLS hosts on 443 with HTTP/1.1 and HTTP/2 only, plain ones on 80 alone; a host under `cert:` is
// served from its files and kept out of ACME by name, and one file pair is loaded once.
func TestConfigServesTLSAndPlainHostsApart(t *testing.T) {
	cert := &CertFiles{Certificate: "/certs/boks/_.example.com.crt", Key: "/certs/boks/_.example.com.key"}
	b, err := Config([]Fragment{{App: "a", Routes: []Route{
		{Host: "plain.example.com", Dial: "a:80"},
		{Host: "auto.example.com", Dial: "a:81", TLS: true},
		{Host: "w1.example.com", Dial: "a:82", TLS: true, Cert: cert},
		{Host: "w2.example.com", Dial: "a:83", TLS: true, Cert: cert},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	https, http := dig(m, "apps", "http", "servers", "https"), dig(m, "apps", "http", "servers", "http")
	if l := dig(https, "listen").([]any); l[0] != ":443" || len(dig(https, "routes").([]any)) != 3 {
		t.Errorf("want the three TLS hosts on 443: %v", https)
	}
	if p, _ := json.Marshal(dig(https, "protocols")); string(p) != `["h1","h2"]` {
		t.Errorf("want no HTTP/3 on a port whose udp is not published: %s", p)
	}
	if l := dig(http, "listen").([]any); l[0] != ":80" || len(dig(http, "routes").([]any)) != 1 {
		t.Errorf("want the plain host alone on 80: %v", http)
	}
	if s, _ := json.Marshal(dig(https, "automatic_https", "skip_certificates")); string(s) != `["w1.example.com","w2.example.com"]` {
		t.Errorf("want the hosts under the certificate kept out of ACME: %s", s)
	}
	if f, _ := json.Marshal(dig(m, "apps", "tls", "certificates", "load_files")); string(f) != `[{"certificate":"/certs/boks/_.example.com.crt","key":"/certs/boks/_.example.com.key"}]` {
		t.Errorf("want the file pair loaded once: %s", f)
	}
	h := dig(https, "routes").([]any)[0].(map[string]any)["handle"].([]any)[0]
	if u, _ := json.Marshal(dig(h, "upstreams")); dig(h, "handler") != "reverse_proxy" || string(u) != `[{"dial":"a:81"}]` {
		t.Errorf("want the host proxied to its dial: %v", h)
	}
	if persist := dig(m, "admin", "config", "persist"); persist != false {
		t.Errorf("the file is the config; no autosave beside it: %v", persist)
	}
	// Without a TLS host there is no 443 server and no tls app.
	plain, _ := Config([]Fragment{{App: "a", Routes: []Route{{Host: "p.example.com", Dial: "a:1"}}}})
	if pm := decoded(t, plain); dig(pm, "apps", "http", "servers", "https") != nil || dig(pm, "apps", "tls") != nil {
		t.Errorf("want plain HTTP only: %s", plain)
	}
}

// Nothing trusted stands in front of boks (#48): Caddy is told of no trusted proxy, so it sets
// X-Forwarded-For from the connection and drops the visitor's own — measured on boks-lab.
func TestConfigTrustsNoForwardedHeaders(t *testing.T) {
	b, err := Config([]Fragment{{App: "a", Routes: []Route{{Host: "a.example.com", Dial: "a:1", TLS: true}, {Host: "p.example.com", Dial: "a:2"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"trusted_proxies", "client_ip_headers", "headers"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("the config sets %s, which would let a visitor's forwarded headers through:\n%s", key, b)
		}
	}
}

// A first route reloads the running proxy with the new config, and only once Caddy took it are the
// fragment and the applied config written.
func TestSetRoutesReloadsAndThenRecords(t *testing.T) {
	d := newDisk()
	reloaded, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
	if err != nil || !reloaded {
		t.Fatalf("want a reload, got %v %v", reloaded, err)
	}
	if !strings.Contains(d.files[Dir+"/routes/demo.json"], `"dial": "demo:3000"`) {
		t.Errorf("want the fragment recorded: %q", d.files[Dir+"/routes/demo.json"])
	}
	want, _ := Config([]Fragment{{App: "demo", Routes: web}})
	if d.files[Dir+"/caddy.json"] != string(want) || d.files[Dir+"/caddy.next.json"] != "" {
		t.Errorf("want the applied config in place and no next left: %v", d.files)
	}
	reload, frag := index(d.calls, reloadNext), index(d.calls, "upload "+Dir+"/routes/demo.json")
	if reload < 0 || frag < reload {
		t.Errorf("want the reload before the fragment: %v", d.calls)
	}
}

// The same routes again reload nothing: a reload drops connections.
func TestSetRoutesLeavesAnUnchangedProxyAlone(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	reloaded, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
	if err != nil || reloaded || d.ran("docker exec") || d.ran("upload") {
		t.Errorf("want nothing done, got %v %v %v", reloaded, err, d.calls)
	}
}

// A run cut after Caddy took the config leaves the fragment behind it: the next run writes the
// fragment and reloads nothing, since the proxy already runs that config.
func TestSetRoutesCatchesUpALaggingFragment(t *testing.T) {
	d := newDisk()
	body, _ := Config([]Fragment{{App: "demo", Routes: web}})
	d.files[Dir+"/caddy.json"] = string(body)
	reloaded, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
	if err != nil || reloaded || d.ran("docker exec") || d.files[Dir+"/routes/demo.json"] == "" {
		t.Errorf("want the fragment written and no reload: %v %v %v", reloaded, err, d.calls)
	}
}

// A config Caddy refuses leaves everything as it was: Caddy keeps serving the old one, and no fragment
// or applied config claims the refused one — or every later run would assemble it again.
func TestSetRoutesRecordsNothingCaddyRefused(t *testing.T) {
	d := newDisk()
	d.fail[reloadNext] = errors.New("loading new config: open /certs/boks/x.crt: no such file")
	_, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
	if err == nil || !strings.Contains(err.Error(), "keeps the ones it had") {
		t.Fatalf("want the refusal, got %v", err)
	}
	if _, ok := d.files[Dir+"/routes/demo.json"]; ok {
		t.Errorf("no fragment for a refused config: %v", d.files)
	}
	if _, ok := d.files[Dir+"/caddy.json"]; ok {
		t.Errorf("no applied config for a refused one: %v", d.files)
	}
}

// A proxy that is not running — or is still kamal-proxy — is not reloaded; the files are written for
// the Caddy that starts next to load.
func TestSetRoutesWritesTheFilesForAProxyThatIsNotRunning(t *testing.T) {
	for _, ps := range []string{"exited\tcaddy", "", "running\t"} {
		d := newDisk()
		d.ps = ps
		reloaded, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
		if err != nil || reloaded || d.ran("docker exec") {
			t.Errorf("%q: want no reload, got %v %v %v", ps, reloaded, err, d.calls)
		}
		if d.files[Dir+"/routes/demo.json"] == "" || d.files[Dir+"/caddy.json"] == "" {
			t.Errorf("%q: want the files written: %v", ps, d.files)
		}
	}
}

// No routes removes the app's fragment and reloads without its hosts; another app's stay.
func TestSetRoutesRemovesAnAppsRoutes(t *testing.T) {
	d := newDisk()
	other := []Route{{Host: "o.example.com", Dial: "other:80"}}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", other); err != nil {
		t.Fatal(err)
	}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	reloaded, err := SetRoutes(context.Background(), d, io.Discard, "demo", nil)
	if err != nil || !reloaded {
		t.Fatalf("want a reload, got %v %v", reloaded, err)
	}
	want, _ := Config([]Fragment{{App: "other", Routes: other}})
	if _, ok := d.files[Dir+"/routes/demo.json"]; ok || d.files[Dir+"/caddy.json"] != string(want) {
		t.Errorf("want demo's routes gone and other's kept: %v", d.files)
	}
}

// A host another app holds is refused before anything changes.
func TestCheckHostsRefusesAnotherAppsHost(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", web); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	if err := CheckHosts(context.Background(), d, "demo", web); err == nil || d.ran("upload") || d.ran("docker exec") {
		t.Errorf("want a refusal that changes nothing, got %v %v", err, d.calls)
	}
	if err := CheckHosts(context.Background(), d, "other", web); err != nil {
		t.Errorf("an app's own host is its own: %v", err)
	}
}

// A renewal keeps the paths and replaces the files behind them, which Caddy reads only on a load it
// would skip for an unchanged config — hence --force.
func TestReloadIsForced(t *testing.T) {
	d := newDisk()
	if err := Reload(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if !d.ran("docker exec boks-proxy caddy reload --config /etc/boks/caddy.json --force") {
		t.Errorf("want a forced reload of the applied config: %v", d.calls)
	}
}

// The container is labelled as Caddy, keeps its ACME state and the certificate volume kamal-proxy
// used, and reads the state directory, not one file, read-only.
func TestCreateArgs(t *testing.T) {
	got := strings.Join(CreateArgs(DefaultImage, "/home/u/.boks/_proxy"), " ")
	want := "docker create --name boks-proxy --restart unless-stopped --label boks.proxy=caddy --network boks -p 80:80 -p 443:443 " +
		"-v boks-proxy-data:/data -v boks-certs:/certs -v /home/u/.boks/_proxy:/etc/boks:ro " +
		"caddy:2.11.7-alpine caddy run --config /etc/boks/caddy.json"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func index(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}
