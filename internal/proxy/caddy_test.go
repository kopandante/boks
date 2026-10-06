package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// disk is a server as far as the proxy's state goes: files under Dir, the proxy container's state
// and label, and what it was asked to run.
type disk struct {
	files map[string]string
	ps    string // what `docker ps` prints for the proxy: "<state>\t<label>"
	fail  map[string]error
	// lost acts as asked and then answers with the error, once: an answer lost after the command ran.
	lost map[string]error
	// caddy is the config Caddy runs: what the last reload it took loaded. caddy.json is only boks's
	// record of it, and a run cut after a reload leaves the two apart.
	caddy string
	calls []string
}

func newDisk() *disk {
	return &disk{files: map[string]string{}, ps: "running\tcaddy", fail: map[string]error{}, lost: map[string]error{}}
}

func (d *disk) Run(ctx context.Context, args ...string) (string, error) {
	out, err := d.run(ctx, args...)
	if err == nil {
		err = d.lose(strings.Join(args, " "))
	}
	return out, err
}

func (d *disk) lose(cmd string) error {
	for prefix, err := range d.lost {
		if strings.HasPrefix(cmd, prefix) {
			delete(d.lost, prefix)
			return err
		}
	}
	return nil
}

func (d *disk) run(_ context.Context, args ...string) (string, error) {
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
	case strings.HasPrefix(cmd, reloadNext):
		d.caddy = d.files[Dir+"/caddy.next.json"]
	case args[0] == "mv":
		d.files[args[2]] = d.files[args[1]]
		delete(d.files, args[1])
	case args[0] == "rm":
		delete(d.files, args[2])
	}
	return "", nil
}

// Pipe takes an atomic upload: the destination is the last quoted token after `mv`. A lost answer
// is keyed as the call is recorded: "upload <path>".
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
	return "", d.lose("upload " + strings.Trim(dest, "'"))
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
	one, err := Config(Policy{}, []Fragment{a, b})
	if err != nil {
		t.Fatal(err)
	}
	two, _ := Config(Policy{}, []Fragment{b, a})
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
	_, err := Config(Policy{}, []Fragment{{App: "a", Routes: web}, {App: "b", Routes: []Route{{Host: "Demo.Example.com", Dial: "b:1"}}}})
	if err == nil || !strings.Contains(err.Error(), "routed by both a and b") {
		t.Errorf("want the host refused, got %v", err)
	}
}

// TLS hosts on 443 with HTTP/1.1 and HTTP/2 only, plain ones on 80 alone; a host under `cert:` is
// served from its files and kept out of ACME by name, and one file pair is loaded once.
func TestConfigServesTLSAndPlainHostsApart(t *testing.T) {
	cert := &CertFiles{Certificate: "/certs/boks/_.example.com.crt", Key: "/certs/boks/_.example.com.key"}
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{
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
	if l := dig(https, "listen").([]any); l[0] != ":443" || len(dig(https, "routes").([]any)) != 4 {
		t.Errorf("want the three TLS hosts on 443, then the 404 for any other: %v", https)
	}
	if last, _ := json.Marshal(dig(https, "routes").([]any)[3]); string(last) != `{"handle":[{"handler":"static_response","status_code":404}],"terminal":true}` {
		t.Errorf("want HTTPS for a host no route names answered 404: %s", last)
	}
	if p, _ := json.Marshal(dig(https, "protocols")); string(p) != `["h1","h2"]` {
		t.Errorf("want no HTTP/3 on a port whose udp is not published: %s", p)
	}
	if l := dig(http, "listen").([]any); l[0] != ":80" || len(dig(http, "routes").([]any)) != 3 {
		t.Errorf("want the plain host on 80, the TLS hosts' redirect, then the 404: %v", http)
	}
	// Caddy adds redirects of its own before the 404 only while it manages some certificate; with
	// every TLS host under `cert:` it would not, so boks's redirect is what keeps plain HTTP for
	// them from answering 404.
	redir, _ := json.Marshal(dig(http, "routes").([]any)[1])
	if want := `{"handle":[{"handler":"static_response","headers":{"Location":["https://{http.request.host}{http.request.uri}"]},"status_code":308}],"match":[{"host":["auto.example.com","w1.example.com","w2.example.com"],"not":[{"host":["plain.example.com"]}]}],"terminal":true}`; string(redir) != want {
		t.Errorf("want plain HTTP for the TLS hosts redirected:\n got %s\nwant %s", redir, want)
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
	plain, _ := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "p.example.com", Dial: "a:1"}}}})
	if pm := decoded(t, plain); dig(pm, "apps", "http", "servers", "https") != nil || dig(pm, "apps", "tls") != nil {
		t.Errorf("want plain HTTP only: %s", plain)
	}
}

// With TLS hosts alone, 80 is still boks's own server — the redirect, then the 404 — and Caddy's
// redirects are off: its server of its own on 80 would redirect every host, known or not, and
// nothing boks puts ahead of routes would run there.
func TestConfigOwnsPort80BesideTLS(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "a.example.com", Dial: "a:1", TLS: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	routes, _ := json.Marshal(dig(m, "apps", "http", "servers", "http", "routes"))
	if want := `[{"handle":[{"handler":"static_response","headers":{"Location":["https://{http.request.host}{http.request.uri}"]},"status_code":308}],"match":[{"host":["a.example.com"]}],"terminal":true},{"handle":[{"handler":"static_response","status_code":404}],"terminal":true}]`; string(routes) != want {
		t.Errorf("want 80 to redirect the TLS host and 404 the rest:\n got %s\nwant %s", routes, want)
	}
	if l, _ := json.Marshal(dig(m, "apps", "http", "servers", "http", "listen")); string(l) != `[":80"]` {
		t.Errorf("want boks's own server on 80: %s", l)
	}
	if dig(m, "apps", "http", "servers", "http", "logs") == nil {
		t.Errorf("want 80 logging its requests like 443")
	}
	if d := dig(m, "apps", "http", "servers", "https", "automatic_https", "disable_redirects"); d != true {
		t.Errorf("want Caddy's own redirects off: %v", d)
	}
}

// Nothing trusted stands in front of boks (#48): Caddy is told of no trusted proxy, so it sets
// X-Forwarded-For from the connection and drops the visitor's own — measured on boks-lab. The one
// header every route touches is Forwarded, which it deletes: kamal-proxy did, and Caddy passes it on.
func TestConfigTrustsNoForwardedHeaders(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "a.example.com", Dial: "a:1", TLS: true}, {Host: "p.example.com", Dial: "a:2"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"trusted_proxies", "client_ip_headers", "set", "add", "replace"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("the config sets %s, which would let a visitor's forwarded headers through:\n%s", key, b)
		}
	}
	for _, srv := range []string{"http", "https"} {
		routes, _ := dig(decoded(t, b), "apps", "http", "servers", srv, "routes").([]any)
		h := dig(routes[0], "handle").([]any)[0]
		if del, _ := dig(h, "headers", "request", "delete").([]any); len(del) != 1 || del[0] != "Forwarded" {
			t.Errorf("%s: want Forwarded deleted from the request, got %v", srv, dig(h, "headers"))
		}
		if dig(decoded(t, b), "apps", "http", "servers", srv, "logs") == nil {
			t.Errorf("%s: want access logs on, as kamal-proxy wrote them", srv)
		}
	}
}

// A reload must not cut the WebSockets of the apps it does not change: every route keeps its streams
// open past the unload of the config they came through. And every route bounds the wait for headers.
func TestConfigKeepsStreamsAcrossAReload(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "a.example.com", Dial: "a:80"}, {Host: "s.example.com", Dial: "a:81", TLS: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range []string{"http", "https"} {
		routes, _ := dig(decoded(t, b), "apps", "http", "servers", srv, "routes").([]any)
		// The app's route comes first; what follows is boks's own (the 404 for any other host).
		if len(routes) == 0 {
			t.Fatalf("%s: want the app's route, got none", srv)
		}
		h := dig(routes[0], "handle").([]any)[0]
		if d := dig(h, "stream_close_delay"); d != "24h" {
			t.Errorf("%s: want stream_close_delay 24h, got %v", srv, d)
		}
		// And a copy that takes a request and sends no headers gets a 504 at kamal-proxy's 30s, not never.
		if d := dig(h, "transport", "response_header_timeout"); d != "30s" || dig(h, "transport", "protocol") != "http" {
			t.Errorf("%s: want the http transport with response_header_timeout 30s, got %v", srv, dig(h, "transport"))
		}
	}
}

// A first route reloads the running proxy with the new config: the fragment is written before the
// reload, the applied config only once Caddy took it.
func TestSetRoutesReloadsAndThenRecords(t *testing.T) {
	d := newDisk()
	reloaded, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
	if err != nil || !reloaded {
		t.Fatalf("want a reload, got %v %v", reloaded, err)
	}
	if !strings.Contains(d.files[Dir+"/routes/demo.json"], `"dial": "demo:3000"`) {
		t.Errorf("want the fragment recorded: %q", d.files[Dir+"/routes/demo.json"])
	}
	want, _ := Config(Policy{}, []Fragment{{App: "demo", Routes: web}})
	if d.files[Dir+"/caddy.json"] != string(want) || d.files[Dir+"/caddy.next.json"] != "" {
		t.Errorf("want the applied config in place and no next left: %v", d.files)
	}
	reload, frag := index(d.calls, reloadNext), index(d.calls, "upload "+Dir+"/routes/demo.json")
	applied := index(d.calls, "mv "+Dir+"/caddy.next.json")
	if frag < 0 || reload < frag || applied < reload {
		t.Errorf("want the fragment, then the reload, then the applied config: %v", d.calls)
	}
}

// A run cut after Caddy took the config, before it was recorded as applied, leaves a fragment the
// applied config does not match: the next run, of another app, reloads with this app's new routes
// rather than putting them back on the copy it left (stopped, in stop-first).
func TestSetRoutesKeepsTheRoutesOfARunCutAfterItsReload(t *testing.T) {
	d := newDisk()
	old := []Route{{Host: "demo.example.com", Dial: "demo-old:3000", TLS: true}}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", old); err != nil {
		t.Fatal(err)
	}
	d.fail["mv "+Dir+"/caddy.next.json"] = errors.New("connection lost")
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err == nil {
		t.Fatal("want the cut run's error")
	}
	delete(d.fail, "mv "+Dir+"/caddy.next.json")
	other := []Route{{Host: "o.example.com", Dial: "other:80"}}
	d.calls = nil
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", other); err != nil {
		t.Fatal(err)
	}
	want, _ := Config(Policy{}, []Fragment{{App: "demo", Routes: web}, {App: "other", Routes: other}})
	if d.files[Dir+"/caddy.json"] != string(want) || !d.ran(reloadNext) {
		t.Errorf("want the other app's reload to keep demo on its new copy: %s", d.files[Dir+"/caddy.json"])
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
	body, _ := Config(Policy{}, []Fragment{{App: "demo", Routes: web}})
	d.files[Dir+"/caddy.json"] = string(body)
	reloaded, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
	if err != nil || reloaded || d.ran("docker exec") || d.files[Dir+"/routes/demo.json"] == "" {
		t.Errorf("want the fragment written and no reload: %v %v %v", reloaded, err, d.calls)
	}
}

// A lagging fragment that differs from the new routes only in what C2–C4 added — the path, the
// rewrite, a header — is still caught up: it is what the next run of any app assembles from.
func TestSetRoutesCatchesUpAFragmentThatDiffersOnlyInRouting(t *testing.T) {
	nosniff := &Headers{Response: map[string]string{"X-Content-Type-Options": "nosniff"}}
	stripped := []Route{{Host: "demo.example.com", Path: "/api", StripPath: true, Dial: "demo:3000", Headers: nosniff}}
	rewritten := []Route{{Host: "demo.example.com", Path: "/api", PathRewrite: "/img", Dial: "demo:3000",
		Headers: &Headers{Request: map[string]string{"Cookie": ""}, Response: map[string]string{"X-Content-Type-Options": "nosniff"}}}}
	for name, c := range map[string]struct{ routed, old []Route }{
		"path":    {stripped, []Route{{Host: "demo.example.com", Path: "/v1", StripPath: true, Dial: "demo:3000", Headers: nosniff}}},
		"strip":   {stripped, []Route{{Host: "demo.example.com", Path: "/api", Dial: "demo:3000", Headers: nosniff}}},
		"headers": {stripped, []Route{{Host: "demo.example.com", Path: "/api", StripPath: true, Dial: "demo:3000"}}},
		"rewrite": {rewritten, []Route{{Host: "demo.example.com", Path: "/api", PathRewrite: "/old", Dial: "demo:3000", Headers: rewritten[0].Headers}}},
		"request header value": {rewritten, []Route{{Host: "demo.example.com", Path: "/api", PathRewrite: "/img", Dial: "demo:3000",
			Headers: &Headers{Request: map[string]string{"Cookie": "x"}, Response: rewritten[0].Headers.Response}}}},
		"response header value": {rewritten, []Route{{Host: "demo.example.com", Path: "/api", PathRewrite: "/img", Dial: "demo:3000",
			Headers: &Headers{Request: rewritten[0].Headers.Request, Response: map[string]string{"X-Content-Type-Options": ""}}}}},
	} {
		d := newDisk()
		body, _ := Config(Policy{}, []Fragment{{App: "demo", Routes: c.routed}})
		d.files[Dir+"/caddy.json"] = string(body)
		frag, _ := json.MarshalIndent(Fragment{App: "demo", Routes: c.old}, "", "  ")
		d.files[Dir+"/routes/demo.json"] = string(frag) + "\n"
		if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", c.routed); err != nil {
			t.Fatal(err)
		}
		fs, _ := Fragments(context.Background(), d)
		if !reflect.DeepEqual(Of(fs, "demo"), c.routed) {
			t.Errorf("%s: want the fragment caught up, got %+v", name, Of(fs, "demo"))
		}
	}
}

// A config Caddy refuses: Caddy keeps serving the old one, the applied config does not claim the
// refused one, and the caller is told to put the routes back — after which no fragment claims it
// either, or every later run would assemble it again.
func TestSetRoutesRecordsNothingCaddyRefused(t *testing.T) {
	d := newDisk()
	old := []Route{{Host: "demo.example.com", Dial: "demo-old:3000", TLS: true}}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", old); err != nil {
		t.Fatal(err)
	}
	before := d.files[Dir+"/caddy.json"]
	d.fail[reloadNext] = errors.New("loading new config: open /certs/boks/x.crt: no such file")
	touched, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
	// A failed call is not known to be a refusal: the message names the reload and claims neither.
	if err == nil || !strings.Contains(err.Error(), "reloading the proxy with the routes of demo failed") ||
		!strings.Contains(err.Error(), "may have been lost") {
		t.Fatalf("want the failed reload, neither refusal nor success claimed, got %v", err)
	}
	// Whether Caddy acted is not known from a failed call, so the caller is told to put routes back.
	if !touched {
		t.Error("a failed reload may have gone through")
	}
	if d.files[Dir+"/caddy.json"] != before {
		t.Errorf("no applied config for a refused one: %v", d.files)
	}
	delete(d.fail, reloadNext)
	if err := RestoreRoutes(context.Background(), d, io.Discard, "demo", old); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.files[Dir+"/routes/demo.json"], "demo-old:3000") || d.files[Dir+"/caddy.json"] != before {
		t.Errorf("want the previous routes recorded again: %v", d.files)
	}
}

// Any failure once the fragment may have been written tells the caller to put the routes back: the
// fragment is what the next run of any app reloads with.
func TestSetRoutesReportsTouchedOnceTheFragmentMayBeWritten(t *testing.T) {
	for _, fail := range []string{"upload " + "sh -c umask 077 && mkdir -p '" + Dir + "/routes'", "upload sh -c umask 077 && mkdir -p '" + Dir + "' && cat > '" + Dir + "/caddy.next.json"} {
		d := newDisk()
		d.fail[fail] = errors.New("connection lost")
		touched, err := SetRoutes(context.Background(), d, io.Discard, "demo", web)
		if err == nil || !touched {
			t.Errorf("%s: want an error and touched, got %v %v", fail, touched, err)
		}
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
	want, _ := Config(Policy{}, []Fragment{{App: "other", Routes: other}})
	if _, ok := d.files[Dir+"/routes/demo.json"]; ok || d.files[Dir+"/caddy.json"] != string(want) {
		t.Errorf("want demo's routes gone and other's kept: %v", d.files)
	}
}

// After a failed reload the files still say what the proxy ran before, and may be wrong: putting
// the routes back reloads with them anyway, forced, and records them.
func TestRestoreRoutesReloadsEvenWhenNothingChanged(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	d.calls = nil
	if err := RestoreRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if !d.ran(reloadNext + " --force") {
		t.Errorf("want a forced reload: %v", d.calls)
	}
	want, _ := Config(Policy{}, []Fragment{{App: "demo", Routes: web}})
	if d.files[Dir+"/caddy.json"] != string(want) || d.files[Dir+"/caddy.next.json"] != "" {
		t.Errorf("want the restored config applied: %v", d.files)
	}
}

// A put-back whose reload fails leaves the fragment naming the copy that is kept — the one the routes
// were moved to — not the copies they were to go back to, which may be stopped until revived: the next
// run of any app reloads with the fragment.
func TestRestoreRoutesThatFailsLeavesTheFragmentOnTheKeptCopy(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	d.fail[reloadNext] = errors.New("connection lost")
	old := []Route{{Host: "demo.example.com", Dial: "demo-old:3000", TLS: true}}
	if err := RestoreRoutes(context.Background(), d, io.Discard, "demo", old); err == nil {
		t.Fatal("want the failure")
	}
	if !strings.Contains(d.files[Dir+"/routes/demo.json"], "demo:3000") {
		t.Errorf("want the fragment still on the kept copy: %s", d.files[Dir+"/routes/demo.json"])
	}
	// A put-back that succeeds records the routes it put back, after the reload.
	delete(d.fail, reloadNext)
	d.calls = nil
	if err := RestoreRoutes(context.Background(), d, io.Discard, "demo", old); err != nil {
		t.Fatal(err)
	}
	if reload, frag := index(d.calls, reloadNext), index(d.calls, "upload "+Dir+"/routes/demo.json"); reload < 0 || frag < reload {
		t.Errorf("want the reload, then the fragment: %v", d.calls)
	}
}

// A wildcard goes after every exact host, whatever their spelling sorts to: Caddy takes the first route
// that matches, and kamal-proxy served an exact host before a wildcard that covers it.
func TestConfigPutsAWildcardAfterTheExactHosts(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "*.example.com", Dial: "a:80"}}},
		{App: "b", Routes: []Route{{Host: "api.example.com", Dial: "b:80"}, {Host: "zz.example.com", Dial: "b:81"}}}})
	if err != nil {
		t.Fatal(err)
	}
	routes, _ := dig(decoded(t, b), "apps", "http", "servers", "http", "routes").([]any)
	var hosts []any
	for _, rt := range routes {
		if dig(rt, "match") == nil {
			continue // the 404 for any other host
		}
		hosts = append(hosts, dig(rt, "match").([]any)[0].(map[string]any)["host"].([]any)[0])
	}
	if len(hosts) != 3 || hosts[0] != "api.example.com" || hosts[1] != "zz.example.com" || hosts[2] != "*.example.com" {
		t.Errorf("want the exact hosts first, then the wildcard: %v", hosts)
	}
}

// An exact host with TLS covered by a wildcard without TLS lives on the other server, and on :80 Caddy
// redirects only after its own routes: the wildcard leaves out the hosts with TLS it covers, so their
// plain HTTP gets Caddy's redirect, as kamal-proxy redirected it. Hosts it does not cover, a wildcard
// with TLS, and a host two labels deeper stay out of it.
func TestConfigWildcardWithoutTLSLeavesTheTLSHostsItCovers(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "*.example.com", Dial: "a:80"}}},
		{App: "b", Routes: []Route{{Host: "API.example.com", Dial: "b:80", TLS: true}, {Host: "b.example.com", Dial: "b:81", TLS: true},
			{Host: "plain.example.com", Dial: "b:82"}, {Host: "x.y.example.com", Dial: "b:83", TLS: true},
			{Host: "other.org", Dial: "b:84", TLS: true}, {Host: "*.tls.example.com", Dial: "b:85", TLS: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	routes, _ := dig(decoded(t, b), "apps", "http", "servers", "http", "routes").([]any)
	last := matchFor(routes, "*.example.com")
	not, _ := last["not"].([]any)
	if last == nil || len(not) != 1 {
		t.Fatalf("want the wildcard with one negated set: %v", routes)
	}
	got := fmt.Sprint(not[0].(map[string]any)["host"])
	if got != "[API.example.com b.example.com]" {
		t.Errorf("want only the exact TLS hosts it covers left out, got %s", got)
	}
	// No TLS host under it: the match is the host alone, the bytes as before.
	c, _ := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "*.example.com", Dial: "a:80"}}}})
	if strings.Contains(string(c), `"not"`) {
		t.Errorf("no negation without a TLS host to leave out:\n%s", c)
	}
}

// Validate asks Caddy about the config with the app's routes, and changes nothing: no fragment, no
// applied config, and the file it asked about is gone.
func TestValidateChangesNothing(t *testing.T) {
	d := newDisk()
	if err := Validate(context.Background(), d, "demo", web); err != nil {
		t.Fatal(err)
	}
	if !d.ran("docker exec boks-proxy caddy validate --config /etc/boks/caddy.check.json") || len(d.files) != 0 {
		t.Errorf("want a validate and no file left: %v %v", d.calls, d.files)
	}
	d.fail["docker exec boks-proxy caddy validate"] = errors.New("loading config: tls: failed to find any PEM data in key input")
	if err := Validate(context.Background(), d, "demo", web); err == nil || !strings.Contains(err.Error(), "would refuse") || len(d.files) != 0 {
		t.Errorf("want the refusal named and no file left: %v %v", err, d.files)
	}
}

// The other way round: a wildcard with TLS leaves out the exact hosts without TLS it covers, so HTTPS
// for one of them does not reach the wildcard's app — kamal-proxy gave the exact host to its own app.
func TestConfigWildcardWithTLSLeavesThePlainHostsItCovers(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "*.example.com", Dial: "a:443", TLS: true,
		Cert: &CertFiles{Certificate: "/certs/boks/_.example.com.crt", Key: "/certs/boks/_.example.com.key"}}}},
		{App: "b", Routes: []Route{{Host: "api.example.com", Dial: "b:80"}, {Host: "secure.example.com", Dial: "b:81", TLS: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	routes, _ := dig(decoded(t, b), "apps", "http", "servers", "https", "routes").([]any)
	last := matchFor(routes, "*.example.com")
	not, _ := last["not"].([]any)
	if last == nil || len(not) != 1 || fmt.Sprint(not[0].(map[string]any)["host"]) != "[api.example.com]" {
		t.Errorf("want the TLS wildcard to leave out the plain exact host only: %v", last)
	}
}

// matchFor is the matcher set of the route for host among routes — not the last route: boks's own
// (the redirect, the 404 for any other host) come after the apps'.
func matchFor(routes []any, host string) map[string]any {
	for _, rt := range routes {
		if m, ok := dig(rt, "match").([]any); ok {
			if set := m[0].(map[string]any); set["host"] != nil && set["host"].([]any)[0] == host {
				return set
			}
		}
	}
	return nil
}

// peek is a disk that keeps what the config Validate asked about said when Caddy was asked.
type peek struct {
	*disk
	asked string
}

func (p *peek) Run(ctx context.Context, args ...string) (string, error) {
	if strings.HasPrefix(strings.Join(args, " "), "docker exec boks-proxy caddy validate") {
		p.asked = p.files[Dir+"/caddy.check.json"]
	}
	return p.disk.Run(ctx, args...)
}

// What Caddy is asked about is the config the reload would load: the app's new routes in place of its
// old ones, and every other app's routes, certificate files included.
func TestValidateAsksAboutTheConfigTheReloadWouldLoad(t *testing.T) {
	d := newDisk()
	certified := []Route{{Host: "w.example.com", Dial: "other:80", TLS: true, Cert: &CertFiles{Certificate: "/certs/boks/w.crt", Key: "/certs/boks/w.key"}}}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", certified); err != nil {
		t.Fatal(err)
	}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", []Route{{Host: "demo.example.com", Dial: "demo-old:3000", TLS: true}}); err != nil {
		t.Fatal(err)
	}
	p := &peek{disk: d}
	if err := Validate(context.Background(), p, "demo", web); err != nil {
		t.Fatal(err)
	}
	want, err := Config(Policy{}, []Fragment{{App: "demo", Routes: web}, {App: "other", Routes: certified}})
	if err != nil {
		t.Fatal(err)
	}
	if p.asked != string(want) {
		t.Errorf("Caddy was asked about\n%s\nwant\n%s", p.asked, want)
	}
}

// A host another app holds is refused before anything changes.
func TestCheckHostsRefusesAnotherAppsHost(t *testing.T) {
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "other", web); err != nil {
		t.Fatal(err)
	}
	fs, err := Fragments(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckHosts(fs, "demo", web); err == nil {
		t.Errorf("want a refusal, got %v", err)
	}
	if err := CheckHosts(fs, "other", web); err != nil {
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
	if !d.ran(reloadNext + " --force") {
		t.Errorf("want a forced reload: %v", d.calls)
	}
}

// A reload loads the config the fragments make, not caddy.json as it lies: a run cut after writing its
// fragment left caddy.json behind it, and loading that would send its routes back to the copy it left.
func TestReloadLoadsWhatTheFragmentsSay(t *testing.T) {
	d := newDisk()
	old := []Route{{Host: "demo.example.com", Dial: "demo-old:3000", TLS: true}}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", old); err != nil {
		t.Fatal(err)
	}
	d.fail["mv "+Dir+"/caddy.next.json"] = errors.New("connection lost")
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err == nil {
		t.Fatal("want the cut run's error")
	}
	delete(d.fail, "mv "+Dir+"/caddy.next.json")
	if err := Reload(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	want, _ := Config(Policy{}, []Fragment{{App: "demo", Routes: web}})
	if d.files[Dir+"/caddy.json"] != string(want) {
		t.Errorf("want the reload to load demo's new routes: %s", d.files[Dir+"/caddy.json"])
	}
}

// The container is labelled as Caddy, has the sysctl a lossless reload needs, keeps its ACME state and
// the certificate volume kamal-proxy used, reads the state directory, not one file, read-only, and
// keeps its request log rotated.
func TestCreateArgs(t *testing.T) {
	got := strings.Join(CreateArgs("caddy:2.11.7-alpine", "/home/u/.boks/_proxy", Shape{}), " ")
	want := "docker create --name boks-proxy --restart unless-stopped --label boks.proxy=caddy " +
		"--log-driver json-file --log-opt max-size=10m --log-opt max-file=5 " +
		"--sysctl net.ipv4.tcp_migrate_req=1 --network boks -p 80:80 -p 443:443 " +
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

// Caddy takes the first route that matches: exact hosts come before wildcards, on one host the longer
// path before the shorter and the bare host last, and whatever no route names gets 404 — which is
// what kamal-proxy answered and not Caddy's own empty 200.
func TestConfigOrdersRoutesSoTheMostSpecificWins(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{
		{App: "site", Routes: []Route{{Host: "cars.example.com", Dial: "site:3000"}, {Host: "*.example.com", Dial: "site:3001"}}},
		{App: "gw", Routes: []Route{{Host: "cars.example.com", Path: "/api/cn/images", Dial: "gw:8080"}}},
		{App: "api", Routes: []Route{{Host: "api.example.com", Dial: "api:1"}, {Host: "cars.example.com", Path: "/api", Dial: "api:2"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range dig(decoded(t, b), "apps", "http", "servers", "http", "routes").([]any) {
		m, _ := json.Marshal(r.(map[string]any)["match"])
		got = append(got, string(m))
	}
	want := []string{
		`[{"host":["api.example.com"]}]`,
		`[{"host":["cars.example.com"],"path":["/api/cn/images","/api/cn/images/*"]}]`,
		`[{"host":["cars.example.com"],"path":["/api","/api/*"]}]`,
		`[{"host":["cars.example.com"]}]`,
		`[{"host":["*.example.com"]}]`,
		`null`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("routes in this order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Without a TLS host the last route on 80 is still the 404 for a host no route names.
	routes := dig(decoded(t, b), "apps", "http", "servers", "http", "routes").([]any)
	if last, _ := json.Marshal(routes[len(routes)-1]); string(last) != `{"handle":[{"handler":"static_response","status_code":404}],"terminal":true}` {
		t.Errorf("want the 404 last on a plain-only server: %s", last)
	}
	// Host and path are unique together, across apps.
	if _, err := Config(Policy{}, []Fragment{
		{App: "a", Routes: []Route{{Host: "h.example.com", Path: "/x", Dial: "a:1"}}},
		{App: "b", Routes: []Route{{Host: "H.example.com", Path: "/x", Dial: "b:1"}}},
	}); err == nil || !strings.Contains(err.Error(), "routed by both a and b") {
		t.Errorf("want a refusal of one host and path routed twice, got %v", err)
	}
	// Caddy matches paths without regard to case: the same path in capitals is the same route.
	if _, err := Config(Policy{}, []Fragment{
		{App: "a", Routes: []Route{{Host: "h.example.com", Path: "/img", Dial: "a:1"}}},
		{App: "b", Routes: []Route{{Host: "h.example.com", Path: "/Img", Dial: "b:1"}}},
	}); err == nil || !strings.Contains(err.Error(), "routed by both a and b") {
		t.Errorf("want a refusal of one path in two cases, got %v", err)
	}
	// A bare host in capitals still goes after a path of the same host; by spelling it would sort
	// first and take the path's requests.
	b, err = Config(Policy{}, []Fragment{
		{App: "a", Routes: []Route{{Host: "API.example.com", Dial: "a:1"}}},
		{App: "b", Routes: []Route{{Host: "api.example.com", Path: "/images", Dial: "b:1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(dig(decoded(t, b), "apps", "http", "servers", "http", "routes").([]any)[0].(map[string]any)["match"])
	if string(first) != `[{"host":["api.example.com"],"path":["/images","/images/*"]}]` {
		t.Errorf("want the path before the bare host whatever the case: %s", first)
	}
}

// Routes of one host from different apps share its TLS mode: a path without TLS on a TLS host would
// be served on 80 alone, and HTTPS for it would go to the host's other routes.
func TestConfigRefusesAHostWithAndWithoutTLS(t *testing.T) {
	for _, fs := range [][]Fragment{
		{{App: "a", Routes: []Route{{Host: "h.example.com", Dial: "a:1", TLS: true}}}, {App: "b", Routes: []Route{{Host: "h.example.com", Path: "/b", Dial: "b:1"}}}},
		{{App: "b", Routes: []Route{{Host: "h.example.com", Path: "/b", Dial: "b:1"}}}, {App: "a", Routes: []Route{{Host: "H.example.com", Dial: "a:1", TLS: true}}}},
	} {
		if _, err := Config(Policy{}, fs); err == nil || !strings.Contains(err.Error(), "with TLS by a and without it by b") {
			t.Errorf("want the mixed host refused, got %v", err)
		}
	}
}

// A route rewrites the path when it asks — strip the prefix, or put another in its place, measured on
// boks-lab to keep the query — and changes headers on the request and the response; "" removes one.
func TestConfigRewritesPathsAndHeaders(t *testing.T) {
	b, err := Config(Policy{}, []Fragment{{App: "gw", Routes: []Route{
		{Host: "cars.example.com", Path: "/api/cn/images", PathRewrite: "/img", Dial: "gw:8080",
			Headers: &Headers{Request: map[string]string{"Cookie": "", "X-Gateway": "images"}, Response: map[string]string{"Set-Cookie": "", "X-Content-Type-Options": "nosniff"}}},
		{Host: "cars.example.com", Path: "/old", StripPath: true, Dial: "gw:8081"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	routes := dig(decoded(t, b), "apps", "http", "servers", "http", "routes").([]any)
	handle := func(i int) string {
		h, _ := json.Marshal(routes[i].(map[string]any)["handle"])
		return string(h)
	}
	// A path that cleaning would change — a dot segment or an empty one, which escapes get past the
	// matcher's cleaning but not the strip's — is refused before any rewrite: stripping would miss
	// the prefix and the app would resolve the path outside the new one.
	unclean := `{"group":"path","handle":[{"handler":"static_response","status_code":400}],` +
		`"match":[{"vars_regexp":{"{http.request.uri.path}":{"pattern":"(^|/)\\.\\.?(/|$)|//|[\\x{130}\\x{212A}]"}}}],"terminal":false},`
	// The path itself is replaced whole; below it the prefix is stripped the way the matcher compares
	// (no case, no escapes) and the new one put in front.
	if h := handle(0); h != `[{"handler":"subroute","routes":[`+unclean+
		`{"group":"path","handle":[{"handler":"rewrite","uri":"/img"}],"match":[{"path":["/api/cn/images"]}],"terminal":false},`+
		`{"group":"path","handle":[{"handler":"rewrite","path_regexp":[{"find":"^/","replace":"/img/"}],"strip_path_prefix":"/api/cn/images"}],"terminal":false}]},`+
		// The response's changes in a headers handler applied as the response is written, so the 101 of
		// a WebSocket handshake gets them too; reverse_proxy's own skip it.
		`{"handler":"headers","response":{"deferred":true,"delete":["Set-Cookie"],"set":{"X-Content-Type-Options":["nosniff"]}}},`+
		`{"handler":"reverse_proxy","headers":{"request":{"delete":["Forwarded","Cookie"],"set":{"X-Gateway":["images"]}}},"stream_close_delay":"24h","transport":{"protocol":"http","response_header_timeout":"30s"},`+
		`"upstreams":[{"dial":"gw:8080"}]}]` {
		t.Errorf("unexpected rewrite and headers: %s", h)
	}
	if h := handle(1); h != `[{"handler":"subroute","routes":[`+unclean+`{"group":"path","handle":[{"handler":"rewrite","strip_path_prefix":"/old"}],"terminal":false}]},{"handler":"reverse_proxy","headers":{"request":{"delete":["Forwarded"]}},`+
		`"stream_close_delay":"24h","transport":{"protocol":"http","response_header_timeout":"30s"},"upstreams":[{"dial":"gw:8081"}]}]` {
		t.Errorf("unexpected strip: %s", h)
	}
	// `$` in the new prefix is a character of the path, not a regexp group.
	q, _ := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "h", Path: "/v1.0", PathRewrite: "/v$1", Dial: "a:1"}}}})
	if !strings.Contains(string(q), `"replace": "/v$$1/"`) || !strings.Contains(string(q), `"uri": "/v$1"`) {
		t.Errorf("want $ literal in the rewrite: %s", q)
	}
}

// A host routed on several paths, or spelled in two cases, is one host to Caddy, which refuses a host
// matcher that names one twice: the wildcard's exclusions, the redirect on 80 and the ACME skip list
// name it once.
func TestConfigNamesAHostOnceInAMatcher(t *testing.T) {
	cert := &CertFiles{Certificate: "/certs/boks/x.crt", Key: "/certs/boks/x.key"}
	b, err := Config(Policy{}, []Fragment{
		{App: "plain", Routes: []Route{{Host: "*.example.com", Dial: "p:1"}}},
		{App: "tls", Routes: []Route{
			{Host: "api.example.com", Path: "/one", Dial: "t:1", TLS: true, Cert: cert},
			{Host: "API.example.com", Path: "/two", Dial: "t:2", TLS: true, Cert: cert},
			{Host: "api.example.com", Dial: "t:3", TLS: true, Cert: cert},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	all, _ := json.Marshal(m)
	for _, want := range []string{
		`"not":[{"host":["api.example.com"]}]`, // the plain wildcard leaves the TLS host out, once
		`"skip_certificates":["api.example.com"]`,
	} {
		if !strings.Contains(string(all), want) {
			t.Errorf("want %s in %s", want, all)
		}
	}
	redir, _ := json.Marshal(dig(m, "apps", "http", "servers", "http", "routes").([]any)[1].(map[string]any)["match"])
	if string(redir) != `[{"host":["api.example.com"]}]` {
		t.Errorf("want the TLS host redirected, named once: %s", redir)
	}
}

// uncleanPath finds exactly what cleaning a decoded path would change.
func TestUncleanPathIsWhatCleaningChanges(t *testing.T) {
	re := regexp.MustCompile(uncleanPath)
	for p, unclean := range map[string]bool{
		"/api/images/x": false, "/api/images/": false, "/": false, "/a/.well-known/b": false, "/a/..b/c.": false,
		"/x/../api": true, "/./api": true, "/api/..": true, "/api/.": true, "//api/x": true, "/api//images": true, "/api/images//": true,
		"/\u212Aey/x": true, "/ap\u0130/x": true, "/фото/Ä.jpg": false,
	} {
		if re.MatchString(p) != unclean {
			t.Errorf("%s: unclean %v, want %v", p, !unclean, unclean)
		}
		if clean := path.Clean(p); !unclean && clean != strings.TrimSuffix(p, "/") && p != "/" {
			t.Errorf("%s is called clean, but cleaning makes it %s", p, clean)
		}
	}
}

// The matcher lowercases the whole decoded path the way Go does; the strip folds ASCII byte by byte.
// They disagree exactly on the characters that lowercase into ASCII, and uncleanPath refuses them all.
func TestUncleanPathFoldsLikeTheMatcher(t *testing.T) {
	re := regexp.MustCompile(uncleanPath)
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if l := strings.ToLower(string(r)); l != string(r) && strings.IndexFunc(l, func(c rune) bool { return c < 0x80 }) >= 0 && !re.MatchString("/"+string(r)) {
			t.Errorf("%U lowercases to %q, which the strip would not fold, and is let through", r, l)
		}
	}
}

// A fragment file opens with its format, which the boks of C1 cannot read as routes and stops at —
// rather than reload the proxy without the paths and header rules it does not know. Files written
// before the format are read as they are; a newer format is refused.
func TestFragmentsCarryTheirFormat(t *testing.T) {
	d := newDisk()
	routed := []Route{{Host: "demo.example.com", Path: "/api", PathRewrite: "/img", Dial: "demo:3000"}}
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", routed); err != nil {
		t.Fatal(err)
	}
	written := d.files[Dir+"/routes/demo.json"]
	if !strings.HasPrefix(written, fmt.Sprintf("%d\n{", FragmentFormat)) {
		t.Fatalf("want the format first: %q", written)
	}
	// What C1 does with it: decode the stream as fragments.
	type c1Fragment struct {
		App    string            `json:"app"`
		Routes []json.RawMessage `json:"routes"`
	}
	var f c1Fragment
	if err := json.NewDecoder(strings.NewReader(written)).Decode(&f); err == nil {
		t.Errorf("an older boks must stop at the format, read %+v", f)
	}
	d.files[Dir+"/routes/old.json"] = `{"app": "old", "routes": [{"host": "old.example.com", "dial": "old:1", "tls": false}]}` + "\n"
	fs, err := Fragments(context.Background(), d)
	if err != nil || len(fs) != 2 || fs[0].App != "demo" || !reflect.DeepEqual(fs[0].Routes, routed) || fs[1].App != "old" {
		t.Fatalf("want both fragments, with and without a format: %+v %v", fs, err)
	}
	d.files[Dir+"/routes/new.json"] = fmt.Sprintf("%d\n{\"app\": \"new\", \"routes\": []}\n", FragmentFormat+1)
	if _, err := Fragments(context.Background(), d); err == nil || !strings.Contains(err.Error(), "newer than this boks") {
		t.Errorf("want a newer format refused, got %v", err)
	}
}

// Apps routing one host in Unicode and in punycode are refused like apps routing one host twice:
// Caddy would give it to whichever route came first. Fragments written before boks compared this way
// are caught too — the check runs on every assembly.
func TestConfigRefusesOneHostInTwoSpellings(t *testing.T) {
	_, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "пример.рф", Dial: "a:1"}}},
		{App: "b", Routes: []Route{{Host: "xn--e1afmkfd.XN--P1AI", Dial: "b:1"}}}})
	if err == nil || !strings.Contains(err.Error(), "routed by both a and b") {
		t.Errorf("want the host refused, got %v", err)
	}
}

// Two spellings of one host are one host everywhere the config names hosts, not only in the duplicate
// check: its TLS mode, its place in the order, the hosts a wildcard leaves out, and each matcher, which
// Caddy refuses when it names one host twice.
func TestConfigTreatsTwoSpellingsAsOneHost(t *testing.T) {
	if _, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "XN--E1AFMKFD.xn--p1ai", Dial: "a:1", TLS: true}}},
		{App: "b", Routes: []Route{{Host: "пример.рф", Path: "/b", Dial: "b:1"}}}}); err == nil ||
		!strings.Contains(err.Error(), "with TLS by a and without it by b") {
		t.Errorf("want one host with and without TLS refused, got %v", err)
	}
	// By spelling the punycode bare host sorts first ('x' before Cyrillic) and would take the path's requests.
	b, err := Config(Policy{}, []Fragment{{App: "a", Routes: []Route{{Host: "xn--e1afmkfd.xn--p1ai", Dial: "a:1"}}},
		{App: "b", Routes: []Route{{Host: "пример.рф", Path: "/images", Dial: "b:1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(dig(decoded(t, b), "apps", "http", "servers", "http", "routes").([]any)[0].(map[string]any)["match"])
	if string(first) != `[{"host":["пример.рф"],"path":["/images","/images/*"]}]` {
		t.Errorf("want the path before the bare host whatever the spelling: %s", first)
	}
	cert := &CertFiles{Certificate: "/certs/boks/x.crt", Key: "/certs/boks/x.key"}
	b, err = Config(Policy{}, []Fragment{
		{App: "plain", Routes: []Route{{Host: "*.пример.рф", Dial: "p:1"}}},
		{App: "tls", Routes: []Route{
			{Host: "api.пример.рф", Path: "/one", Dial: "t:1", TLS: true, Cert: cert},
			{Host: "api.xn--e1afmkfd.xn--p1ai", Path: "/two", Dial: "t:2", TLS: true, Cert: cert},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	all, _ := json.Marshal(m)
	for _, want := range []string{
		`"not":[{"host":["api.пример.рф"]}]`, // the plain wildcard leaves the TLS host out, once
		`"skip_certificates":["api.пример.рф"]`,
	} {
		if !strings.Contains(string(all), want) {
			t.Errorf("want %s in %s", want, all)
		}
	}
	redir, _ := json.Marshal(dig(m, "apps", "http", "servers", "http", "routes").([]any)[1].(map[string]any)["match"])
	if string(redir) != `[{"host":["api.пример.рф"]}]` {
		t.Errorf("want the TLS host redirected, named once: %s", redir)
	}
}
