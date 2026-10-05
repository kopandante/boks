package proxy

// The proxy's config: assembled from a route fragment per app, applied by reload, and the
// container that runs it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/kopandante/boks/internal/remote"
)

const (
	// DataVolume is Caddy's /data: the ACME account and the certificates Caddy obtained itself. Losing
	// it means issuing them all again, against Let's Encrypt's rate limits.
	DataVolume = "boks-proxy-data"
	// Kind is the boks.proxy label of the Caddy container. A boks-proxy without it is the kamal-proxy
	// an earlier boks ran.
	Kind = "caddy"

	// Dir holds the proxy's state on the server: a routes fragment per app and the config assembled
	// from them. Not `.boks/proxy`: that is where the releases of an app named proxy would live, and
	// the directory is mounted into the proxy — an underscore keeps it out of every app's namespace.
	Dir = ".boks/_proxy"
	// mountDir is Dir as the proxy sees it. A directory, not the config file alone: a file bind mount
	// keeps the inode it was given, and an atomic write replaces the inode, so the proxy would go on
	// reading the old file.
	mountDir = "/etc/boks"

	// streamCloseDelay keeps WebSockets and other streams open when a reload unloads the config they
	// came through. Caddy closes them at once by default, and every deploy reloads the config of every
	// app: each deploy would cut the WebSockets of all the other apps on the server, which kamal-proxy,
	// changing one service at a time, never touched (measured, boks-lab2, 2.11.7: a reload that changed
	// only another host closed the stream at once, and with the delay kept it). The streams of the copy
	// a deploy replaces end anyway when it is retired after the drain.
	streamCloseDelay = "24h"
	// responseHeaderTimeout is kamal-proxy's response timeout (30s by default, its ResponseHeaderTimeout):
	// a copy that takes a request and sends no headers gets a 504 instead of holding it forever, which is
	// Caddy's default.
	responseHeaderTimeout = "30s"
)

// Route is one host the proxy serves for an app: requests for Host go to Dial, the `container:port`
// of the copy that serves it — a deploy moves the route by reloading with the new copy's. The json tags are load-bearing: the fragment on the
// server is the record of what the proxy serves.
type Route struct {
	Host string `json:"host"`
	// Path narrows the route to requests under a prefix — the path itself and anything below it; empty
	// is the whole host. Routes of one host, from one app or several, differ by path.
	Path string `json:"path,omitempty"`
	// StripPath removes Path before the request reaches the app; PathRewrite puts another prefix in
	// its place. At most one of them is set.
	StripPath   bool   `json:"strip_path,omitempty"`
	PathRewrite string `json:"path_rewrite,omitempty"`
	Dial        string `json:"dial"`
	TLS         bool   `json:"tls"`
	// Cert is the certificate file pair of a host under `cert:`; nil leaves a TLS host to Caddy's ACME.
	Cert *CertFiles `json:"cert,omitempty"`
	// Headers are set on the request to the app and the response to the visitor; "" removes one.
	Headers *Headers `json:"headers,omitempty"`
}

// Headers changes headers on the way to the app (Request) and back to the visitor (Response); an
// empty value removes the header.
type Headers struct {
	Request  map[string]string `json:"request,omitempty"`
	Response map[string]string `json:"response,omitempty"`
}

// CertFiles are the paths of a certificate and its key as the proxy sees them.
type CertFiles struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

// Fragment is one app's routes, kept on the server in a file of its own.
type Fragment struct {
	App    string  `json:"app"`
	Routes []Route `json:"routes"`
}

func fragmentPath(app string) string { return path.Join(Dir, "routes", app+".json") }

// appliedPath is the config the proxy runs: written only once Caddy has taken it, and loaded by a
// proxy that starts.
func appliedPath() string { return path.Join(Dir, "caddy.json") }

// nextPath is a config on its way in. Caddy reads it for the reload, and only once it has taken it
// does it become appliedPath: a config Caddy refused must not be what it loads on its next start.
func nextPath() string { return path.Join(Dir, "caddy.next.json") }

// Config assembles Caddy's JSON config from the fragments of every app, in a stable order so that the
// same routes always make the same bytes: comparing bytes is how a run tells whether the proxy has to
// be reloaded at all. A host claimed twice is refused: Caddy would send it to the first route and
// silently drop the second.
//
// Hosts with TLS go to a server on 443, where Caddy's automatic HTTPS obtains their certificates by
// HTTP-01 and redirects their plain HTTP; a host under `cert:` is served with its file instead and
// left out of ACME. Hosts without TLS go to a server on 80 alone, as kamal-proxy served them.
//
// There is no trusted_proxies: nothing trusted stands in front of boks, so Caddy sets X-Forwarded-For
// to the address of the connection and drops what the visitor sent (#48) — its default.
func Config(fragments []Fragment) ([]byte, error) {
	type entry struct {
		app string
		r   Route
	}
	var all []entry
	owner := map[string]string{}
	for _, f := range fragments {
		for _, r := range f.Routes {
			key := strings.ToLower(r.Host) + " " + r.Path
			if o, ok := owner[key]; ok {
				return nil, fmt.Errorf("host %s%s is routed by both %s and %s", r.Host, r.Path, o, f.App)
			}
			owner[key] = f.App
			all = append(all, entry{f.App, r})
		}
	}
	// Caddy takes the first route that matches, so the order is the routing rule: exact hosts before
	// wildcards (`*` sorts before letters, and `*.example.com` would otherwise take `api.example.com`
	// from the app that names it), and on one host the longer path before the shorter, the bare host
	// last. Host and path are unique together, so the order is total whatever order the fragments came in.
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i].r, all[j].r
		if wa, wb := strings.HasPrefix(a.Host, "*."), strings.HasPrefix(b.Host, "*."); wa != wb {
			return wb
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if len(a.Path) != len(b.Path) {
			return len(a.Path) > len(b.Path)
		}
		return a.Path < b.Path
	})

	// A wildcard and an exact host it covers can sit on different servers, one with TLS and one
	// without, where the exact host comes before the wildcard no more: the wildcard would take plain
	// HTTP for an exact host with TLS (Caddy redirects on :80 only after its own routes), or HTTPS for
	// an exact host without it. kamal-proxy gave an exact host to its own app in either case; so does
	// this, by keeping the exact hosts of the other mode out of the wildcard's match.
	exact := map[bool][]string{}
	for _, e := range all {
		if !strings.HasPrefix(e.r.Host, "*") {
			exact[e.r.TLS] = append(exact[e.r.TLS], e.r.Host)
		}
	}

	servers := map[string]*server{}
	var files []loadFile
	var skip []string
	for _, e := range all {
		name, listen := "http", ":80"
		if e.r.TLS {
			name, listen = "https", ":443"
		}
		s := servers[name]
		if s == nil {
			// Logs on: every request in `docker logs boks-proxy`, as kamal-proxy wrote them. Caddy logs none
			// by default.
			s = &server{Listen: []string{listen}, Logs: &struct{}{}}
			if e.r.TLS {
				// No HTTP/3: 443/udp is not published, and a client sent there by Alt-Svc would wait out
				// a timeout before falling back. kamal-proxy spoke HTTP/1.1 and HTTP/2 too.
				s.Protocols = []string{"h1", "h2"}
			}
			servers[name] = s
		}
		m := routeMatch(e.r)
		if suffix, ok := strings.CutPrefix(strings.ToLower(e.r.Host), "*"); ok {
			var covered []string
			for _, h := range exact[!e.r.TLS] {
				// Caddy's wildcard stands for one label.
				if label, ok := strings.CutSuffix(strings.ToLower(h), suffix); ok && label != "" && !strings.Contains(label, ".") {
					covered = append(covered, h)
				}
			}
			if len(covered) > 0 {
				m.Not = []match{{Host: covered}}
			}
		}
		s.Routes = append(s.Routes, caddyRoute{Match: []match{m}, Handle: routeHandle(e.r), Terminal: true})
		if e.r.TLS && e.r.Cert != nil && !slices.Contains(skip, e.r.Host) {
			// Left out of ACME by name rather than by Caddy noticing the loaded certificate covers it:
			// what Caddy counts as covered is its rule, and an attempt at HTTP-01 for a host behind a
			// wildcard is a failure in the log every few minutes, or a rate limit spent.
			skip = append(skip, e.r.Host)
			lf := loadFile{Certificate: e.r.Cert.Certificate, Key: e.r.Cert.Key}
			if !slices.Contains(files, lf) {
				files = append(files, lf)
			}
		}
	}
	// Plain HTTP for a TLS host is redirected to HTTPS, as kamal-proxy did, by boks's own route on 80
	// rather than Caddy's: Caddy inserts its redirects where its own rules put them — only while it
	// manages some certificate, or into a server of its own on 80 that knows nothing of the routes
	// before it — and a 404 or a filter ahead of them would change what they do. So Caddy's are off,
	// and 80 always exists beside 443: the TLS hosts' redirect, then the 404. ACME's HTTP-01
	// challenges are answered before any route (server.go, HandleHTTPChallenge).
	var tlsHosts []string
	for _, e := range all {
		if e.r.TLS && !slices.Contains(tlsHosts, e.r.Host) {
			tlsHosts = append(tlsHosts, e.r.Host)
		}
	}
	if len(tlsHosts) > 0 {
		s := servers["http"]
		if s == nil {
			s = &server{Listen: []string{":80"}}
			servers["http"] = s
		}
		s.Routes = append(s.Routes, caddyRoute{Match: []match{{Host: tlsHosts}}, Handle: []handler{{Handler: "static_response",
			StatusCode: 308, Headers: map[string][]string{"Location": {"https://{http.request.host}{http.request.uri}"}}}}, Terminal: true})
		https := servers["https"]
		if https.AutoHTTPS == nil {
			https.AutoHTTPS = &autoHTTPS{}
		}
		https.AutoHTTPS.DisableRedirects = true
	}
	if len(skip) > 0 {
		servers["https"].AutoHTTPS.SkipCertificates = skip
	}
	// A host no route names gets 404, as it did from kamal-proxy: Caddy alone answers it with an
	// empty 200, which reads as a working site that lost its content.
	for _, s := range servers {
		s.Routes = append(s.Routes, caddyRoute{Handle: []handler{{Handler: "static_response", StatusCode: 404}}, Terminal: true})
	}
	c := caddyConfig{Admin: admin{Listen: "localhost:2019"}, Apps: apps{HTTP: httpApp{Servers: servers}}}
	if len(files) > 0 {
		c.Apps.TLS = &tlsApp{Certificates: certificates{LoadFiles: files}}
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// The shape of Caddy's JSON config, as far as boks writes it.
type (
	caddyConfig struct {
		Admin admin `json:"admin"`
		Apps  apps  `json:"apps"`
	}
	admin struct {
		Listen string `json:"listen"`
		// Config.Persist is false: the file on the server is the config, and an autosaved copy in the
		// container would be a second one to disagree with it.
		Config struct {
			Persist bool `json:"persist"`
		} `json:"config"`
	}
	apps struct {
		HTTP httpApp `json:"http"`
		TLS  *tlsApp `json:"tls,omitempty"`
	}
	httpApp struct {
		Servers map[string]*server `json:"servers"`
	}
	server struct {
		Listen    []string     `json:"listen"`
		Routes    []caddyRoute `json:"routes"`
		Protocols []string     `json:"protocols,omitempty"`
		AutoHTTPS *autoHTTPS   `json:"automatic_https,omitempty"`
		Logs      *struct{}    `json:"logs,omitempty"`
	}
	autoHTTPS struct {
		SkipCertificates []string `json:"skip_certificates,omitempty"`
		DisableRedirects bool     `json:"disable_redirects,omitempty"`
	}
	caddyRoute struct {
		Match    []match   `json:"match,omitempty"`
		Handle   []handler `json:"handle"`
		Terminal bool      `json:"terminal"`
	}
	match struct {
		Host []string `json:"host,omitempty"`
		Path []string `json:"path,omitempty"`
		Not  []match  `json:"not,omitempty"`
	}
	handler struct {
		Handler string `json:"handler"`
		// reverse_proxy
		Upstreams        []upstream `json:"upstreams,omitempty"`
		StreamCloseDelay string     `json:"stream_close_delay,omitempty"`
		Transport        *transport `json:"transport,omitempty"`
		// Headers is *proxyHeaders for reverse_proxy and the response's headers for static_response:
		// Caddy names both "headers".
		Headers any `json:"headers,omitempty"`
		// rewrite
		StripPathPrefix string          `json:"strip_path_prefix,omitempty"`
		PathRegexp      []regexpReplace `json:"path_regexp,omitempty"`
		// static_response
		StatusCode int `json:"status_code,omitempty"`
	}
	proxyHeaders struct {
		Request  *headerOps `json:"request,omitempty"`
		Response *headerOps `json:"response,omitempty"`
	}
	headerOps struct {
		Set    map[string][]string `json:"set,omitempty"`
		Delete []string            `json:"delete,omitempty"`
	}
	transport struct {
		Protocol              string `json:"protocol"`
		ResponseHeaderTimeout string `json:"response_header_timeout,omitempty"`
	}
	regexpReplace struct {
		Find    string `json:"find"`
		Replace string `json:"replace"`
	}
	upstream struct {
		Dial string `json:"dial"`
	}
	tlsApp struct {
		Certificates certificates `json:"certificates"`
	}
	certificates struct {
		LoadFiles []loadFile `json:"load_files"`
	}
	loadFile struct {
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
	}
)

// routeMatch is the host and, for a route under a path, the path itself and everything below it —
// not every path that merely starts with the same letters (`/img` must not take `/images`).
func routeMatch(r Route) match {
	m := match{Host: []string{r.Host}}
	if r.Path != "" {
		m.Path = []string{r.Path, r.Path + "/*"}
	}
	return m
}

// routeHandle rewrites the path if the route asks, then proxies with its header changes.
func routeHandle(r Route) []handler {
	var hs []handler
	switch {
	case r.StripPath:
		hs = append(hs, handler{Handler: "rewrite", StripPathPrefix: r.Path})
	case r.PathRewrite != "":
		hs = append(hs, handler{Handler: "rewrite", PathRegexp: []regexpReplace{{Find: "^" + regexp.QuoteMeta(r.Path), Replace: r.PathRewrite}}})
	}
	// RFC 7239 Forwarded is the visitor's to forge, and Caddy, unlike kamal-proxy, passes it on; the
	// port's own header changes come after.
	req, resp := &headerOps{}, (*headerOps)(nil)
	if r.Headers != nil {
		if o := ops(r.Headers.Request); o != nil {
			req = o
		}
		resp = ops(r.Headers.Response)
	}
	req.Delete = append([]string{"Forwarded"}, req.Delete...)
	rp := handler{Handler: "reverse_proxy", Upstreams: []upstream{{Dial: r.Dial}}, StreamCloseDelay: streamCloseDelay,
		Transport: &transport{Protocol: "http", ResponseHeaderTimeout: responseHeaderTimeout},
		Headers:   &proxyHeaders{Request: req, Response: resp}}
	return append(hs, rp)
}

// ops turns name→value into Caddy's set and delete lists, in a stable order: "" deletes.
func ops(h map[string]string) *headerOps {
	if len(h) == 0 {
		return nil
	}
	o := &headerOps{}
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if h[n] == "" {
			o.Delete = append(o.Delete, n)
			continue
		}
		if o.Set == nil {
			o.Set = map[string][]string{}
		}
		o.Set[n] = []string{h[n]}
	}
	return o
}

// Fragments reads the routes of every app from the server, sorted by app. A server without any has
// none, which is an answer; a failed read is an error, not an empty proxy.
func Fragments(ctx context.Context, r remote.Runner) ([]Fragment, error) {
	dir := remote.Quote(path.Join(Dir, "routes"))
	out, err := r.Run(ctx, "sh", "-c", "for f in "+dir+"/*.json; do [ -f \"$f\" ] && cat \"$f\"; done; true")
	if err != nil {
		return nil, fmt.Errorf("reading the proxy's routes: %w", err)
	}
	var fs []Fragment
	d := json.NewDecoder(strings.NewReader(out))
	for {
		var f Fragment
		if err := d.Decode(&f); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("reading the proxy's routes: %w", err)
		}
		fs = append(fs, f)
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].App < fs[j].App })
	return fs, nil
}

// CheckHosts refuses routes whose host another app's fragment already holds, before anything changes:
// found only when the config is assembled, it would stop a run whose new copy already serves.
func CheckHosts(fragments []Fragment, app string, routes []Route) error {
	_, err := Config(withRoutes(fragments, app, routes))
	return err
}

// Of is app's routes among fragments; none when it has no fragment.
func Of(fragments []Fragment, app string) []Route {
	for _, f := range fragments {
		if f.App == app {
			return f.Routes
		}
	}
	return nil
}

// withRoutes is fragments with app's routes set to routes; none removes the app's fragment.
func withRoutes(fragments []Fragment, app string, routes []Route) []Fragment {
	var out []Fragment
	for _, f := range fragments {
		if f.App != app {
			out = append(out, f)
		}
	}
	if len(routes) > 0 {
		out = append(out, Fragment{App: app, Routes: routes})
	}
	return out
}

// SetRoutes makes app's routes those given — none removes them — and reports whether the proxy may
// now run them, or will once it loads its files: true after a reload, and after any failure from the
// moment the fragment is written, since a failed call's answer can be lost after the server or Caddy
// acted (RestoreRoutes puts the previous routes back for certain). The proxy reloads only when the
// assembled config differs from the one it runs; the fragment alone is rewritten when only it lags.
//
// The fragment is written before the reload, and the applied config after it. A run cut anywhere in
// between leaves a fragment that the applied config does not match yet, and the next run of any app
// assembles the config again and reloads with it: the routes this run moved stay moved. Written after
// the reload, a fragment cut off by the run would match the applied config it never replaced, and the
// next run of another app would quietly reload this app's routes back onto the copies it left — a
// stopped one, in stop-first. A config Caddy refuses leaves the fragment until the caller puts the
// routes back, which it does for any failure here.
//
// The caller holds the server's admission lock: the config is every app's, and two runs assembling it
// at once would each apply a config without the other's change.
//
// A proxy that is not running is not reloaded: the files are what it loads when it starts.
func SetRoutes(ctx context.Context, r remote.Runner, log io.Writer, app string, routes []Route) (bool, error) {
	return setRoutes(ctx, r, log, app, routes, false)
}

// RestoreRoutes is SetRoutes for a run whose reload failed, which does not tell whether Caddy took the
// config: the answer can be lost after Caddy acted. So it reloads even when the files say the proxy
// already runs these routes — they said so before the failed reload too.
func RestoreRoutes(ctx context.Context, r remote.Runner, log io.Writer, app string, routes []Route) error {
	_, err := setRoutes(ctx, r, log, app, routes, true)
	return err
}

func setRoutes(ctx context.Context, r remote.Runner, log io.Writer, app string, routes []Route, force bool) (bool, error) {
	fs, err := Fragments(ctx, r)
	if err != nil {
		return false, err
	}
	next := withRoutes(fs, app, routes)
	if _, err := Config(next); err != nil {
		return false, err
	}
	record := func() error {
		if !force && sameRoutes(Of(fs, app), routes) {
			return nil
		}
		var err error
		if len(routes) == 0 {
			_, err = r.Run(ctx, "rm", "-f", fragmentPath(app))
		} else {
			var frag []byte
			if frag, err = json.MarshalIndent(Fragment{App: app, Routes: routes}, "", "  "); err == nil {
				err = remote.UploadAtomic(ctx, r, append(frag, '\n'), fragmentPath(app))
			}
		}
		if err != nil {
			return fmt.Errorf("recording the routes of %s: %w", app, err)
		}
		return nil
	}
	// The fragment always names copies that are alive if the run is cut there. Moving the routes to a
	// new copy, the new copy is up and has passed its health check: the fragment goes first. Putting
	// them back, the copies they go back to may be stopped until the caller revives them, while the
	// copy they leave stays until the caller removes it once this returns: the fragment goes last, so a
	// put-back that fails leaves it naming the copy that is kept.
	if !force {
		if err := record(); err != nil {
			// The write may have gone through with its answer lost: the routes are put back either way.
			return true, err
		}
	}
	reloaded, err := converge(ctx, r, log, next, force, "the routes of "+app)
	if err != nil {
		return true, err
	}
	if force {
		if err := record(); err != nil {
			return true, err
		}
	}
	return reloaded, nil
}

// Validate asks the proxy whether it would take the config with app's routes set to routes, changing
// nothing: Caddy loads every certificate file a config names, so a file another run left broken fails
// here rather than in the reload. A stop-first deploy asks before it stops anything — after the stop,
// a refused reload would leave its app with no copy running. The caller holds the server's admission
// lock, so the fragments do not change between this and the reload.
func Validate(ctx context.Context, r remote.Runner, app string, routes []Route) error {
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	body, err := Config(withRoutes(fs, app, routes))
	if err != nil {
		return err
	}
	if err := remote.UploadAtomic(ctx, r, body, checkPath()); err != nil {
		return err
	}
	out, err := r.Run(ctx, "docker", "exec", Container, "caddy", "validate", "--config", inProxy(checkPath()))
	_, _ = r.Run(context.WithoutCancel(ctx), "rm", "-f", checkPath())
	if err != nil {
		return fmt.Errorf("the proxy would refuse the routes of %s: %w %s", app, err, strings.TrimSpace(out))
	}
	return nil
}

// checkPath is a config Validate asks about; nothing loads it.
func checkPath() string { return path.Join(Dir, "caddy.check.json") }

// Lags says whether an applied config is there and differs from the one the fragments fs assemble:
// a run was cut after writing its fragment, and the proxy has not caught up.
func Lags(ctx context.Context, r remote.Runner, fs []Fragment) (bool, error) {
	body, err := Config(fs)
	if err != nil {
		return false, err
	}
	applied, present, err := readFile(ctx, r, appliedPath())
	return present && applied != string(body), err
}

// converge makes the proxy run the config the fragments fs assemble, and records it as applied: a
// reload when the applied config differs (or force, for a reload whose answer was lost), and for a
// proxy that is not running, the applied config alone — what it loads when it starts. Every way
// boks makes the proxy load a config goes through here, so none of them loads caddy.json as it lies:
// a run cut after writing its fragment leaves caddy.json behind the fragments, and loading it would
// send that run's routes back to the copies it left. The caller holds the server's admission lock.
func converge(ctx context.Context, r remote.Runner, log io.Writer, fs []Fragment, force bool, what string) (bool, error) {
	body, err := Config(fs)
	if err != nil {
		return false, err
	}
	applied, present, err := readFile(ctx, r, appliedPath())
	if err != nil {
		return false, err
	}
	if present && applied == string(body) && !force {
		return false, nil
	}
	running, err := caddyRunning(ctx, r)
	if err != nil {
		return false, err
	}
	if !running {
		if err := remote.UploadAtomic(ctx, r, body, appliedPath()); err != nil {
			return false, fmt.Errorf("recording the proxy's config: %w", err)
		}
		return false, nil
	}
	if err := remote.UploadAtomic(ctx, r, body, nextPath()); err != nil {
		return false, err
	}
	fmt.Fprintf(log, "proxy: reloading with %s\n", what)
	reloadArgs := []string{"docker", "exec", Container, "caddy", "reload", "--config", inProxy(nextPath())}
	if force {
		// Unchanged in Caddy's eyes when a lost reload did go through, or when only the files behind
		// its certificate paths are new; without --force it would do nothing.
		reloadArgs = append(reloadArgs, "--force")
	}
	if _, err := r.Run(ctx, reloadArgs...); err != nil {
		// Caddy checks a config before it lets go of the running one, so a refused reload leaves the
		// proxy serving what it served. A failed call is not a refusal, though: its answer can be lost
		// after Caddy took the config, so the message claims neither.
		return false, fmt.Errorf("reloading the proxy with %s failed: if Caddy refused the config it still runs the one it had, "+
			"but the answer may have been lost after it took the new one: %w", what, err)
	}
	if _, err := r.Run(ctx, "mv", nextPath(), appliedPath()); err != nil {
		return true, fmt.Errorf("recording the proxy's config: %w", err)
	}
	return true, nil
}

// sameRoutes compares two route lists field by field; nil and empty are the same: no routes. Every
// field counts: a fragment that differs only in a path or a header would otherwise stay behind the
// applied config, and the next run of any app would assemble the old routes from it.
func sameRoutes(a, b []Route) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// Reload makes the proxy load its config again although it has not changed — what a certificate
// renewal needs: the paths stay, the files behind them are new, and Caddy reads them only when it
// loads a config. Forced: without --force Caddy sees an unchanged config and does nothing. The caller
// holds the server's admission lock.
func Reload(ctx context.Context, r remote.Runner) error {
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	_, err = converge(ctx, r, io.Discard, fs, true, "the certificate files")
	return err
}

// inProxy is a file of Dir as the proxy sees it.
func inProxy(p string) string { return path.Join(mountDir, strings.TrimPrefix(p, Dir+"/")) }

// readFile reads a file of the proxy's state on the server and says whether it is there. Only the
// server's answer that it is not counts as absence; a failed call is an error.
func readFile(ctx context.Context, r remote.Runner, p string) (string, bool, error) {
	q := remote.Quote(p)
	out, err := r.Run(ctx, "sh", "-c", "if [ -f "+q+" ]; then echo present; cat "+q+"; else echo absent; fi")
	if err != nil {
		return "", false, fmt.Errorf("reading %s: %w", p, err)
	}
	mark, body, _ := strings.Cut(out, "\n")
	if mark != "present" {
		return "", false, nil
	}
	// The runner trims what a command prints, and every file boks writes here ends in one newline.
	return body + "\n", true, nil
}

// caddyRunning says whether the proxy container is running and is the Caddy boks runs.
func caddyRunning(ctx context.Context, r remote.Runner) (bool, error) {
	state, kind, err := State(ctx, r)
	return state == "running" && kind == Kind, err
}

// CreateArgs create the Caddy proxy container, not started, with the state directory at abs — an
// absolute path, since docker takes nothing else as a bind source. Caddy loads the applied config
// when it starts; the certificate volume is the one kamal-proxy used, so files installed for it are
// where Caddy looks. The sysctl is per network namespace, so it is the container's own. Caddy logs
// every request, and Docker rotates no log by default: the proxy's log is capped at 5 × 10 MB, with
// the driver named so the caps apply whatever the daemon's default driver is.
func CreateArgs(image, abs string) []string {
	return []string{"docker", "create", "--name", Container, "--restart", "unless-stopped", "--label", "boks.proxy=" + Kind,
		"--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=5",
		"--sysctl", migrateReq + "=1", "--network", Network, "-p", "80:80", "-p", "443:443",
		"-v", DataVolume + ":/data", "-v", CertsVolume + ":/certs", "-v", abs + ":" + mountDir + ":ro",
		image, "caddy", "run", "--config", inProxy(appliedPath())}
}
