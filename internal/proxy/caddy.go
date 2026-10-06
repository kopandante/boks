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
	Dial string `json:"dial"`
	TLS  bool   `json:"tls"`
	// Cert is the certificate file pair of a host under `cert:`; nil leaves a TLS host to Caddy's ACME.
	Cert *CertFiles `json:"cert,omitempty"`
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
			host := strings.ToLower(r.Host)
			if o, ok := owner[host]; ok {
				return nil, fmt.Errorf("host %s is routed by both %s and %s", r.Host, o, f.App)
			}
			owner[host] = f.App
			all = append(all, entry{f.App, r})
		}
	}
	// Hosts are unique, so ordering by host alone is total, whatever order the fragments came in. A
	// wildcard goes after every exact host: Caddy takes the first route that matches, and kamal-proxy
	// served an exact host before a wildcard that also covers it.
	sort.Slice(all, func(i, j int) bool {
		wi, wj := strings.HasPrefix(all[i].r.Host, "*"), strings.HasPrefix(all[j].r.Host, "*")
		if wi != wj {
			return wj
		}
		return all[i].r.Host < all[j].r.Host
	})

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
		s.Routes = append(s.Routes, caddyRoute{
			Match: []match{{Host: []string{e.r.Host}}},
			Handle: []handler{{Handler: "reverse_proxy", Upstreams: []upstream{{Dial: e.r.Dial}}, StreamCloseDelay: streamCloseDelay,
				Transport: &transport{Protocol: "http", ResponseHeaderTimeout: responseHeaderTimeout},
				// RFC 7239 Forwarded is the visitor's to forge, and Caddy, unlike kamal-proxy, passes it on.
				Headers: &proxyHeaders{Request: &headerOps{Delete: []string{"Forwarded"}}}}},
			Terminal: true,
		})
		if e.r.TLS && e.r.Cert != nil {
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
	if s := servers["https"]; s != nil && len(skip) > 0 {
		s.AutoHTTPS = &autoHTTPS{SkipCertificates: skip}
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
	}
	caddyRoute struct {
		Match    []match   `json:"match"`
		Handle   []handler `json:"handle"`
		Terminal bool      `json:"terminal"`
	}
	match struct {
		Host []string `json:"host"`
	}
	handler struct {
		Handler          string        `json:"handler"`
		Upstreams        []upstream    `json:"upstreams"`
		StreamCloseDelay string        `json:"stream_close_delay,omitempty"`
		Transport        *transport    `json:"transport,omitempty"`
		Headers          *proxyHeaders `json:"headers,omitempty"`
	}
	proxyHeaders struct {
		Request *headerOps `json:"request,omitempty"`
	}
	headerOps struct {
		Delete []string `json:"delete,omitempty"`
	}
	transport struct {
		Protocol              string `json:"protocol"`
		ResponseHeaderTimeout string `json:"response_header_timeout,omitempty"`
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
		// proxy serving what it served.
		return false, fmt.Errorf("the proxy refused the new routes and keeps the ones it had: %w", err)
	}
	if _, err := r.Run(ctx, "mv", nextPath(), appliedPath()); err != nil {
		return true, fmt.Errorf("recording the proxy's config: %w", err)
	}
	return true, nil
}

// sameRoutes compares two route lists; nil and empty are the same: no routes.
func sameRoutes(a, b []Route) bool {
	return slices.EqualFunc(a, b, func(x, y Route) bool {
		return x.Host == y.Host && x.Dial == y.Dial && x.TLS == y.TLS &&
			(x.Cert == nil) == (y.Cert == nil) && (x.Cert == nil || *x.Cert == *y.Cert)
	})
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
// where Caddy looks. The sysctl is per network namespace, so it is the container's own.
func CreateArgs(image, abs string) []string {
	return []string{"docker", "create", "--name", Container, "--restart", "unless-stopped", "--label", "boks.proxy=" + Kind,
		"--sysctl", migrateReq + "=1", "--network", Network, "-p", "80:80", "-p", "443:443",
		"-v", DataVolume + ":/data", "-v", CertsVolume + ":/certs", "-v", abs + ":" + mountDir + ":ro",
		image, "caddy", "run", "--config", inProxy(appliedPath())}
}
