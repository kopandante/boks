package gate

// Which paths the gate checks: request-gate's exemptions, gated prefixes and probe, on the path as
// Caddy and the apps resolve it, and the paths the two resolve differently, which are refused.

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

const (
	tokenPath  = "/api/auth/token"
	healthPath = "/api/health"
)

// Exempt is one exemption: a path given exactly, a prefix, or a pattern on the cleaned path; for the
// Methods named, or for any when none are.
type Exempt struct {
	Exact   string   `json:"exact,omitempty"`
	Prefix  string   `json:"prefix,omitempty"`
	Regex   string   `json:"regex,omitempty"`
	Methods []string `json:"methods,omitempty"`
}

// defaultExempt are every site's: SECURITY_DEFAULTS.exemptPaths and UNSIGNED_API_PREFIXES — the token's
// own issue, the env check, and the routes with an authorization of their own.
var defaultExempt = []Exempt{
	{Exact: tokenPath},
	{Exact: "/api/env-check"},
	{Prefix: "/api/admin/"},
	{Prefix: "/api/auth/"},
}

type exemptRule struct {
	Exempt
	re *regexp.Regexp
}

func compileExempt(list []Exempt) ([]exemptRule, error) {
	var out []exemptRule
	for i, e := range list {
		n := 0
		for _, s := range []string{e.Exact, e.Prefix, e.Regex} {
			if s != "" {
				n++
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("[%d]: one of exact, prefix and regex", i)
		}
		r := exemptRule{Exempt: e}
		if e.Regex != "" {
			re, err := regexp.Compile(e.Regex)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			r.re = re
		} else if !strings.HasPrefix(e.Exact+e.Prefix, "/api/") {
			return nil, fmt.Errorf("[%d]: %q is not under /api/, where the gate checks", i, e.Exact+e.Prefix)
		}
		out = append(out, r)
	}
	return out, nil
}

// nextData is a Next.js data URL: /_next/data/<build id>/<route>.json, which Next.js serves as <route>
// before anything is dispatched — /_next/data/<id>/api/x.json runs the API route /api/x. The sites'
// middleware sees it under the route's own path.
var nextData = regexp.MustCompile(`^/_next/data/[^/]+(/.*)\.json$`)

// routePath is the path a request is judged on: cleaned, as Caddy's matchers and the apps resolve it,
// and a Next.js data URL as the route it names. Next.js denormalizes the page path as it reads one:
// /index is the root, and a leading /index/ goes, once — /_next/data/<id>/index/api/x.json runs /api/x.
func routePath(raw string) string {
	p := path.Clean(raw)
	if m := nextData.FindStringSubmatch(p); m != nil {
		p = path.Clean(m[1])
		switch {
		case p == "/index":
			p = "/"
		case strings.HasPrefix(p, "/index/"):
			p = strings.TrimPrefix(p, "/index")
		}
	}
	return p
}

// underPrefix is request-gate's prefix: the paths that start with it, and its root without the slash
// it ends in — /api/encar/ covers /api/encar too, not /api/encarx.
func underPrefix(p, prefix string) bool {
	return strings.HasPrefix(p, prefix) || p == strings.TrimSuffix(prefix, "/")
}

// exempted says whether a request on p goes without a token. A gated prefix wins over every exemption.
func (h *Handler) exempted(p, method string) bool {
	if slices.ContainsFunc(h.Gated, func(g string) bool { return underPrefix(p, g) }) {
		return false
	}
	for _, e := range h.exempt {
		if len(e.Methods) > 0 && !slices.Contains(e.Methods, method) {
			continue
		}
		switch {
		case e.Exact != "" && p == e.Exact,
			e.Prefix != "" && underPrefix(p, e.Prefix),
			e.re != nil && e.re.MatchString(p):
			return true
		}
	}
	return false
}

// unclean finds a path that Go and the app would resolve to different routes. Go decodes %2F and %5C
// into the path and keeps a backslash as a character, where the WHATWG URL of Next.js keeps the escapes
// as part of a segment and reads a backslash as a slash; and Go's path.Clean drops an empty segment
// before `..`, which WHATWG pops instead. With a dot segment in the path any of them moves where `..`
// lands — /p%2fq/../api/encar is /p/api/encar to Go and /api/encar to Next.js, /api/encar//../admin
// the other way round — so such a path is refused on any route, a page's included. Without one, a path
// that is under /api/ to either reading is refused too: the gate would judge a route the app never
// serves (/api/auth%2Ftoken is the token's issue to Go, nothing to Next.js), or miss one it does
// (/api\encar is /api/encar to Next.js). Browsers send none of these.
func unclean(u *url.URL) bool {
	esc := strings.ToLower(u.EscapedPath())
	backslash := strings.Contains(u.Path, `\`)
	if !backslash && !strings.Contains(u.Path, "//") && !strings.Contains(esc, "%2f") && !strings.Contains(esc, "%5c") {
		return false
	}
	slashed := strings.ReplaceAll(u.Path, `\`, "/")
	for _, seg := range strings.Split(slashed, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return strings.HasPrefix(routePath(slashed), "/api/") || strings.HasPrefix(routePath(u.Path), "/api/")
}

// sameOrigin is request-gate's check on the token's issue: the Origin, or the Referer without one,
// names the request's own host — else the token would go to another site's page.
func sameOrigin(r *http.Request) bool {
	source := r.Header.Get("Origin")
	if source == "" {
		source = r.Header.Get("Referer")
	}
	if r.Host == "" || source == "" {
		return false
	}
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return false
	}
	return originHost(u) == r.Host
}

// originHost is a URL's host as WHATWG writes it: lowercase, without the scheme's default port.
func originHost(u *url.URL) string {
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return host
	}
	return host + ":" + port
}
