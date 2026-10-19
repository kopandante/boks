// Package gate is the Caddy handler behind a server's `gate:` policy: the sites' API token checked by
// the proxy rather than by each site's request-gate. One handler is one group — one app's hosts, which
// boks names in the route's matcher (internal/proxy, gateRoute) — with the site's secret, its exempt
// paths and its mode. In enforce it answers as request-gate 1.7.0 answers, with the same codes and
// bodies, so the sites' client (lib/security 2.5) refreshes and retries as it does now; in log it
// writes its verdict into the access log and lets everything through to the site, which still checks.
//
// The handler keeps no state: a reload or a restart of the proxy loses nothing.
package gate

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() { caddy.RegisterModule(Handler{}) }

const (
	cookieName  = "x-api-token"
	tokenHeader = "X-Api-Token"
	fpHeader    = "X-Fingerprint"
	minSecret   = 32
)

// Handler is http.handlers.boks_gate, one group of the policy.
type Handler struct {
	// Name and App name the group in the journal.
	Name string `json:"name"`
	App  string `json:"app,omitempty"`
	// Mode is log — the verdict in the access log, every request passed on — or enforce. off passes
	// everything without a word; boks writes no route for a group that is off.
	Mode string `json:"mode"`
	// Secrets are the site's API_SECRET_CURRENT and, while one is rotated out, the previous one: a
	// token signed with either passes, the proxy signs with the first.
	Secrets []string `json:"secrets"`
	// SkipFP are path prefixes where the fingerprint is not compared: <img src="/api/encar/pics/…">
	// sends none (request-gate's skipFingerprintPrefixes).
	SkipFP []string `json:"skip_fp,omitempty"`
	// Exempt are the paths under /api/ the site lets through without a token, beside the defaults
	// every site has (defaultExempt): request-gate's exemptPaths, exemptPrefixes and exemptPatterns.
	Exempt []Exempt `json:"exempt,omitempty"`
	// Gated are path prefixes kept under the gate though an exemption covers them — the site's
	// gatedPrefixes: /api/admin/revalidate of autogroup and kiramax has no authorization of its own.
	Gated []string `json:"gated,omitempty"`
	// Bearer lets a partner's server read without the browser's token (glavdoroga).
	Bearer *Bearer `json:"bearer,omitempty"`

	exempt []exemptRule
	bearer *bearer
	logger *zap.Logger
	now    func() time.Time
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.boks_gate", New: func() caddy.Module { return new(Handler) }}
}

// Provision sets the logger and the clock.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.now == nil {
		h.now = time.Now
	}
	var err error
	if h.exempt, err = compileExempt(append(slices.Clone(defaultExempt), h.Exempt...)); err != nil {
		return fmt.Errorf("exempt: %w", err)
	}
	if h.Bearer != nil {
		if h.bearer, err = h.Bearer.compile(); err != nil {
			return fmt.Errorf("bearer: %w", err)
		}
	}
	return nil
}

// Validate refuses a group that would refuse every token or take any.
func (h *Handler) Validate() error {
	switch {
	case h.Name == "":
		return errors.New("name: required")
	case h.Mode != "off" && h.Mode != "log" && h.Mode != "enforce":
		return fmt.Errorf("mode %q must be off, log or enforce", h.Mode)
	case len(h.Secrets) == 0 || len(h.Secrets) > 2:
		return fmt.Errorf("secrets: %d of them; the current one, and the previous one while it is rotated out", len(h.Secrets))
	}
	for i, s := range h.Secrets {
		if len(s) < minSecret {
			return fmt.Errorf("secrets[%d]: shorter than %d characters, as the sites refuse it", i, minSecret)
		}
	}
	return nil
}

// refusal is a response of the gate: the code and the error request-gate answers with.
type refusal struct {
	status int
	error  string
}

var (
	accessDenied    = &refusal{http.StatusUnauthorized, "Access denied"}
	foreignOrigin   = &refusal{http.StatusForbidden, "Access denied"}
	forbidden       = &refusal{http.StatusForbidden, "Forbidden"}
	fpMismatch      = &refusal{http.StatusForbidden, "Fingerprint mismatch"}
	addressMismatch = &refusal{http.StatusForbidden, "Token address mismatch"}
	badPath         = &refusal{http.StatusBadRequest, "Bad request"}
)

// decision is the gate's verdict on a request: what the access log records, and the refusal when there is one.
type decision struct {
	verdict string // allow, deny
	reason  string
	refuse  *refusal
}

func allow(reason string) decision { return decision{verdict: "allow", reason: reason} }
func deny(reason string, r *refusal) decision {
	return decision{verdict: "deny", reason: reason, refuse: r}
}

// ServeHTTP decides, and in enforce answers a refused request itself.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.Mode == "off" {
		return next.ServeHTTP(w, r)
	}
	ip := clientIP(r)
	d := h.decide(r, ip)
	if h.Mode == "enforce" {
		switch {
		case d.refuse != nil:
			return refuse(w, d.refuse)
		case d.verdict == "issue":
			return h.issue(w, r, ip)
		}
		w = h.cookieWriter(w, r, ip)
	}
	return next.ServeHTTP(w, r)
}

// cookieWriter is w fixing the token's cookie of the response (cookie.go). Whether the proxy sets its
// own is decided by the request, before it goes on: a page without a valid token of this address, the
// fingerprint kept from the token it brings when the group's secret signed it.
func (h *Handler) cookieWriter(w http.ResponseWriter, r *http.Request, ip string) http.ResponseWriter {
	own, ownFP := false, ""
	if pageRequest(r, path.Clean(r.URL.Path)) {
		own = true
		if pl, reason := h.verify(requestToken(r), h.now()); reason == "" {
			own, ownFP = pl.ip != ip, pl.fp
		}
	}
	return &cookieWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		fix: func(hdr http.Header) { h.cookies(hdr, r, ip, own, ownFP) }}
}

// requestToken is the token a request brings: the cookie, or the header when the cookie is missing or
// empty, as request-gate reads it.
func requestToken(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return r.Header.Get(tokenHeader)
}

// decide is the API gate of request-gate.ts (apiGate), on the cleaned path, as Caddy's path matcher and
// the apps see it: the exemptions, the partner's Bearer, then the token from the cookie or the header,
// its signature and age, the fingerprint, the address. A token without the address is refused, where
// the site lets it through: the proxy never issues one, and the pages' tokens without it are what the
// gate closes.
func (h *Handler) decide(r *http.Request, ip string) decision {
	if unclean(r.URL) {
		return deny("unclean_path", badPath)
	}
	p := path.Clean(r.URL.Path)
	if !strings.HasPrefix(p, "/api/") {
		return decision{verdict: "page"}
	}
	// Before the gated prefixes, as request-gate answers the probe before its API gate.
	if p == healthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		return allow("health")
	}
	if h.exempted(p, r.Method) {
		if p == tokenPath && !sameOrigin(r) {
			return deny("foreign_origin", foreignOrigin)
		}
		if p == tokenPath && r.Method == http.MethodPost {
			return decision{verdict: "issue"}
		}
		return allow("exempt")
	}
	if h.bearer != nil && h.bearer.admits(r, p) {
		return allow("bearer")
	}
	tok := requestToken(r)
	if tok == "" {
		return deny("no_token", accessDenied)
	}
	pl, reason := h.verify(tok, h.now())
	if reason != "" {
		return deny(reason, accessDenied)
	}
	if pl.ip == "" {
		return deny("no_ip", accessDenied)
	}
	if !slices.ContainsFunc(h.SkipFP, func(s string) bool { return strings.HasPrefix(p, s) }) {
		if fp := r.Header.Get(fpHeader); fp != "" {
			// A token without the fingerprint passes a GET: the same GET without the header passes
			// anyway (request-gate 1.7.0), and the pages' tokens have none.
			if pl.fp != "" && pl.fp != fp {
				return deny("fp_mismatch", fpMismatch)
			}
			if pl.fp == "" && r.Method != http.MethodGet {
				return deny("fp_missing", fpMismatch)
			}
		} else if r.Method != http.MethodGet {
			return deny("no_fp_header", forbidden)
		}
	}
	if pl.ip != ip {
		return deny("ip_mismatch", addressMismatch)
	}
	return allow("token")
}

// refuse answers as NextResponse.json({error}, {status}) does.
func refuse(w http.ResponseWriter, f *refusal) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_, err := io.WriteString(w, `{"error":"`+f.error+`"}`)
	return err
}

// clientIP is the client's address as Caddy decided it — past the trusted proxies of the server, as
// its logs, its client_ip matcher and boks_ban see it — or the connection's when Caddy set none;
// "unknown", as the sites write it, when neither is an address.
func clientIP(r *http.Request) string {
	s, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if s == "" {
		s = r.RemoteAddr
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "unknown"
	}
	return a.WithZone("").Unmap().String()
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
