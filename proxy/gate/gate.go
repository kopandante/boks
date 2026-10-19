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
	// SiteGate says whether the site still checks the token itself: on, the default, while it does —
	// a failure of this handler passes the request on to that check; off once the site no longer does
	// — a failure is 503, never a pass (owner's decision 2). off only in enforce.
	SiteGate string `json:"site_gate,omitempty"`
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
	// fault and cookieFault, when set, run where the handler decides and where it fixes a cookie: the
	// tests' way to make it fail.
	fault, cookieFault func()
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
	case h.SiteGate != "" && h.SiteGate != "on" && h.SiteGate != "off":
		return fmt.Errorf("site_gate %q must be on or off", h.SiteGate)
	case h.SiteGate == "off" && h.Mode != "enforce":
		return errors.New("site_gate off goes with mode enforce: with the site's own check gone, only the proxy's stands")
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
	unavailable     = &refusal{http.StatusServiceUnavailable, "Service unavailable"}
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

// ServeHTTP decides, writes the verdict into the access log, and in enforce answers a refused request
// and the token's issue itself and fixes the token's cookie of the app's response. In log and enforce
// the app gets X-Forwarded-For with the address Caddy decided alone: its getClientIp takes the first
// one, which a visitor behind a trusted proxy could otherwise write, and the token is bound to Caddy's.
// reverse_proxy adds a trusted peer's address after it, or replaces it with the connection's — the
// same address — when the peer is not trusted.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.Mode == "off" {
		return next.ServeHTTP(w, r)
	}
	ip := clientIP(r)
	if ip != "unknown" {
		r.Header.Set("X-Forwarded-For", ip)
	}
	var d decision
	if !h.guard(r, func() { d = h.decide(r, ip) }) {
		return h.failed(w, r, next)
	}
	h.record(r, d)
	if h.Mode != "enforce" {
		return next.ServeHTTP(w, r)
	}
	switch {
	case d.refuse != nil:
		return refuse(w, d.refuse)
	case d.verdict == "issue":
		var err error
		if !h.guard(r, func() { err = h.issue(w, r, ip) }) {
			return h.failed(w, r, next)
		}
		return err
	}
	cw := w
	if !h.guard(r, func() { cw = h.cookieWriter(w, r, ip) }) {
		return h.failed(w, r, next)
	}
	return next.ServeHTTP(cw, r)
}

// guard runs fn and says whether it returned: a panic is written to the journal and the access log,
// not left to Caddy's 500.
func (h *Handler) guard(r *http.Request, fn func()) (ok bool) {
	defer func() {
		if v := recover(); v != nil {
			h.logger.Error("gate failed", zap.String("group", h.Name), zap.String("host", r.Host),
				zap.String("path", r.URL.Path), zap.Any("panic", v), zap.String("site_gate", h.siteGate()))
			setField(r, zap.String("gate_verdict", "error"))
			ok = false
		}
	}()
	fn()
	return true
}

// failed answers a request the handler failed on: passed on to the site's own check while it has one,
// 503 once the proxy is the only gate.
func (h *Handler) failed(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.siteGate() == "off" {
		return refuse(w, unavailable)
	}
	return next.ServeHTTP(w, r)
}

func (h *Handler) siteGate() string {
	if h.SiteGate == "" {
		return "on"
	}
	return h.SiteGate
}

// record writes a verdict on /api/ into the access log's entry of the request: one entry then holds
// the proxy's verdict and the site's status, which is what log mode is read for.
func (h *Handler) record(r *http.Request, d decision) {
	if d.verdict == "page" {
		return
	}
	setField(r, zap.String("gate_group", h.Name))
	setField(r, zap.String("gate_mode", h.Mode))
	setField(r, zap.String("gate_verdict", d.verdict))
	if d.reason != "" {
		setField(r, zap.String("gate_reason", d.reason))
	}
}

func setField(r *http.Request, f zap.Field) {
	if extra, ok := r.Context().Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields); ok {
		extra.Set(f)
	}
}

// cookieWriter is w fixing the token's cookie of the response (cookie.go). Whether the proxy sets its
// own is decided by the request, before it goes on: a page without a valid token of this address, the
// fingerprint kept from the token it brings when the group's secret signed it.
func (h *Handler) cookieWriter(w http.ResponseWriter, r *http.Request, ip string) http.ResponseWriter {
	own, reqFP := false, ""
	if pageRequest(r, path.Clean(r.URL.Path)) {
		pl, reason := h.verify(requestToken(r), h.now())
		own = reason != "" || pl.ip != ip
		reqFP = signedFP(pl, reason)
	}
	return &cookieWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		fix: func(hdr http.Header) {
			// A failure leaves the headers as the site wrote them: the response is already under way.
			h.guard(r, func() {
				if h.cookieFault != nil {
					h.cookieFault()
				}
				h.cookies(hdr, r, ip, own, reqFP)
			})
		}}
}

// signedFP is the fingerprint of a token the group's secret signed, expired or not: a renewal keeps it.
func signedFP(pl payload, reason string) string {
	if reason == "" || reason == "expired" {
		return pl.fp
	}
	return ""
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
	if h.fault != nil {
		h.fault()
	}
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
