// Package gate is the Caddy handler behind a server's `gate:` policy: the sites' API token checked by
// the proxy rather than by each site's request-gate. One handler is one group — one app's hosts, which
// boks names in the route's matcher (internal/proxy, gateRoute) — with the site's secret, its exempt
// paths and its mode. In enforce it answers as request-gate 1.7.0 answers, with the same codes and
// bodies, so the sites' client (lib/security 2.5) refreshes and retries as it does now; in log it
// writes its verdict into the access log and lets everything through to the site, which still checks.
//
// The handler keeps no state but the addresses its signatures banned (signature.go): a reload loses
// nothing, a restart of the proxy those bans.
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
	// maxTokenTTL bounds a group's token_ttl: the token stays a proof of a visit from the address, not a key.
	maxTokenTTL = 24 * time.Hour
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
	// TokenTTL is how long a token of this group lives, for a site that checks no token itself and whose
	// page renews none — the proxy alone issues it (encarexport): three minutes unless set, from three
	// minutes to a day, only with site_gate off, as a site still checking would refuse a token past its
	// own three. Set, the proxy also renews the token on the responses of the visitor's requests — a page
	// or the API — once half of it is spent, so a visitor scrolling a catalog keeps a valid one.
	TokenTTL caddy.Duration `json:"token_ttl,omitempty"`
	// Checks are what the gate asks of a request beside its token — the fingerprint header, Fetch
	// Metadata, h2 from a browser — each off, log or enforce (checks.go).
	Checks *Checks `json:"checks,omitempty"`
	// Signatures are shapes of headers no browser sends, each off, log or enforce; SignatureBan, when
	// set, is how long an address an enforced one matched is refused by the group (signature.go).
	Signatures   []Signature    `json:"signatures,omitempty"`
	SignatureBan caddy.Duration `json:"signature_ban,omitempty"`
	// PageFirst, when on, refuses the API to an address that asked for no page of the group within its
	// window (pagefirst.go).
	PageFirst *PageFirst `json:"page_first,omitempty"`

	exempt       []exemptRule
	checksExempt []netip.Prefix
	bearer       *bearer
	bans         *banStore  // the tests' own; sharedBans when nil
	pages        *pageStore // the tests' own; sharedPages when nil
	logger       *zap.Logger
	now          func() time.Time
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
	if h.Checks != nil {
		if h.checksExempt, err = parseRanges(h.Checks.ExemptRanges); err != nil {
			return err
		}
	}
	for i := range h.Signatures {
		if err := h.Signatures[i].compile(); err != nil {
			return err
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
	case h.TokenTTL != 0 && (time.Duration(h.TokenTTL) < tokenTTL || time.Duration(h.TokenTTL) > maxTokenTTL):
		return fmt.Errorf("token_ttl %s must be from %s to %s", time.Duration(h.TokenTTL), tokenTTL, maxTokenTTL)
	case h.TokenTTL != 0 && h.SiteGate != "off":
		return errors.New("token_ttl goes with site_gate off: a site that checks the token itself refuses one past its three minutes")
	case len(h.Secrets) == 0 || len(h.Secrets) > 2:
		return fmt.Errorf("secrets: %d of them; the current one, and the previous one while it is rotated out", len(h.Secrets))
	}
	for i, s := range h.Secrets {
		if len(s) < minSecret {
			return fmt.Errorf("secrets[%d]: shorter than %d characters, as the sites refuse it", i, minSecret)
		}
	}
	if err := h.validateSignatures(); err != nil {
		return err
	}
	if h.PageFirst != nil {
		if err := h.PageFirst.validate(h.Mode); err != nil {
			return err
		}
	}
	if h.Checks != nil {
		return h.Checks.validate(h.Mode)
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
	shadow  string // the checks the request fails, comma-separated (checks.go)
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
	if d.shadow != "" {
		setField(r, zap.String("gate_shadow", d.shadow))
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
	if p := path.Clean(r.URL.Path); pageRequest(r, p) {
		pl, reason := h.verify(requestToken(r), h.now())
		own = reason != "" || pl.ip != ip || h.halfSpent(pl)
		reqFP = signedFP(pl, reason)
	} else if h.TokenTTL != 0 && strings.HasPrefix(p, "/api/") {
		// A request decide let through with a token: renewed once half spent, as nothing else renews it.
		if pl, reason := h.verify(requestToken(r), h.now()); reason == "" && pl.ip == ip && h.halfSpent(pl) {
			own, reqFP = true, pl.fp
		}
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

// ttl is how long the group's token lives.
func (h *Handler) ttl() time.Duration {
	if h.TokenTTL != 0 {
		return time.Duration(h.TokenTTL)
	}
	return tokenTTL
}

// halfSpent says whether a valid token of a group with its own lifetime is past half of it: the proxy
// renews it then. Never for a group without token_ttl — its sites renew their own.
func (h *Handler) halfSpent(pl payload) bool {
	return h.TokenTTL != 0 && float64(h.now().UnixMilli())-pl.iat > float64(h.ttl().Milliseconds())/2
}

// signedFP is the fingerprint of a token the group's secret signed, expired or not: a renewal keeps it.
func signedFP(pl payload, reason string) string {
	if reason == "" || reason == "expired" {
		return pl.fp
	}
	return ""
}

// requestToken is the token a request brings: the cookie, or the header when the cookie is missing or
// empty, as request-gate reads it. Of two cookies of the name the last counts, as Next.js's parser keeps
// it (Map.set per pair); r.Cookie would take the first.
func requestToken(r *http.Request) string {
	tok := ""
	for _, c := range r.CookiesNamed(cookieName) {
		tok = c.Value
	}
	if tok != "" {
		return tok
	}
	return r.Header.Get(tokenHeader)
}

// decide is the API gate of request-gate.ts (apiGate), on the cleaned path, as Caddy's path matcher and
// the apps see it. Past the path's own refusals, the signatures and their bans (signature.go) are asked of
// every request, pages, the probe and the exemptions too; then, on /api/, the exemptions, the partner's Bearer, then the token from the cookie or the header,
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
	if nextData(p) {
		return deny("next_data", badPath)
	}
	if d, ok := h.signed(r, ip); ok {
		return d
	}
	if !strings.HasPrefix(p, "/api/") {
		h.sawPage(r, p, ip)
		return decision{verdict: "page"}
	}
	// Before the gated prefixes, as request-gate answers the probe before its API gate.
	if p == healthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		return allow("health")
	}
	if d, ok := h.pageless(r, p, ip); ok {
		return d
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
	d, pl := h.decideToken(r, p, ip)
	failed := h.shadow(r, p, ip, pl)
	d.shadow = names(failed)
	if d.refuse == nil {
		for _, k := range failed {
			if k.mode(h.Checks) == "enforce" {
				return decision{verdict: "deny", reason: "check_" + k.name, refuse: k.refuse, shadow: d.shadow}
			}
		}
	}
	return d
}

// skipFP says whether the fingerprint is not compared on the cleaned path p.
func (h *Handler) skipFP(p string) bool {
	return slices.ContainsFunc(h.SkipFP, func(s string) bool { return strings.HasPrefix(p, s) })
}

// decideToken is decide's verdict on the token of a request to a gated path, and the token's payload
// when its signature and age pass, nil otherwise.
func (h *Handler) decideToken(r *http.Request, p, ip string) (decision, *payload) {
	tok := requestToken(r)
	if tok == "" {
		return deny("no_token", accessDenied), nil
	}
	pl, reason := h.verify(tok, h.now())
	if reason != "" {
		return deny(reason, accessDenied), nil
	}
	if pl.ip == "" {
		return deny("no_ip", accessDenied), &pl
	}
	if !h.skipFP(p) {
		if fp := r.Header.Get(fpHeader); fp != "" {
			// A token without the fingerprint passes a GET: the same GET without the header passes
			// anyway (request-gate 1.7.0), and the pages' tokens have none.
			if pl.fp != "" && pl.fp != fp {
				return deny("fp_mismatch", fpMismatch), &pl
			}
			if pl.fp == "" && r.Method != http.MethodGet {
				return deny("fp_missing", fpMismatch), &pl
			}
		} else if r.Method != http.MethodGet {
			return deny("no_fp_header", forbidden), &pl
		}
	}
	if pl.ip != ip {
		return deny("ip_mismatch", addressMismatch), &pl
	}
	return allow("token"), &pl
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
