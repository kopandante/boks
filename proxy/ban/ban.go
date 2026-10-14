// Package ban is the Caddy handler behind a server's `ban:` policy: an address that sends more
// requests than one of the Rules allows within its window gets 403 from every host of the server for
// Duration, without a request reaching any app. boks puts it first on the servers on 80 and 443
// (internal/proxy, banRoute), so it counts what the whole server serves; xcaddy builds it into boks's proxy image (proxy/Dockerfile).
//
// The heuristics (heuristics.go) flag the requests no browser sends, and the fingerprint a cluster of
// addresses sends them with.
//
// The counts and the bans outlive the handler: boks reloads Caddy's config on every deploy of every
// app, and each reload provisions a new handler. They live in the package (shared), so a reload keeps
// them; a restart of the proxy's container loses them, which the policy accepts.
package ban

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() { caddy.RegisterModule(Handler{}) }

// DefaultMaxTracked bounds the addresses tracked at once: an address is some 100 bytes with the map's
// share, and 40 more for each rule that counted it. At the bound, with 16 rules each counting every
// address, that is some 155 MB measured on the heap (TestTheWorstCaseMemory, Go 1.27); with one rule,
// 30 MB, and with three 52 MB (append grows a counters slice by doubling) — the memory a flood of
// distinct addresses can take.
const DefaultMaxTracked = 200_000

// private are the ranges never counted: loopback, the private networks — boks's own WireGuard and app
// networks among them (10.240.1.1 sent 900 requests a minute on hb-sites) — CGNAT's shared space and
// IPv6's unique local and link-local addresses.
var private = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// assetDest are the Sec-Fetch-Dest values of the subresources a page pulls in: a visitor's one page
// is dozens of them, and they say nothing of a crawler walking pages. A client chooses what it claims,
// so the rules of class api and those on paths count their requests whatever they claim.
var assetDest = []string{"image", "video", "audio", "font", "style", "script"}

// maxRules bounds the rules of a handler: a request's rules are a bit each of a uint64.
const maxRules = 64

// Handler is http.handlers.boks_ban.
type Handler struct {
	// Rules count on their own; the first one an address goes past bans it.
	Rules []Rule `json:"rules,omitempty"`
	// Limit and Window are the handler of format 6: one rule, default, of class all. They go without
	// Rules, so a proxy of this image runs the config of an older boks as it ran.
	Limit  int            `json:"limit,omitempty"`
	Window caddy.Duration `json:"window,omitempty"`
	// Duration is how long a banned address gets 403.
	Duration caddy.Duration `json:"duration"`
	// MaxTracked bounds the addresses tracked at once, DefaultMaxTracked when not given.
	MaxTracked int `json:"max_tracked,omitempty"`
	// ExemptPaths are patterns on the request's path never counted, beside Next.js's /_next/.
	ExemptPaths []string `json:"exempt_paths,omitempty"`
	// ExemptRanges are CIDR ranges never counted, beside the private ones.
	ExemptRanges []string `json:"exempt_ranges,omitempty"`
	// Heuristics, when on, flag requests no browser sends and the clusters that send them.
	Heuristics *Heuristics `json:"heuristics,omitempty"`
	// MaxFingerprints bounds the heuristics' fingerprints tracked at once, DefaultMaxFingerprints when
	// not given.
	MaxFingerprints int `json:"max_fingerprints,omitempty"`

	rules  []rule
	paths  []*regexp.Regexp
	ranges []netip.Prefix
	store  *store
	logger *zap.Logger
}

// Rule counts the requests of an address it selects: those of Class and, when Paths are given, on a
// path one of them matches. The one past Limit within Window — fixed, from the first it counted —
// starts the ban.
type Rule struct {
	Name   string         `json:"name"`
	Limit  int            `json:"limit"`
	Window caddy.Duration `json:"window"`
	// Class is all — every request not left out — when not given; page, a GET outside /api/ that is
	// not Next.js's prefetch; api, a request under /api/.
	Class string `json:"class,omitempty"`
	// Paths are patterns on the cleaned path.
	Paths []string `json:"paths,omitempty"`
}

// rule is a Rule with its paths compiled.
type rule struct {
	name   string
	limit  int
	window time.Duration
	class  string
	paths  []*regexp.Regexp
}

// declared are the handler's rules as its config gives them: Rules, or Limit and Window as default.
func (h *Handler) declared() []Rule {
	if len(h.Rules) > 0 {
		return h.Rules
	}
	return []Rule{{Name: "default", Limit: h.Limit, Window: h.Window, Class: "all"}}
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.boks_ban", New: func() caddy.Module { return new(Handler) }}
}

// Provision compiles the rules and the exemptions and joins the shared store. It reads nothing of the
// store and changes nothing of it: a reload's rules reach the counts through the requests they count.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.MaxTracked == 0 {
		h.MaxTracked = DefaultMaxTracked
	}
	if h.MaxFingerprints == 0 {
		h.MaxFingerprints = DefaultMaxFingerprints
	}
	h.rules = nil
	for _, d := range h.declared() {
		r := rule{name: d.Name, limit: d.Limit, window: time.Duration(d.Window), class: d.Class}
		if r.class == "" {
			r.class = "all"
		}
		for _, p := range d.Paths {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("rules[%s]: paths: %q: %w", d.Name, p, err)
			}
			r.paths = append(r.paths, re)
		}
		h.rules = append(h.rules, r)
	}
	h.paths, h.ranges = nil, slices.Clone(private)
	for _, p := range h.ExemptPaths {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("exempt_paths: %q: %w", p, err)
		}
		h.paths = append(h.paths, re)
	}
	for _, s := range h.ExemptRanges {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("exempt_ranges: %w", err)
		}
		h.ranges = append(h.ranges, p.Masked())
	}
	if h.store == nil {
		h.store = shared
	}
	return nil
}

// Validate refuses a handler that would ban everyone or no one, and rules it could not tell apart.
func (h *Handler) Validate() error {
	switch {
	case len(h.Rules) > 0 && (h.Limit != 0 || h.Window != 0):
		return errors.New("limit and window go without rules")
	case len(h.Rules) > maxRules:
		return fmt.Errorf("rules: %d of them, more than %d", len(h.Rules), maxRules)
	case h.Duration <= 0:
		return fmt.Errorf("duration %s: must be positive", time.Duration(h.Duration))
	case h.MaxTracked < 1:
		return fmt.Errorf("max_tracked %d: must be at least 1", h.MaxTracked)
	case h.MaxFingerprints < 1:
		return fmt.Errorf("max_fingerprints %d: must be at least 1", h.MaxFingerprints)
	}
	if err := h.Heuristics.validate(); err != nil {
		return fmt.Errorf("heuristics: %w", err)
	}
	names := map[string]bool{}
	for _, r := range h.declared() {
		switch {
		case r.Name == "":
			return errors.New("rules: a rule without a name")
		case names[r.Name]:
			return fmt.Errorf("rules[%s]: the name is used twice", r.Name)
		case r.Limit < 1:
			return fmt.Errorf("rules[%s]: limit %d: must be at least 1", r.Name, r.Limit)
		case r.Window <= 0:
			return fmt.Errorf("rules[%s]: window %s: must be positive", r.Name, time.Duration(r.Window))
		case r.Class != "" && r.Class != "all" && r.Class != "page" && r.Class != "api":
			return fmt.Errorf("rules[%s]: class %q must be all, page or api", r.Name, r.Class)
		}
		names[r.Name] = true
	}
	return nil
}

// ServeHTTP answers 403 to a banned address and passes everything else on, counting what counts. A
// request no rule counts for what it asks for — /_next/, a subresource, an exempt path — is still
// refused to a banned address: the ban keeps the address from every app, its images and Next.js's
// image optimizer included. An address in an exempt range is neither counted nor refused, so adding
// a banned address's range to exempt_ranges lifts its ban with the next apply — and its fingerprint's
// too. With the heuristics on, a request with the strong sign goes to its fingerprint's cluster first,
// and in mode ban a banned fingerprint's flagged requests get 403 from any address. ACME's challenge
// never gets here: Caddy answers it before any route, and boks's ban route leaves it out by its matcher.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	addr, ok := clientAddr(r)
	if !ok || h.exemptAddr(addr) {
		return next.ServeHTTP(w, r)
	}
	if h.Heuristics.on() && forged(r.Header) && h.flag(r, addr) {
		return refuse(w, "Forbidden\n")
	}
	switch v := h.store.hit(addr, h.rules, h.counting(r), time.Duration(h.Duration), h.MaxTracked); v.outcome {
	case banned:
		return refuse(w, tooMany)
	case newlyBanned:
		h.logger.Warn("address banned", zap.String("ip", addr.String()), zap.String("host", r.Host),
			zap.String("rule", v.rule.name), zap.Int("count", v.count), zap.Stringer("window", v.rule.window),
			zap.String("until", v.until.UTC().Format(time.RFC3339)))
		return refuse(w, tooMany)
	case full:
		h.logger.Error("too many addresses tracked; new ones pass uncounted until old ones expire",
			zap.Int("max_tracked", h.MaxTracked))
	}
	return next.ServeHTTP(w, r)
}

// flag counts a flagged request toward its fingerprint's cluster, writes what the journal is to have
// of it, and says whether to refuse it.
func (h *Handler) flag(r *http.Request, addr netip.Addr) bool {
	fp := fingerprint(r)
	v := h.store.forged(addr, fp, h.Heuristics.cluster(), h.Heuristics.Mode, time.Duration(h.Duration), h.MaxFingerprints)
	ua := r.UserAgent()
	if len(ua) > uaSample {
		ua = ua[:uaSample]
	}
	if v.joined {
		h.logger.Info("forged request", zap.String("ip", addr.String()), zap.String("host", r.Host), zap.String("fingerprint", fp),
			zap.String("user_agent", ua), zap.String("path", r.URL.Path), zap.String("weak", strings.Join(weakSigns(r), ", ")))
	}
	if v.flagged {
		h.logger.Warn("cluster flagged", zap.String("fingerprint", fp), zap.Int("count", v.count),
			zap.Stringer("window", time.Duration(h.Heuristics.Cluster.Window)), zap.String("user_agent", ua), zap.String("mode", h.Heuristics.Mode))
	}
	if v.newlyBanned {
		h.logger.Warn("fingerprint banned", zap.String("fingerprint", fp), zap.String("until", v.until.UTC().Format(time.RFC3339)))
	}
	if v.full {
		h.logger.Error("too many fingerprints tracked; new ones pass unflagged until old ones expire",
			zap.Int("max_fingerprints", h.MaxFingerprints))
	}
	return v.refuse
}

const tooMany = "Forbidden: too many requests from this address\n"

func refuse(w http.ResponseWriter, body string) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, err := io.WriteString(w, body)
	return err
}

// clientAddr is the client's address as Caddy decided it — past the trusted proxies of the server,
// as its logs and client_ip matcher see it — or the connection's when Caddy set none.
func clientAddr(r *http.Request) (netip.Addr, bool) {
	s, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if s == "" {
		s = r.RemoteAddr
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// exemptAddr says whether an address is never counted: in a private or an exempt range.
func (h *Handler) exemptAddr(a netip.Addr) bool {
	for _, p := range h.ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// counting are the rules that count r, a bit each by their place. The path is judged cleaned, as
// Caddy's path matcher and the apps judge it: /_next/../en/encar/1 is the page it names, not a file
// of Next.js. Next.js's own files and the exempt paths no rule counts; a page's subresources by
// Sec-Fetch-Dest the rules of class all and page leave out — a page is dozens of them — while a rule
// of class api or on paths counts its endpoint whatever the request claims to be.
func (h *Handler) counting(r *http.Request) uint64 {
	p := path.Clean(r.URL.Path)
	if strings.HasPrefix(p, "/_next/") {
		return 0
	}
	for _, re := range h.paths {
		if re.MatchString(p) {
			return 0
		}
	}
	asset := slices.Contains(assetDest, strings.ToLower(r.Header.Get("Sec-Fetch-Dest")))
	api := p == "/api" || strings.HasPrefix(p, "/api/")
	page := r.Method == http.MethodGet && !api && r.Header.Get("Next-Router-Prefetch") == ""
	var bits uint64
	for i, ru := range h.rules {
		switch {
		case ru.class == "page" && !page, ru.class == "api" && !api:
			continue
		case len(ru.paths) > 0:
			if !slices.ContainsFunc(ru.paths, func(re *regexp.Regexp) bool { return re.MatchString(p) }) {
				continue
			}
		case asset && ru.class != "api":
			continue
		}
		bits |= 1 << i
	}
	return bits
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
