// Package ban is the Caddy handler behind a server's `ban:` policy: an address that sends more than
// Limit requests within Window gets 403 from every host of the server for Duration, without a request
// reaching any app. boks puts it first on the servers on 80 and 443 (internal/proxy, banRoute), so it
// counts what the whole server serves; xcaddy builds it into boks's proxy image (proxy/Dockerfile).
//
// The counts and the bans outlive the handler: boks reloads Caddy's config on every deploy of every
// app, and each reload provisions a new handler. They live in the package (shared), so a reload keeps
// them; a restart of the proxy's container loses them, which the policy accepts.
package ban

import (
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

// DefaultMaxTracked bounds the addresses tracked at once: an entry is some 100 bytes with the map's
// share, so 200k is some 20 MB at most — the memory a flood of distinct addresses can take.
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
// is dozens of them, and they say nothing of a crawler walking pages.
var assetDest = []string{"image", "video", "audio", "font", "style", "script"}

// Handler is http.handlers.boks_ban.
type Handler struct {
	// Limit is the requests an address may send within Window; the one past it starts the ban.
	Limit int `json:"limit"`
	// Window is the fixed window the requests are counted in, from an address's first request.
	Window caddy.Duration `json:"window"`
	// Duration is how long a banned address gets 403.
	Duration caddy.Duration `json:"duration"`
	// MaxTracked bounds the addresses tracked at once, DefaultMaxTracked when not given.
	MaxTracked int `json:"max_tracked,omitempty"`
	// ExemptPaths are patterns on the request's path never counted, beside Next.js's /_next/.
	ExemptPaths []string `json:"exempt_paths,omitempty"`
	// ExemptRanges are CIDR ranges never counted, beside the private ones.
	ExemptRanges []string `json:"exempt_ranges,omitempty"`

	paths  []*regexp.Regexp
	ranges []netip.Prefix
	store  *store
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.boks_ban", New: func() caddy.Module { return new(Handler) }}
}

// Provision compiles the exemptions and joins the shared store.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.MaxTracked == 0 {
		h.MaxTracked = DefaultMaxTracked
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

// Validate refuses a handler that would ban everyone or no one.
func (h *Handler) Validate() error {
	switch {
	case h.Limit < 1:
		return fmt.Errorf("limit %d: must be at least 1", h.Limit)
	case h.Window <= 0:
		return fmt.Errorf("window %s: must be positive", time.Duration(h.Window))
	case h.Duration <= 0:
		return fmt.Errorf("duration %s: must be positive", time.Duration(h.Duration))
	case h.MaxTracked < 1:
		return fmt.Errorf("max_tracked %d: must be at least 1", h.MaxTracked)
	}
	return nil
}

// ServeHTTP answers 403 to a banned address and passes everything else on, counting what counts. A
// request left uncounted for what it asks for — /_next/, a subresource, an exempt path — is still
// refused to a banned address: the ban keeps the address from every app, its images and Next.js's
// image optimizer included. An address in an exempt range is neither counted nor refused, so adding
// a banned address's range to exempt_ranges lifts its ban with the next apply. ACME's challenge never
// gets here: Caddy answers it before any route, and boks's ban route leaves it out by its matcher.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	addr, ok := clientAddr(r)
	if !ok || h.exemptAddr(addr) {
		return next.ServeHTTP(w, r)
	}
	if h.exemptRequest(r) {
		if h.store.banned(addr) {
			return refuse(w)
		}
		return next.ServeHTTP(w, r)
	}
	switch v := h.store.hit(addr, h.Limit, time.Duration(h.Window), time.Duration(h.Duration), h.MaxTracked); v.outcome {
	case banned:
		return refuse(w)
	case newlyBanned:
		h.logger.Warn("address banned", zap.String("ip", addr.String()), zap.String("host", r.Host),
			zap.Int("count", v.count), zap.String("until", v.until.UTC().Format(time.RFC3339)))
		return refuse(w)
	case full:
		h.logger.Error("too many addresses tracked; new ones pass uncounted until old ones expire",
			zap.Int("max_tracked", h.MaxTracked))
	}
	return next.ServeHTTP(w, r)
}

func refuse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, err := io.WriteString(w, "Forbidden: too many requests from this address\n")
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

// exemptRequest says whether a request is not counted for what it asks for: Next.js's own files, a
// subresource of a page, or a path an exemption names. The path is judged cleaned, as Caddy's path
// matcher and the apps judge it: /_next/../en/encar/1 is the page it names, not a file of Next.js.
func (h *Handler) exemptRequest(r *http.Request) bool {
	p := path.Clean(r.URL.Path)
	if strings.HasPrefix(p, "/_next/") {
		return true
	}
	if slices.Contains(assetDest, strings.ToLower(r.Header.Get("Sec-Fetch-Dest"))) {
		return true
	}
	for _, re := range h.paths {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
