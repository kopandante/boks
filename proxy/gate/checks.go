package gate

// The gate's checks beside the token (plan docs/plans/20261023-gate-checks.md): what the request says of
// the client that sent it, which a script that took a page's cookie, or asked the proxy for a token,
// does not say as a browser does. Each check is off, log — its failure goes into the access log as
// gate_shadow and nothing else changes — or enforce, where a failure refuses a request the token lets
// through. They judge the requests the token judges: not the exemptions, not the partner's Bearer.
//
//   - fp: the X-Fingerprint header on every method, and a token that carries the fingerprint. Without
//     it a GET passes with the token alone (request-gate 1.7.0) — a page's token, which has none.
//   - fetch_meta: Sec-Fetch-Site same-origin, Sec-Fetch-Mode cors, Sec-Fetch-Dest empty, as every
//     browser's fetch() of the site's own API sends them. On the skip_fp paths, where the browser's
//     <img> asks with no-cors and image, Sec-Fetch-Site alone.
//   - alpn: a browser's User-Agent on a TLS connection straight from the client that did not choose h2.
//     Every browser does; HTTP/1.1 there is a client of its own under a browser's name. Past a trusted
//     proxy the protocol is the proxy's and says nothing.
//
// Googlebot and Google's user-triggered fetchers (Read Aloud) send neither Fetch Metadata nor h2: their
// published ranges (google.go) pass fetch_meta and alpn. So do Yandex's robots: a User-Agent that names
// Yandex from Yandex's AS (yandex.go). The group's exempt_ranges pass every check.

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Checks are a group's checks, each off (the default), log or enforce.
type Checks struct {
	FP        string `json:"fp,omitempty"`
	FetchMeta string `json:"fetch_meta,omitempty"`
	ALPN      string `json:"alpn,omitempty"`
	// ExemptRanges are the addresses — one address or a CIDR range — no check is asked of: our own
	// probes, a client's office whose proxy drops h2.
	ExemptRanges []string `json:"exempt_ranges,omitempty"`
}

// check is one check of a request: its name, as gate_shadow and gate_reason write it, and how it
// refuses — fp as the client refreshes its token on, the others as request-gate's Forbidden.
type check struct {
	name    string
	refuse  *refusal
	mode    func(*Checks) string
	crawler bool // Google's and Yandex's crawlers and fetchers pass it
}

var checks = []check{
	{"fp", fpMismatch, func(c *Checks) string { return c.FP }, false},
	{"fetch_meta", forbidden, func(c *Checks) string { return c.FetchMeta }, true},
	{"alpn", forbidden, func(c *Checks) string { return c.ALPN }, true},
}

// validate refuses a mode the handler would not know, an enforced check in a group that is not, and a
// range that is not one or holds every address.
func (c *Checks) validate(groupMode string) error {
	for _, k := range checks {
		switch m := k.mode(c); m {
		case "", "off", "log":
		case "enforce":
			if groupMode != "enforce" {
				return fmt.Errorf("checks.%s enforce goes with the group's mode enforce", k.name)
			}
		default:
			return fmt.Errorf("checks.%s %q must be off, log or enforce", k.name, m)
		}
	}
	_, err := parseRanges(c.ExemptRanges)
	return err
}

func parseRanges(ss []string) ([]netip.Prefix, error) {
	return parseRangesOf("checks.exempt_ranges", ss)
}

// parseRangesOf is parseRanges for the field named field, which its errors name.
func parseRangesOf(field string, ss []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%s: %q is neither an address nor a CIDR range", field, s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("%s: %q holds every address", field, s)
		}
		if p.Addr().Is4In6() {
			return nil, errors.New(field + ": " + s + ": an IPv4 address goes as IPv4")
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// shadow are the checks r fails, in the order of checks: every one that is not off, whatever the
// token's verdict. pl is the token's payload when it is valid, nil otherwise.
func (h *Handler) shadow(r *http.Request, p, ip string, pl *payload) []check {
	if h.Checks == nil {
		return nil
	}
	skipFP := h.skipFP(p)
	var failed []check
	for _, k := range checks {
		if m := k.mode(h.Checks); m != "" && m != "off" && !k.passes(r, skipFP, pl) {
			failed = append(failed, k)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	// The ranges are asked only of a request that fails: Google's are hundreds.
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return failed
	}
	if inRanges(h.checksExempt, a) {
		return nil
	}
	if isGoogle(a) || isYandex(a, r.UserAgent()) {
		failed = slices.DeleteFunc(failed, func(k check) bool { return k.crawler })
	}
	return failed
}

// passes says whether r passes k.
func (k check) passes(r *http.Request, skipFP bool, pl *payload) bool {
	switch k.name {
	case "fp":
		if skipFP {
			return true
		}
		hdr := r.Header.Get(fpHeader)
		return hdr != "" && (pl == nil || pl.fp != "")
	case "fetch_meta":
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" {
			return false
		}
		return skipFP || (r.Header.Get("Sec-Fetch-Mode") == "cors" && r.Header.Get("Sec-Fetch-Dest") == "empty")
	case "alpn":
		return r.ProtoMajor >= 2 || r.TLS == nil || !browser(r.UserAgent()) || !direct(r)
	}
	return true
}

// browser says whether ua names one of the browsers that all speak h2: Chromium's, Safari's, Firefox's.
func browser(ua string) bool {
	if !strings.HasPrefix(ua, "Mozilla/5.0 ") {
		return false
	}
	for _, t := range []string{"Chrome/", "CriOS/", "Firefox/", "FxiOS/", "Safari/"} {
		if strings.Contains(ua, t) {
			return true
		}
	}
	return false
}

// direct says whether r's connection is the client's own, not a trusted proxy's in front of the server.
func direct(r *http.Request) bool {
	trusted, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
	return !trusted
}

func inRanges(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// names are the checks' names, comma-separated, as gate_shadow writes them.
func names(cs []check) string {
	s := make([]string, len(cs))
	for i, c := range cs {
		s[i] = c.name
	}
	return strings.Join(s, ",")
}
