package gate

// The token's cookie on the responses of a group's hosts in enforce. A page of a site sets a token
// without the address (createApiToken() in its proxy.ts) — the hole the gate closes — and the browser
// loads <img src="/api/encar/pics…"> with it before the client's script runs, which the client does not
// retry. So the proxy does not strip the site's cookie: it replaces its value with a token of the
// address Caddy decided, keeping the fingerprint the site's token carried when the group's secret
// signed it (pakim sets the old token's on every response). Where the site set none, the proxy sets its
// own on the requests the sites set it on today; once the sites stop issuing, it is the only source.
// A response carries at most one x-api-token line either way.

import (
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// metadataPaths are Next.js's metadata files without an extension, which the sites set no cookie on
// (koreaautotrade src/proxy.ts, METADATA_PATHS).
var metadataPaths = []string{"/favicon", "/icon", "/apple-icon", "/manifest"}

// assetRe is a public file by its extension, as the sites' isStaticPath tells it.
var assetRe = regexp.MustCompile(`\.\w{2,5}$`)

// pageRequest says whether the sites set the token's cookie on a request: a GET outside /api/ and the
// static files. Told by the request, not the response: an RSC navigation answers text/x-component and
// a 304 no type at all, and the sites set it on both.
func pageRequest(r *http.Request, p string) bool {
	if r.Method != http.MethodGet || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/_next/") || assetRe.MatchString(p) {
		return false
	}
	for _, m := range metadataPaths {
		if strings.HasPrefix(p, m) {
			return false
		}
	}
	return true
}

// cookies fixes the token's Set-Cookie lines of a response: the site's first one gets the proxy's value,
// further ones go; with none and own set, the proxy's own cookie is added, with ownFP.
func (h *Handler) cookies(hdr http.Header, r *http.Request, ip string, own bool, ownFP string) {
	lines := hdr.Values("Set-Cookie")
	var out []string
	found := false
	for _, l := range lines {
		name, rest, _ := strings.Cut(l, "=")
		if strings.TrimSpace(name) != cookieName {
			out = append(out, l)
			continue
		}
		if found {
			continue
		}
		found = true
		value, attrs, _ := strings.Cut(rest, ";")
		fp := ""
		if pl, reason := h.verify(strings.TrimSpace(value), h.now()); reason == "" {
			fp = pl.fp
		}
		if attrs != "" {
			attrs = ";" + attrs
		}
		out = append(out, cookieName+"="+h.sign(fp, ip)+attrs)
	}
	if !found && own {
		out = append(out, h.cookie(h.sign(ownFP, ip), r).String())
	}
	if len(out) == 0 {
		return
	}
	hdr["Set-Cookie"] = out
}

// cookieWriter calls fix on the headers once, before they leave: at the final status, the first byte of
// the body or a flush — whichever comes first. Unwrap (from ResponseWriterWrapper) hands Caddy's
// ResponseController the writer below, for hijacking and deadlines.
type cookieWriter struct {
	*caddyhttp.ResponseWriterWrapper
	fix   func(http.Header)
	fixed bool
}

func (w *cookieWriter) WriteHeader(code int) {
	// An informational status leaves before the response's own headers (103 Early Hints); 101 is final.
	if !w.fixed && (code >= http.StatusOK || code == http.StatusSwitchingProtocols) {
		w.fixed = true
		w.fix(w.Header())
	}
	w.ResponseWriterWrapper.WriteHeader(code)
}

func (w *cookieWriter) Write(b []byte) (int, error) {
	if !w.fixed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriterWrapper.Write(b)
}

func (w *cookieWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.fixed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriterWrapper.ReadFrom(r)
}

func (w *cookieWriter) FlushError() error {
	if !w.fixed {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *cookieWriter) Flush() { _ = w.FlushError() }
