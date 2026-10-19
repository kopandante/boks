package gate

// The token's issue, POST /api/auth/token, answered by the proxy in enforce as the sites' route.ts
// answers it (cars-cli registry/security/api-routes/auth/token/route.ts): a JSON body with the
// fingerprint the browser computed, a cookie back. The token carries the address Caddy decided, the
// one the gate compares.

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// maxIssueBody bounds the body read: the browser's is some 90 bytes.
const maxIssueBody = 4 << 10

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// issue answers the token's issue; the origin was checked in decide.
func (h *Handler) issue(w http.ResponseWriter, r *http.Request, ip string) error {
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return refuse(w, forbidden)
	}
	// A body cut at the bound is no JSON, and refused with the rest.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIssueBody))
	if err != nil {
		return refuse(w, forbidden)
	}
	var req struct {
		Fingerprint any `json:"fingerprint"`
	}
	if json.Unmarshal(body, &req) != nil {
		return refuse(w, forbidden)
	}
	fp, _ := req.Fingerprint.(string)
	if !fingerprintRe.MatchString(fp) {
		return refuse(w, forbidden)
	}
	http.SetCookie(w, h.cookie(h.sign(fp, ip), r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = io.WriteString(w, `{"ok":true}`)
	return err
}

// cookie is the token's cookie as the sites set it: readable by the page's script (the client sends it
// back as a header too), strict, for three minutes, Secure when the visitor came by HTTPS.
func (h *Handler) cookie(tok string, r *http.Request) *http.Cookie {
	return &http.Cookie{Name: cookieName, Value: tok, Path: "/", MaxAge: int(tokenTTL / time.Second),
		Expires: h.now().Add(tokenTTL), Secure: https(r), SameSite: http.SameSiteStrictMode}
}

// https says whether the visitor came by HTTPS: to this server, or to a trusted proxy in front of it
// that says so — a forwarded header from anyone else is the visitor's own to write.
func https(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	trusted, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
	return trusted && r.Header.Get("X-Forwarded-Proto") == "https"
}
