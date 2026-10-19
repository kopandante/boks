package gate

import (
	"context"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func ctxForTest(t *testing.T) caddy.Context {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	return ctx
}

// provisioned is h as Caddy loads it: provisioned, then validated.
func provisioned(t *testing.T, h *Handler) *Handler {
	t.Helper()
	if err := h.Provision(ctxForTest(t)); err != nil {
		t.Fatal(err)
	}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	return h
}

// withVars is r with the variables Caddy's server sets before any handler: the client's address it
// decided and whether the connection came from a trusted proxy.
func withVars(r *http.Request, clientIP string, trusted bool) *http.Request {
	vars := map[string]any{caddyhttp.ClientIPVarKey: clientIP, caddyhttp.TrustedProxyVarKey: trusted}
	return r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
}
