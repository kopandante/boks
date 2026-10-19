package gate

import (
	"context"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// provisioned is h as Caddy loads it: provisioned, then validated.
func provisioned(t *testing.T, h *Handler) *Handler {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	return h
}
