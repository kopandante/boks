// Package hostname compares hosts the way Caddy does: one name in Unicode and in punycode, in any
// case, is one host to its matcher, so it must be one host to boks — or two apps could claim it and
// Caddy would give it to whichever route comes first.
package hostname

import (
	"strings"

	"golang.org/x/net/idna"
)

// Canonical is host as Caddy 2.11.7's host matcher compares it: idna.ToASCII, then lower case
// (modules/caddyhttp/matchers.go). A wildcard keeps its `*.` and has the rest converted. The order
// is Caddy's, and it matters: idna does not fold case, so ПРИМЕР.РФ and пример.рф are two hosts to
// Caddy, and to boks. A host idna refuses — its lenient profile refuses next to nothing — comes back
// lower-cased as it was.
func Canonical(host string) string {
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		return "*." + Canonical(rest)
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	return strings.ToLower(host)
}

// Same says whether a and b are one host to Caddy.
func Same(a, b string) bool { return Canonical(a) == Canonical(b) }
