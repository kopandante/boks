package gate

// A partner's server reading the catalog by Bearer token, as glavdoroga's encar-bearer.ts lets it:
// GET and HEAD on the paths given, the token's SHA-256 among the group's digests. A Bearer that does
// not match is no exemption — the request goes to the token check like any other.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Bearer is the group's partner access: Digests are the hex SHA-256 of the tokens, never the tokens.
type Bearer struct {
	Paths   []string `json:"paths"`
	Methods []string `json:"methods,omitempty"`
	Digests []string `json:"digests"`
}

type bearer struct {
	paths   []*regexp.Regexp
	methods []string
	digests [][]byte
}

var bearerScheme = regexp.MustCompile(`(?i)^bearer\s+`)

func (b *Bearer) compile() (*bearer, error) {
	out := &bearer{methods: b.Methods}
	if len(out.methods) == 0 {
		out.methods = []string{http.MethodGet, http.MethodHead}
	}
	if len(b.Paths) == 0 {
		return nil, fmt.Errorf("paths: at least one")
	}
	for _, p := range b.Paths {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("paths: %w", err)
		}
		out.paths = append(out.paths, re)
	}
	if len(b.Digests) == 0 {
		return nil, fmt.Errorf("digests: at least one")
	}
	for i, d := range b.Digests {
		raw, err := hex.DecodeString(d)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("digests[%d]: not the hex of a SHA-256", i)
		}
		out.digests = append(out.digests, raw)
	}
	return out, nil
}

// admits says whether the request is a partner's read: every digest is compared, in constant time.
func (b *bearer) admits(r *http.Request, p string) bool {
	if !slices.Contains(b.methods, r.Method) || !slices.ContainsFunc(b.paths, func(re *regexp.Regexp) bool { return re.MatchString(p) }) {
		return false
	}
	header := r.Header.Get("Authorization")
	scheme := bearerScheme.FindString(header)
	if scheme == "" {
		return false
	}
	presented := strings.TrimSpace(header[len(scheme):])
	if presented == "" {
		return false
	}
	sum := sha256.Sum256([]byte(presented))
	match := 0
	for _, d := range b.digests {
		match |= subtle.ConstantTimeCompare(sum[:], d)
	}
	return match == 1
}

// keyed says whether r is a partner's read the group's Bearer lets in, on its cleaned path.
func (h *Handler) keyed(r *http.Request) bool {
	return h.bearer != nil && h.bearer.admits(r, path.Clean(r.URL.Path))
}
