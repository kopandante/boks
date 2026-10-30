package ban

// A partner's read by key: a gate group's Bearer (proxy/gate, bearer.go) on the hosts of the group's app,
// which boks hands the ban beside the gate's handler. The owner sells that read, and the partner's
// server reads at a pace no visitor's browser keeps: counted, it would be banned on every host of the
// server for the ban's duration. So a request the key lets in is neither counted nor flagged nor
// refused for its address's ban; deny_ranges, the owner's own refusal, stays stronger than any key.
// The key is checked as the gate checks it, by the SHA-256 of the token among the group's digests —
// a header alone would let any scraper out of the ban by writing `Authorization: Bearer x`. The gate's
// module is another one, so the check is written here again, as it is there.

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

// Bearer is one gate group's partner access as boks writes it for the ban: the hosts of the group's
// app — exact, or a wildcard of one label — the paths and methods of its bearer, and the hex SHA-256 of
// its tokens.
type Bearer struct {
	Hosts   []string `json:"hosts"`
	Paths   []string `json:"paths"`
	Methods []string `json:"methods,omitempty"`
	Digests []string `json:"digests"`
}

type bearer struct {
	hosts   []string
	paths   []*regexp.Regexp
	methods []string
	digests [][]byte
}

var bearerScheme = regexp.MustCompile(`(?i)^bearer\s+`)

// compile is b with its hosts lowercase, its patterns compiled and its digests decoded.
func (b *Bearer) compile() (*bearer, error) {
	if len(b.Hosts) == 0 || len(b.Paths) == 0 || len(b.Digests) == 0 {
		return nil, fmt.Errorf("hosts, paths and digests: at least one each")
	}
	out := &bearer{methods: b.Methods}
	if len(out.methods) == 0 {
		out.methods = []string{http.MethodGet, http.MethodHead}
	}
	for _, h := range b.Hosts {
		out.hosts = append(out.hosts, strings.ToLower(h))
	}
	var err error
	if out.paths, err = compilePaths(b.Paths); err != nil {
		return nil, err
	}
	out.digests, err = decodeDigests(b.Digests)
	return out, err
}

func compilePaths(paths []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range paths {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("paths: %w", err)
		}
		out = append(out, re)
	}
	return out, nil
}

func decodeDigests(digests []string) ([][]byte, error) {
	var out [][]byte
	for i, d := range digests {
		raw, err := hex.DecodeString(d)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("digests[%d]: not the hex of a SHA-256", i)
		}
		out = append(out, raw)
	}
	return out, nil
}

// admits says whether r is a read the group's key lets in: its host, method and cleaned path, then the
// token, compared with every digest in constant time.
func (b *bearer) admits(r *http.Request) bool {
	p := path.Clean(r.URL.Path)
	if !slices.ContainsFunc(b.hosts, hostIs(r.Host)) || !slices.Contains(b.methods, r.Method) ||
		!slices.ContainsFunc(b.paths, func(re *regexp.Regexp) bool { return re.MatchString(p) }) {
		return false
	}
	return b.holds(r.Header.Get("Authorization"))
}

// holds says whether the Authorization header carries a token among the digests.
func (b *bearer) holds(header string) bool {
	scheme := bearerScheme.FindString(header)
	presented := strings.TrimSpace(header[len(scheme):])
	if scheme == "" || presented == "" {
		return false
	}
	sum := sha256.Sum256([]byte(presented))
	match := 0
	for _, d := range b.digests {
		match |= subtle.ConstantTimeCompare(sum[:], d)
	}
	return match == 1
}

// hostIs matches a host of the policy against the request's Host, without its port and the root's dot,
// in any case: exactly, or as Caddy's wildcard does — one label in place of the star.
func hostIs(requested string) func(string) bool {
	h := strings.ToLower(requested)
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	return func(host string) bool {
		suffix, wild := strings.CutPrefix(host, "*")
		if !wild {
			return h == host
		}
		label, ok := strings.CutSuffix(h, suffix)
		return ok && label != "" && !strings.Contains(label, ".")
	}
}

// keyed says whether r is a partner's read one of the handler's keys lets in.
func (h *Handler) keyed(r *http.Request) bool {
	return slices.ContainsFunc(h.bearers, func(b *bearer) bool { return b.admits(r) })
}
