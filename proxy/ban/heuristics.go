package ban

// The heuristics look past the rate of one address, at requests no browser sends. A browser sends
// Fetch Metadata — Sec-Fetch-Site, -Mode and -Dest — as the three together (Chromium 80+, Firefox
// 90+, Safari 16.4+), or none of it when older, but for Chromium 76–79, which sent Site and Mode
// before Dest existed; a request with Sec-Fetch-Mode and without one of the others, and not of those
// Chromiums, was made by something copying a browser's headers in part. That is the strong sign, read from
// the headers alone, which reach boks as the client sent them: the node's Caddy terminates TLS and
// nothing in front rewrites them. Of a storm of many addresses each under every rule — the one on dbauto, 72 home addresses at
// 37 requests an hour — the sign is what is common, and the cluster is its fingerprint across them.

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// DefaultMaxFingerprints bounds the fingerprints tracked at once. A fingerprint holds the addresses of
// its cluster up to min_addresses (100 at most); at the bound, all of them holding the most, the
// fingerprints are some 48 MB measured on the heap (TestTheWorstCaseMemory) — a storm of UAs made up
// per request is the way to fill them.
const DefaultMaxFingerprints = 10_000

// maxMinAddresses bounds a cluster's min_addresses: the addresses a fingerprint keeps.
const maxMinAddresses = 100

// uaSample is the length of the User-Agent kept for the journal.
const uaSample = 160

// Heuristics is the handler's look at requests no browser sends.
type Heuristics struct {
	// Mode is off — nothing looked at — when not given; log writes the flagged requests and the
	// clusters in the journal; ban refuses a flagged cluster's requests for the ban's duration too.
	Mode    string  `json:"mode,omitempty"`
	Cluster Cluster `json:"cluster"`
}

// Cluster is a fingerprint sending more than Limit flagged requests within Window — fixed, from its
// first — from at least MinAddresses addresses.
type Cluster struct {
	Limit        int            `json:"limit"`
	Window       caddy.Duration `json:"window"`
	MinAddresses int            `json:"min_addresses"`
}

// cluster is a Cluster as the store takes it.
type cluster struct {
	limit        int
	window       time.Duration
	minAddresses int
}

// validate refuses a mode it does not know and, unless off, a cluster that flags everyone or no one.
func (h *Heuristics) validate() error {
	if !h.on() {
		if h != nil && h.Mode != "" && h.Mode != "off" {
			return fmt.Errorf("mode %q must be off, log or ban", h.Mode)
		}
		return nil
	}
	c := h.Cluster
	switch {
	case h.Mode != "log" && h.Mode != "ban":
		return fmt.Errorf("mode %q must be off, log or ban", h.Mode)
	case c.Limit < 1:
		return fmt.Errorf("cluster: limit %d: must be at least 1", c.Limit)
	case c.Window <= 0:
		return fmt.Errorf("cluster: window %s: must be positive", time.Duration(c.Window))
	case c.MinAddresses < 1 || c.MinAddresses > maxMinAddresses:
		return fmt.Errorf("cluster: min_addresses %d: must be from 1 to %d", c.MinAddresses, maxMinAddresses)
	}
	return nil
}

func (h *Heuristics) on() bool { return h != nil && h.Mode != "" && h.Mode != "off" }

func (h *Heuristics) cluster() cluster {
	return cluster{limit: h.Cluster.Limit, window: time.Duration(h.Cluster.Window), minAddresses: h.Cluster.MinAddresses}
}

// forged is the strong sign: Sec-Fetch-Mode without Sec-Fetch-Site or Sec-Fetch-Dest. Told by the
// headers' presence, as a browser either sends one or does not; Site and Mode without Dest is what
// Chromium 76–79 sent (Dest came with 80), so it is the sign only from another UA.
func forged(h http.Header) bool {
	_, mode := h["Sec-Fetch-Mode"]
	_, site := h["Sec-Fetch-Site"]
	_, dest := h["Sec-Fetch-Dest"]
	switch {
	case !mode || site && dest:
		return false
	case site:
		return !beforeDest(h.Get("User-Agent"))
	}
	return true
}

// beforeDest says whether ua is of a Chromium from before Sec-Fetch-Dest: 76 to 79. Edge, Opera,
// Samsung Internet and WebView on it name Chrome's token too.
func beforeDest(ua string) bool {
	_, rest, ok := strings.Cut(ua, "Chrome/")
	return ok && len(rest) > 2 && rest[0] == '7' && rest[1] >= '6' && rest[1] <= '9' && (rest[2] < '0' || rest[2] > '9')
}

// weakSigns are what a browser may send too, so they go to the journal beside the strong sign and
// nowhere else: a Chromium UA without client hints is a WebView or an in-app browser as often as not,
// and HTTP/1 on a connection straight from the client is Chrome behind a network that drops h2. Past a
// proxy in front of boks, the protocol is the proxy's and says nothing.
func weakSigns(r *http.Request) []string {
	var w []string
	if strings.Contains(r.UserAgent(), "Chrome/") && r.Header.Get("Sec-Ch-Ua") == "" {
		w = append(w, "chromium without sec-ch-ua")
	}
	if r.ProtoMajor == 1 && r.TLS != nil && direct(r) {
		w = append(w, "http/1 on direct tls")
	}
	return w
}

// direct says whether r's connection is the client's own: Caddy decided no other client past it.
func direct(r *http.Request) bool {
	s, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if s == "" {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, errA := netip.ParseAddr(s)
	b, errB := netip.ParseAddr(host)
	return errA == nil && errB == nil && a.Unmap() == b.Unmap()
}

// families are the browsers a fingerprint tells apart, by their UA's token, in the order they are
// looked for: Edge, Opera and the rest name Chrome's token too, and Chrome Safari's Version/ in WebView.
var families = []struct{ token, name string }{
	{"Edg/", "edge"}, {"OPR/", "opera"}, {"YaBrowser/", "yandex"}, {"SamsungBrowser/", "samsung"},
	{"Firefox/", "firefox"}, {"FxiOS/", "firefox"}, {"CriOS/", "chrome"}, {"Chrome/", "chrome"}, {"Version/", "safari"},
}

// fetchMetadata are the headers whose presence the fingerprint records.
var fetchMetadata = []struct{ header, name string }{
	{"Sec-Fetch-Mode", "mode"}, {"Sec-Fetch-Site", "site"}, {"Sec-Fetch-Dest", "dest"}, {"Sec-Fetch-User", "user"},
}

// fingerprint is what a cluster's requests share however many addresses send them: the browser's
// family and major version, the first language's primary tag, and which of Fetch Metadata is there.
// Nothing else a client sends goes in, so headers made up per request do not split a cluster; a UA
// made up per request does, which the heuristics leave to the rules. Its length is bounded whatever
// the client sends.
func fingerprint(r *http.Request) string {
	var b strings.Builder
	b.WriteString(family(r.UserAgent()))
	b.WriteByte(' ')
	b.WriteString(language(r.Header.Get("Accept-Language")))
	for _, f := range fetchMetadata {
		if _, ok := r.Header[f.header]; ok {
			b.WriteByte(' ')
			b.WriteString(f.name)
		}
	}
	return b.String()
}

// family is the UA's browser and major version, such as chrome/149, or other.
func family(ua string) string {
	for _, f := range families {
		if _, rest, ok := strings.Cut(ua, f.token); ok {
			n := 0
			for n < len(rest) && n < 4 && rest[n] >= '0' && rest[n] <= '9' {
				n++
			}
			return f.name + "/" + rest[:n]
		}
	}
	return "other"
}

// language is the primary tag of Accept-Language's first language, lowercased and at most 8 letters
// as a tag's are, or - when there is none.
func language(h string) string {
	tag, _, _ := strings.Cut(h, ",")
	tag, _, _ = strings.Cut(tag, ";")
	tag, _, _ = strings.Cut(strings.TrimSpace(tag), "-")
	tag = strings.ToLower(tag)
	if tag == "" || len(tag) > 8 || strings.Trim(tag, "abcdefghijklmnopqrstuvwxyz*") != "" {
		return "-"
	}
	return tag
}
