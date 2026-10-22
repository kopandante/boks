package gate

// Google's published ranges, as downloaded on the date each file's creationTime says, from
// https://developers.google.com/static/crawling/ipranges/ (the old search/apis/ipranges/ URLs redirect
// there): common-crawlers.json — Googlebot — and user-triggered-fetchers-google.json — Google's own
// fetchers a user asks for, Read Aloud among them. An address in them passes fetch_meta and alpn: by
// the address Google publishes, never by a User-Agent anyone can write. The lists change rarely; a new
// download is a new image.

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
)

//go:embed google/*.json
var googleFiles embed.FS

var googleRanges = sync.OnceValue(func() []netip.Prefix {
	ps, err := readGoogle()
	if err != nil {
		// The files are the image's own; a test reads them all (TestGoogleRanges).
		panic(err)
	}
	return ps
})

func readGoogle() ([]netip.Prefix, error) {
	entries, err := googleFiles.ReadDir("google")
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, e := range entries {
		b, err := googleFiles.ReadFile("google/" + e.Name())
		if err != nil {
			return nil, err
		}
		var f struct {
			Prefixes []struct {
				IPv4 string `json:"ipv4Prefix"`
				IPv6 string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for _, p := range f.Prefixes {
			s := p.IPv4 + p.IPv6
			pr, err := netip.ParsePrefix(s)
			if err != nil || pr.Bits() == 0 {
				return nil, fmt.Errorf("%s: prefix %q", e.Name(), s)
			}
			out = append(out, pr.Masked())
		}
	}
	return out, nil
}

// isGoogle says whether a is in Google's published ranges of Googlebot and its user-triggered fetchers.
func isGoogle(a netip.Addr) bool { return inRanges(googleRanges(), a) }
