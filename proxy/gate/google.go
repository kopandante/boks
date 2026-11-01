package gate

// Google's published ranges, as downloaded on the date each file's creationTime says, from
// https://developers.google.com/static/crawling/ipranges/ (the old search/apis/ipranges/ URLs redirect
// there): common-crawlers.json — Googlebot — and user-triggered-fetchers-google.json — Google's own
// fetchers a user asks for, Read Aloud among them. An address in either passes fetch_meta and alpn: by
// the address Google publishes, never by a User-Agent anyone can write. Only common-crawlers.json lets a
// token pass from a neighbouring address (googlePool, #138): the files are not interchangeable, and a
// prefix moved from one to the other widens or narrows that exception. The files are Google's JSON
// compacted to one line (`curl -sL <url> | jq -c .`), the same data. The lists change rarely; a new
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

// googleRanges are the ranges of every file, by its name.
var googleRanges = sync.OnceValue(func() map[string][]netip.Prefix {
	ps, err := readGoogle()
	if err != nil {
		// The files are the image's own; a test reads them all (TestGoogleRanges).
		panic(err)
	}
	return ps
})

// googlebotFile is Google's common crawlers — Googlebot and its siblings (GoogleOther,
// Google-InspectionTool…) — googlebot.json before Google renamed it; userFetchersFile is the fetchers a
// user of Google asks for.
const (
	googlebotFile    = "common-crawlers.json"
	userFetchersFile = "user-triggered-fetchers-google.json"
)

func readGoogle() (map[string][]netip.Prefix, error) {
	entries, err := googleFiles.ReadDir("google")
	if err != nil {
		return nil, err
	}
	out := map[string][]netip.Prefix{}
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
			out[e.Name()] = append(out[e.Name()], pr.Masked())
		}
	}
	if len(out[googlebotFile]) == 0 {
		return nil, fmt.Errorf("no ranges in %s", googlebotFile)
	}
	return out, nil
}

// isGoogle says whether a is in Google's published ranges of Googlebot and its user-triggered fetchers.
func isGoogle(a netip.Addr) bool {
	for _, ps := range googleRanges() {
		if inRanges(ps, a) {
			return true
		}
	}
	return false
}

// isGooglebot says whether a is one of Google's common crawlers' addresses (googlebotFile), where
// Googlebot crawls: not a user-triggered fetcher's, which a user of Google programs himself — Apps
// Script among them.
func isGooglebot(a netip.Addr) bool { return inRanges(googleRanges()[googlebotFile], a) }
