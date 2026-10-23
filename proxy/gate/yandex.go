package gate

// Yandex's robots — YandexBot, YandexRenderResourcesBot, which renders a page and fetches its /api over
// HTTP/1.1 without Fetch Metadata, and the rest of the Yandex* ones — pass fetch_meta and alpn as Google's
// do. Yandex publishes no list of its robots' addresses; its own way to tell one (yandex.com/support/webmaster,
// "How to check that a robot belongs to Yandex") is a reverse lookup that ends in yandex.ru, yandex.net or
// yandex.com and a forward lookup back to the same address. The gate does not ask DNS on a request: it
// would wait on a resolver for every request that fails a check, a cache would need its own bounds, and a
// resolver that is down would decide the verdict. It holds the prefixes Yandex's own AS, AS13238, announces
// instead (yandex/as13238.txt, a file in the image like Google's): every robot address seen on the sites
// is in them and resolves both ways to spider.yandex.com, and Yandex Cloud, where anyone can rent a
// machine, is another AS. An address there passes only with a User-Agent that names Yandex: the address
// alone is Yandex's other services, and the name alone is anyone's. A new list is a new image.

import (
	_ "embed"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

//go:embed yandex/as13238.txt
var yandexFile string

var yandexRanges = sync.OnceValue(func() []netip.Prefix {
	ps, err := readYandex(yandexFile)
	if err != nil {
		// The file is the image's own; a test reads it whole (TestYandexRanges).
		panic(err)
	}
	return ps
})

// readYandex reads one CIDR prefix a line; blank lines and # comments are skipped.
func readYandex(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		p, err := netip.ParsePrefix(l)
		if err != nil || p.Bits() == 0 {
			return nil, fmt.Errorf("yandex/as13238.txt:%d: prefix %q", i+1, l)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// isYandex says whether a request from a with User-Agent ua is Yandex's robot: a name of Yandex from
// Yandex's AS.
func isYandex(a netip.Addr, ua string) bool {
	return strings.Contains(ua, "Yandex") && inRanges(yandexRanges(), a)
}
