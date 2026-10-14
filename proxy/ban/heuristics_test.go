package ban

import (
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

// visitor is a request as a client sends it: its protocol and its headers in the order it sends them.
type visitor struct {
	name   string
	proto  int // 1 or 2
	header [][2]string
}

// as is v's request from ip for p, as Caddy hands it to the handler: on a direct TLS connection.
func (v visitor) as(ip, p string) *http.Request {
	r := request(ip, p)
	r.RemoteAddr = ip + ":40000"
	if strings.Contains(ip, ":") {
		r.RemoteAddr = "[" + ip + "]:40000"
	}
	if v.proto == 2 {
		r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0
	}
	r.Header = http.Header{}
	for _, h := range v.header {
		r.Header.Add(h[0], h[1])
	}
	return r
}

// storm is the request of the storm on dbauto: 72 home addresses in Japan, some 37 requests an hour
// each, every one with Sec-Fetch-Mode and none with Sec-Fetch-Site or Sec-Fetch-Dest, over HTTP/1.1,
// these headers and no others (Loki, hb-sites).
var storm = visitor{"the storm on dbauto", 1, [][2]string{
	{"Accept", "*/*"},
	{"Accept-Encoding", "gzip, deflate, br"},
	{"Accept-Language", "en,ko;q=0.8"},
	{"Connection", "keep-alive"},
	{"Cookie", "NEXT_LOCALE=en"},
	{"Referer", "https://cars.dbauto.kr/en/encar"},
	{"Sec-Fetch-Mode", "cors"},
	{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"},
}}

// browsers are what real clients send. None carries the strong sign: a browser sends Fetch Metadata
// as the three together or — before Chromium 76, Firefox 90, Safari 16.4 — not at all, but for
// Chromium 76–79, which sent Site and Mode without Dest.
var browsers = []visitor{
	// The crawler of the night of 14.10 (217.81.103.213): headless Chrome with a desktop Linux UA and
	// the headers Chrome sends, client hints and Fetch Metadata whole. The rules' volume catches it,
	// not the heuristics.
	{"the night's crawler", 2, [][2]string{
		{"sec-ch-ua", `"Chromium";v="141", "Not?A_Brand";v="8"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Linux"`},
		{"user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
		{"accept", "*/*"},
		{"sec-fetch-site", "same-origin"},
		{"sec-fetch-mode", "cors"},
		{"sec-fetch-dest", "empty"},
		{"referer", "https://cars.dbauto.kr/en/encar"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=1, i"},
	}},
	{"Chrome on Windows, a page over HTTP/2", 2, [][2]string{
		{"sec-ch-ua", `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"},
		{"priority", "u=0, i"},
	}},
	// Over HTTP/1.1 — a proxy or a network that does not let h2 through — Chrome sends the same: Fetch
	// Metadata and client hints go to every https origin, whatever the protocol.
	{"Chrome on macOS, an API call over HTTP/1.1", 1, [][2]string{
		{"Connection", "keep-alive"},
		{"sec-ch-ua-platform", `"macOS"`},
		{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
		{"sec-ch-ua", `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`},
		{"sec-ch-ua-mobile", "?0"},
		{"Accept", "*/*"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
		{"Referer", "https://cars.dbauto.kr/en/encar"},
		{"Accept-Encoding", "gzip, deflate, br, zstd"},
		{"Accept-Language", "en-US,en;q=0.9"},
	}},
	// Firefox sends no client hints at all.
	{"Firefox on Windows, a page over HTTP/2", 2, [][2]string{
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"accept-language", "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"upgrade-insecure-requests", "1"},
		{"sec-fetch-dest", "document"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-user", "?1"},
		{"priority", "u=0, i"},
		{"te", "trailers"},
	}},
	{"Firefox on Linux, an API call over HTTP/1.1", 1, [][2]string{
		{"User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"},
		{"Accept", "*/*"},
		{"Accept-Language", "en-US,en;q=0.5"},
		{"Accept-Encoding", "gzip, deflate, br, zstd"},
		{"Referer", "https://cars.dbauto.kr/en/encar"},
		{"Connection", "keep-alive"},
		{"Sec-Fetch-Dest", "empty"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Site", "same-origin"},
	}},
	// Safari sends Fetch Metadata from 16.4 and no client hints. Whether it sends Sec-Fetch-User on a
	// navigation is not checked here: the strong sign does not look at it.
	{"Safari on macOS, a page over HTTP/2", 2, [][2]string{
		{"sec-fetch-dest", "document"},
		{"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"accept-language", "ko-KR,ko;q=0.9"},
		{"accept-encoding", "gzip, deflate, br"},
	}},
	{"Safari on iPhone, an API call over HTTP/1.1", 1, [][2]string{
		{"Accept", "*/*"},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Dest", "empty"},
		{"Accept-Language", "ru"},
		{"Sec-Fetch-Mode", "cors"},
		{"User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"},
		{"Referer", "https://cars.dbauto.kr/ru/encar"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Connection", "keep-alive"},
	}},
	// Android WebView is Chromium and sends Fetch Metadata whole. It sends no client hints in the apps
	// this was written against — whether a WebView of a given version does depends on it and the app,
	// which is why their absence is a weak sign only. X-Requested-With names the app.
	{"Android WebView", 2, [][2]string{
		{"upgrade-insecure-requests", "1"},
		{"user-agent", "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/129.0.6668.100 Mobile Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"x-requested-with", "com.kakao.talk"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"},
	}},
	// Telegram's in-app browser on Android is a WebView with Telegram's suffix on the UA (on iOS it is
	// Safari's view, and sends Safari's headers). The suffix's exact form varies by version.
	{"Telegram in-app on Android", 2, [][2]string{
		{"user-agent", "Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/AP2A.240905.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/129.0.6668.100 Mobile Safari/537.36 Telegram-Android/11.2.3 (Google Pixel 7; Android 14; SDK 34; HIGH)"},
		{"accept", "*/*"},
		{"x-requested-with", "org.telegram.messenger"},
		{"sec-fetch-site", "same-origin"},
		{"sec-fetch-mode", "cors"},
		{"sec-fetch-dest", "empty"},
		{"referer", "https://cars.dbauto.kr/ru/encar/1"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
	}},
	// Safari before 16.4 sends no Fetch Metadata at all: nothing to be inconsistent with.
	{"Safari 15 on an old iPhone, without Fetch Metadata", 1, [][2]string{
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "ko-KR,ko;q=0.9"},
		{"Connection", "keep-alive"},
		{"User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Mobile/15E148 Safari/604.1"},
	}},
	// Chromium 76–79 sent Site, Mode and User; Dest came with 80. Samsung Internet 12 is Chromium 79.
	{"Samsung Internet 12, Chromium 79, without Sec-Fetch-Dest", 2, [][2]string{
		{"upgrade-insecure-requests", "1"},
		{"user-agent", "Mozilla/5.0 (Linux; Android 10; SM-A505F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/12.1 Chrome/79.0.3945.136 Mobile Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		{"sec-fetch-site", "same-origin"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"accept-encoding", "gzip, deflate, br"},
		{"accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
	}},
	// Chrome before 76 sent neither Fetch Metadata nor client hints.
	{"Chrome 70, without Fetch Metadata", 1, [][2]string{
		{"Connection", "keep-alive"},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
	}},
}

// heuristics is a ban whose rules no test here reaches, with a cluster small enough to count by
// hand: more than 5 flagged requests in 10 minutes from 3 addresses or more.
func heuristics(mode string) string {
	return `{"duration": "24h", "rules": [{"name": "all", "limit": 100000, "window": "1m"}], "exempt_ranges": ["203.0.113.0/24"],
		"heuristics": {"mode": "` + mode + `", "cluster": {"limit": 5, "window": "10m", "min_addresses": 3}}}`
}

// home is the storm's n-th address.
func home(n int) string { return fmt.Sprintf("126.%d.%d.%d", 200+n/250, n%250, 7) }

// The storm's request is flagged; no browser's is — not the crawler's, not WebView's or Telegram's,
// not one without Fetch Metadata — over either protocol, however many addresses send it.
func TestOnlyTheStormIsFlagged(t *testing.T) {
	fixture(t)
	h, logs := provisioned(t, heuristics("ban"))
	for _, b := range browsers {
		for n := range 20 {
			if code := serve(t, h, b.as(fmt.Sprintf("198.51.%d.%d", 100+n%2, n), "/api/encar/info/1")); code != 200 {
				t.Fatalf("%s: %d", b.name, code)
			}
		}
		if logs.Len() > 0 {
			t.Fatalf("%s: want nothing flagged, got %v", b.name, logs.All())
		}
	}
	serve(t, h, storm.as(home(0), "/api/encar/info/1"))
	if logs.Len() != 1 || logs.All()[0].Message != "forged request" {
		t.Fatalf("want the storm's request flagged: %v", logs.All())
	}
	f := logs.All()[0].ContextMap()
	if f["ip"] != home(0) || f["fingerprint"] != "chrome/149 en mode" || !strings.HasPrefix(f["user_agent"].(string), "Mozilla/5.0 (Macintosh") ||
		f["weak"] != "chromium without sec-ch-ua, http/1 on direct tls" {
		t.Errorf("the line: %v", f)
	}
}

// The weak signs are for the journal, and only beside the strong one: WebView alone sends no client
// hints, and a proxy in front of boks speaks HTTP/1.1 for whoever it carries.
func TestWeakSigns(t *testing.T) {
	for _, c := range []struct {
		r    *http.Request
		want string
	}{
		{storm.as("198.51.100.1", "/"), "chromium without sec-ch-ua, http/1 on direct tls"},
		{browsers[0].as("198.51.100.1", "/"), ""},
		{browsers[7].as("198.51.100.1", "/"), "chromium without sec-ch-ua"},
		{browsers[3].as("198.51.100.1", "/"), ""},
		// Past a proxy in front of boks: the client's address is not the connection's.
		{request("198.51.100.1", "/", "User-Agent", "Mozilla/5.0 Chrome/141.0.0.0"), "chromium without sec-ch-ua"},
	} {
		if got := strings.Join(weakSigns(c.r), ", "); got != c.want {
			t.Errorf("%s %v: want %q, got %q", c.r.Proto, c.r.UserAgent(), c.want, got)
		}
	}
}

// The fingerprint is the browser family and major version, the first language, and which of Fetch
// Metadata is there — nothing a client adds beside, so headers made up per request do not split a
// cluster.
func TestFingerprint(t *testing.T) {
	for ua, want := range map[string]string{
		storm.header[7][1]: "chrome/149",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0": "edge/141",
		browsers[3].header[0][1]: "firefox/131",
		browsers[5].header[1][1]: "safari/18",
		browsers[7].header[1][1]: "chrome/129",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.7390.41 Mobile/15E148 Safari/604.1": "chrome/141",
		"python-requests/2.32.3": "other",
		"":                       "other",
	} {
		r := request("198.51.100.1", "/", "User-Agent", ua, "Sec-Fetch-Mode", "cors")
		if got := fingerprint(r); got != want+" - mode" {
			t.Errorf("%q: want %q, got %q", ua, want+" - mode", got)
		}
	}
	a := storm.as("198.51.100.1", "/")
	b := storm.as("198.51.100.2", "/")
	b.Header.Set("X-Request-Id", "8f2c")
	b.Header.Set("X-Forwarded-Proto", "https")
	b.Header.Set("Accept-Language", "EN-us, ko")
	if fingerprint(a) != fingerprint(b) {
		t.Errorf("want headers beside and the language's region left out: %q, %q", fingerprint(a), fingerprint(b))
	}
	c := storm.as("198.51.100.3", "/")
	c.Header.Set("Sec-Fetch-Site", "same-origin")
	if fingerprint(c) != "chrome/149 en mode site" {
		t.Errorf("want which of Fetch Metadata is there in it: %q", fingerprint(c))
	}
	long := request("198.51.100.1", "/", "User-Agent", "Mozilla/5.0 Chrome/99999999999", "Accept-Language", strings.Repeat("x", 200))
	if got := fingerprint(long); len(got) > 40 {
		t.Errorf("want a fingerprint of bounded length: %q", got)
	}
}

// In mode log a cluster is written down and nothing refused; one address alone, however many requests
// it sends, is no cluster.
func TestAClusterInModeLog(t *testing.T) {
	fixture(t)
	h, logs := provisioned(t, heuristics("log"))
	for range 10 {
		serve(t, h, storm.as(home(0), "/"))
	}
	if n := logs.FilterMessage("cluster flagged").Len(); n != 0 {
		t.Fatalf("one address: want no cluster, got %d", n)
	}
	if n := logs.FilterMessage("forged request").Len(); n != 1 {
		t.Errorf("want one line per address and fingerprint a window, got %d", n)
	}
	for n := 1; n < 72; n++ {
		r := storm.as(home(n), "/api/encar/info/1")
		r.Header.Set(fmt.Sprintf("X-Junk-%d", n), "1") // made up per request: does not split it
		if code := serve(t, h, r); code != 200 {
			t.Fatalf("mode log: want nothing refused, got %d", code)
		}
	}
	flagged := logs.FilterMessage("cluster flagged")
	if flagged.Len() != 1 {
		t.Fatalf("want the cluster flagged once a window, got %d", flagged.Len())
	}
	if f := flagged.All()[0].ContextMap(); f["fingerprint"] != "chrome/149 en mode" || f["count"] != int64(12) || f["mode"] != "log" {
		t.Errorf("the line: %v", f)
	}
	// A line per address only until the cluster has min_addresses: the cluster's line says the rest.
	if n := logs.FilterMessage("forged request").Len(); n != 3 {
		t.Errorf("want the forged lines bounded by min_addresses, got %d", n)
	}
	if logs.FilterMessage("fingerprint banned").Len() != 0 {
		t.Error("mode log: want no fingerprint banned")
	}
}

// In mode ban the fingerprint is refused to every address once flagged, a new one included, for the
// ban's duration — its flagged requests only: the same addresses' requests without the sign pass, and
// an exempt range passes whatever it sends. Back to mode log, nothing is refused from the next request.
func TestAClusterInModeBan(t *testing.T) {
	c := fixture(t)
	h, logs := provisioned(t, heuristics("ban"))
	codes := map[int]int{}
	for n := range 6 {
		codes[serve(t, h, storm.as(home(n%3), "/"))]++
	}
	if codes[200] != 5 || codes[403] != 1 {
		t.Fatalf("want the sixth request, past the limit from three addresses, refused: %v", codes)
	}
	if b := logs.FilterMessage("fingerprint banned"); b.Len() != 1 || b.All()[0].ContextMap()["until"] != "2026-10-15T01:47:00Z" {
		t.Errorf("want the ban logged: %v", b.All())
	}
	if code := serve(t, h, storm.as(home(50), "/")); code != 403 {
		t.Errorf("a new address with the fingerprint: want 403, got %d", code)
	}
	if code := serve(t, h, browsers[1].as(home(0), "/")); code != 200 {
		t.Errorf("the same address without the sign: want it passed, got %d", code)
	}
	if code := serve(t, h, storm.as("203.0.113.9", "/")); code != 200 {
		t.Errorf("an exempt range: want it passed, got %d", code)
	}
	c.add(time.Hour)
	if code := serve(t, h, storm.as(home(51), "/")); code != 403 {
		t.Errorf("within the ban's day: want 403, got %d", code)
	}
	relaxed, _ := provisioned(t, heuristics("log"))
	if code := serve(t, relaxed, storm.as(home(52), "/")); code != 200 {
		t.Errorf("back to mode log: want the fingerprint's ban not enforced, got %d", code)
	}
	off, offLogs := provisioned(t, `{"duration": "24h", "rules": [{"name": "all", "limit": 100000, "window": "1m"}]}`)
	if code := serve(t, off, storm.as(home(53), "/")); code != 200 || offLogs.Len() != 0 {
		t.Errorf("without heuristics: want nothing asked, got %d %v", code, offLogs.All())
	}
	c.add(24 * time.Hour)
	if code := serve(t, h, storm.as(home(54), "/")); code != 200 {
		t.Errorf("after the ban's day: want it passed, got %d", code)
	}
}

// The fingerprints tracked are bounded: past the bound a new one passes untracked, logged once, while
// the ones tracked stay; addresses are kept per fingerprint only up to min_addresses, and the UA's
// sample is cut.
func TestFingerprintsAreBounded(t *testing.T) {
	c := fixture(t)
	h, logs := provisioned(t, `{"duration": "24h", "rules": [{"name": "all", "limit": 100000, "window": "1m"}], "max_fingerprints": 3,
		"heuristics": {"mode": "ban", "cluster": {"limit": 5, "window": "10m", "min_addresses": 3}}}`)
	as := func(v, n int) *http.Request {
		r := storm.as(home(n), "/")
		r.Header.Set("User-Agent", fmt.Sprintf("Mozilla/5.0 Chrome/%d.0.0.0 %s", 100+v, strings.Repeat("x", 300)))
		return r
	}
	for n := range 6 { // the first fingerprint goes past its limit and is banned
		serve(t, h, as(0, n%3))
	}
	for v := 1; v < 5; v++ {
		for n := range 4 {
			if code := serve(t, h, as(v, n)); code != 200 {
				t.Fatalf("fingerprint %d: want it passed, tracked or not, got %d", v, code)
			}
		}
	}
	if code := serve(t, h, as(0, 7)); code != 403 {
		t.Errorf("a banned fingerprint, the table full: want 403 held, got %d", code)
	}
	if n := shared.fingerprints(); n != 3 {
		t.Errorf("want the fingerprints held at their bound, got %d", n)
	}
	if n := logs.FilterMessage("too many fingerprints tracked; new ones pass unflagged until old ones expire").Len(); n != 1 {
		t.Errorf("want the overflow logged once, got %d", n)
	}
	for _, e := range logs.FilterMessage("forged request").All() {
		if ua := e.ContextMap()["user_agent"].(string); len(ua) > 160 {
			t.Errorf("want the UA's sample cut to 160, got %d", len(ua))
		}
	}
	if n := shared.addressesOf("chrome/100 en mode"); n > 3 {
		t.Errorf("want at most min_addresses kept, got %d", n)
	}
	c.add(10 * time.Minute)
	r := storm.as(home(0), "/")
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	serve(t, h, r)
	if n := shared.fingerprints(); n != 2 {
		t.Errorf("want the window's fingerprints swept but the banned one, the new one tracked: %d", n)
	}
}

// The worst case the bounds allow, measured: DefaultMaxTracked addresses with a count for each of 16
// rules, and DefaultMaxFingerprints fingerprints each holding the most addresses a cluster keeps.
// Filled to a share of the bounds and scaled, to keep the test quick.
func TestTheWorstCaseMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("measures the heap")
	}
	const share = 10
	var rs []rule
	for i := range 16 {
		rs = append(rs, rule{name: fmt.Sprintf("rule-%02d", i), limit: 1 << 30, window: time.Hour, class: "all"})
	}
	measure := func(fill func(s *store)) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		s := newStore(time.Now)
		fill(s)
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(s)
		return (after.HeapAlloc - before.HeapAlloc) * share
	}
	addresses := measure(func(s *store) {
		for i := range DefaultMaxTracked / share {
			s.hit(addrOf(i), rs, 1<<16-1, time.Hour, DefaultMaxTracked)
		}
	})
	cl := cluster{limit: 1 << 30, window: time.Hour, minAddresses: 100}
	prints := measure(func(s *store) {
		for f := range DefaultMaxFingerprints / share {
			for i := range cl.minAddresses - 1 {
				s.forged(addrOf(i), fmt.Sprintf("chrome/%d en mode", f), cl, "log", time.Hour, DefaultMaxFingerprints)
			}
		}
	})
	t.Logf("addresses: %d MB; fingerprints: %d MB", addresses>>20, prints>>20)
	if addresses > 180<<20 || prints > 64<<20 {
		t.Errorf("want the worst case within 180 MB for addresses and 64 MB for fingerprints: %d MB, %d MB", addresses>>20, prints>>20)
	}
}

func addrOf(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)})
}

// fingerprints is the number of fingerprints tracked.
func (s *store) fingerprints() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.prints)
}

// addressesOf is the number of addresses fp keeps.
func (s *store) addressesOf(fp string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.prints[fp]; p != nil {
		return len(p.addrs)
	}
	return 0
}

// The strong sign is Mode without either of the others, whichever is missing; Site and Mode without
// Dest only from a UA not of Chromium 76–79.
func TestTheStrongSign(t *testing.T) {
	const chrome149 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	const edge79 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.74 Safari/537.36 Edg/79.0.309.43"
	for _, c := range []struct {
		name   string
		header []string
		want   bool
	}{
		{"nothing", []string{"User-Agent", chrome149}, false},
		{"the three", []string{"User-Agent", chrome149, "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Dest", "empty"}, false},
		{"mode alone", []string{"User-Agent", chrome149, "Sec-Fetch-Mode", "cors"}, true},
		{"without site", []string{"User-Agent", chrome149, "Sec-Fetch-Mode", "cors", "Sec-Fetch-Dest", "empty"}, true},
		{"without dest", []string{"User-Agent", chrome149, "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin"}, true},
		{"without dest, Edge 79", []string{"User-Agent", edge79, "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin"}, false},
		{"without dest, Chrome 76", []string{"User-Agent", "Mozilla/5.0 Chrome/76.0.3809.100 Safari/537.36", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "none"}, false},
		{"without dest, Chrome 75", []string{"User-Agent", "Mozilla/5.0 Chrome/75.0.3770.100 Safari/537.36", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "none"}, true},
		{"without dest, Chrome 790", []string{"User-Agent", "Mozilla/5.0 Chrome/790.0 Safari/537.36", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "none"}, true},
		{"mode alone, Chrome 79", []string{"User-Agent", edge79, "Sec-Fetch-Mode", "cors"}, true},
		{"without site, Chrome 79", []string{"User-Agent", edge79, "Sec-Fetch-Mode", "cors", "Sec-Fetch-Dest", "empty"}, true},
	} {
		if got := forged(request("198.51.100.1", "/", c.header...).Header); got != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, got)
		}
	}
}

// A reload that raises min_addresses within a cluster's window counts the addresses again: the
// cluster reached under the old one does not ban under the new.
func TestAReloadWithAnotherMinAddresses(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, heuristics("log"))
	for n := range 6 {
		serve(t, h, storm.as(home(n%3), "/"))
	}
	raised, logs := provisioned(t, `{"duration": "24h", "rules": [{"name": "all", "limit": 100000, "window": "1m"}],
		"heuristics": {"mode": "ban", "cluster": {"limit": 5, "window": "10m", "min_addresses": 10}}}`)
	for n := range 9 {
		if code := serve(t, raised, storm.as(home(n%3), "/")); code != 200 {
			t.Fatalf("three addresses under min_addresses 10: want 200, got %d", code)
		}
	}
	if logs.FilterMessage("fingerprint banned").Len() != 0 {
		t.Error("want no ban under the raised min_addresses")
	}
	for n := 3; n < 10; n++ {
		serve(t, raised, storm.as(home(n), "/"))
	}
	if logs.FilterMessage("fingerprint banned").Len() != 1 {
		t.Error("want the ban once ten addresses sent past the limit")
	}
}

// A cluster's window starts again when it passed, whether or not a sweep came between: a second
// fingerprint's window ends between two sweeps the first one's requests ran.
func TestAClusterWindowStartsAgainBetweenSweeps(t *testing.T) {
	c := fixture(t)
	h, logs := provisioned(t, heuristics("log"))
	other := storm.as(home(0), "/")
	other.Header.Set("Accept-Language", "ja")
	serve(t, h, storm.as(home(0), "/")) // sweeps at 0
	c.add(5 * time.Minute)
	for range 5 {
		r := other.Clone(other.Context())
		serve(t, h, r)
	}
	c.add(5 * time.Minute)
	serve(t, h, storm.as(home(0), "/")) // sweeps at 10m: the other's window, from 5m, holds
	c.add(6 * time.Minute)              // 16m: the other's window passed, no sweep due until 20m
	for n := range 3 {
		r := storm.as(home(n), "/")
		r.Header.Set("Accept-Language", "ja")
		serve(t, h, r)
	}
	if n := logs.FilterMessage("cluster flagged").Len(); n != 0 {
		t.Errorf("want the other's count started again, not 8 past the limit of 5: %d flagged", n)
	}
}
