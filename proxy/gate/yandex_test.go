package gate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	yandexTranslateUA  = "Mozilla/5.0 (compatible; YandexTranslate/2.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0"
	yandexScreenshotUA = "Mozilla/5.0 (compatible; YandexScreenshotBot/3.0; +http://yandex.com/bots)"
	// notYandexPTR is an address of AS13238 whose reverse name, in the tests' DNS, is not Yandex's.
	notYandexPTR = "77.88.44.10"
)

// The tests never ask real DNS: the process's store asks fakeDNS, where every address of AS13238 is
// spider-<n>.spider.yandex.com both ways but notYandexPTR, and any other address has no name.
func init() {
	sharedYandex = newYandexStore(&fakeDNS{
		ptr: func(a netip.Addr) ([]string, error) {
			if a == netip.MustParseAddr(notYandexPTR) {
				return []string{"host.example.net."}, nil
			}
			if inRanges(yandexRanges(), a) {
				return []string{spiderName(a) + "."}, nil
			}
			return nil, notFound
		},
		fwd: func(n string) ([]netip.Addr, error) {
			if a, ok := strings.CutPrefix(strings.TrimSuffix(n, ".spider.yandex.com"), "spider-"); ok {
				if a, err := netip.ParseAddr(strings.ReplaceAll(a, "-", ":")); err == nil {
					return []netip.Addr{a}, nil
				}
			}
			return nil, notFound
		},
	})
}

// spiderName is a's name in the tests' DNS: its address in sixteen bytes, every colon a dash, which
// reads back as a (an IPv4 address as its IPv4-mapped form, which the lookup unmaps).
func spiderName(a netip.Addr) string {
	if a.Is4() {
		a = netip.AddrFrom16(a.As16())
	}
	return "spider-" + strings.ReplaceAll(a.StringExpanded(), ":", "-") + ".spider.yandex.com"
}

var notFound = &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}

// fakeDNS answers with ptr and fwd and counts the questions.
type fakeDNS struct {
	ptr        func(netip.Addr) ([]string, error)
	fwd        func(string) ([]netip.Addr, error)
	ptrs, fwds atomic.Int32
	deadline   time.Duration // how far the last question's deadline was
}

func (d *fakeDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	d.ptrs.Add(1)
	if dl, ok := ctx.Deadline(); ok {
		d.deadline = time.Until(dl)
	}
	return d.ptr(netip.MustParseAddr(addr))
}

func (d *fakeDNS) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	d.fwds.Add(1)
	if network != "ip" {
		return nil, fmt.Errorf("network %s", network)
	}
	return d.fwd(host)
}

// static is a DNS of one address: a's reverse names and what each of them resolves to.
func static(names map[string][]string, ptrErr error) *fakeDNS {
	return &fakeDNS{
		ptr: func(a netip.Addr) ([]string, error) {
			if ptrErr != nil {
				return nil, ptrErr
			}
			out := []string{}
			for n := range names {
				out = append(out, n)
			}
			return out, nil
		},
		fwd: func(n string) ([]netip.Addr, error) {
			var addrs []string
			ok := false
			for k, v := range names {
				if strings.ToLower(strings.TrimSuffix(k, ".")) == n {
					addrs, ok = v, true
				}
			}
			if !ok {
				return nil, notFound
			}
			if len(addrs) == 1 && strings.HasPrefix(addrs[0], "err:") {
				return nil, errors.New(addrs[0])
			}
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		},
	}
}

var timeout = &net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true}

// What the checks ask of a request with a robot's name from Yandex's AS, by what DNS answers: only a
// reverse name of Yandex's that resolves back to the address passes fetch_meta and alpn; a resolver
// that fails keeps the old verdict and says so in the log; a fetcher's name and an address outside the
// AS ask no DNS.
func TestYandexRobotByDNS(t *testing.T) {
	const ip = "213.180.203.222"
	cases := []struct {
		name       string
		ua, ip     string
		dns        *fakeDNS
		want       string // gate_shadow
		ptrs, fwds int32
		failed     bool // gate_yandex_dns: unavailable
	}{
		{"confirmed", yandexUA, ip, static(map[string][]string{"spider-213-180-203-222.spider.yandex.com.": {ip}}, nil), "", 1, 1, false},
		{"confirmed in .yandex.ru, upper case", yandexBotUA, ip, static(map[string][]string{"Spider.YANDEX.RU.": {"5.5.5.5", ip}}, nil), "", 1, 1, false},
		{"confirmed in .yandex.net, no trailing dot", yandexBotUA, ip, static(map[string][]string{"x.yandex.net": {ip}}, nil), "", 1, 1, false},
		{"confirmed over IPv6", "Mozilla/5.0 (compatible; YandexMobileBot/3.0)", "2a02:6b8:c0e:500:1::1", static(map[string][]string{"a.yandex.com.": {"2a02:6b8:c0e:500:1::1"}}, nil), "", 1, 1, false},
		{"a foreign reverse name", yandexUA, ip, static(map[string][]string{"spider.yandex.com.evil.net.": {ip}}, nil), "fetch_meta,alpn", 1, 0, false},
		{"a name ending in yandex.com but not its domain", yandexUA, ip, static(map[string][]string{"notyandex.com.": {ip}}, nil), "fetch_meta,alpn", 1, 0, false},
		{"Yandex's reverse name, the forward lookup another address", yandexUA, ip, static(map[string][]string{"spider.yandex.com.": {"213.180.203.223"}}, nil), "fetch_meta,alpn", 1, 1, false},
		{"Yandex's reverse name that does not resolve", yandexUA, ip, static(map[string][]string{"spider.yandex.com.": nil}, nil), "fetch_meta,alpn", 1, 1, false},
		{"no reverse name (NXDOMAIN)", yandexUA, ip, static(nil, notFound), "fetch_meta,alpn", 1, 0, false},
		{"the reverse lookup times out", yandexUA, ip, static(nil, timeout), "", 1, 0, true},
		{"the reverse lookup fails", yandexUA, ip, static(nil, errors.New("connection refused")), "", 1, 0, true},
		{"the forward lookup fails", yandexUA, ip, static(map[string][]string{"spider.yandex.com.": {"err: servfail"}}, nil), "", 1, 1, true},
		{"YandexTranslate: no DNS", yandexTranslateUA, ip, static(map[string][]string{"spider.yandex.com.": {ip}}, nil), "fetch_meta,alpn", 0, 0, false},
		{"YandexScreenshotBot: no DNS", yandexScreenshotUA, ip, static(map[string][]string{"spider.yandex.com.": {ip}}, nil), "fetch_meta", 0, 0, false},
		{"the robot's name outside AS13238: no DNS", yandexUA, "158.160.1.2", static(map[string][]string{"spider.yandex.com.": {"158.160.1.2"}}, nil), "fetch_meta,alpn", 0, 0, false},
	}
	for _, c := range cases {
		h := enforcing(t, &Handler{Checks: allLog, yandex: newYandexStore(c.dns)}, time.Now())
		h.Mode = "log"
		r, extra := withLog(client{ua: c.ua, fpHeader: true, tokenFP: true, ip: c.ip}.request(h, "GET", "/api/encar/catalog"))
		if w := serve(t, h, r); w.Code != 200 {
			t.Errorf("%s: %d", c.name, w.Code)
		}
		got, _ := fields(extra)["gate_shadow"].(string)
		_, failed := fields(extra)["gate_yandex_dns"]
		if got != c.want || c.dns.ptrs.Load() != c.ptrs || c.dns.fwds.Load() != c.fwds || failed != c.failed {
			t.Errorf("%s: gate_shadow %q, %d reverse and %d forward lookups, unavailable %v; want %q, %d, %d, %v",
				c.name, got, c.dns.ptrs.Load(), c.dns.fwds.Load(), failed, c.want, c.ptrs, c.fwds, c.failed)
		}
		if c.ptrs > 0 && (c.dns.deadline <= 0 || c.dns.deadline > yandexTimeout) {
			t.Errorf("%s: the lookup's deadline is %v away", c.name, c.dns.deadline)
		}
	}
}

// The robot spared by DNS is spared the signatures; refused, it is matched and banned as anyone.
func TestYandexRobotSignature(t *testing.T) {
	const ip = "213.180.203.222"
	for _, c := range []struct {
		name   string
		dns    *fakeDNS
		want   int
		reason string
	}{
		{"confirmed", static(map[string][]string{"spider.yandex.com.": {ip}}, nil), 200, "token"},
		{"refused", static(map[string][]string{"spider.example.com.": {ip}}, nil), 403, "signature"},
		{"the resolver down", static(nil, timeout), 200, "token"},
	} {
		now := time.Now()
		h := signing(t, &now, scraperSig)
		h.yandex = newYandexStore(c.dns)
		r, extra := withLog(browserClient(yandexBotUA, ip).request(h, "GET", "/api/auctions/heydealer/cars"))
		r.Header.Set("Accept-Encoding", scraperAE)
		if w := serve(t, h, r); w.Code != c.want || fields(extra)["gate_reason"] != c.reason {
			t.Errorf("%s: %d %v, want %d %s", c.name, w.Code, fields(extra), c.want, c.reason)
		}
	}
}

// An answer is kept a day when it confirms, an hour when it refuses or the resolver failed: within it
// the address asks DNS once however many requests it sends, past it once more.
func TestYandexCache(t *testing.T) {
	a := netip.MustParseAddr("213.180.203.222")
	for _, c := range []struct {
		name string
		dns  *fakeDNS
		want yandexVerdict
		ttl  time.Duration
	}{
		{"confirmed", static(map[string][]string{"spider.yandex.com.": {a.String()}}, nil), yandexYes, 24 * time.Hour},
		{"refused", static(nil, notFound), yandexNo, time.Hour},
		{"failed", static(nil, timeout), yandexUnknown, time.Hour},
	} {
		s := newYandexStore(c.dns)
		t0 := time.Now()
		for i, at := range []time.Time{t0, t0.Add(time.Second), t0.Add(time.Minute), t0.Add(30 * time.Minute), t0.Add(c.ttl - time.Second)} {
			if v := s.ask(a, at); v != c.want || c.dns.ptrs.Load() != 1 {
				t.Errorf("%s, ask %d: %v after %d lookups", c.name, i, v, c.dns.ptrs.Load())
			}
		}
		for i, at := range []time.Time{t0.Add(c.ttl), t0.Add(c.ttl + time.Minute)} {
			if v := s.ask(a, at); v != c.want || c.dns.ptrs.Load() != 2 {
				t.Errorf("%s, past its time, ask %d: %v after %d lookups", c.name, i, v, c.dns.ptrs.Load())
			}
		}
	}
}

// Requests of a robot through the handler ask DNS once an hour at most, whatever DNS answered: once
// for every request within the hour, once more past it.
func TestYandexCacheThroughHandler(t *testing.T) {
	const ip = "213.180.203.222"
	for _, c := range []struct {
		name   string
		dns    *fakeDNS
		shadow string
	}{
		{"confirmed", static(map[string][]string{"spider.yandex.com.": {ip}}, nil), ""},
		{"refused", static(nil, notFound), "fetch_meta,alpn"},
		{"failed", static(nil, timeout), ""},
	} {
		now := time.Now()
		h := enforcing(t, &Handler{Checks: allLog, yandex: newYandexStore(c.dns)}, now)
		h.Mode = "log"
		h.now = func() time.Time { return now }
		start := now
		for i, at := range []time.Duration{0, time.Second, 10 * time.Minute, time.Hour - time.Second, time.Hour} {
			now = start.Add(at)
			r, extra := withLog(client{ua: yandexUA, fpHeader: true, tokenFP: true, ip: ip}.request(h, "GET", "/api/encar/catalog"))
			serve(t, h, r)
			if got, _ := fields(extra)["gate_shadow"].(string); got != c.shadow {
				t.Errorf("%s, request %d: gate_shadow %q", c.name, i, got)
			}
			want := int32(1)
			if at >= time.Hour && c.name != "confirmed" {
				want = 2
			}
			if n := c.dns.ptrs.Load(); n != want {
				t.Errorf("%s, request %d at %v: %d lookups, want %d", c.name, i, at, n, want)
			}
		}
	}
}

// blocking is a DNS whose every question hangs, its deadline or not, until release closes or for two
// seconds, which a gate that waits for the resolver would show.
func blocking(release chan struct{}) *fakeDNS {
	hang := func() {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}
	return &fakeDNS{
		ptr: func(netip.Addr) ([]string, error) { hang(); return nil, timeout },
		fwd: func(string) ([]netip.Addr, error) { hang(); return nil, timeout },
	}
}

// A resolver that does not answer keeps the request no longer than yandexTimeout, for the reverse and
// the forward lookup together, and the verdict is the failed resolver's.
func TestYandexDeadline(t *testing.T) {
	a := netip.MustParseAddr("213.180.203.222")
	release := make(chan struct{})
	defer close(release)
	slowFwd := &fakeDNS{
		ptr: func(netip.Addr) ([]string, error) {
			time.Sleep(300 * time.Millisecond)
			return []string{"spider.yandex.com."}, nil
		},
		fwd: blocking(release).fwd,
	}
	for _, c := range []struct {
		name string
		dns  *fakeDNS
	}{
		{"the reverse lookup hangs", blocking(release)},
		{"each lookup in time, both together not", slowFwd},
	} {
		s := newYandexStore(c.dns)
		t0 := time.Now()
		v := s.ask(a, t0)
		if took := time.Since(t0); v != yandexUnknown || took > yandexTimeout+150*time.Millisecond || took < yandexTimeout-50*time.Millisecond {
			t.Errorf("%s: %v in %v", c.name, v, took)
		}
	}
	if yandexTimeout > 400*time.Millisecond {
		t.Errorf("the deadline is %v", yandexTimeout)
	}
	// Through the handler: the robot is answered within the deadline, spared, and the log says why.
	h := enforcing(t, &Handler{Checks: allLog, yandex: newYandexStore(blocking(release))}, time.Now())
	h.Mode = "log"
	r, extra := withLog(client{ua: yandexUA, fpHeader: true, tokenFP: true, ip: a.String()}.request(h, "GET", "/api/encar/catalog"))
	t0 := time.Now()
	w := serve(t, h, r)
	if took := time.Since(t0); w.Code != 200 || took > yandexTimeout+150*time.Millisecond || fields(extra)["gate_yandex_dns"] != "unavailable" || fields(extra)["gate_shadow"] != nil {
		t.Errorf("%d in %v, %v", w.Code, took, fields(extra))
	}
}

// A resolver that fails or does not answer leaves the robot unconfirmed, as it was before DNS was
// asked: spared, a signature that matches it neither refuses nor bans it, page_first and static_rhythm
// do not refuse it. Refused by DNS, it is refused and banned as anyone.
func TestYandexResolverDownSpares(t *testing.T) {
	const ip = "213.180.203.222"
	release := make(chan struct{})
	defer close(release)
	robot := browserClient(yandexBotUA, ip)
	for _, c := range []struct {
		name  string
		dns   func() *fakeDNS
		spare bool
	}{
		{"the resolver errs", func() *fakeDNS { return static(nil, errors.New("connection refused")) }, true},
		{"the resolver times out", func() *fakeDNS { return static(nil, timeout) }, true},
		{"the resolver hangs", func() *fakeDNS { return blocking(release) }, true},
		{"refused by DNS", func() *fakeDNS { return static(nil, notFound) }, false},
	} {
		code := func(spared int) int {
			if c.spare {
				return spared
			}
			return 403
		}
		now := time.Now()
		sig := signing(t, &now, scraperSig)
		sig.yandex = newYandexStore(c.dns())
		r := robot.request(sig, "GET", "/api/auctions/heydealer/cars")
		r.Header.Set("Accept-Encoding", scraperAE)
		if w := serve(t, sig, r); w.Code != code(200) || sig.bans.banned(sig.Name, netip.MustParseAddr(ip), now) == c.spare {
			t.Errorf("%s, a signature: %d, banned %v", c.name, w.Code, sig.bans.banned(sig.Name, netip.MustParseAddr(ip), now))
		}

		pf := pageFirsting(t, &now, "enforce")
		pf.yandex = newYandexStore(c.dns())
		if w := serve(t, pf, robot.request(pf, "GET", "/api/x")); w.Code != code(200) {
			t.Errorf("%s, page_first: %d", c.name, w.Code)
		}

		rh := rhythming(t, &now, "enforce")
		rh.yandex = newYandexStore(c.dns())
		files(t, rh, &now, robot, 6, time.Second)
		if got, _ := apiOf(t, rh, robot, "/api/x"); got != code(200) {
			t.Errorf("%s, static_rhythm: %d", c.name, got)
		}
	}
}

// Requests of one address while its lookup is in flight wait for it and ask no DNS of their own.
func TestYandexOneLookupPerAddress(t *testing.T) {
	a := netip.MustParseAddr("213.180.203.222")
	release := make(chan struct{})
	dns := &fakeDNS{
		ptr: func(netip.Addr) ([]string, error) { <-release; return []string{"spider.yandex.com."}, nil },
		fwd: func(string) ([]netip.Addr, error) { return []netip.Addr{a}, nil },
	}
	s := newYandexStore(dns)
	now := time.Now()
	var wg sync.WaitGroup
	got := make([]yandexVerdict, 20)
	for i := range got {
		wg.Add(1)
		go func() { defer wg.Done(); got[i] = s.ask(a, now) }()
	}
	for {
		s.mu.Lock()
		in := len(s.calls)
		s.mu.Unlock()
		if in == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // the rest reach the wait
	close(release)
	wg.Wait()
	for i, v := range got {
		if v != yandexYes {
			t.Errorf("request %d: %v", i, v)
		}
	}
	if n := dns.ptrs.Load(); n != 1 {
		t.Errorf("%d lookups", n)
	}
}

// The store holds at most yandexEntries addresses; a full one drops the expired ones first.
func TestYandexBounded(t *testing.T) {
	s := newYandexStore(static(nil, notFound))
	now := time.Now()
	old := netip.MustParseAddr("10.0.0.1")
	s.answers[old] = yandexEntry{yandexYes, now.Add(-time.Second)}
	kept := netip.MustParseAddr("10.0.0.2")
	s.answers[kept] = yandexEntry{yandexYes, now.Add(time.Hour)}
	for i := 0; len(s.answers) < yandexEntries; i++ {
		s.answers[netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})] = yandexEntry{yandexNo, now.Add(time.Hour)}
	}
	s.ask(netip.MustParseAddr("213.180.203.222"), now)
	if _, ok := s.answers[old]; ok || len(s.answers) != yandexEntries {
		t.Errorf("the expired answer kept: %v, %d answers", ok, len(s.answers))
	}
	if _, ok := s.answers[kept]; !ok {
		t.Error("a live answer dropped while an expired one made room")
	}
	for i := range 100 {
		s.ask(netip.AddrFrom4([4]byte{11, 0, 0, byte(i)}), now)
	}
	if len(s.answers) != yandexEntries {
		t.Errorf("%d answers", len(s.answers))
	}
}

// Only the search robots' names ask DNS.
func TestYandexRobotUA(t *testing.T) {
	for ua, want := range map[string]bool{
		yandexBotUA: true,
		yandexUA:    true,
		"Mozilla/5.0 (compatible; YandexMobileBot/3.0; +http://yandex.com/bots)": true,
		"Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)":    true,
		"Mozilla/5.0 (compatible; YandexVideo/3.0; +http://yandex.com/bots)":     true,
		yandexTranslateUA:  false,
		yandexScreenshotUA: false,
		"Mozilla/5.0 (compatible; YandexMetrika/2.0; +http://yandex.com/bots)": false,
		"Mozilla/5.0 (compatible; YandexBot)":                                  false,
		googleUA:                                                               false,
		chromeUA + " YaBrowser/25.8.0.0":                                       false,
	} {
		if yandexRobotUA(ua) != want {
			t.Errorf("%q: %v", ua, !want)
		}
	}
}
