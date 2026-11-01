package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// originDir holds the certificates the live test of the origin pull runs with (proxy/gate,
// TestOriginPullThroughCaddy) and the connection policies boks writes for them, which it loads.
const originDir = "../../proxy/gate/testdata/originpull/"

// testCA is the test CA's certificate as the policy holds it, DER.
func testCA(t *testing.T) [][]byte {
	t.Helper()
	b, err := os.ReadFile(originDir + "ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	return [][]byte{blk.Bytes}
}

// pulled is a policy whose proxy in front, 127.0.0.1, brings a certificate of the test CA, with a ban.
func pulled(t *testing.T) Policy {
	return Policy{Revision: 1, TrustedProxies: []string{"127.0.0.1/32"}, TrustedProxiesCA: testCA(t),
		Ban: &Ban{Duration: "24h", Rules: []BanRule{{Name: "default", Limit: 300, Window: "1m", Class: "all"}}, ExemptRanges: []string{"203.0.113.9/32"}}}
}

var pulledRoutes = []Fragment{{App: "a", Routes: []Route{{Host: "a.example.com", Dial: "a:1", TLS: true}, {Host: "p.example.com", Dial: "a:2"}}}}

// With the CA, 443 asks a connection from the proxies for a client certificate of it and refuses one
// without at the handshake, while a visitor from anywhere else is asked for none; it keeps trusting
// the proxies' headers, which only a certificate lets in now, and leaves strict_sni_host off. The
// policies are the ones the live test loads into Caddy.
func TestOriginPullAsksTheProxiesForTheCertificate(t *testing.T) {
	b, err := Config(pulled(t), pulledRoutes)
	if err != nil {
		t.Fatal(err)
	}
	https := dig(decoded(t, b), "apps", "http", "servers", "https")
	got, _ := json.MarshalIndent(dig(https, "tls_connection_policies"), "", "  ")
	got = append(got, '\n')
	if os.Getenv("BOKS_UPDATE") == "1" {
		if err := os.WriteFile(originDir+"policies.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(originDir + "policies.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("tls_connection_policies\n%s\nwant (%s, BOKS_UPDATE=1 to rewrite)\n%s", got, originDir+"policies.json", want)
	}
	for _, s := range []string{`"remote_ip": {`, `"ranges": [`, `"127.0.0.1/32"`, `"provider": "inline"`, `"mode": "require_and_verify"`, "},\n  {}\n]"} {
		if !strings.Contains(string(got), s) {
			t.Errorf("want %s in the policies: %s", s, got)
		}
	}
	if dig(https, "strict_sni_host") != false {
		t.Errorf("want strict_sni_host off, got %v", dig(https, "strict_sni_host"))
	}
	if trusted, _ := json.Marshal(dig(https, "trusted_proxies")); string(trusted) != `{"ranges":["127.0.0.1/32"],"source":"static"}` {
		t.Errorf("443: want the proxies trusted, got %s", trusted)
	}
}

// Plain HTTP carries no certificate: with the CA, 80 trusts no one, and its ban counts the proxies'
// nodes no more — the client there is the node, whose ban would refuse every visitor it carries. 443
// keeps counting them as written: there they are the client only when they say so with a certificate.
func TestOriginPullTrustsNoOneOnPlainHTTP(t *testing.T) {
	b, err := Config(pulled(t), pulledRoutes)
	if err != nil {
		t.Fatal(err)
	}
	m := decoded(t, b)
	http := dig(m, "apps", "http", "servers", "http")
	for _, k := range []string{"trusted_proxies", "client_ip_headers", "trusted_proxies_strict", "tls_connection_policies"} {
		if v := dig(http, k); v != nil {
			t.Errorf("80: want no %s, got %v", k, v)
		}
	}
	exempt := func(srv string) string {
		routes, _ := dig(m, "apps", "http", "servers", srv, "routes").([]any)
		h := dig(routes[0], "handle").([]any)[0]
		if dig(h, "handler") != "boks_ban" {
			t.Fatalf("%s: want the ban first, got %v", srv, h)
		}
		got, _ := json.Marshal(dig(h, "exempt_ranges"))
		return string(got)
	}
	if got := exempt("http"); got != `["203.0.113.9/32","127.0.0.1/32"]` {
		t.Errorf("80: ban exempt_ranges %s", got)
	}
	if got := exempt("https"); got != `["203.0.113.9/32"]` {
		t.Errorf("443: ban exempt_ranges %s", got)
	}
	// The policy's own ban is left as it was: the exemption is the server's on 80 alone.
	if p := pulled(t); len(p.Ban.ExemptRanges) != 1 {
		t.Errorf("the policy's ban changed: %v", p.Ban.ExemptRanges)
	}
}

// Without the CA nothing of it is written: the config is the one boks wrote before.
func TestNoCAWritesNoConnectionPolicies(t *testing.T) {
	p := pulled(t)
	p.TrustedProxiesCA = nil
	b, err := Config(p, pulledRoutes)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"tls_connection_policies", "strict_sni_host", "client_authentication"} {
		if strings.Contains(string(b), s) {
			t.Errorf("want no %s without the CA", s)
		}
	}
	m := decoded(t, b)
	for _, srv := range []string{"http", "https"} {
		if dig(m, "apps", "http", "servers", srv, "trusted_proxies") == nil {
			t.Errorf("%s: want the proxies trusted without the CA", srv)
		}
	}
}

// The CA needs format 11, above a key: a boks of format 10 would read the policy without it and trust
// the headers of every connection from the proxies' addresses again. Without it the marker stays what
// the rest of the policy asks, so a server stays open to older boks.
func TestOriginPullMarksFormat11(t *testing.T) {
	keyed := spared()
	keyed.TrustedProxies, keyed.TrustedProxiesCA = []string{"127.0.0.1/32"}, testCA(t)
	for _, c := range []struct {
		name string
		p    Policy
		want int
	}{{"pulled", pulled(t), OriginPullFormat}, {"pulled and keyed", keyed, OriginPullFormat}, {"plain", habsida, FragmentFormat}, {"keyed", spared(), KeyFormat}} {
		if got := policyFormat(c.p); got != c.want {
			t.Errorf("%s: want format %d, got %d", c.name, c.want, got)
		}
	}
	d := newDisk()
	if _, err := SetRoutes(context.Background(), d, io.Discard, "demo", web); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicy(context.Background(), d, io.Discard, pulled(t)); err != nil {
		t.Fatal(err)
	}
	if marker := d.files[Dir+"/routes/_server.json"]; marker != "11\n" {
		t.Errorf("want the marker at 11: %q", marker)
	}
	if !strings.Contains(d.files[policyPath()], `"trusted_proxies_ca"`) {
		t.Errorf("want the CA in the policy: %s", d.files[policyPath()])
	}
}

// The status names the certificate's CA, or says only whom the headers are trusted from without one.
func TestTrustedString(t *testing.T) {
	if got := TrustedString(Policy{}); got != "" {
		t.Errorf("none: %q", got)
	}
	p := pulled(t)
	if got := TrustedString(p); got != "X-Forwarded-For trusted from 127.0.0.1/32 over TLS only, with a client certificate of CN=boks test origin-pull CA; the rest refused at the handshake" {
		t.Errorf("with the CA: %q", got)
	}
	p.TrustedProxiesCA = nil
	if got := TrustedString(p); got != "X-Forwarded-For trusted from 127.0.0.1/32" {
		t.Errorf("without: %q", got)
	}
}

// Apply and rollback refuse a CA out of force — the proxies in front would be refused at the handshake —
// and take one in force, or none.
func TestCheckCATerm(t *testing.T) {
	p := pulled(t)
	for _, now := range []time.Time{time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if err := CheckCATerm(p, now); err == nil || !strings.Contains(err.Error(), "trusted_proxies_ca: certificate 1 (CN=boks test origin-pull CA) is valid from") {
			t.Errorf("at %s: want the CA refused out of force, got %v", now.Format(time.DateOnly), err)
		}
	}
	if err := CheckCATerm(p, time.Now()); err != nil {
		t.Errorf("want the CA in force taken: %v", err)
	}
	if err := CheckCATerm(Policy{}, time.Now()); err != nil {
		t.Errorf("want a policy without a CA taken: %v", err)
	}
}
