package ban

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

var (
	partnerKey = strings.Repeat("p", 40)
	partnerSum = sha256.Sum256([]byte(partnerKey))
)

// keyedPolicy bans past 3 requests a minute, flags the storm's clusters past 2 requests from 2 addresses,
// denies 89.167.100.21, and knows glavdoroga's partner key on its hosts.
var keyedPolicy = `{"duration": "24h", "rules": [{"name": "all", "limit": 3, "window": "1m"}],
	"heuristics": {"mode": "ban", "cluster": {"limit": 2, "window": "10m", "min_addresses": 2}},
	"deny_ranges": ["89.167.100.21/32"],
	"bearer": [{"hosts": ["cars.glavdoroga.ru", "*.glavdoroga.ru"], "paths": ["^/api/encar(/|$)"], "methods": ["GET", "HEAD"],
		"digests": ["` + strings.Repeat("0", 64) + `", "` + hex.EncodeToString(partnerSum[:]) + `"]}]}`

// read is a request from ip to host for p with the Authorization header auth, when given.
func read(ip, host, method, p, auth string) *http.Request {
	r := request(ip, p)
	r.Host, r.Method = host, method
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

// A read with a valid key of the group is counted by no rule and passes an address the rules banned;
// the address's other requests are counted and refused as before (todo#419).
func TestAKeyedReadIsNotCounted(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, keyedPolicy)
	ip := "198.51.100.20"
	for i := range 20 {
		if code := serve(t, h, read(ip, "cars.glavdoroga.ru", "GET", "/api/encar/catalog", "Bearer "+partnerKey)); code != 200 {
			t.Fatalf("keyed read %d: %d", i, code)
		}
	}
	if n := shared.len(); n != 0 {
		t.Fatalf("want keyed reads counted by no rule, %d addresses tracked", n)
	}
	for i := range 3 {
		if code := serve(t, h, request(ip, "/")); code != 200 {
			t.Fatalf("plain request %d: %d", i, code)
		}
	}
	if code := serve(t, h, request(ip, "/")); code != 403 {
		t.Fatalf("the plain request past the rule: want 403, got %d", code)
	}
	if code := serve(t, h, read(ip, "Cars.Glavdoroga.RU:443", "HEAD", "/api/encar", "bearer  "+partnerKey+" ")); code != 200 {
		t.Errorf("a keyed read from the banned address: want 200, got %d", code)
	}
	if code := serve(t, h, read(ip, "cars.glavdoroga.ru", "GET", "/en/catalog", "Bearer "+partnerKey)); code != 403 {
		t.Errorf("the banned address outside the key's paths: want 403, got %d", code)
	}
}

// What the key does not let in is counted and banned like any request: another token, a header alone,
// a write, a path or a host outside the group's.
func TestAReadTheKeyDoesNotLetInIsCounted(t *testing.T) {
	cases := []struct{ name, host, method, path, auth string }{
		{"another token", "cars.glavdoroga.ru", "GET", "/api/encar/catalog", "Bearer " + strings.Repeat("q", 40)},
		{"an empty token", "cars.glavdoroga.ru", "GET", "/api/encar/catalog", "Bearer "},
		{"no scheme", "cars.glavdoroga.ru", "GET", "/api/encar/catalog", partnerKey},
		{"a write", "cars.glavdoroga.ru", "POST", "/api/encar/catalog", "Bearer " + partnerKey},
		{"outside its paths", "cars.glavdoroga.ru", "GET", "/api/rates", "Bearer " + partnerKey},
		{"another site", "cars.dbauto.kr", "GET", "/api/encar/catalog", "Bearer " + partnerKey},
		{"two labels under the wildcard", "a.b.glavdoroga.ru", "GET", "/api/encar/catalog", "Bearer " + partnerKey},
		{"a host that ends like it", "xglavdoroga.ru", "GET", "/api/encar/catalog", "Bearer " + partnerKey},
	}
	for _, c := range cases {
		fixture(t)
		h, _ := provisioned(t, keyedPolicy)
		codes := []int{}
		for range 4 {
			codes = append(codes, serve(t, h, read("198.51.100.30", c.host, c.method, c.path, c.auth)))
		}
		if codes[2] != 200 || codes[3] != 403 {
			t.Errorf("%s: want the fourth request banned, got %v", c.name, codes)
		}
	}
}

// A keyed read is not flagged by the heuristics, whatever headers its library sends; the same read with
// another token is, and its cluster is banned.
func TestAKeyedReadIsNotFlagged(t *testing.T) {
	fixture(t)
	h, logs := provisioned(t, keyedPolicy)
	stormRead := func(n int, auth string) *http.Request {
		r := storm.as(home(n), "/api/encar/catalog")
		r.Host = "cars.glavdoroga.ru"
		r.Header.Set("Authorization", auth)
		return r
	}
	for n := range 3 {
		if code := serve(t, h, stormRead(n, "Bearer "+partnerKey)); code != 200 {
			t.Fatalf("keyed read %d: %d", n, code)
		}
	}
	if n, forged := len(shared.prints), logs.FilterMessage("forged request").Len(); n != 0 || forged != 0 {
		t.Fatalf("want keyed reads kept from the heuristics: %d fingerprints, %d lines", n, forged)
	}
	codes := []int{}
	for n := range 3 {
		codes = append(codes, serve(t, h, stormRead(10+n, "Bearer "+strings.Repeat("q", 40))))
	}
	if codes[2] != 403 || len(shared.prints) == 0 {
		t.Errorf("another token: want the cluster flagged and banned, got %v", codes)
	}
	if code := serve(t, h, stormRead(20, "Bearer "+partnerKey)); code != 200 {
		t.Errorf("a keyed read of the banned fingerprint: want 200, got %d", code)
	}
}

// deny_ranges, the owner's own refusal, is stronger than any key.
func TestADeniedAddressIsRefusedWithAKey(t *testing.T) {
	fixture(t)
	h, _ := provisioned(t, keyedPolicy)
	if code := serve(t, h, read("89.167.100.21", "cars.glavdoroga.ru", "GET", "/api/encar/catalog", "Bearer "+partnerKey)); code != 403 {
		t.Errorf("a denied address with a valid key: want 403, got %d", code)
	}
}

// A key without hosts, paths or digests, or with a digest that is no SHA-256, is refused at provision.
func TestABearerMustBeWhole(t *testing.T) {
	for name, b := range map[string]string{
		"no hosts":    `{"paths": ["^/api/"], "digests": ["` + strings.Repeat("0", 64) + `"]}`,
		"no paths":    `{"hosts": ["a.example.com"], "digests": ["` + strings.Repeat("0", 64) + `"]}`,
		"no digests":  `{"hosts": ["a.example.com"], "paths": ["^/api/"]}`,
		"a short one": `{"hosts": ["a.example.com"], "paths": ["^/api/"], "digests": ["abc"]}`,
		"a bad path":  `{"hosts": ["a.example.com"], "paths": ["("], "digests": ["` + strings.Repeat("0", 64) + `"]}`,
	} {
		var h Handler
		if err := json.Unmarshal([]byte(`{"duration": "1h", "bearer": [`+b+`]}`), &h); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		if err := h.Provision(ctx); err == nil || !strings.Contains(err.Error(), "bearer[0]") {
			t.Errorf("%s: want refused, got %v", name, err)
		}
		cancel()
	}
}
