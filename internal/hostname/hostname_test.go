package hostname

import "testing"

// One host to Caddy is one host here: Unicode and its punycode, in any ASCII case, a wildcard's
// rest converted — and in Caddy's order, so Unicode capitals stay a different host.
func TestCanonicalIsCaddys(t *testing.T) {
	for in, want := range map[string]string{
		"пример.рф":             "xn--e1afmkfd.xn--p1ai",
		"XN--E1AFMKFD.xn--P1AI": "xn--e1afmkfd.xn--p1ai",
		"*.пример.рф":           "*.xn--e1afmkfd.xn--p1ai",
		"Api.Example.COM":       "api.example.com",
		"ПРИМЕР.РФ":             "xn--h0afmkfd.xn--s0ai",
	} {
		if got := Canonical(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	if !Same("пример.рф", "xn--e1afmkfd.xn--p1ai") || Same("пример.рф", "ПРИМЕР.РФ") {
		t.Error("Same disagrees with Canonical")
	}
}
