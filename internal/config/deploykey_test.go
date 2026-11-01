package config

import (
	"strings"
	"testing"
)

// edKey is an ed25519 public key made for these tests; no one holds its private half.
const edKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN2dRDHyVokdan3Hc3xKeeo0b3EHb7NRJDfT/T3dozGa"

// A deploy key goes into authorized_keys as its type and base64 alone; options, a second line, a type
// boks does not take and a blob of another type are refused (#154, stage 3).
func TestDeployKey(t *testing.T) {
	if k, err := DeployKey(edKey + " ci@shop"); err != nil || k != edKey {
		t.Errorf("%q %v", k, err)
	}
	for key, want := range map[string]string{
		`command="sh" ` + edKey:          "options before the type",
		"no-pty " + edKey:                "options before the type",
		edKey + "\nssh-ed25519 AAAA":     "one line",
		"ssh-ed25519":                    "one line",
		"ssh-dss AAAAB3NzaC1kc3MAAACBAP": "is none of",
		"ssh-ed25519 !!!":                "not base64",
		"ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIN2dRDHyVokdan3Hc3xKeeo0b3EHb7NRJDfT/T3dozGa": "not a ssh-rsa key",
	} {
		if _, err := DeployKey(key); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", key, err, want)
		}
	}
}

func TestServerDeployKeys(t *testing.T) {
	head := "servers: [a]\n" + commitSum + "apps: {shop: shop.yml}\n"
	if s, err := ParseServer([]byte(head + "deploy_keys: {shop: \"" + edKey + " ci\"}\n")); err != nil || s.DeployKeys["shop"] == "" {
		t.Fatalf("%+v %v", s, err)
	}
	for doc, want := range map[string]string{
		"deploy_keys: {blog: \"" + edKey + "\"}\n":        "blog is not an app of apps",
		"deploy_keys: {shop: \"no-pty " + edKey + "\"}\n": "deploy_keys: shop: type",
	} {
		if _, err := ParseServer([]byte(head + doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", doc, err, want)
		}
	}
}
