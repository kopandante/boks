package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

// boks#178: `proxy upgrade` from a config that does not name proxy_image must stop before it opens a
// connection to any server — the built-in image is older than what a server runs, and taking it would
// swap the proxy of the whole node for an old one. --force lifts the refusal to go back to an older
// image, not the refusal to guess one.
func TestProxyUpgradeWithoutProxyImageIsRefusedBeforeTheServer(t *testing.T) {
	cfg, err := config.Parse([]byte("app: demo\nimage: ghcr.io/x/y\nservers: [boks-test-no-such-server.invalid]\nports:\n  - {name: web, port: 3000, host: demo.example.com}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"upgrade"}, {"upgrade", "--force"}} {
		var out bytes.Buffer
		err := proxyCmd(context.Background(), cfg, args, &out)
		if err == nil || !strings.Contains(err.Error(), "no proxy_image in the config") {
			t.Errorf("%v: want the refusal, got %v", args, err)
		}
		if strings.Contains(out.String(), "==") {
			t.Errorf("%v: a server was visited (%q): the refusal came too late", args, out.String())
		}
	}
}
