package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const policyRead = "sh -c if [ -f '.boks/_server/policy.json' ]"

// Every server is asked before any changes: b has moved past the file's revision, so a is not
// touched either — a refusal halfway down the list would leave the fleet on two policies. No
// boks.yml is read: server.yml belongs to the server.
func TestServerApplyAsksEveryServerFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte("servers: [a, b]\nrevision: 4\nbots:\n  block:\n    - {name: crawlers, user_agent: gptbot}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &recorder{server: server{policyRead: "present\n{\"revision\":3,\"floor\":3}"}}
	b := &recorder{server: server{policyRead: "present\n{\"revision\":5,\"floor\":5}"}}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	var errw strings.Builder
	if code := run([]string{"-f", filepath.Join(dir, "missing-boks.yml"), "server", "apply", path}, io.Discard, &errw); code != 1 {
		t.Fatalf("want a refusal, got %d", code)
	}
	if !strings.Contains(errw.String(), "b: server.yml is revision 4, but this server has applied up to 5") {
		t.Errorf("want b named: %s", errw.String())
	}
	if a.ran("ln -sn") || len(a.stdin) > 0 {
		t.Errorf("a was changed before b was asked: %v", a.calls)
	}
}
