package config

import (
	"strings"
	"testing"
)

// server.yml's boks names the server's one boks by commit and sha256 per architecture; a commit or a sum
// that is not one, an architecture boks is not built for, and none at all are refused (#154).
func TestServerBoks(t *testing.T) {
	commit, sum := strings.Repeat("a", 40), strings.Repeat("b", 64)
	s, err := ParseServer([]byte("servers: [a]\nboks:\n  commit: " + commit + "\n  sha256: {amd64: " + sum + "}\n"))
	if err != nil || s.Boks == nil || s.Boks.Commit != commit || s.Boks.SHA256["amd64"] != sum {
		t.Fatalf("%+v %v", s, err)
	}
	for doc, want := range map[string]string{
		"boks:\n  commit: abc\n  sha256: {amd64: " + sum + "}\n":                             "boks: commit",
		"boks:\n  commit: " + strings.Repeat("A", 40) + "\n  sha256: {amd64: " + sum + "}\n": "boks: commit",
		"boks:\n  commit: " + commit + "\n":                                                  "boks: sha256: required",
		"boks:\n  commit: " + commit + "\n  sha256: {riscv64: " + sum + "}\n":                "sha256.riscv64",
		"boks:\n  commit: " + commit + "\n  sha256: {amd64: abc}\n":                          "sha256.amd64",
		"boks:\n  commit: " + commit + "\n  version: 2\n":                                    "version",
	} {
		if _, err := ParseServer([]byte("servers: [a]\n" + doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", doc, err, want)
		}
	}
}
