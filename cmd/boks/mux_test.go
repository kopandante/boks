package main

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runWithFakeSSH runs boks with the production connect and an ssh on PATH that records its
// arguments and exits with code, and returns the recorded calls.
func runWithFakeSSH(t *testing.T, config string, code string, args ...string) (int, []string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	log := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\nexit " + code + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BOKS_SSH_MUX", "")
	if err := os.WriteFile("boks.yml", []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := run(args, io.Discard, io.Discard)
	b, _ := os.ReadFile(log)
	return rc, strings.Split(strings.TrimSpace(string(b)), "\n")
}

var controlDir = regexp.MustCompile(`ControlPath=(/tmp/boks-[^/ ]+)/%C`)

// checkShared asserts that every call to the servers went through one directory of the run, that
// the run closed its connection to each of them, and that the directory is gone.
func checkShared(t *testing.T, calls []string, servers ...string) {
	t.Helper()
	m := controlDir.FindStringSubmatch(calls[0])
	if m == nil {
		t.Fatalf("want calls through the run's shared connection, got:\n%s", strings.Join(calls, "\n"))
	}
	dir := m[1]
	for _, s := range servers {
		reached, closed := false, false
		for _, c := range calls {
			if !strings.Contains(c, "ControlPath="+dir+"/%C") {
				t.Errorf("a call outside the run's directory %s: %q", dir, c)
			}
			reached = reached || strings.Contains(c, "ControlMaster=auto") && strings.Contains(c, " "+s+" ")
			closed = closed || c == "-o ControlPath="+dir+"/%C -O exit "+s
		}
		if !reached || !closed {
			t.Errorf("server %s: reached %v, closed %v, calls:\n%s", s, reached, closed, strings.Join(calls, "\n"))
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("want the run's socket directory removed: %v", err)
	}
}

// A command reaches every server through the run's shared connections and closes them at the end.
func TestRunSharesConnectionsAndClosesThem(t *testing.T) {
	rc, calls := runWithFakeSSH(t, "app: demo\nimage: x\nservers: [a, b]\n", "0", "ps")
	if rc != 0 {
		t.Fatalf("ps failed: %d", rc)
	}
	checkShared(t, calls, "a", "b")
}

// cert pull goes through the same connections, and a command that fails still closes them.
func TestCertPullSharesTheConnectionAndAFailureClosesIt(t *testing.T) {
	cfg := "app: demo\nimage: x\nservers: [a, b]\ncert: {domains: ['*.x.y'], dns: cloudflare, email: a@b.c}\n"
	rc, calls := runWithFakeSSH(t, cfg, "1", "cert", "pull")
	if rc != 1 {
		t.Fatalf("want cert pull to fail on a server that refuses, got %d", rc)
	}
	checkShared(t, calls, "a")
}
