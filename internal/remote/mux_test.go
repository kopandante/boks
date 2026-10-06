package remote

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSSH puts an ssh on PATH that records its arguments, one call per line.
func fakeSSH(t *testing.T) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(bin, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// Calls of one run share a connection per server through a socket in the run's own directory, and
// Close ends exactly the connections this run opened, then removes the directory.
func TestMuxSharesAConnectionPerRunAndClosesIt(t *testing.T) {
	log := fakeSSH(t)
	t.Setenv("BOKS_SSH_MUX", "")
	m, err := NewMux()
	if err != nil || m == nil {
		t.Fatalf("want a mux, got %v %v", m, err)
	}
	if !strings.HasPrefix(m.dir, "/tmp/boks-") || len(m.dir)+1+40 > 100 {
		t.Errorf("want a short socket directory under /tmp, got %s", m.dir)
	}
	if _, err := m.SSH("a").Run(context.Background(), "true"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SSH("a").Run(context.Background(), "true"); err != nil {
		t.Fatal(err)
	}
	m.Close()
	calls, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	want := "-o ControlMaster=auto -o ControlPath=" + m.dir + "/%C -o ControlPersist=60s a"
	if len(lines) != 3 || !strings.Contains(lines[0], want) || !strings.Contains(lines[1], want) {
		t.Fatalf("want two shared calls, got:\n%s", calls)
	}
	if lines[2] != "-o ControlPath="+m.dir+"/%C -O exit a" {
		t.Errorf("want this run's connection to a closed, got %q", lines[2])
	}
	if _, err := os.Stat(m.dir); !os.IsNotExist(err) {
		t.Errorf("want the socket directory removed: %v", err)
	}
}

// BOKS_SSH_MUX=0 turns sharing off: a call per connection, as before, and nothing to close.
func TestMuxCanBeTurnedOff(t *testing.T) {
	log := fakeSSH(t)
	t.Setenv("BOKS_SSH_MUX", "0")
	m, err := NewMux()
	if err != nil || m != nil {
		t.Fatalf("want no mux, got %v %v", m, err)
	}
	if _, err := m.SSH("a").Run(context.Background(), "true"); err != nil {
		t.Fatal(err)
	}
	m.Close()
	calls, _ := os.ReadFile(log)
	if strings.Contains(string(calls), "Control") || strings.Count(string(calls), "\n") != 1 {
		t.Errorf("want one plain call: %s", calls)
	}
}
