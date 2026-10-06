package remote

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSSH puts an ssh on PATH that records its arguments, one call per line, then runs body.
func fakeSSH(t *testing.T, body string) (log string) {
	t.Helper()
	bin := t.TempDir()
	log = filepath.Join(bin, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n" + body
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	b, _ := os.ReadFile(log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// Calls of one run share a connection per server through a socket in the run's own directory, and
// Close ends exactly the connections this run opened, on every server, then removes the directory.
// A run side by side has its own directory and keeps it.
func TestMuxSharesAConnectionPerRunAndClosesIt(t *testing.T) {
	log := fakeSSH(t, "")
	t.Setenv("BOKS_SSH_MUX", "")
	m, err := NewMux()
	if err != nil || m == nil {
		t.Fatalf("want a mux, got %v %v", m, err)
	}
	other, err := NewMux()
	if err != nil || other == nil {
		t.Fatalf("want a second mux, got %v %v", other, err)
	}
	defer other.Close()
	if other.dir == m.dir {
		t.Fatalf("two runs share the socket directory %s", m.dir)
	}
	if !strings.HasPrefix(m.dir, "/tmp/boks-") || len(m.dir)+1+40 > 100 {
		t.Errorf("want a short socket directory under /tmp, got %s", m.dir)
	}
	for _, host := range []string{"a", "a", "b"} {
		if _, err := m.SSH(host).Run(context.Background(), "true"); err != nil {
			t.Fatal(err)
		}
	}
	m.Close()
	got := calls(t, log)
	if len(got) != 5 {
		t.Fatalf("want three shared calls and two exits, got:\n%s", strings.Join(got, "\n"))
	}
	for i, host := range []string{"a", "a", "b"} {
		want := "-o ControlMaster=auto -o ControlPath=" + m.dir + "/%C -o ControlPersist=60s " + host + " "
		if !strings.Contains(got[i], want) {
			t.Errorf("call %d: want %q in %q", i, want, got[i])
		}
	}
	exits := got[3:]
	slices.Sort(exits)
	if exits[0] != "-o ControlPath="+m.dir+"/%C -O exit a" || exits[1] != "-o ControlPath="+m.dir+"/%C -O exit b" {
		t.Errorf("want this run's connections to a and b closed, got %q", exits)
	}
	if _, err := os.Stat(m.dir); !os.IsNotExist(err) {
		t.Errorf("want the socket directory removed: %v", err)
	}
	if _, err := os.Stat(other.dir); err != nil {
		t.Errorf("closing one run removed another's directory: %v", err)
	}
}

// BOKS_SSH_MUX=0 turns sharing off: a call per connection, as before, and nothing to close.
func TestMuxCanBeTurnedOff(t *testing.T) {
	log := fakeSSH(t, "")
	t.Setenv("BOKS_SSH_MUX", "0")
	m, err := NewMux()
	if err != nil || m != nil {
		t.Fatalf("want no mux, got %v %v", m, err)
	}
	if _, err := m.SSH("a").Run(context.Background(), "true"); err != nil {
		t.Fatal(err)
	}
	m.Close()
	b, _ := os.ReadFile(log)
	if strings.Contains(string(b), "Control") || strings.Count(string(b), "\n") != 1 {
		t.Errorf("want one plain call: %s", b)
	}
}

// A call cut off by its context returns at it even when something outlives the killed ssh and holds
// its output open — what a ControlMaster does while the remote command of that session still runs.
// Deadlines in deploy and proxy (health probe, drain, proxy answer) rely on this.
func TestCancelledCallEndsAtItsContext(t *testing.T) {
	holder := filepath.Join(t.TempDir(), "holder")
	fakeSSH(t, "sleep 30 &\necho $! > "+holder+"\nsleep 30\n")
	t.Cleanup(func() {
		if b, err := os.ReadFile(holder); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p.Kill()
				}
			}
		}
	})
	// Cancel once the holder runs: from then on only WaitDelay can end the call.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cancelled time.Time
	go func() {
		for {
			if b, _ := os.ReadFile(holder); len(b) > 0 {
				cancelled = time.Now()
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	_, err := SSH{Host: "a", ControlDir: t.TempDir()}.Run(ctx, "sleep", "30")
	if err == nil {
		t.Fatal("want the cancelled call to fail")
	}
	if took := time.Since(cancelled); took > waitDelay+5*time.Second {
		t.Errorf("the call outlived its context by %s", took)
	}
}
