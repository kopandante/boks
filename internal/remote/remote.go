package remote

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Runner executes commands on one server.
type Runner interface {
	// Run executes args as a single command and returns its trimmed stdout.
	Run(ctx context.Context, args ...string) (string, error)
	// Pipe executes args with content on stdin and returns its trimmed stdout.
	Pipe(ctx context.Context, content []byte, args ...string) (string, error)
}

// Upload writes content to remotePath with mode 0600, creating parent directories. The path is
// named in the error: the underlying command is a shell script, so without this a failure reads
// only as "sh".
func Upload(ctx context.Context, r Runner, content []byte, remotePath string) error {
	_, err := r.Pipe(ctx, content, "sh", "-c",
		"umask 077 && mkdir -p "+Quote(path.Dir(remotePath))+" && cat > "+Quote(remotePath))
	if err != nil {
		return fmt.Errorf("upload %s: %w", remotePath, err)
	}
	return nil
}

// UploadAtomic writes content so that a reader never sees a partial file: the bytes land in a
// neighbouring temporary file and are moved into place with rename, which is atomic within a
// filesystem. A half-written release snapshot would be worse than a missing one — rollback would
// run something that never existed. The rename also waits for the byte count: a connection that
// drops mid-transfer ends `cat` with a plain end of input, which it reports as success.
func UploadAtomic(ctx context.Context, r Runner, content []byte, remotePath string) error {
	tmp := Quote(remotePath + ".tmp")
	script := "umask 077 && mkdir -p " + Quote(path.Dir(remotePath)) + " && cat > " + tmp +
		" && { [ $(($(wc -c < " + tmp + "))) -eq " + strconv.Itoa(len(content)) + " ] || { rm -f " + tmp + "; exit 1; }; }" +
		" && mv " + tmp + " " + Quote(remotePath)
	if _, err := r.Pipe(ctx, content, "sh", "-c", script); err != nil {
		return fmt.Errorf("write %s: %w", remotePath, err)
	}
	return nil
}

// Append adds a line to a file, creating it if needed. Used for the operation journal, where the
// order of entries is the information. An earlier append cut short (a full disk) can leave the file
// ending mid-line; the new content then starts on a line of its own instead of being glued to that
// fragment, which would make a reader skip both.
func Append(ctx context.Context, r Runner, content []byte, remotePath string) error {
	q := Quote(remotePath)
	script := "umask 077 && mkdir -p " + Quote(path.Dir(remotePath)) +
		" && { if [ -s " + q + " ] && [ -n \"$(tail -c 1 " + q + ")\" ]; then echo >> " + q + "; fi; } && cat >> " + q
	if _, err := r.Pipe(ctx, content, "sh", "-c", script); err != nil {
		return fmt.Errorf("append %s: %w", remotePath, err)
	}
	return nil
}

// SSH runs commands through the system ssh client, so ~/.ssh/config, agents and
// ProxyJump apply without any configuration of our own.
type SSH struct {
	Host string
	// ControlDir, when set, holds the socket of one SSH connection per server that every call of
	// this run shares (see Mux); empty opens a connection per call.
	ControlDir string
}

// Mux shares one SSH connection per server across a run. Each call used to open its own, and to a
// distant server that is seconds per call — in a stop-first deploy, seconds the app is down between
// stopping the old copy and starting the new one. The sockets live in a directory of this run
// alone, so runs side by side never close each other's connections, and Close ends the ones this
// run opened. A nil Mux shares nothing.
type Mux struct {
	dir  string
	used map[string]bool
}

// NewMux makes the run's socket directory, under /tmp: a socket path is capped at about 100 bytes,
// and a macOS $TMPDIR alone takes half of that. BOKS_SSH_MUX=0 turns sharing off.
func NewMux() (*Mux, error) {
	if os.Getenv("BOKS_SSH_MUX") == "0" {
		return nil, nil
	}
	dir, err := os.MkdirTemp("/tmp", "boks-")
	if err != nil {
		return nil, fmt.Errorf("making the ssh socket directory: %w", err)
	}
	return &Mux{dir: dir, used: map[string]bool{}}, nil
}

// SSH is the runner for host, sharing this run's connection to it.
func (m *Mux) SSH(host string) SSH {
	if m == nil {
		return SSH{Host: host}
	}
	m.used[host] = true
	return SSH{Host: host, ControlDir: m.dir}
}

// Close ends the connections this run opened and removes their directory. A connection left by a
// run that died ends by itself once idle for ControlPersist.
func (m *Mux) Close() {
	if m == nil {
		return
	}
	for h := range m.used {
		_ = exec.Command("ssh", "-o", "ControlPath="+controlPath(m.dir), "-O", "exit", h).Run()
	}
	_ = os.RemoveAll(m.dir)
}

// waitDelay is how long a call waits for its output to close once its ssh is gone (see exec).
const waitDelay = 2 * time.Second

// controlPath is the socket of one connection in dir: %C is ssh's hash of the user, host, port and
// jump host, so two servers never share one.
func controlPath(dir string) string { return filepath.Join(dir, "%C") }

func (s SSH) Run(ctx context.Context, args ...string) (string, error) {
	return s.exec(ctx, nil, args[0], Shell(args...))
}

func (s SSH) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	return s.exec(ctx, content, args[0], Shell(args...))
}

// exec runs script on the host; label names the command in errors (the server itself is
// named by the caller, which iterates servers).
func (s SSH) exec(ctx context.Context, stdin []byte, label, script string) (string, error) {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=15"}
	if s.ControlDir != "" {
		// Options on the command line win over ~/.ssh/config, so a ControlMaster of the user's own
		// does not take these connections into a socket another process may close.
		args = append(args, "-o", "ControlMaster=auto", "-o", "ControlPath="+controlPath(s.ControlDir), "-o", "ControlPersist=60s")
	}
	cmd := exec.CommandContext(ctx, "ssh", append(args, s.Host, script)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	// A cancelled call ends at its context even when something else holds its output open: a
	// ControlMaster keeps the descriptors of a session whose remote command still runs, and without
	// this bound a call cut off by its deadline would wait for that command to finish.
	cmd.WaitDelay = waitDelay
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", label, err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// Quote single-quotes s for a POSIX shell.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Shell joins args into one quoted command line.
func Shell(args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = Quote(a)
	}
	return strings.Join(q, " ")
}
