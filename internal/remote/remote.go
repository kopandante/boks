package remote

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"strings"
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
// run something that never existed.
func UploadAtomic(ctx context.Context, r Runner, content []byte, remotePath string) error {
	tmp := remotePath + ".tmp"
	script := "umask 077 && mkdir -p " + Quote(path.Dir(remotePath)) +
		" && cat > " + Quote(tmp) + " && mv " + Quote(tmp) + " " + Quote(remotePath)
	if _, err := r.Pipe(ctx, content, "sh", "-c", script); err != nil {
		return fmt.Errorf("write %s: %w", remotePath, err)
	}
	return nil
}

// Append adds a line to a file, creating it if needed. Used for the operation journal, where the
// order of entries is the information.
func Append(ctx context.Context, r Runner, content []byte, remotePath string) error {
	script := "umask 077 && mkdir -p " + Quote(path.Dir(remotePath)) + " && cat >> " + Quote(remotePath)
	if _, err := r.Pipe(ctx, content, "sh", "-c", script); err != nil {
		return fmt.Errorf("append %s: %w", remotePath, err)
	}
	return nil
}

// SSH runs commands through the system ssh client, so ~/.ssh/config, agents and
// ProxyJump apply without any configuration of our own.
type SSH struct {
	Host string
}

func (s SSH) Run(ctx context.Context, args ...string) (string, error) {
	return s.exec(ctx, nil, args[0], Shell(args...))
}

func (s SSH) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	return s.exec(ctx, content, args[0], Shell(args...))
}

// exec runs script on the host; label names the command in errors (the server itself is
// named by the caller, which iterates servers).
func (s SSH) exec(ctx context.Context, stdin []byte, label, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", s.Host, script)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
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
