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

// Upload writes content to remotePath with mode 0600, creating parent directories.
func Upload(ctx context.Context, r Runner, content []byte, remotePath string) error {
	_, err := r.Pipe(ctx, content, "sh", "-c",
		"umask 077 && mkdir -p "+Quote(path.Dir(remotePath))+" && cat > "+Quote(remotePath))
	return err
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
