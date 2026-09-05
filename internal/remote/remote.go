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
	// Upload writes content to remotePath with mode 0600, creating parent directories.
	Upload(ctx context.Context, content []byte, remotePath string) error
}

// SSH runs commands through the system ssh client, so ~/.ssh/config, agents and
// ProxyJump apply without any configuration of our own.
type SSH struct {
	Host string
}

func (s SSH) Run(ctx context.Context, args ...string) (string, error) {
	return s.exec(ctx, nil, Shell(args...))
}

func (s SSH) Upload(ctx context.Context, content []byte, remotePath string) error {
	script := "umask 077 && " + Shell("mkdir", "-p", path.Dir(remotePath)) + " && cat > " + Quote(remotePath)
	_, err := s.exec(ctx, content, script)
	return err
}

func (s SSH) exec(ctx context.Context, stdin []byte, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", s.Host, script)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s: %w: %s", s.Host, head(script), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func head(script string) string {
	if i := strings.IndexByte(script, ' '); i > 0 && i < 60 {
		return script[:i]
	}
	if len(script) > 60 {
		return script[:60] + "…"
	}
	return script
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
