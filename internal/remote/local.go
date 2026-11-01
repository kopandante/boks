package remote

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Local runs commands on the machine boks runs on, as SSH runs them on a server: the same script
// through sh, from Dir — the home directory, where ssh starts — so the paths boks writes relative to
// the home are the same ones. It is how the server's own boks reaches the server.
type Local struct {
	Dir string
}

func (l Local) Run(ctx context.Context, args ...string) (string, error) {
	return l.exec(ctx, nil, args)
}

func (l Local) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	return l.exec(ctx, content, args)
}

func (l Local) exec(ctx context.Context, stdin []byte, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", Shell(args...))
	cmd.Dir = l.Dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	// As SSH: a cancelled call ends at its context even when a child of the command holds its output.
	cmd.WaitDelay = waitDelay
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}
