//go:build unix

package remote

import (
	"context"
	"os/exec"
	"syscall"
)

// command starts a child in a process group of its own. A Ctrl-C at the terminal goes to the whole
// foreground group, and ssh dies on SIGINT: in boks's group it would be cut off under every command,
// including the ones boks runs to the end on purpose — the stop of an old copy, the cleanup after an
// interrupt. In a group of its own it hears nothing from the terminal; boks gets the signal, cancels
// the run's context, and the context is what ends the commands that may be ended.
func command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}
