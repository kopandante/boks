//go:build unix

package remote

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A child runs in a process group of its own, so the terminal's Ctrl-C — SIGINT to boks's whole
// group — does not reach it: boks alone decides, through the context, which commands an interrupt
// ends. The scene is played in a helper process with a group of its own, standing in for boks, so
// the SIGINT stays inside it and never reaches the test runner.
func TestAChildDoesNotHearTheTerminal(t *testing.T) {
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperBoks$")
	helper.Env = append(os.Environ(), "BOKS_HELPER=1")
	helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := helper.Output()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if verdict, ok := strings.CutPrefix(sc.Text(), "child: "); ok {
			if verdict != "alive" {
				t.Fatalf("the child heard the group's SIGINT: %s", verdict)
			}
			return
		}
	}
	t.Fatalf("no verdict from the helper:\n%s", out)
}

// TestHelperBoks is the boks side of the scene above; it runs only inside that helper.
func TestHelperBoks(t *testing.T) {
	if os.Getenv("BOKS_HELPER") != "1" {
		t.Skip("helper for TestAChildDoesNotHearTheTerminal")
	}
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, os.Interrupt) // boks catches the first Ctrl-C
	child := command(context.Background(), "sleep", "5")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	if err := syscall.Kill(-syscall.Getpgrp(), syscall.SIGINT); err != nil { // what the terminal does
		t.Fatal(err)
	}
	<-caught
	select {
	case err := <-exited:
		fmt.Printf("child: died (%v)\n", err)
	case <-time.After(300 * time.Millisecond):
		fmt.Println("child: alive")
		_ = child.Process.Kill()
		<-exited
	}
}

// The context still ends a child: cancelling it is how an interrupt reaches the commands it may end.
func TestTheContextStillEndsAChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := command(ctx, "sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling the context did not end the child")
	}
}
