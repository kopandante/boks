package remote

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// local runs the scripts for real, in a directory of its own, so the tests check what the shell
// does with them rather than how they are spelled.
type local struct{ dir string }

func (l local) Run(ctx context.Context, args ...string) (string, error) {
	return l.Pipe(ctx, nil, args...)
}

func (l local) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = l.dir
	cmd.Stdin = bytes.NewReader(content)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func TestUploadAtomicReplacesTheFileAndLeavesNoTemporary(t *testing.T) {
	l := local{t.TempDir()}
	for _, body := range []string{"first\n", "second\n"} {
		if err := UploadAtomic(context.Background(), l, []byte(body), ".boks/demo/current"); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(l.dir, ".boks/demo/current"))
		if err != nil || string(got) != body {
			t.Fatalf("want %q, got %q (%v)", body, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(l.dir, ".boks/demo/current.tmp")); !os.IsNotExist(err) {
		t.Errorf("the temporary file must be moved into place, not left behind: %v", err)
	}
	if info, _ := os.Stat(filepath.Join(l.dir, ".boks/demo/current")); info.Mode().Perm()&0o077 != 0 {
		t.Errorf("the file is readable by others: %v", info.Mode())
	}
}

// The directories a write creates are the owner's alone: a release's files are made readable by all
// for the container, and only these directories keep other users of the server from them.
func TestUploadAtomicCreatesOwnerOnlyDirectories(t *testing.T) {
	l := local{t.TempDir()}
	if err := UploadAtomic(context.Background(), l, []byte("x"), ".boks/demo/files/demo-v1-1/0-site.conf"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{".boks", ".boks/demo", ".boks/demo/files", ".boks/demo/files/demo-v1-1"} {
		if info, err := os.Stat(filepath.Join(l.dir, d)); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("%s must be 0700: %v %v", d, info, err)
		}
	}
}

func TestAppendKeepsWhatWasThere(t *testing.T) {
	l := local{t.TempDir()}
	for _, line := range []string{"a\n", "b\n"} {
		if err := Append(context.Background(), l, []byte(line), ".boks/demo/journal.jsonl"); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(l.dir, ".boks/demo/journal.jsonl")); string(got) != "a\nb\n" {
		t.Errorf("want both lines in order, got %q", got)
	}
}

// An append cut short leaves the file mid-line; the next entry must still be a line of its own.
func TestAppendStartsANewLineAfterACutShortOne(t *testing.T) {
	l := local{t.TempDir()}
	path := filepath.Join(l.dir, "journal.jsonl")
	if err := os.WriteFile(path, []byte("{\"op\":\"1\"}\n{\"op\":\"2\",\"act"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Append(context.Background(), l, []byte("{\"op\":\"3\"}\n"), "journal.jsonl"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n"); len(lines) != 3 || lines[2] != "{\"op\":\"3\"}" {
		t.Errorf("the new entry must stand on its own line, got %q", got)
	}
}

func TestAppendFailureNamesThePath(t *testing.T) {
	l := local{t.TempDir()}
	if err := os.WriteFile(filepath.Join(l.dir, "blocker"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Append(context.Background(), l, []byte("x\n"), "blocker/journal.jsonl")
	if err == nil || !strings.Contains(err.Error(), "blocker/journal.jsonl") {
		t.Errorf("want an error naming the path, got %v", err)
	}
}

// cut delivers only half of what it is given, the way a connection that drops mid-transfer does:
// the remote end sees a plain end of input.
type cut struct{ local }

func (c cut) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	return c.local.Pipe(ctx, content[:len(content)/2], args...)
}

func TestUploadAtomicKeepsTheOldFileWhenTheTransferIsCut(t *testing.T) {
	l := local{t.TempDir()}
	if err := UploadAtomic(context.Background(), l, []byte("demo-v1-100\n"), "current"); err != nil {
		t.Fatal(err)
	}
	err := UploadAtomic(context.Background(), cut{l}, []byte("demo-v2-200\n"), "current")
	if err == nil || !strings.Contains(err.Error(), "current") {
		t.Fatalf("want an error naming the file, got %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(l.dir, "current")); string(got) != "demo-v1-100\n" {
		t.Errorf("a cut transfer must leave the old file whole, got %q", got)
	}
	if _, err := os.Stat(filepath.Join(l.dir, "current.tmp")); !os.IsNotExist(err) {
		t.Errorf("the partial temporary file must be removed: %v", err)
	}
}
