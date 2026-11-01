package remote

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Local runs a command as SSH does on a server: quoted, through sh, from its directory, with the
// output trimmed — so a path relative to the home names the same file either way.
func TestLocalRunsFromItsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "it's here"), []byte("  found\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := Local{Dir: dir}.Run(context.Background(), "cat", "it's here")
	if err != nil || out != "found" {
		t.Errorf("Run = %q, %v; want the file's content, trimmed", out, err)
	}
	out, err = Local{Dir: dir}.Run(context.Background(), "pwd", "-P")
	want, _ := filepath.EvalSymlinks(dir)
	if err != nil || out != want {
		t.Errorf("pwd = %q, %v; want %s", out, err, want)
	}
}

func TestLocalPipesItsInput(t *testing.T) {
	out, err := Local{Dir: t.TempDir()}.Pipe(context.Background(), []byte("a; b\n"), "cat")
	if err != nil || out != "a; b" {
		t.Errorf("Pipe = %q, %v", out, err)
	}
}

// A failure names the command and carries what it said on stderr.
func TestLocalFailureSaysWhy(t *testing.T) {
	_, err := Local{Dir: t.TempDir()}.Run(context.Background(), "sh", "-c", "echo broken >&2; exit 3")
	if err == nil || !strings.HasPrefix(err.Error(), "sh:") || !strings.Contains(err.Error(), "broken") {
		t.Errorf("err = %v", err)
	}
}
