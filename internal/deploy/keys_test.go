package deploy

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const edKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN2dRDHyVokdan3Hc3xKeeo0b3EHb7NRJDfT/T3dozGa"

func writeKeys(t *testing.T, h *home, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(h.dir, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, authorizedKeys), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func keysFile(t *testing.T, h *home) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, authorizedKeys))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The server's own lines stay byte for byte — the last one without its newline, one in CRLF — and boks's
// block follows them, each key bound to deploy-hook of its app under restrict (#154, stage 3).
func TestPutDeployKeysKeepsTheServersLines(t *testing.T) {
	h := newHome(t)
	own := "ssh-ed25519 AAAAown operator\r\n# a note\n\nssh-rsa AAAAx last-without-newline"
	writeKeys(t, h, own)
	if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey, "blog": edKey}); err != nil {
		t.Fatal(err)
	}
	want := own + "\n" + keysBegin + "\n" +
		`command=".boks/bin/boks deploy-hook blog",restrict ` + edKey + " boks-deploy-blog\n" +
		`command=".boks/bin/boks deploy-hook shop",restrict ` + edKey + " boks-deploy-shop\n" + keysEnd + "\n"
	if got := keysFile(t, h); got != want {
		t.Errorf("authorized_keys:\n%q\nwant\n%q", got, want)
	}
	if fi, _ := os.Stat(filepath.Join(h.dir, authorizedKeys)); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", fi.Mode().Perm())
	}
	// Written again with one key: the block is replaced, not added.
	if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey}); err != nil {
		t.Fatal(err)
	}
	got := keysFile(t, h)
	if strings.Count(got, keysBegin) != 1 || strings.Contains(got, "deploy-hook blog") || !strings.HasPrefix(got, own+"\n") {
		t.Errorf("after one key: %q", got)
	}
	// No keys: the block goes, the server's lines stay.
	if err := PutDeployKeys(context.Background(), h, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if got := keysFile(t, h); got != own+"\n" {
		t.Errorf("without keys: %q", got)
	}
}

// Blank lines at the end and leading spaces of the server's lines stay as they are.
func TestPutDeployKeysKeepsBlankLines(t *testing.T) {
	h := newHome(t)
	own := "  ssh-ed25519 AAAAown\n\n\n"
	writeKeys(t, h, own)
	if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey}); err != nil {
		t.Fatal(err)
	}
	if got := keysFile(t, h); !strings.HasPrefix(got, own+keysBegin+"\n") {
		t.Errorf("%q", got)
	}
}

// A file without the block and no keys is not touched; one absent is made with the block alone.
func TestPutDeployKeysTouchesNothingWithoutKeys(t *testing.T) {
	h := newHome(t)
	writeKeys(t, h, "ssh-ed25519 AAAAown")
	h.calls = nil
	if err := PutDeployKeys(context.Background(), h, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if len(h.calls) != 1 || keysFile(t, h) != "ssh-ed25519 AAAAown" {
		t.Errorf("touched: %v %q", h.calls, keysFile(t, h))
	}
	fresh := newHome(t)
	if err := PutDeployKeys(context.Background(), fresh, io.Discard, map[string]string{"shop": edKey}); err != nil {
		t.Fatal(err)
	}
	if got := keysFile(t, fresh); !strings.HasPrefix(got, keysBegin+"\n") || !strings.HasSuffix(got, keysEnd+"\n") {
		t.Errorf("made: %q", got)
	}
}

// A link, a block without its end and a block twice are refused, with the file left as it was.
func TestPutDeployKeysRefuses(t *testing.T) {
	for want, body := range map[string]string{
		"without its end":       "own\n" + keysBegin + "\nx\n",
		"without its beginning": "own\n" + keysEnd + "\n",
		"twice":                 keysBegin + "\n" + keysEnd + "\n" + keysBegin + "\n" + keysEnd + "\n",
	} {
		h := newHome(t)
		writeKeys(t, h, body)
		if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", want, err)
		}
		if keysFile(t, h) != body {
			t.Errorf("%q: changed", want)
		}
	}
	h := newHome(t)
	writeKeys(t, h, "own\n")
	if err := os.Rename(filepath.Join(h.dir, authorizedKeys), filepath.Join(h.dir, ".ssh/real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(h.dir, authorizedKeys)); err != nil {
		t.Fatal(err)
	}
	if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey}); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Errorf("link: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.dir, ".ssh/real")); string(b) != "own\n" {
		t.Errorf("link: the file it names changed: %q", b)
	}
}
