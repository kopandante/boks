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

// A deploy key one of the server's own lines already holds is refused: sshd would take that line, above
// the block, and the key would keep its shell. A commented-out copy holds nothing and is kept.
func TestPutDeployKeysRefusesAKeyTheServerHolds(t *testing.T) {
	for _, body := range []string{edKey + " ci\n", `from="10.0.0.1",no-pty ` + edKey + "\n", "other\n" + keysBegin + "\n" + keysEnd + "\n" + edKey + "\n"} {
		h := newHome(t)
		writeKeys(t, h, body)
		if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey}); err == nil || !strings.Contains(err.Error(), "the key of shop is already in") {
			t.Errorf("%q: %v", body, err)
		}
		if keysFile(t, h) != body {
			t.Errorf("%q: changed", body)
		}
	}
	h := newHome(t)
	writeKeys(t, h, "# "+edKey+" retired\n")
	if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey}); err != nil {
		t.Errorf("commented out: %v", err)
	}
}

// An authorized_keys boks cannot read is refused, not taken for an empty one: written again, the server's
// own keys would be gone.
func TestPutDeployKeysRefusesAFileItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	h := newHome(t)
	writeKeys(t, h, "ssh-ed25519 AAAAown\n")
	p := filepath.Join(h.dir, authorizedKeys)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o600) })
	if err := PutDeployKeys(context.Background(), h, io.Discard, map[string]string{"shop": edKey}); err == nil {
		t.Error("an unreadable file was written over")
	}
	os.Chmod(p, 0o600)
	if keysFile(t, h) != "ssh-ed25519 AAAAown\n" {
		t.Errorf("changed: %q", keysFile(t, h))
	}
}

// A server without deploy keys applies whatever its authorized_keys is — a link, a file its user cannot
// read — as before deploy keys were: without a line of boks's block there is nothing to take out.
func TestPutDeployKeysWithoutKeysLeavesAnyFile(t *testing.T) {
	h := newHome(t)
	writeKeys(t, h, "own\n")
	real := filepath.Join(h.dir, ".ssh/real")
	if err := os.Rename(filepath.Join(h.dir, authorizedKeys), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(h.dir, authorizedKeys)); err != nil {
		t.Fatal(err)
	}
	if err := PutDeployKeys(context.Background(), h, io.Discard, nil); err != nil {
		t.Errorf("link: %v", err)
	}
	// A link that holds boks's block is still refused: taking the block out would write over the link.
	if err := os.WriteFile(real, []byte("own\n"+keysBegin+"\n"+keysEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PutDeployKeys(context.Background(), h, io.Discard, nil); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Errorf("link with the block: %v", err)
	}
	if os.Geteuid() == 0 {
		return
	}
	u := newHome(t)
	writeKeys(t, u, "own\n")
	p := filepath.Join(u.dir, authorizedKeys)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o600) })
	if err := PutDeployKeys(context.Background(), u, io.Discard, nil); err != nil {
		t.Errorf("unreadable: %v", err)
	}
}
