package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// The server's one boks (#154): each build in binDir by its commit, and binLink naming the one that runs.
// The link is relative, so the tree stays whole wherever the home is.
const (
	binDir  = ".boks/_server/bin"
	binLink = ".boks/bin/boks"
)

// BoksURL is where boks's CI puts the linux build of commit for arch: a release of the commit, tagged
// bin-<commit>. The repository is public, so no token is asked.
func BoksURL(commit, arch string) string {
	return "https://github.com/kopandante/boks/releases/download/bin-" + commit + "/boks-linux-" + arch
}

// ServerArch is the server's architecture as boks's builds name it.
func ServerArch(ctx context.Context, r remote.Runner) (string, error) {
	out, err := r.Run(ctx, "uname", "-m")
	if err != nil {
		return "", err
	}
	switch m := strings.TrimSpace(out); m {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("the server is %s, and boks is built for amd64 and arm64", m)
	}
}

// RunningBoks is the commit of the boks the server's link names; "" with no link.
func RunningBoks(ctx context.Context, r remote.Runner) (string, error) {
	out, err := r.Run(ctx, "sh", "-c", "readlink "+binLink+" 2>/dev/null; true")
	if err != nil {
		return "", err
	}
	_, commit, _ := strings.Cut(strings.TrimSpace(out), "/boks-")
	return commit, nil
}

// Fetch gets the bytes at a URL.
type Fetch func(ctx context.Context, url string) ([]byte, error)

// InstallBoks makes b the server's boks: the build for the server's architecture is fetched here, checked
// against the sha256 server.yml writes, written beside the others, checked again there — the sum and
// what the build says its commit is — and only then named by the link, in one rename. Anything that fails
// leaves the boks that ran. A server whose link names b's build, of the right sum, is left alone. Builds
// other than the new one and the one it replaced are removed.
func InstallBoks(ctx context.Context, r remote.Runner, log io.Writer, b *config.ServerBoks, fetch Fetch) error {
	arch, err := ServerArch(ctx, r)
	if err != nil {
		return err
	}
	want, ok := b.SHA256[arch]
	if !ok {
		return fmt.Errorf("boks: server.yml writes no sha256 for %s, the server's architecture; nothing was changed", arch)
	}
	name := binDir + "/boks-" + b.Commit
	rel := "../_server/bin/boks-" + b.Commit
	have, err := r.Run(ctx, "sh", "-c", "[ \"$(readlink "+binLink+" 2>/dev/null)\" = "+remote.Quote(rel)+" ] && "+
		"sha256sum "+remote.Quote(name)+" 2>/dev/null | cut -d' ' -f1; true")
	if err != nil {
		return err
	}
	if strings.TrimSpace(have) == want {
		fmt.Fprintf(log, "boks: runs %s already\n", short(b.Commit))
		return nil
	}
	url := BoksURL(b.Commit, arch)
	fmt.Fprintf(log, "boks: fetching %s\n", url)
	body, err := fetch(ctx, url)
	if err != nil {
		return fmt.Errorf("boks: fetch %s: %w; nothing was changed", url, err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("boks: %s has sha256 %x, and server.yml writes %s; nothing was changed", url, sum, want)
	}
	if err := remote.UploadAtomic(ctx, r, body, name); err != nil {
		return fmt.Errorf("boks: %w; the boks that ran is left", err)
	}
	q, prev := remote.Quote(name), "$(readlink "+binLink+" 2>/dev/null)"
	script := "chmod 700 " + q + " && " +
		"[ \"$(sha256sum " + q + " | cut -d' ' -f1)\" = " + remote.Quote(want) + " ] || { rm -f " + q + "; echo 'boks: the build written differs from the one fetched' >&2; exit 1; }\n" +
		"v=$(" + q + " version 2>&1) && [ \"$v\" = " + remote.Quote(b.Commit) + " ] || { rm -f " + q + "; echo \"boks: the build says it is $v, not " + b.Commit + "\" >&2; exit 1; }\n" +
		"prev=" + prev + "\n" +
		"mkdir -p .boks/bin && ln -sfn " + remote.Quote(rel) + " " + binLink + ".new && mv -f " + binLink + ".new " + binLink + "\n" +
		// Kept: the new build and the one it replaced, to go back to by hand.
		"for f in " + binDir + "/boks-*; do case \"../_server/bin/${f##*/}\" in " + remote.Quote(rel) + "|\"$prev\") ;; *) rm -f \"$f\";; esac; done; true"
	if _, err := r.Run(ctx, "sh", "-c", script); err != nil {
		return fmt.Errorf("boks: %w; the boks that ran is left", err)
	}
	fmt.Fprintf(log, "boks: runs %s\n", short(b.Commit))
	return nil
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
