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

// Remember is fetch that gets each URL once in a run, and says so in log: the build is checked on every
// server before any changes, and then installed on each, without being fetched again.
func Remember(fetch Fetch, log io.Writer) Fetch {
	got := map[string][]byte{}
	return func(ctx context.Context, url string) ([]byte, error) {
		if b, ok := got[url]; ok {
			return b, nil
		}
		fmt.Fprintf(log, "boks: fetching %s\n", url)
		b, err := fetch(ctx, url)
		if err == nil {
			got[url] = b
		}
		return b, err
	}
}

// boksPlan is what InstallBoks needs to know of a server before it changes anything.
type boksPlan struct {
	arch, want, name, rel string
	already               bool
}

func planBoks(ctx context.Context, r remote.Runner, b *config.ServerBoks) (boksPlan, error) {
	arch, err := ServerArch(ctx, r)
	if err != nil {
		return boksPlan{}, err
	}
	want, ok := b.SHA256[arch]
	if !ok {
		return boksPlan{}, fmt.Errorf("boks: server.yml writes no sha256 for %s, the server's architecture; nothing was changed", arch)
	}
	p := boksPlan{arch: arch, want: want, name: binDir + "/boks-" + b.Commit, rel: "../_server/bin/boks-" + b.Commit}
	have, err := r.Run(ctx, "sh", "-c", "[ \"$(readlink "+binLink+" 2>/dev/null)\" = "+remote.Quote(p.rel)+" ] && "+
		"sha256sum "+remote.Quote(p.name)+" 2>/dev/null | cut -d' ' -f1; true")
	if err != nil {
		return boksPlan{}, err
	}
	p.already = strings.TrimSpace(have) == want
	return p, nil
}

// fetchChecked is the build of p fetched and checked against the sum server.yml writes.
func fetchChecked(ctx context.Context, b *config.ServerBoks, p boksPlan, fetch Fetch) ([]byte, error) {
	url := BoksURL(b.Commit, p.arch)
	body, err := fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("boks: fetch %s: %w; nothing was changed", url, err)
	}
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != p.want {
		return nil, fmt.Errorf("boks: %s has sha256 %x, and server.yml writes %s; nothing was changed", url, sum, p.want)
	}
	return body, nil
}

// CheckBoks refuses, before any server is changed, what InstallBoks would refuse on this side: no sum for
// the server's architecture, a build that does not fetch or is not of the sum. With fetch from Remember,
// the install after it fetches nothing again.
func CheckBoks(ctx context.Context, r remote.Runner, log io.Writer, b *config.ServerBoks, fetch Fetch) error {
	p, err := planBoks(ctx, r, b)
	if err != nil || p.already {
		return err
	}
	_, err = fetchChecked(ctx, b, p, fetch)
	return err
}

// InstallBoks makes b the server's boks: the build for the server's architecture is fetched here, checked
// against the sha256 server.yml writes, written beside the others, checked again there — the sum and
// what the build says its commit is — and only then named by the link, in one rename. Anything that fails
// leaves the boks that ran. A server whose link names b's build, of the right sum, is left alone. Builds
// other than the new one and the one it replaced are removed.
func InstallBoks(ctx context.Context, r remote.Runner, log io.Writer, b *config.ServerBoks, fetch Fetch) error {
	p, err := planBoks(ctx, r, b)
	if err != nil {
		return err
	}
	if p.already {
		fmt.Fprintf(log, "boks: runs %s already\n", short(b.Commit))
		return nil
	}
	body, err := fetchChecked(ctx, b, p, fetch)
	if err != nil {
		return err
	}
	// Written beside the build it may replace — the link may name a build of the same commit whose file
	// is not of the sum — and put in its place only once checked, so a refusal removes the new file alone.
	next := p.name + ".new"
	if err := remote.UploadAtomic(ctx, r, body, next); err != nil {
		return fmt.Errorf("boks: %w; the boks that ran is left", err)
	}
	q, n, prev := remote.Quote(p.name), remote.Quote(next), "$(readlink "+binLink+" 2>/dev/null)"
	script :=
		// One install at a time: another one's cleanup would otherwise remove this build between its
		// check and the link. A file it removed fails the check below. flock is there on every server
		// install prepared; a home without it (a test's) goes unlocked.
		"if command -v flock >/dev/null; then exec 9>" + binDir + "/.lock && flock -w 300 9 || { echo 'boks: another install holds the lock' >&2; exit 1; }; fi\n" +
			"chmod 700 " + n + " && " +
			"[ \"$(sha256sum " + n + " | cut -d' ' -f1)\" = " + remote.Quote(p.want) + " ] || { rm -f " + n + "; echo 'boks: the build written differs from the one fetched' >&2; exit 1; }\n" +
			"v=$(" + n + " version 2>&1) && [ \"$v\" = " + remote.Quote(b.Commit) + " ] || { rm -f " + n + "; echo \"boks: the build says it is $v, not " + b.Commit + "\" >&2; exit 1; }\n" +
			"mv -f " + n + " " + q + " || { rm -f " + n + "; exit 1; }\n" +
			"prev=" + prev + "\n" +
			"mkdir -p .boks/bin && ln -sfn " + remote.Quote(p.rel) + " " + binLink + ".new && mv -f " + binLink + ".new " + binLink + " || { echo 'boks: the link was not switched' >&2; exit 1; }\n" +
			// Kept: the new build and the one it replaced, to go back to by hand.
			"for f in " + binDir + "/boks-*; do case \"../_server/bin/${f##*/}\" in " + remote.Quote(p.rel) + "|\"$prev\") ;; *) rm -f \"$f\";; esac; done; true"
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
