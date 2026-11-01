package deploy

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/kopandante/boks/internal/remote"
)

// authorizedKeys is the server user's authorized_keys, relative to the home.
const authorizedKeys = ".ssh/authorized_keys"

// The block of authorized_keys boks keeps: the deploy keys of server.yml (#154, stage 3), each bound to
// `boks deploy-hook <app>`. Every line outside it is the server's own, and kept byte for byte.
const (
	keysBegin = "# boks deploy-hook keys: begin (written by boks server apply from server.yml; edit that, not these lines)"
	keysEnd   = "# boks deploy-hook keys: end"
)

// HookLine is the authorized_keys line of app's deploy key: the key runs `boks deploy-hook <app>` and
// nothing else — restrict takes away the pty, forwarding and the rest — whatever the client asks for.
func HookLine(app, key string) string {
	return `command=".boks/bin/boks deploy-hook ` + app + `",restrict ` + key + " boks-deploy-" + app
}

// PutDeployKeys makes keys — by app, each as config.DeployKey writes it — the deploy keys authorized_keys
// holds: boks's block written again, every other line left as it is. A file without the block and no
// keys is not touched. An authorized_keys that is a link, or a block with no end, is refused: rewritten,
// the one would replace the file the link names with a copy, the other would take every line after it.
func PutDeployKeys(ctx context.Context, r remote.Runner, log io.Writer, keys map[string]string) error {
	out, err := r.Run(ctx, "sh", "-c", "if [ -L "+authorizedKeys+" ]; then echo link; elif [ -f "+authorizedKeys+" ]; then echo present && cat "+
		authorizedKeys+" && echo .; else echo absent; fi")
	if err != nil {
		return fmt.Errorf("deploy keys: reading %s: %w", authorizedKeys, err)
	}
	mark, rest, _ := strings.Cut(out, "\n")
	var have string
	switch mark {
	case "link":
		return fmt.Errorf("deploy keys: %s is a link; boks writes its keys only into a file of its own; the file was not changed", authorizedKeys)
	case "present":
		// The runner trims what a command prints: the dot keeps the file's last newlines.
		have = strings.TrimSuffix(rest, ".")
	case "absent":
	default:
		return fmt.Errorf("deploy keys: reading %s: unexpected answer %q", authorizedKeys, mark)
	}
	others, had, err := outsideBlock(have)
	if err != nil {
		return err
	}
	if !had && len(keys) == 0 {
		return nil
	}
	if err := keysOutside(others, keys); err != nil {
		return err
	}
	next := others
	if len(keys) > 0 {
		if next != "" && !strings.HasSuffix(next, "\n") {
			next += "\n"
		}
		next += keysBegin + "\n"
		for _, app := range slices.Sorted(maps.Keys(keys)) {
			next += HookLine(app, keys[app]) + "\n"
		}
		next += keysEnd + "\n"
	}
	if next == have {
		return nil
	}
	if err := remote.UploadAtomic(ctx, r, []byte(next), authorizedKeys); err != nil {
		return fmt.Errorf("deploy keys: writing %s: %w", authorizedKeys, err)
	}
	fmt.Fprintf(log, "deploy keys: %d in %s\n", len(keys), authorizedKeys)
	return nil
}

// keysOutside refuses a deploy key that one of the server's own lines already holds: sshd takes the first
// line with the key, and that one, above boks's block, would give the key the shell its own line does
// rather than deploy-hook. Commented-out lines hold nothing.
func keysOutside(others string, keys map[string]string) error {
	for _, l := range strings.Split(others, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		for _, app := range slices.Sorted(maps.Keys(keys)) {
			_, b64, _ := strings.Cut(keys[app], " ")
			if slices.Contains(f, b64) {
				return fmt.Errorf("deploy keys: the key of %s is already in %s on one of the server's own lines, outside boks's block, where it can do more than deploy; "+
					"remove that line and apply again; the file was not changed", app, authorizedKeys)
			}
		}
	}
	return nil
}

// outsideBlock is authorized_keys without boks's block, and whether it had one.
func outsideBlock(file string) (string, bool, error) {
	lines := strings.SplitAfter(file, "\n")
	var out strings.Builder
	in, had := false, false
	for _, l := range lines {
		switch strings.TrimRight(l, "\r\n") {
		case keysBegin:
			if in || had {
				return "", false, fmt.Errorf("deploy keys: %s holds boks's block twice; the file was not changed", authorizedKeys)
			}
			in, had = true, true
			continue
		case keysEnd:
			if !in {
				return "", false, fmt.Errorf("deploy keys: %s has the end of boks's block without its beginning; the file was not changed", authorizedKeys)
			}
			in = false
			continue
		}
		if !in {
			out.WriteString(l)
		}
	}
	if in {
		return "", false, fmt.Errorf("deploy keys: %s has the beginning of boks's block without its end; the file was not changed", authorizedKeys)
	}
	return out.String(), had, nil
}
