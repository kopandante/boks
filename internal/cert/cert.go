// Package cert obtains DNS-01 certificates with lego on the operator's machine and installs
// them into the proxy's certificate volume on each server.
//
// Two facts shape this design, both measured on the stand:
//   - Caddy reads a certificate file when it loads a config, and only then: new files under the
//     same paths change nothing until a reload, and a reload of an unchanged config is skipped
//     unless forced (boks-lab, caddy 2.11.7, 2026-10-06). So installing a renewal ends in a
//     forced reload, which re-reads the files for every route on the server.
//   - DNS tokens are often IP-restricted — the Cloudflare token for these zones is rejected from
//     the servers and works from the laptop — so issuance belongs on the operator/CI side and
//     the server only ever receives the finished files.
package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/remote"
)

const stagingCA = "https://acme-staging-v02.api.letsencrypt.org/directory"

// dir is where installed certificates live inside the proxy container.
const dir = "/certs/boks"

// ServerPaths are the certificate paths as the proxy sees them.
func ServerPaths(c *config.Cert) (crt, key string) {
	return dir + "/" + c.Slug() + ".crt", dir + "/" + c.Slug() + ".key"
}

// metaPath is lego's own metadata for the certificate. The server keeps a copy because it is
// what a renewal elsewhere needs to decide whether anything is due: measured against lego 5,
// a bare .crt is ignored and a fresh certificate is issued, while .crt plus .json is recognised
// and skipped until it is actually time. The private key is not part of that decision.
func metaPath(c *config.Cert) string { return dir + "/" + c.Slug() + ".json" }

// reloadedPath records the certificate the proxy last loaded. Every load is a reload of the whole
// config — for a renewal, or for a deploy that changed the routes — so it reaches every route on the
// server, and one mark answers for all of them. It is written only after the load succeeded, so an
// interrupted run leaves the mark stale and the next run loads again instead of reporting
// "unchanged" forever. The file keeps the name it had when a restart of kamal-proxy was the load: a
// server moved to Caddy loaded the same files when Caddy started, and the mark stays true.
func reloadedPath(c *config.Cert) string { return dir + "/" + c.Slug() + ".restarted" }

// LocalPaths are the files lego writes.
func LocalPaths(cfg *config.Config) (crt, key string) {
	base := localBase(cfg)
	return base + ".crt", base + ".key"
}

func localBase(cfg *config.Config) string {
	return filepath.Join(cfg.LegoPath(), "certificates", cfg.Cert.Slug())
}

// Obtain runs lego. lego decides on its own whether a renewal is due (`--renew-days`, or a
// third of the lifetime by default) and leaves the files untouched when it is not, which is what
// makes a daily cron safe against rate limits. force re-issues regardless.
func Obtain(ctx context.Context, log io.Writer, cfg *config.Config, force bool) error {
	c := cfg.Cert
	args := []string{"run", "--accept-tos", "--email", c.Email, "--dns", c.DNS, "--path", cfg.LegoPath()}
	for _, d := range c.Domains {
		args = append(args, "--domains", d)
	}
	if c.Staging {
		args = append(args, "--server", stagingCA)
	}
	if c.RenewDays > 0 {
		args = append(args, "--renew-days", strconv.Itoa(c.RenewDays))
	}
	if force {
		args = append(args, "--renew-force")
	}
	fmt.Fprintf(log, "lego %s\n", args[0])
	cmd := exec.CommandContext(ctx, "lego", args...)
	cmd.Env = os.Environ() // the DNS provider reads its credentials from the environment
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lego: %w (is the DNS provider's token exported?)", err)
	}
	return nil
}

// Install copies the local certificate into the proxy's volume on one server. It writes
// whenever the server's copy differs, and says nothing about whether the proxy has loaded it —
// that is Pending's job.
func Install(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	crtPath, keyPath := LocalPaths(cfg)
	crt, err := os.ReadFile(crtPath)
	if err != nil {
		return fmt.Errorf("%w (run `boks cert issue` first)", err)
	}
	crtRemote, keyRemote := ServerPaths(cfg.Cert)
	current, _ := read(ctx, r, crtRemote) // absent or unreadable counts as different
	changed := !bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(crt))
	// The private key is read only on the path that actually writes it. Reading it unconditionally
	// would break the case this whole feature exists for: a renewal running where `cert pull` left
	// only the certificate and its metadata, on any of the ~59 days out of 60 when lego decides
	// nothing is due.
	var key []byte
	if changed {
		key, err = os.ReadFile(keyPath)
		if err != nil {
			// A bare ENOENT here reads as a bug in boks. It is the expected state on a CI runner,
			// where `cert pull` deliberately brings back no key, and it only surfaces when some
			// server turns out to lag behind the certificate that runner holds.
			return fmt.Errorf("%w — this server's certificate differs from the local one and "+
				"installing it needs the key, which `cert pull` never fetches; run this where the "+
				"pair was issued, or `boks cert issue` to issue a new pair everywhere", err)
		}
		// `cert pull` refreshes the certificate and never the key — the key stays on the server
		// that issued it. So a machine that issued once and later pulled a renewal holds a
		// certificate and a key from different issuances, and installing that pair would leave the
		// proxy serving a certificate its key cannot answer for: TLS broken for every host the
		// wildcard covers, with nothing failing at install time. Refuse instead.
		if _, err := tls.X509KeyPair(crt, key); err != nil {
			return fmt.Errorf("%s and %s are not a pair (%w) — a pulled certificate comes without "+
				"its key; run `boks cert issue` to issue a matched pair", crtPath, keyPath, err)
		}
	}
	// Metadata is reconciled independently of whether the certificate changed: a server set up by
	// a boks that did not store it holds the current certificate and no .json, and that
	// combination would otherwise be unrepairable — the certificate matches, so nothing is written
	// while `cert pull` needs the .json to exist. It goes after the refusal above, though, so a
	// run that refuses leaves the server exactly as it found it rather than moving its metadata on
	// to an issuance whose certificate never arrives.
	if err := installMeta(ctx, r, log, cfg); err != nil {
		return err
	}
	if !changed {
		return nil
	}
	// The pair goes in beside the old one and replaces it with two renames in one command: Caddy loads
	// every certificate file a config names on every load, so a pair a cut run left mismatched would
	// stop every app's deploy, and a proxy restarted onto it would not start — and `boks cert`, which
	// boots the proxy first, could not repair it. A run that dies before the renames leaves the old
	// pair in place, and the comparison above — on the certificate, renamed last — writes it again.
	if err := write(ctx, r, key, keyRemote+".new"); err != nil {
		return err
	}
	if err := write(ctx, r, crt, crtRemote+".new"); err != nil {
		return err
	}
	swap := "mv " + remote.Quote(keyRemote+".new") + " " + remote.Quote(keyRemote) + " && mv " + remote.Quote(crtRemote+".new") + " " + remote.Quote(crtRemote)
	if _, err := r.Run(ctx, "docker", "exec", "-u", "0", proxy.Container, "sh", "-c", swap); err != nil {
		return fmt.Errorf("install %s: %w", crtRemote, err)
	}
	fmt.Fprintf(log, "cert installed: %s\n", crtRemote)
	return nil
}

// installMeta puts lego's metadata on the server when the local copy differs from what is there.
// Absent locally means there is nothing to install — not an error.
func installMeta(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	meta, err := os.ReadFile(localBase(cfg) + ".json")
	if err != nil {
		return nil
	}
	current, _ := read(ctx, r, metaPath(cfg.Cert))
	if bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(meta)) {
		return nil
	}
	if err := write(ctx, r, meta, metaPath(cfg.Cert)); err != nil {
		return err
	}
	fmt.Fprintf(log, "cert metadata installed: %s\n", metaPath(cfg.Cert))
	return nil
}

// Pull copies the certificate and lego's metadata for it back from a server into the local lego
// directory — the two files a renewal needs to decide whether anything is due. Neither is
// secret, so a scheduled renewal elsewhere never has to hold the private key.
func Pull(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	crtRemote, _ := ServerPaths(cfg.Cert)
	files := []struct{ remote, local string }{
		{crtRemote, localBase(cfg) + ".crt"},
		{metaPath(cfg.Cert), localBase(cfg) + ".json"},
	}
	// Both are fetched before either is written. Writing the certificate and then failing on the
	// metadata would leave exactly the state that makes lego ignore what is there and issue a
	// fresh certificate on every run.
	got := make([][]byte, len(files))
	for i, f := range files {
		content, err := read(ctx, r, f.remote)
		if err != nil {
			return fmt.Errorf("pull %s: %w (a server set up before boks stored the metadata has "+
				"no .json; run `boks cert renew` once where the lego state lives to install it)", f.remote, err)
		}
		got[i] = append(bytes.TrimSpace(content), '\n')
	}
	if err := os.MkdirAll(filepath.Dir(localBase(cfg)), 0o700); err != nil {
		return err
	}
	for i, f := range files {
		if err := os.WriteFile(f.local, got[i], 0o600); err != nil {
			return err
		}
		fmt.Fprintf(log, "pulled %s\n", f.local)
	}
	// Say so straight away rather than let the next install refuse. Which of the two issuances is
	// the newer one is not knowable from here: normally the server's, but a server rolled back or
	// given a recreated volume serves an older certificate than this machine holds, and the pull
	// just overwrote the newer one. So report the mismatch and where to look, not a direction.
	if key, err := os.ReadFile(localBase(cfg) + ".key"); err == nil {
		if _, err := tls.X509KeyPair(got[0], key); err != nil {
			fmt.Fprintf(log, "warning: %s.key does not match the certificate just pulled — they come "+
				"from different issuances, and this pull overwrote the local certificate with the "+
				"server's. `boks cert status` shows what each server is serving; `boks cert issue` "+
				"replaces both with a fresh matched pair\n", localBase(cfg))
		}
	}
	return nil
}

// Pending reports whether the proxy still has to load what is on the server's disk. Both sides of
// the comparison come from the server, so this answers the same way from a machine that has no lego
// state at all — a CI runner, or a second operator.
func Pending(ctx context.Context, r remote.Runner, cfg *config.Config) (bool, error) {
	installed, err := serverFingerprint(ctx, r, cfg)
	if err != nil {
		return false, err
	}
	return !markMatches(ctx, r, installed, reloadedPath(cfg.Cert)), nil
}

// markMatches reports whether any of the given marks records the installed certificate. An absent
// or unreadable mark means "not loaded this way", so the answer errs towards loading again.
func markMatches(ctx context.Context, r remote.Runner, installed string, paths ...string) bool {
	for _, p := range paths {
		if mark, err := read(ctx, r, p); err == nil && string(bytes.TrimSpace(mark)) == installed {
			return true
		}
	}
	return false
}

// Reload makes the proxy load the certificate files again, then records what it loaded. The caller
// holds the server's admission lock: a reload racing a deploy's could put the proxy back on the routes
// that deploy just replaced.
func Reload(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	fmt.Fprintln(log, "reloading the proxy to load the certificate")
	if err := proxy.Reload(ctx, r); err != nil {
		return err
	}
	return MarkReloaded(ctx, r, cfg)
}

// MarkReloaded records that the proxy now serves the installed certificate. A deploy whose routes
// changed calls it after its own reload, which read the files as well.
func MarkReloaded(ctx context.Context, r remote.Runner, cfg *config.Config) error {
	return mark(ctx, r, cfg, reloadedPath(cfg.Cert))
}

func mark(ctx context.Context, r remote.Runner, cfg *config.Config, path string) error {
	installed, err := serverFingerprint(ctx, r, cfg)
	if err != nil {
		return err
	}
	return write(ctx, r, []byte(installed+"\n"), path)
}

func serverFingerprint(ctx context.Context, r remote.Runner, cfg *config.Config) (string, error) {
	crtRemote, _ := ServerPaths(cfg.Cert)
	content, err := read(ctx, r, crtRemote)
	if err != nil {
		return "", fmt.Errorf("%s: %w (run `boks cert issue` first)", crtRemote, err)
	}
	return fingerprint(content), nil
}

// Installed reports whether this server already has the certificate a deploy would route its hosts
// at. Caddy refuses a config naming a file that is not there, and a proxy starting with one exits.
func Installed(ctx context.Context, r remote.Runner, cfg *config.Config) bool {
	crtRemote, _ := ServerPaths(cfg.Cert)
	out, err := read(ctx, r, crtRemote)
	return err == nil && len(bytes.TrimSpace(out)) > 0
}

// Status is what a server holds: the certificate on disk, and whether the proxy has actually
// loaded it. Reporting only the file would confirm a renewal that never took effect.
type Status struct {
	Cert    *x509.Certificate
	Pending bool
}

func Read(ctx context.Context, r remote.Runner, cfg *config.Config) (*Status, error) {
	crtRemote, _ := ServerPaths(cfg.Cert)
	content, err := read(ctx, r, crtRemote)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("%s: not a PEM certificate", crtRemote)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	settled := markMatches(ctx, r, fingerprint(content), reloadedPath(cfg.Cert))
	return &Status{Cert: parsed, Pending: !settled}, nil
}

func fingerprint(pemBytes []byte) string {
	sum := sha256.Sum256(bytes.TrimSpace(pemBytes))
	return hex.EncodeToString(sum[:])
}

// write puts the file inside the proxy container as root, which Caddy runs as: mode 640 so the key
// is not world-readable, and the directory 750.
func write(ctx context.Context, r remote.Runner, content []byte, path string) error {
	script := "set -e; umask 077; mkdir -p " + remote.Quote(dir) + "; cat > " + remote.Quote(path) +
		"; chmod 750 " + remote.Quote(dir) + "; chmod 640 " + remote.Quote(path)
	if _, err := r.Pipe(ctx, content, "docker", "exec", "-i", "-u", "0", proxy.Container, "sh", "-c", script); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

func read(ctx context.Context, r remote.Runner, path string) ([]byte, error) {
	out, err := r.Run(ctx, "docker", "exec", proxy.Container, "cat", path)
	return []byte(out), err
}
