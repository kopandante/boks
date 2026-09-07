// Package cert obtains DNS-01 certificates with lego on the operator's machine and installs
// them into the proxy's certificate volume on each server.
//
// Three facts shape this design, all measured on the stand:
//   - A freshly created certificate volume is owned by root (`0:0 755`) and `docker exec`
//     inherits the image's `USER kamal-proxy`, so the proxy user cannot write there at all.
//     Files go in as root and are handed over with chown/chmod.
//   - kamal-proxy keeps a certificate in memory and never re-reads the file. Restarting the
//     container makes it read the paths recorded in its state again; that costs about 0.19 s of
//     unavailability and preserves routes and TLS.
//   - DNS tokens are often IP-restricted — the Cloudflare token for these zones is rejected from
//     the servers and works from the laptop — so issuance belongs on the operator/CI side and
//     the server only ever receives the finished files.
package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
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

// proxyUID is the uid:gid of the `kamal-proxy` user in the image; installed files are handed to
// it because the proxy process is what has to read them.
const proxyUID = "1001:1001"

// ServerPaths are the certificate paths as kamal-proxy sees them.
func ServerPaths(c *config.Cert) (crt, key string) {
	return dir + "/" + c.Slug() + ".crt", dir + "/" + c.Slug() + ".key"
}

// metaPath is lego's own metadata for the certificate. The server keeps a copy because it is
// what a renewal elsewhere needs to decide whether anything is due: measured against lego 5,
// a bare .crt is ignored and a fresh certificate is issued, while .crt plus .json is recognised
// and skipped until it is actually time. The private key is not part of that decision.
func metaPath(c *config.Cert) string { return dir + "/" + c.Slug() + ".json" }

// There are two ways the proxy comes to hold a certificate, and they differ in reach — which is
// why they are recorded apart. A restart makes it re-read the files for EVERY service on the
// server; deploying a route makes it read them for that service only (measured on the stand:
// replacing the files alone changes nothing until one or the other happens). Collapsing the two
// into a single mark would let one app's deploy vouch for apps it never touched, and a second
// app under the same wildcard would then serve the old certificate until expiry with nothing
// reporting a debt.
//
// Written only after the load actually succeeded, so an interrupted run leaves the mark stale
// and the next run loads again instead of reporting "unchanged" forever.
func restartedPath(c *config.Cert) string { return dir + "/" + c.Slug() + ".restarted" }

func loadedPath(cfg *config.Config) string {
	return dir + "/" + cfg.Cert.Slug() + "." + cfg.App + ".loaded"
}

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
	// Metadata is reconciled on its own, before the certificate comparison below: a server set up
	// by a boks that did not store it holds the current certificate and no .json, and that
	// combination would otherwise be unrepairable — the certificate matches, so the comparison
	// returns early and never writes anything, while `cert pull` needs the .json to exist.
	if err := installMeta(ctx, r, log, cfg); err != nil {
		return err
	}
	crtRemote, keyRemote := ServerPaths(cfg.Cert)
	current, _ := read(ctx, r, crtRemote) // absent or unreadable counts as different
	if bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(crt)) {
		return nil
	}
	// The private key is read only now, on the path that actually writes it. Reading it earlier
	// would break the case this whole feature exists for: a renewal running where `cert pull`
	// left only the certificate and its metadata, on any of the ~59 days out of 60 when lego
	// decides nothing is due.
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	// A run that dies partway leaves a mismatched set on the server whichever order these go in.
	// What makes that recoverable is the comparison above — the next run sees a .crt that differs
	// from the local one and writes everything again — and the marker, which was never updated,
	// so the proxy is not restarted onto a half-written pair. The certificate goes last for the
	// same reason: it is what that comparison keys on.
	if err := write(ctx, r, key, keyRemote); err != nil {
		return err
	}
	if err := write(ctx, r, crt, crtRemote); err != nil {
		return err
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
	return nil
}

// Pending reports whether the proxy still has to load what is on the server's disk. Both sides
// of the comparison come from the server, so this answers the same way from a machine that has
// no lego state at all — a CI runner, or a second operator.
func Pending(ctx context.Context, r remote.Runner, cfg *config.Config) (bool, error) {
	installed, err := serverFingerprint(ctx, r, cfg)
	if err != nil {
		return false, err
	}
	return !loaded(ctx, r, cfg, installed), nil
}

// loaded reports whether this app's routes are serving the installed certificate: either the
// proxy was restarted with it, which covers every service, or this app's own routes were
// deployed with it. An absent mark means "not this way", so the answer errs towards reloading.
func loaded(ctx context.Context, r remote.Runner, cfg *config.Config, installed string) bool {
	for _, p := range []string{restartedPath(cfg.Cert), loadedPath(cfg)} {
		if mark, err := read(ctx, r, p); err == nil && string(bytes.TrimSpace(mark)) == installed {
			return true
		}
	}
	return false
}

// Reload restarts the proxy so it re-reads the certificate files, then records what it loaded.
// Measured on the stand: about 0.19 s of unavailability, routes and TLS preserved.
func Reload(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	fmt.Fprintln(log, "restarting the proxy to load the certificate (~0.2s)")
	if _, err := r.Run(ctx, "docker", "restart", proxy.Container); err != nil {
		return err
	}
	return mark(ctx, r, cfg, restartedPath(cfg.Cert))
}

// MarkLoaded records that this app's routes now serve the installed certificate. A deploy calls
// it: pointing a route at a certificate path makes kamal-proxy read the file there and then, so
// without this an ordinary deploy would leave `cert status` claiming a reload was owed. It
// deliberately marks this app only — a deploy says nothing about anyone else's services.
func MarkLoaded(ctx context.Context, r remote.Runner, cfg *config.Config) error {
	return mark(ctx, r, cfg, loadedPath(cfg))
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

// Installed reports whether this server already has the certificate a deploy would point
// kamal-proxy at.
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
	return &Status{Cert: parsed, Pending: !loaded(ctx, r, cfg, fingerprint(content))}, nil
}

func fingerprint(pemBytes []byte) string {
	sum := sha256.Sum256(bytes.TrimSpace(pemBytes))
	return hex.EncodeToString(sum[:])
}

// write puts the file inside the proxy container as root, then hands it to the proxy user:
// mode 640 so the key is not world-readable, and the directory 750. Writing as the proxy user
// instead fails outright on a fresh volume, which is root-owned (measured: `0:0 755`).
func write(ctx context.Context, r remote.Runner, content []byte, path string) error {
	script := "set -e; umask 077; mkdir -p " + remote.Quote(dir) + "; cat > " + remote.Quote(path) +
		"; chown " + proxyUID + " " + remote.Quote(dir) + " " + remote.Quote(path) +
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
