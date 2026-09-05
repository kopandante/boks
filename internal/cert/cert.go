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

// loadedPath holds the fingerprint of the certificate the proxy was last restarted for. It is
// what makes a partial failure recoverable: the file is written only after a successful reload,
// so an interrupted run leaves it stale and the next run reloads again instead of reporting
// "unchanged" forever.
func loadedPath(c *config.Cert) string { return dir + "/" + c.Slug() + ".loaded" }

// LocalPaths are the files lego writes.
func LocalPaths(cfg *config.Config) (crt, key string) {
	base := filepath.Join(cfg.LegoPath(), "certificates", cfg.Cert.Slug())
	return base + ".crt", base + ".key"
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
	crt, key, err := local(cfg)
	if err != nil {
		return err
	}
	crtRemote, keyRemote := ServerPaths(cfg.Cert)
	current, _ := read(ctx, r, crtRemote) // absent or unreadable counts as different
	if bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(crt)) {
		return nil
	}
	// A run that dies between the two writes leaves a mismatched pair on the server whichever
	// order they go in. What makes that recoverable is the comparison above — the next run sees
	// a .crt that differs from the local one and writes both again — and the marker, which was
	// never updated, so the proxy is not restarted onto the half-written pair.
	if err := write(ctx, r, key, keyRemote); err != nil {
		return err
	}
	if err := write(ctx, r, crt, crtRemote); err != nil {
		return err
	}
	fmt.Fprintf(log, "cert installed: %s\n", crtRemote)
	return nil
}

// Pending reports whether the proxy still has to be restarted to serve what is on disk.
func Pending(ctx context.Context, r remote.Runner, cfg *config.Config) (bool, error) {
	crt, _, err := local(cfg)
	if err != nil {
		return false, err
	}
	loaded, _ := read(ctx, r, loadedPath(cfg.Cert)) // absent marker means "never loaded"
	return string(bytes.TrimSpace(loaded)) != fingerprint(crt), nil
}

// Reload restarts the proxy so it re-reads the certificate files, then records what it loaded.
// Measured on the stand: about 0.19 s of unavailability, routes and TLS preserved.
func Reload(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	crt, _, err := local(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintln(log, "restarting the proxy to load the certificate (~0.2s)")
	if _, err := r.Run(ctx, "docker", "restart", proxy.Container); err != nil {
		return err
	}
	return write(ctx, r, []byte(fingerprint(crt)+"\n"), loadedPath(cfg.Cert))
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
	loaded, _ := read(ctx, r, loadedPath(cfg.Cert))
	return &Status{Cert: parsed, Pending: string(bytes.TrimSpace(loaded)) != fingerprint(content)}, nil
}

func local(cfg *config.Config) (crt, key []byte, err error) {
	crtPath, keyPath := LocalPaths(cfg)
	if crt, err = os.ReadFile(crtPath); err != nil {
		return nil, nil, fmt.Errorf("%w (run `boks cert issue` first)", err)
	}
	key, err = os.ReadFile(keyPath)
	return crt, key, err
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
