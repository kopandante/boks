// Package cert obtains DNS-01 certificates with lego on the operator's machine and installs
// them into the proxy's certificate volume on each server.
//
// Two facts shape this design, both measured on the stand:
//   - kamal-proxy keeps a manual certificate in memory and never re-reads the file, so a renewal
//     only takes effect after the routes are deployed again (see deploy.Reroute).
//   - DNS tokens are often IP-restricted — the Cloudflare token for these zones is rejected from
//     the servers and works from the laptop — so issuance belongs on the operator/CI side and
//     the server only ever receives the finished files.
package cert

import (
	"bytes"
	"context"
	"crypto/x509"
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

// dir is where installed certificates live inside the proxy container. The volume's root is
// owned by the proxy user, so files written through `docker exec` land with the right owner and
// no chown is needed.
const dir = "/certs/boks"

// ServerPaths are the certificate paths as kamal-proxy sees them.
func ServerPaths(c *config.Cert) (crt, key string) {
	return dir + "/" + c.Slug() + ".crt", dir + "/" + c.Slug() + ".key"
}

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
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = io.MultiWriter(log, &errb), io.MultiWriter(log, &errb)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("lego: %w (is the DNS provider's token exported?)", err)
	}
	return nil
}

// Install copies the local certificate into the proxy's volume on one server and reports
// whether the server's copy changed — an unchanged copy means there is nothing to reload.
func Install(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) (bool, error) {
	crtLocal, keyLocal := LocalPaths(cfg)
	crt, err := os.ReadFile(crtLocal)
	if err != nil {
		return false, fmt.Errorf("%w (run `boks cert issue` first)", err)
	}
	key, err := os.ReadFile(keyLocal)
	if err != nil {
		return false, err
	}
	crtRemote, keyRemote := ServerPaths(cfg.Cert)
	current, _ := read(ctx, r, crtRemote) // absent or unreadable counts as changed
	if bytes.Equal(bytes.TrimSpace(current), bytes.TrimSpace(crt)) {
		return false, nil
	}
	for _, f := range []struct {
		content []byte
		path    string
	}{{crt, crtRemote}, {key, keyRemote}} {
		if err := write(ctx, r, f.content, f.path); err != nil {
			return false, err
		}
	}
	fmt.Fprintf(log, "cert installed: %s\n", crtRemote)
	return true, nil
}

// Status reads the certificate a server currently serves from disk.
func Status(ctx context.Context, r remote.Runner, cfg *config.Config) (*x509.Certificate, error) {
	crtRemote, _ := ServerPaths(cfg.Cert)
	content, err := read(ctx, r, crtRemote)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("%s: not a PEM certificate", crtRemote)
	}
	return x509.ParseCertificate(block.Bytes)
}

// write creates the file inside the proxy container, so it is owned by the proxy user and
// readable only by it.
func write(ctx context.Context, r remote.Runner, content []byte, path string) error {
	_, err := r.Pipe(ctx, content, "docker", "exec", "-i", proxy.Container, "sh", "-c",
		"umask 077 && mkdir -p "+remote.Quote(dir)+" && cat > "+remote.Quote(path))
	return err
}

func read(ctx context.Context, r remote.Runner, path string) ([]byte, error) {
	out, err := r.Run(ctx, "docker", "exec", proxy.Container, "cat", path)
	return []byte(out), err
}
