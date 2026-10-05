package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
)

type fake struct {
	calls  []string
	writes map[string][]byte
	files  map[string]string // path inside the proxy container → content
}

func newFake() *fake {
	return &fake{writes: map[string][]byte{}, files: map[string]string{}}
}

func (f *fake) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if len(args) == 5 && args[3] == "cat" {
		if content, ok := f.files[args[4]]; ok {
			return content, nil
		}
		return "", os.ErrNotExist
	}
	return "", nil
}

func (f *fake) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	// The write script ends with `cat > '<path>'; chown ...`; recover the path it writes to.
	script := args[len(args)-1]
	if _, rest, ok := strings.Cut(script, "cat > '"); ok {
		path := rest[:strings.Index(rest, "'")]
		f.writes[path] = content
		f.files[path] = string(content)
	}
	return "", nil
}

// newPair returns a real self-signed certificate and its key. Install checks that the two match
// before writing them, so the fixtures have to be genuine crypto rather than PEM-shaped strings.
func newPair(t *testing.T) (crtPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "*.lab.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{"*.lab.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// replacementPair stands in for a renewal: a different certificate, with its key written
// alongside so the local pair stays consistent.
func replacementPair(t *testing.T, cfg *config.Config) []byte {
	t.Helper()
	crt, key := newPair(t)
	if err := os.WriteFile(localBase(cfg)+".key", key, 0o600); err != nil {
		t.Fatal(err)
	}
	return crt
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	certs := filepath.Join(dir, ".lego", "certificates")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	crtPEM, keyPEM := newPair(t)
	for name, content := range map[string][]byte{
		"_.lab.example.com.crt":  crtPEM,
		"_.lab.example.com.key":  keyPEM,
		"_.lab.example.com.json": []byte(`{"domain":"*.lab.example.com"}`), // lego's own metadata
	} {
		if err := os.WriteFile(filepath.Join(certs, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Parse([]byte(`
app: demo
image: ghcr.io/x/y
servers: [lab]
ports:
  - {name: web, port: 3000, host: api.lab.example.com}
cert:
  domains: ["*.lab.example.com"]
  dns: cloudflare
  email: a@b.c
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Dir = dir
	return cfg
}

// A fresh certificate volume is root-owned; the write goes in as root, which Caddy runs as, and keeps
// the key from other users. kamal-proxy's uid is no longer handed anything.
func TestInstallWritesAsRootAndKeepsTheKeyPrivate(t *testing.T) {
	f, cfg := newFake(), testConfig(t)
	if err := Install(context.Background(), f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, c := range f.calls {
		if strings.Contains(c, "cat >") {
			script = c
			break
		}
	}
	for _, want := range []string{"docker exec -i -u 0", "chmod 640", "chmod 750"} {
		if !strings.Contains(script, want) {
			t.Errorf("write script must contain %q, got:\n%s", want, script)
		}
	}
	if strings.Contains(script, "chown") {
		t.Errorf("Caddy runs as root, nothing is handed over: %s", script)
	}
	crt, key := ServerPaths(cfg.Cert)
	// Compared by content, not merely by presence: swapping the two paths would still put a
	// non-empty file at each of them.
	if !bytes.Equal(f.writes[crt], mustRead(t, localBase(cfg)+".crt")) {
		t.Errorf("the certificate path must receive the certificate, got %q", f.writes[crt])
	}
	if !bytes.Equal(f.writes[key], mustRead(t, localBase(cfg)+".key")) {
		t.Errorf("the key path must receive the key, got %q", f.writes[key])
	}
}

func TestInstallSkipsAnIdenticalCertificate(t *testing.T) {
	f, cfg := newFake(), testConfig(t)
	crt, _ := ServerPaths(cfg.Cert)
	f.files[crt] = string(mustRead(t, localBase(cfg)+".crt"))
	meta, err := os.ReadFile(localBase(cfg) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	f.files[metaPath(cfg.Cert)] = string(meta) // a server that is already fully up to date
	if err := Install(context.Background(), f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Errorf("nothing to do, but wrote %v", f.writes)
	}
}

// A deploy whose routes changed reloads the proxy, which reads every certificate file again: it
// records the load as a renewal's reload does, and restarts nothing.
func TestMarkReloadedClearsWhatADeploysReloadLoaded(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if err := MarkReloaded(ctx, f, cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.calls, "\n"), "docker restart") || strings.Contains(strings.Join(f.calls, "\n"), "caddy reload") {
		t.Error("recording a load must not reload anything")
	}
	pending, err := Pending(ctx, f, cfg)
	if err != nil || pending {
		t.Fatalf("nothing owed after a reload loaded it, got %v %v", pending, err)
	}
}

// A reload makes Caddy read the files for every route on the server, so it settles the debt for apps
// that were never deployed — otherwise each of them would trigger its own reload.
func TestAReloadSettlesEveryApp(t *testing.T) {
	ctx, f, app1 := context.Background(), newFake(), testConfig(t)
	app2 := *app1
	app2.App = "other"
	if err := Install(ctx, f, io.Discard, app1); err != nil {
		t.Fatal(err)
	}
	if err := Reload(ctx, f, io.Discard, app1); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []*config.Config{app1, &app2} {
		pending, err := Pending(ctx, f, cfg)
		if err != nil || pending {
			t.Fatalf("%s: a reload covers every route, got %v %v", cfg.App, pending, err)
		}
	}
}

// Pending compares two things that both live on the server, so it answers from a machine with no
// lego state — a CI runner, or a second operator.
func TestPendingWithoutLocalLegoState(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	crtLocal, keyLocal := LocalPaths(cfg)
	for _, p := range []string{crtLocal, keyLocal} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := Pending(ctx, f, cfg)
	if err != nil || !pending {
		t.Fatalf("installed but not loaded is pending regardless of local files, got %v %v", pending, err)
	}
}

// The case the pull exists for: a machine that holds only what pull fetched. On the ~59 days out
// of 60 when lego decides nothing is due, `cert renew` must be a quiet no-op there — reading the
// private key before deciding would break it every one of those days.
func TestInstallSkipsWithoutTheLocalKeyWhenNothingChanged(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(localBase(cfg) + ".key"); err != nil {
		t.Fatal(err)
	}
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatalf("an unchanged certificate must not need the key: %v", err)
	}
}

// A server set up before boks stored the metadata holds the current certificate and no .json.
// The certificate matches, so nothing would ever be written — and `cert pull` needs that file.
func TestInstallRepairsMissingMetadataOnAnUnchangedCertificate(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	delete(f.files, metaPath(cfg.Cert)) // the state a previous release leaves behind
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.files[metaPath(cfg.Cert)]; !ok {
		t.Error("the metadata must be restored without re-issuing the certificate")
	}
}

// A pull that writes the certificate and then fails on the metadata leaves behind exactly the
// bare-.crt state that makes lego issue a fresh certificate on every run.
func TestPullWritesNothingWhenTheMetadataIsMissing(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	delete(f.files, metaPath(cfg.Cert))
	base := localBase(cfg)
	for _, p := range []string{base + ".crt", base + ".json"} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := Pull(ctx, f, io.Discard, cfg); err == nil {
		t.Fatal("want an error when the server has no metadata")
	}
	if _, err := os.Stat(base + ".crt"); err == nil {
		t.Error("a failed pull must not leave a lone certificate behind")
	}
}

// `cert pull` refreshes the certificate and never the key, so an operator who issued here once
// and later pulled a renewal holds a certificate and a key from different issuances. Installing
// that would leave the proxy serving a certificate its key cannot answer for — TLS broken for
// every host under the wildcard, and nothing failing at install time.
func TestInstallRefusesAMismatchedLocalPair(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	renewed, _ := newPair(t) // what a renewal elsewhere produced; its key stayed on the server
	if err := os.WriteFile(localBase(cfg)+".crt", renewed, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Install(ctx, f, io.Discard, cfg)
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "not a pair") {
		t.Errorf("the error must name the problem, got %v", err)
	}
	// Not just the pair: the metadata too. A refusal that had already moved the server's .json on
	// to the new issuance would leave it describing a certificate the server does not have.
	if len(f.writes) != 0 {
		t.Errorf("nothing may reach the server when the pair does not match, wrote %v", f.writes)
	}
}

// The operator is told at pull time, not only when a later install refuses.
func TestPullWarnsThatTheLocalKeyIsNowStale(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	renewed, _ := newPair(t)
	crtRemote, _ := ServerPaths(cfg.Cert)
	f.files[crtRemote] = string(renewed) // the server carries a certificate renewed elsewhere
	var log strings.Builder
	if err := Pull(ctx, f, &log, cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "does not match the certificate just pulled") {
		t.Errorf("the stale key must be called out, log:\n%s", log.String())
	}
}

// The counterpart: a warning that fired every time would pass the test above and teach the
// operator to ignore it. The ordinary pull — the server holds what this machine issued — is silent.
func TestPullIsSilentWhileTheLocalKeyStillMatches(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	if err := Pull(ctx, f, &log, cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "warning") {
		t.Errorf("the pair still matches, nothing to warn about, log:\n%s", log.String())
	}
}

// Pull brings back exactly what a renewal needs to decide, and nothing secret: measured against
// lego 5, a bare .crt is ignored and a fresh certificate issued, while .crt plus .json is
// recognised and skipped until due.
func TestPullFetchesTheCertificateAndMetadataOnly(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	base := localBase(cfg)
	for _, p := range []string{base + ".crt", base + ".json", base + ".key"} {
		os.Remove(p) //nolint:errcheck // why: absence is the state under test, not an error
	}
	if err := Pull(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{base + ".crt", base + ".json"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s must be pulled: %v", p, err)
		}
	}
	if _, err := os.Stat(base + ".key"); err == nil {
		t.Error("the private key must not be pulled — a renewal does not need it")
	}
}

// The whole point of tracking the reload separately: a run that installed the file and then died
// must leave the next run knowing a reload is still owed.
func TestPendingUntilReloadRecordsIt(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	pending, err := Pending(ctx, f, cfg)
	if err != nil || !pending {
		t.Fatalf("installed but never loaded must be pending, got %v %v", pending, err)
	}
	if err := Reload(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	// Forced: the paths are unchanged, and Caddy skips an unchanged config (measured on boks-lab).
	if !strings.Contains(strings.Join(f.calls, "\n"), "docker exec boks-proxy caddy reload --config /etc/boks/caddy.json --force") {
		t.Errorf("reload must force Caddy to load the files again, calls:\n%s", strings.Join(f.calls, "\n"))
	}
	pending, err = Pending(ctx, f, cfg)
	if err != nil || pending {
		t.Fatalf("after a reload nothing is owed, got %v %v", pending, err)
	}
}

// A renewal installed on the server makes a reload owed again, even though the marker exists.
// Note what does NOT make it pending: a new certificate sitting only on the operator's disk —
// the proxy cannot be behind on something the server has never been given.
func TestPendingAgainAfterANewCertificateIsInstalled(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if err := Reload(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	crtLocal, _ := LocalPaths(cfg)
	if err := os.WriteFile(crtLocal, replacementPair(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	pending, err := Pending(ctx, f, cfg)
	if err != nil || pending {
		t.Fatalf("a certificate only on the local disk is not owed to the proxy yet, got %v %v", pending, err)
	}
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	pending, err = Pending(ctx, f, cfg)
	if err != nil || !pending {
		t.Fatalf("once installed it must be pending, got %v %v", pending, err)
	}
}

func TestInstalledReportsWhatADeployWouldFind(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if Installed(ctx, f, cfg) {
		t.Error("nothing installed yet")
	}
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if !Installed(ctx, f, cfg) {
		t.Error("installed certificate must be visible to a deploy")
	}
}
