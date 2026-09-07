package cert

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// certPEM is a syntactically valid PEM block; the tests that use it never parse it.
const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	certs := filepath.Join(dir, ".lego", "certificates")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"_.lab.example.com.crt":  certPEM,
		"_.lab.example.com.key":  "KEY",
		"_.lab.example.com.json": `{"domain":"*.lab.example.com"}`, // lego's own metadata
	} {
		if err := os.WriteFile(filepath.Join(certs, name), []byte(content), 0o600); err != nil {
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

// A fresh certificate volume is root-owned and `docker exec` runs as the image's non-root user,
// so the write has to go in as root and hand the result to the proxy user. Getting this wrong
// meant the feature could never deliver a certificate to a real server.
func TestInstallWritesAsRootAndHandsOverToTheProxyUser(t *testing.T) {
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
	for _, want := range []string{"docker exec -i -u 0", "chown 1001:1001", "chmod 640", "chmod 750"} {
		if !strings.Contains(script, want) {
			t.Errorf("write script must contain %q, got:\n%s", want, script)
		}
	}
	crt, key := ServerPaths(cfg.Cert)
	if string(f.writes[crt]) != certPEM || string(f.writes[key]) != "KEY" {
		t.Errorf("both files must be installed, got %v", f.writes)
	}
}

func TestInstallSkipsAnIdenticalCertificate(t *testing.T) {
	f, cfg := newFake(), testConfig(t)
	crt, _ := ServerPaths(cfg.Cert)
	f.files[crt] = certPEM
	if err := Install(context.Background(), f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Errorf("nothing to do, but wrote %v", f.writes)
	}
}

// A deploy points routes at the certificate path, which makes the proxy read it — so a deploy
// is a load and must clear the debt, or status would keep claiming a reload is owed.
func TestMarkLoadedClearsWhatADeployLoaded(t *testing.T) {
	ctx, f, cfg := context.Background(), newFake(), testConfig(t)
	if err := Install(ctx, f, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if err := MarkLoaded(ctx, f, cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.calls, "\n"), "docker restart") {
		t.Error("recording a load must not restart anything")
	}
	pending, err := Pending(ctx, f, cfg)
	if err != nil || pending {
		t.Fatalf("nothing owed after a deploy loaded it, got %v %v", pending, err)
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
	if !strings.Contains(strings.Join(f.calls, "\n"), "docker restart boks-proxy") {
		t.Errorf("reload must restart the proxy, calls:\n%s", strings.Join(f.calls, "\n"))
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
	if err := os.WriteFile(crtLocal, []byte(strings.Replace(certPEM, "MIIB", "MIIC", 1)), 0o600); err != nil {
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
