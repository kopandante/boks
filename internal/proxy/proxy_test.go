package proxy

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestDeployArgs(t *testing.T) {
	got := strings.Join(DeployArgs(Service{
		Name: "demo.actions", Target: "demo-v2-1:3211", Host: "actions.example.com",
		TLS: true, HealthPath: "/version", HealthPort: 3210, Timeout: "60s",
	}), " ")
	want := "docker exec boks-proxy kamal-proxy deploy demo.actions --target demo-v2-1:3211 " +
		"--host actions.example.com --tls --health-check-path /version --health-check-port 3210 --deploy-timeout 60s"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestDeployArgsWithManualCertificate(t *testing.T) {
	got := strings.Join(DeployArgs(Service{
		Name: "a-web", Target: "a-1:80", Host: "a.example.com", TLS: true,
		CertPath: "/certs/boks/_.example.com.crt", KeyPath: "/certs/boks/_.example.com.key",
	}), " ")
	want := "docker exec boks-proxy kamal-proxy deploy a-web --target a-1:80 --host a.example.com --tls " +
		"--tls-certificate-path /certs/boks/_.example.com.crt --tls-private-key-path /certs/boks/_.example.com.key"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestDeployArgsMinimal(t *testing.T) {
	got := strings.Join(DeployArgs(Service{Name: "a-web", Target: "a-1:80", Host: "a.example.com"}), " ")
	if got != "docker exec boks-proxy kamal-proxy deploy a-web --target a-1:80 --host a.example.com" {
		t.Errorf("got %s", got)
	}
}

type fake struct {
	calls []string
	state string
}

func (f *fake) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if strings.HasPrefix(cmd, "docker ps -a") {
		return f.state, nil
	}
	return "", nil
}

func (f *fake) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return f.Run(ctx, args...)
}

func TestBootIdempotent(t *testing.T) {
	f := &fake{state: "running"}
	if err := Boot(context.Background(), f, io.Discard, "boks", "img"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker run") || strings.HasPrefix(c, "docker start") {
			t.Errorf("running proxy must not be touched, got %s", c)
		}
	}
}

func TestBootStartsMissingProxy(t *testing.T) {
	f := &fake{state: ""}
	if err := Boot(context.Background(), f, io.Discard, "boks", "img"); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-1]
	if !strings.HasPrefix(last, "docker run -d --name boks-proxy") || !strings.HasSuffix(last, " img") {
		t.Errorf("expected docker run, got %s", last)
	}
}

func TestBootRestartsStoppedProxy(t *testing.T) {
	f := &fake{state: "exited"}
	if err := Boot(context.Background(), f, io.Discard, "boks", "img"); err != nil {
		t.Fatal(err)
	}
	if f.calls[len(f.calls)-1] != "docker start boks-proxy" {
		t.Errorf("expected docker start, got %v", f.calls)
	}
}

type said string

func (s said) Run(context.Context, ...string) (string, error)          { return string(s), nil }
func (s said) Pipe(context.Context, []byte, ...string) (string, error) { return string(s), nil }

// What kamal-proxy v0.10.0 prints for `list --json`, verbatim in shape: the deploy decides who
// owns a service and which host it holds from these two fields, so their names are pinned here
// rather than taken from the decoder's own struct tags.
func TestServicesReadsKamalProxysList(t *testing.T) {
	out := said(`{
  "demo-web": {
    "hosts": ["demo.example.com"],
    "path_prefixes": ["/"],
    "tls": true,
    "targets": ["demo-v1-1700000000:3000"],
    "read_targets": [],
    "state": "running",
    "rollout": {"enabled": false, "percentage": 0, "allowlist": [], "targets": [], "read_targets": []}
  },
  "bot.api": {
    "hosts": ["api.example.com"],
    "path_prefixes": ["/"],
    "tls": false,
    "targets": ["bot-v2-1700000001:8080"],
    "read_targets": [],
    "state": "running",
    "rollout": {"enabled": false, "percentage": 0, "allowlist": [], "targets": [], "read_targets": []}
  }
}`)
	services, names, err := Services(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, " ") != "bot.api demo-web" {
		t.Errorf("names %v", names)
	}
	web := services["demo-web"]
	if strings.Join(web.Hosts, ",") != "demo.example.com" || strings.Join(web.Targets, ",") != "demo-v1-1700000000:3000" {
		t.Errorf("demo-web read as %+v", web)
	}
}
