package deploy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
)

type fake struct {
	calls   []string
	uploads map[string]string
	out     map[string]string
	fail    map[string]error
}

func newFake() *fake {
	return &fake{uploads: map[string]string{}, out: map[string]string{}, fail: map[string]error{}}
}

func (f *fake) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	for prefix, err := range f.fail {
		if strings.HasPrefix(cmd, prefix) {
			return "", err
		}
	}
	for prefix, out := range f.out {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	return "", nil
}

func (f *fake) Upload(_ context.Context, content []byte, path string) error {
	f.uploads[path] = string(content)
	return nil
}

func testConfig() *config.Config {
	cfg, err := config.Parse([]byte(`
app: demo
image: ghcr.io/x/y
servers: [lab]
keep: 2
volumes: [data:/data]
ports:
  - {name: web, port: 3000, host: demo.example.com, health_path: /up}
tls: true
`))
	if err != nil {
		panic(err)
	}
	return cfg
}

var fixed = Options{Pull: true, Env: []byte("SECRET=1\n"), Now: func() time.Time { return time.Unix(1700000000, 0) }}

func TestRunHappyPath(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\n"
	f.out["docker images ghcr.io/x/y"] = "v2\nv1\nv0\n"
	if err := Run(context.Background(), f, io.Discard, testConfig(), "v2", fixed); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mkdir /tmp/boks-demo.lock",
		"docker network inspect boks",
		"docker ps -a --filter name=^boks-proxy$ --format {{.State}}",
		"docker pull ghcr.io/x/y:v2",
		"docker ps -a --filter label=boks.app=demo --format {{.Names}}",
		"docker run -d --name demo-v2-1700000000 --network boks --restart unless-stopped " +
			"--label boks.app=demo --label boks.version=v2 --env-file .boks/demo/demo-v2-1700000000.env " +
			"-v demo-data:/data ghcr.io/x/y:v2",
		"docker exec boks-proxy kamal-proxy deploy demo-web --target demo-v2-1700000000:3000 " +
			"--host demo.example.com --tls --health-check-path /up --deploy-timeout 60s",
		"docker stop demo-v1-1",
		"docker rm demo-v1-1",
		"docker images ghcr.io/x/y --format {{.Tag}}",
		"docker rmi ghcr.io/x/y:v0",
		"rmdir /tmp/boks-demo.lock",
	}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(want, "\n"))
	}
	if f.uploads[".boks/demo/demo-v2-1700000000.env"] != "SECRET=1\n" {
		t.Errorf("env not uploaded: %v", f.uploads)
	}
}

func TestRunLocked(t *testing.T) {
	f := newFake()
	f.fail["mkdir"] = errors.New("File exists")
	err := Run(context.Background(), f, io.Discard, testConfig(), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "boks unlock") {
		t.Fatalf("want lock error, got %v", err)
	}
	if len(f.calls) != 1 {
		t.Errorf("nothing must run while locked, got %v", f.calls)
	}
}

func TestRunKeepsOldWhenSwitchFails(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["docker ps -a --filter label=boks.app=demo"] = "demo-v1-1\n"
	f.fail["docker exec boks-proxy kamal-proxy deploy"] = errors.New("health check failed")
	err := Run(context.Background(), f, io.Discard, testConfig(), "v2", fixed)
	if err == nil || !strings.Contains(err.Error(), "still serves traffic") {
		t.Fatalf("want switch error, got %v", err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker stop") || strings.HasPrefix(c, "docker rm ") {
			t.Errorf("old container must survive a failed switch, got %s", c)
		}
	}
	if f.calls[len(f.calls)-1] != "rmdir /tmp/boks-demo.lock" {
		t.Errorf("lock must be released on failure, last call %s", f.calls[len(f.calls)-1])
	}
}

func TestRollbackSkipsPull(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	if err := Run(context.Background(), f, io.Discard, testConfig(), "v1", Options{Now: fixed.Now}); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "docker pull") || strings.Contains(c, "--env-file") {
			t.Errorf("unexpected %s", c)
		}
	}
}

func TestContainerNameSanitizes(t *testing.T) {
	got := ContainerName("app", "sha:ab/12", time.Unix(5, 0))
	if got != "app-sha-ab-12-5" {
		t.Errorf("got %s", got)
	}
}
