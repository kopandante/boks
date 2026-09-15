package deploy

import (
	"context"
	"io"
	"strings"
	"testing"
)

// The point of the journal: a rollback reproduces what actually ran — the image by digest, the
// ports and volumes of that release — rather than today's config with an old tag.
func TestRollbackRunsTheRecordedRelease(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v2-2\n"
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{
		"id":"demo-v1-1","app":"demo","image":"ghcr.io/x/y","tag":"v1","digest":"sha256:old",
		"ports":[{"name":"web","port":3000,"host":"demo.example.com","health_path":"/up","health_port":0}],
		"volumes":["data:/data"],"network":"boks","env_path":".boks/demo/demo-v1-1.env"}`
	if err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed); err != nil {
		t.Fatal(err)
	}
	if !f.has("docker run -d --name demo-v1-1700000000") {
		t.Fatalf("no container started: %v", f.calls)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "ghcr.io/x/y@sha256:old") {
		t.Errorf("the image must be pinned by the recorded digest: %v", f.calls)
	}
	if !strings.Contains(joined, "--env-file .boks/demo/demo-v1-1.env") {
		t.Errorf("the environment of that release must be used: %v", f.calls)
	}
	if !strings.Contains(joined, "kamal-proxy deploy demo.web --target demo-v1-1700000000:3000") {
		t.Errorf("routes must point at the restored container: %v", f.calls)
	}
	if !strings.Contains(f.appends[".boks/demo/journal.jsonl"], `"action":"rollback"`) {
		t.Errorf("the rollback must be journalled: %q", f.appends[".boks/demo/journal.jsonl"])
	}
}

// Without the environment file the release cannot be reproduced, only approximated — say so
// instead of starting the app with today's variables under an old image.
func TestRollbackRefusesWhenTheReleaseEnvIsGone(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v2-2\n"
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{"id":"demo-v1-1","app":"demo","image":"ghcr.io/x/y","tag":"v1","env_path":".boks/demo/demo-v1-1.env"}`
	f.fail["test -f"] = errNotFound
	err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed)
	if err == nil || !strings.Contains(err.Error(), "cannot be reproduced") {
		t.Fatalf("want a refusal about the missing environment, got %v", err)
	}
}

func TestRollbackWithoutAnyEarlierRelease(t *testing.T) {
	f := newFake()
	f.out["docker ps -a --filter name=^boks-proxy$"] = "running"
	err := Rollback(context.Background(), f, io.Discard, parse(t, onePort), "", fixed)
	if err == nil || !strings.Contains(err.Error(), "no earlier release") {
		t.Fatalf("want a clear refusal, got %v", err)
	}
}
