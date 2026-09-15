package release

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fake struct {
	out     map[string]string
	writes  map[string]string
	appends map[string]string
	removed []string
}

func newFake() *fake {
	return &fake{out: map[string]string{}, writes: map[string]string{}, appends: map[string]string{}}
}

func (f *fake) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	if args[0] == "rm" {
		f.removed = append(f.removed, args[2:]...)
	}
	for prefix, out := range f.out {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	return "", nil
}

func (f *fake) Pipe(_ context.Context, content []byte, args ...string) (string, error) {
	script := args[len(args)-1]
	if _, tail, ok := strings.Cut(script, " && mv "); ok {
		_, dest, _ := strings.Cut(tail, "' '")
		f.writes[strings.Trim(dest, "'")] = string(content)
		return "", nil
	}
	if _, path, ok := strings.Cut(script, "cat >> "); ok {
		f.appends[strings.Trim(path, "'")] += string(content)
	}
	return "", nil
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	f := newFake()
	s := Snapshot{ID: "demo-v2-2", App: "demo", Image: "ghcr.io/x/y", Tag: "v2", Digest: "sha256:abc"}
	if err := Save(context.Background(), f, s); err != nil {
		t.Fatal(err)
	}
	body := f.writes[".boks/demo/releases/demo-v2-2.json"]
	if body == "" {
		t.Fatalf("nothing written: %v", f.writes)
	}
	f.out["cat .boks/demo/releases/demo-v2-2.json"] = body
	got, err := Load(context.Background(), f, "demo", "demo-v2-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != "sha256:abc" || got.Tag != "v2" {
		t.Errorf("round trip lost data: %+v", got)
	}
}

// Rollback aims at the release before the current one, not at the newest file on disk.
func TestPreviousSkipsTheCurrentRelease(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\ndemo-v3-3.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v3-3\n"
	prev, err := Previous(context.Background(), f, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if prev != "demo-v2-2" {
		t.Errorf("want demo-v2-2, got %q", prev)
	}
}

// An entry with no result is an operation that never closed — the evidence a deploy was cut short.
func TestUnfinishedFindsTheOpenEntry(t *testing.T) {
	f := newFake()
	f.out["sh -c cat '.boks/demo/journal.jsonl'"] = strings.Join([]string{
		`{"op":"1","action":"deploy","to":"a","started_at":"2026-09-15T10:00:00Z"}`,
		`{"op":"1","result":"ok","finished_at":"2026-09-15T10:00:05Z"}`,
		`{"op":"2","action":"deploy","to":"b","started_at":"2026-09-15T11:00:00Z"}`,
	}, "\n")
	open, err := Unfinished(context.Background(), f, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if open == nil || open.To != "b" {
		t.Fatalf("want the open entry for b, got %+v", open)
	}
}

func TestUnfinishedIsNilWhenEverythingClosed(t *testing.T) {
	f := newFake()
	f.out["sh -c cat '.boks/demo/journal.jsonl'"] = strings.Join([]string{
		`{"op":"1","action":"deploy","to":"a","started_at":"2026-09-15T10:00:00Z"}`,
		`{"op":"1","result":"failed","finished_at":"2026-09-15T10:00:05Z"}`,
	}, "\n")
	open, err := Unfinished(context.Background(), f, "demo")
	if err != nil || open != nil {
		t.Fatalf("want no open entry, got %+v (%v)", open, err)
	}
}

func TestPruneKeepsTheNewest(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\ndemo-v3-3.json\n"
	if err := Prune(context.Background(), f, "demo", 2); err != nil {
		t.Fatal(err)
	}
	if len(f.removed) != 2 || !strings.Contains(f.removed[0], "demo-v1-1.json") {
		t.Errorf("want the oldest release removed with its env, got %v", f.removed)
	}
}

func TestBeginWritesAnOpenEntry(t *testing.T) {
	f := newFake()
	op, err := Begin(context.Background(), f, "demo", "deploy", "old", "new", time.Unix(1700000000, 0))
	if err != nil || op == "" {
		t.Fatalf("begin failed: %v", err)
	}
	line := f.appends[".boks/demo/journal.jsonl"]
	if !strings.Contains(line, `"to":"new"`) || strings.Contains(line, `"result"`) {
		t.Errorf("want an open entry, got %q", line)
	}
}
