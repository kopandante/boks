package release

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
)

type fake struct {
	out     map[string]string
	writes  map[string]string
	appends map[string]string
	removed []string
	// rmFlags is the flags of every rm, in order: a release's files are a directory, which plain -f refuses.
	rmFlags []string
}

func newFake() *fake {
	return &fake{out: map[string]string{}, writes: map[string]string{}, appends: map[string]string{}}
}

func (f *fake) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	if args[0] == "rm" {
		f.removed = append(f.removed, args[2:]...)
		f.rmFlags = append(f.rmFlags, args[1])
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
	s := Snapshot{ID: "demo-v2-2", App: "demo", Image: "ghcr.io/x/y", Tag: "v2", Digest: "sha256:abc", Ports: []config.Port{
		{Name: "img", Port: 8080, Host: "cars.example.com", Path: "/api/images", PathRewrite: "/img",
			Headers: &config.Headers{Request: map[string]string{"Cookie": ""}, Response: map[string]string{"X-Content-Type-Options": "nosniff"}}},
		{Name: "old", Port: 8081, Host: "cars.example.com", Path: "/old", StripPath: true},
	}}
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
	// A rollback routes the release as it ran: its paths, rewrites and header rules come back.
	if !reflect.DeepEqual(got.Ports, s.Ports) {
		t.Errorf("round trip lost the ports' routing:\n got %+v\nwant %+v", got.Ports, s.Ports)
	}
}

// Rollback aims at the release before the current one, not at the newest file on disk.
func TestPreviousSkipsTheCurrentRelease(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\ndemo-v3-3.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v3-3\n"
	f.out["cat .boks/demo/releases/demo-v3-3.json"] = `{"id":"demo-v3-3"}`
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
	if err := Prune(context.Background(), f, "demo", "", 2); err != nil {
		t.Fatal(err)
	}
	if len(f.removed) != 4 || !strings.Contains(f.removed[0], "demo-v1-1.json") || f.removed[2] != ".boks/demo/files/demo-v1-1" || f.removed[3] != ".boks/demo/jobs/demo-v1-1" {
		t.Errorf("want the oldest release removed with its env and files, got %v", f.removed)
	}
	if strings.Join(f.rmFlags, " ") != "-rf" {
		t.Errorf("the files are a directory, so the removal must be recursive: %v", f.rmFlags)
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

// The tag comes before the time in a release name, so sorting names as text orders them by tag.
// With git short SHAs the release just deployed can sort first; it must still be the one kept.
func TestPruneGoesByAgeNotByTag(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-0a1b2c3-400.json\ndemo-c1d2e3f-100.json\ndemo-d4e5f6a-200.json\ndemo-e7f8a9b-300.json\n"
	if err := Prune(context.Background(), f, "demo", "", 3); err != nil {
		t.Fatal(err)
	}
	want := []string{".boks/demo/releases/demo-c1d2e3f-100.json", ".boks/demo/demo-c1d2e3f-100.env", ".boks/demo/files/demo-c1d2e3f-100", ".boks/demo/jobs/demo-c1d2e3f-100"}
	if strings.Join(f.removed, " ") != strings.Join(want, " ") {
		t.Errorf("want only the oldest release and its env removed, got %v", f.removed)
	}
}

func TestIDsAreOldestFirstAcrossTags(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v10-300.json\ndemo-v9-200.json\ndemo-v9-100.json\ndemo-v10-300.json.tmp\n"
	ids, err := IDs(context.Background(), f, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, " ") != "demo-v9-100 demo-v9-200 demo-v10-300" {
		t.Errorf("want oldest first and no temporary files, got %v", ids)
	}
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v10-300\n"
	f.out["cat .boks/demo/releases/demo-v10-300.json"] = `{"id":"demo-v10-300"}`
	if prev, _ := Previous(context.Background(), f, "demo"); prev != "demo-v9-200" {
		t.Errorf("the release before v10 is the newer v9, got %q", prev)
	}
}

func TestPruneKeepsEverythingWithinKeep(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\n"
	if err := Prune(context.Background(), f, "demo", "", 2); err != nil {
		t.Fatal(err)
	}
	if len(f.removed) != 0 {
		t.Errorf("nothing beyond keep, nothing removed: %v", f.removed)
	}
}

// Several open entries happen when a run is cut and the next one is cut too; the newest is the one
// that describes the server now.
func TestUnfinishedPicksTheNewestOpenEntry(t *testing.T) {
	f := newFake()
	f.out["sh -c cat '.boks/demo/journal.jsonl'"] = strings.Join([]string{
		`{"op":"2","action":"deploy","to":"b","started_at":"2026-09-15T11:00:00Z"}`,
		`{"op":"1","action":"deploy","to":"a","started_at":"2026-09-15T10:00:00Z"}`,
		`{"op":"3","action":"deploy","to":"c","started_at":"2026-09-15T12:00:00Z"}`,
		`{"op":"3","result":"abandoned","finished_at":"2026-09-15T13:00:00Z"}`,
		`{"op":"4","action":"deploy","to":"d","sta`,
	}, "\n")
	open, err := Unfinished(context.Background(), f, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if open == nil || open.To != "b" {
		t.Fatalf("want the newest open entry b, got %+v", open)
	}
}

func TestSaveWritesTheFormatVersion(t *testing.T) {
	// 9 is the first format with a port's path, rewrite and headers: a boks reading 8 must refuse
	// such a release rather than route its paths to the whole host.
	if FormatVersion < 9 {
		t.Errorf("format %d cannot carry routing by path", FormatVersion)
	}
	f := newFake()
	if err := Save(context.Background(), f, Snapshot{ID: "demo-v1-1", App: "demo"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.writes[".boks/demo/releases/demo-v1-1.json"], fmt.Sprintf(`"version": %d`, FormatVersion)) {
		t.Errorf("a snapshot must say which format it is: %s", f.writes[".boks/demo/releases/demo-v1-1.json"])
	}
}

// A snapshot newer than current is a deploy that saved it and was cut before moving current; it is
// not the release before current.
func TestPreviousIsTheOneBeforeCurrent(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v1-100.json\ndemo-v2-200.json\ndemo-v3-300.json\n"
	f.out["cat .boks/demo/releases/demo-v1-100.json"] = `{"id":"demo-v1-100"}`
	f.out["cat .boks/demo/releases/demo-v2-200.json"] = `{"id":"demo-v2-200"}`
	for current, want := range map[string]string{"demo-v2-200": "demo-v1-100", "demo-v1-100": "", "": "", "demo-gone-50": ""} {
		f.out["sh -c cat '.boks/demo/current'"] = current + "\n"
		if got, err := Previous(context.Background(), f, "demo"); err != nil || got != want {
			t.Errorf("current %q: want %q, got %q (%v)", current, want, got, err)
		}
	}
}

// An open line carries no finish time and a closing line no start: the field's absence is the
// information, so the zero time must not be written.
func TestJournalLinesCarryOnlyWhatHappened(t *testing.T) {
	f := newFake()
	op, _ := Begin(context.Background(), f, "demo", "deploy", "", "new", time.Unix(1700000000, 0))
	_ = Finish(context.Background(), f, "demo", op, "ok", time.Unix(1700000001, 0))
	lines := strings.Split(strings.TrimSpace(f.appends[".boks/demo/journal.jsonl"]), "\n")
	if len(lines) != 2 || strings.Contains(lines[0], "finished_at") || strings.Contains(lines[1], "started_at") ||
		strings.Contains(lines[1], `"to"`) {
		t.Errorf("want no zero fields, got %q", lines)
	}
}

// Once a rollback has happened, deploy order is not what served before: v4 was deployed over v2,
// after v3 had been rolled back from, so a rollback from v4 must reach v2 and not v3.
func TestPreviousIsWhatTheCurrentReleaseWasDeployedOver(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v1-100.json\ndemo-v2-200.json\ndemo-v3-300.json\ndemo-v4-400.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v4-400\n"
	f.out["cat .boks/demo/releases/demo-v4-400.json"] = `{"id":"demo-v4-400","previous":"demo-v2-200"}`
	if prev, err := Previous(context.Background(), f, "demo"); err != nil || prev != "demo-v2-200" {
		t.Errorf("want the release v4 was deployed over, got %q (%v)", prev, err)
	}
}

// After v1, v2, v3, two rollbacks to v1 and a deploy of v4 over it, the newest three are v2, v3,
// v4; v1 is what v4's rollback has to reach, so it is v2 — oldest of the releases a rollback no
// longer walks through — that goes.
func TestPruneKeepsWhatARollbackReaches(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v1-1.json\ndemo-v2-2.json\ndemo-v3-3.json\ndemo-v4-4.json\n"
	f.out["cat .boks/demo/releases/demo-v4-4.json"] = `{"id":"demo-v4-4","previous":"demo-v1-1"}`
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{"id":"demo-v1-1"}`
	if err := Prune(context.Background(), f, "demo", "demo-v4-4", 3); err != nil {
		t.Fatal(err)
	}
	want := []string{".boks/demo/releases/demo-v2-2.json", ".boks/demo/demo-v2-2.env", ".boks/demo/files/demo-v2-2", ".boks/demo/jobs/demo-v2-2"}
	if strings.Join(f.removed, " ") != strings.Join(want, " ") {
		t.Errorf("want v2 removed and v1 kept, got %v", f.removed)
	}
}

// A predecessor that is no longer kept cannot be returned to, so there is no previous release.
func TestPreviousIsNothingWhenThePredecessorWasPruned(t *testing.T) {
	f := newFake()
	f.out["sh -c ls -1"] = "demo-v2-2.json\ndemo-v3-3.json\n"
	f.out["sh -c cat '.boks/demo/current'"] = "demo-v3-3\n"
	f.out["cat .boks/demo/releases/demo-v3-3.json"] = `{"id":"demo-v3-3","previous":"demo-v1-1"}`
	if prev, err := Previous(context.Background(), f, "demo"); err != nil || prev != "" {
		t.Errorf("want no previous release, got %q (%v)", prev, err)
	}
}

// The memory limit and the replace mode are part of what a release ran, so they survive the trip.
func TestSnapshotKeepsTheLimitAndTheReplaceMode(t *testing.T) {
	f := newFake()
	s := Snapshot{ID: "demo-v2-2", App: "demo", Memory: "512m", Replace: "stop-first"}
	if err := Save(context.Background(), f, s); err != nil {
		t.Fatal(err)
	}
	f.out["cat .boks/demo/releases/demo-v2-2.json"] = f.writes[".boks/demo/releases/demo-v2-2.json"]
	got, err := Load(context.Background(), f, "demo", "demo-v2-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Memory != "512m" || got.Replace != "stop-first" {
		t.Errorf("limit and replace mode lost: %+v", got)
	}
}

// A snapshot of a newer format may carry fields this binary does not know — a replace mode that
// keeps two writers off one volume among them — so it is refused rather than run without them.
func TestLoadRefusesANewerFormat(t *testing.T) {
	f := newFake()
	f.out["cat .boks/demo/releases/demo-v9-9.json"] = fmt.Sprintf(`{"version": %d, "id": "demo-v9-9", "app": "demo"}`, FormatVersion+1)
	if _, err := Load(context.Background(), f, "demo", "demo-v9-9"); err == nil || !strings.Contains(err.Error(), "newer boks") {
		t.Fatalf("want a refusal naming a newer boks, got %v", err)
	}
	f.out["cat .boks/demo/releases/demo-v1-1.json"] = `{"version": 1, "id": "demo-v1-1", "app": "demo"}`
	if _, err := Load(context.Background(), f, "demo", "demo-v1-1"); err != nil {
		t.Fatalf("an older format is still read: %v", err)
	}
}
