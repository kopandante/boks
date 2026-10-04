package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

// server answers commands by prefix; anything else is a missing file.
type server map[string]string

func (s server) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	for prefix, out := range s {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	if args[0] == "cat" || s["fail"] != "" && strings.Contains(cmd, s["fail"]) {
		return "", errors.New("no such file")
	}
	return "", nil
}

func (s server) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return s.Run(ctx, args...)
}

func TestReleasesShowsWhatTheServerRemembers(t *testing.T) {
	s := server{
		"sh -c ls -1":                          "demo-v10-300.json\ndemo-v9-200.json\ndemo-broken-250.json\n",
		"sh -c cat '.boks/demo/current'":       "demo-v10-300\n",
		"cat .boks/demo/releases/demo-v9-200":  `{"id":"demo-v9-200","tag":"v9","digest":"sha256:9","created_at":"2026-09-15T10:00:00Z"}`,
		"cat .boks/demo/releases/demo-v10-300": `{"id":"demo-v10-300","tag":"v10","digest":"sha256:10","created_at":"2026-09-15T11:00:00Z"}`,
		"sh -c cat '.boks/demo/journal.jsonl'": `{"op":"5","action":"deploy","to":"demo-v11-400","started_at":"2026-09-15T12:00:00Z"}`,
	}
	var out strings.Builder
	if err := releases(context.Background(), s, &out, &config.Config{App: "demo"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want three releases and the open operation, got %q", out.String())
	}
	if !strings.HasPrefix(lines[0], "  demo-v9-200  v9  sha256:9") ||
		!strings.Contains(lines[1], "demo-broken-250 (unreadable") ||
		!strings.HasPrefix(lines[2], "* demo-v10-300  v10  sha256:10") {
		t.Errorf("want oldest first with the current one marked, got %q", out.String())
	}
	if !strings.Contains(lines[3], "! deploy started 2026-09-15T12:00:00Z and never finished") {
		t.Errorf("the open operation must be shown, got %q", lines[3])
	}
}

// The journal is the only place an interrupted operation shows; failing to read it is not a clean
// history.
func TestReleasesSaysWhenTheJournalCannotBeRead(t *testing.T) {
	s := server{"fail": "journal.jsonl"}
	err := releases(context.Background(), s, &strings.Builder{}, &config.Config{App: "demo"})
	if err == nil || !strings.Contains(err.Error(), "journal") {
		t.Errorf("want an error about the journal, got %v", err)
	}
}
