// Package release remembers what was deployed. A successful deploy removes the previous
// container, and with it every trace of the version that worked: image, ports, volumes, the
// environment it was given. Swarm keeps that in its raft state and rolls back for free; on plain
// containers it has to be written down, or `rollback` can only guess from a tag and an operation
// interrupted halfway cannot be told from one that finished.
//
// Storage is files on the server, one JSON document per release. When boksd arrives the index
// moves into SQLite beside it; the snapshot format is what has to survive that move, so it is
// plain data with no server-side interpretation.
package release

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// Snapshot is everything needed to run a release again without consulting the current config.
type Snapshot struct {
	ID        string        `json:"id"`
	App       string        `json:"app"`
	Image     string        `json:"image"`
	Tag       string        `json:"tag"`
	Digest    string        `json:"digest,omitempty"`
	Ports     []config.Port `json:"ports"`
	Volumes   []string      `json:"volumes"`
	Network   string        `json:"network"`
	EnvPath   string        `json:"env_path,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

// Entry is one line of the operation journal. Started without Finished is the state that used to
// be invisible: a deploy that died between switching routes and retiring the old container.
type Entry struct {
	Op         string    `json:"op"`
	Action     string    `json:"action"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Result     string    `json:"result,omitempty"`
}

func Dir(app string) string              { return ".boks/" + app }
func snapshotPath(app, id string) string { return path.Join(Dir(app), "releases", id+".json") }
func currentPath(app string) string      { return path.Join(Dir(app), "current") }
func journalPath(app string) string      { return path.Join(Dir(app), "journal.jsonl") }

// Save writes a snapshot. The write is atomic because a half-written snapshot is worse than a
// missing one: rollback would run something that never existed.
func Save(ctx context.Context, r remote.Runner, s Snapshot) error {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return remote.UploadAtomic(ctx, r, append(body, '\n'), snapshotPath(s.App, s.ID))
}

func Load(ctx context.Context, r remote.Runner, app, id string) (*Snapshot, error) {
	out, err := r.Run(ctx, "cat", snapshotPath(app, id))
	if err != nil {
		return nil, fmt.Errorf("release %s of %s: %w", id, app, err)
	}
	var s Snapshot
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		return nil, fmt.Errorf("release %s of %s: %w", id, app, err)
	}
	return &s, nil
}

// IDs lists the releases kept on the server, oldest first. Names carry a unix timestamp, so
// sorting them sorts by age.
func IDs(ctx context.Context, r remote.Runner, app string) ([]string, error) {
	out, err := r.Run(ctx, "sh", "-c", "ls -1 "+remote.Quote(path.Join(Dir(app), "releases"))+" 2>/dev/null || true")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); strings.HasSuffix(name, ".json") {
			ids = append(ids, strings.TrimSuffix(name, ".json"))
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func SetCurrent(ctx context.Context, r remote.Runner, app, id string) error {
	return remote.UploadAtomic(ctx, r, []byte(id+"\n"), currentPath(app))
}

// Current is the release the server believes is serving. Absent means this app has never been
// deployed by a boks that keeps a journal — not an error.
func Current(ctx context.Context, r remote.Runner, app string) (string, error) {
	out, err := r.Run(ctx, "sh", "-c", "cat "+remote.Quote(currentPath(app))+" 2>/dev/null || true")
	return strings.TrimSpace(out), err
}

// Previous is the release before the current one, which is what a rollback aims at.
func Previous(ctx context.Context, r remote.Runner, app string) (string, error) {
	ids, err := IDs(ctx, r, app)
	if err != nil {
		return "", err
	}
	current, err := Current(ctx, r, app)
	if err != nil {
		return "", err
	}
	for i := len(ids) - 1; i >= 0; i-- {
		if ids[i] != current {
			return ids[i], nil
		}
	}
	return "", nil
}

// Prune keeps the newest `keep` snapshots and their env files. It runs after a deploy succeeds,
// so the release just recorded is always among them.
func Prune(ctx context.Context, r remote.Runner, app string, keep int) error {
	ids, err := IDs(ctx, r, app)
	if err != nil || len(ids) <= keep {
		return err
	}
	for _, id := range ids[:len(ids)-keep] {
		if _, err := r.Run(ctx, "rm", "-f", snapshotPath(app, id), path.Join(Dir(app), id+".env")); err != nil {
			return err
		}
	}
	return nil
}

// Begin records that an operation is under way, before anything on the server changes. Finish
// closes it. A journal that ends on a `started` line is the evidence that a deploy was cut short,
// which no amount of looking at containers can tell you.
func Begin(ctx context.Context, r remote.Runner, app, action, from, to string, now time.Time) (string, error) {
	op := fmt.Sprintf("%d", now.UnixNano())
	return op, appendEntry(ctx, r, app, Entry{Op: op, Action: action, From: from, To: to, StartedAt: now})
}

func Finish(ctx context.Context, r remote.Runner, app, op, result string, now time.Time) error {
	return appendEntry(ctx, r, app, Entry{Op: op, Result: result, FinishedAt: now})
}

// Unfinished returns the last operation that was started and never closed.
func Unfinished(ctx context.Context, r remote.Runner, app string) (*Entry, error) {
	out, err := r.Run(ctx, "sh", "-c", "cat "+remote.Quote(journalPath(app))+" 2>/dev/null || true")
	if err != nil || strings.TrimSpace(out) == "" {
		return nil, err
	}
	open := map[string]Entry{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Result == "" {
			open[e.Op] = e
			continue
		}
		delete(open, e.Op)
	}
	var newest *Entry
	for _, e := range open {
		if newest == nil || e.StartedAt.After(newest.StartedAt) {
			entry := e
			newest = &entry
		}
	}
	return newest, nil
}

func appendEntry(ctx context.Context, r remote.Runner, app string, e Entry) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return remote.Append(ctx, r, append(body, '\n'), journalPath(app))
}
