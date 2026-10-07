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
	"io"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// FormatVersion is written into every snapshot. The format is what has to outlive the move to
// boksd, so a reader must be able to tell which shape it is looking at before it trusts a field.
// Version 2 added the memory limit and the replace mode. A version 1 snapshot reads as what it ran:
// no limit, and the replace mode its shape implied. Version 3 added the networks the container
// joined, with the aliases it answered to there; an older snapshot names the one network every app
// shared then. Version 4 added the apps the release used, whose networks it joined: a boks that
// does not know them would put the release back without checking that they are there. Version 5
// added the health check the config gave the container: a boks that drops it would bring a release
// of a stock image back with no health check, and refuse it or leave its consumers unable to tell it
// answers. An older snapshot reads as what it ran: the image's own HEALTHCHECK, if any. Version 6
// added the files mounted into the container: a boks that drops them would bring a release back
// without its configuration files, and the container would start on whatever the image ships.
// Version 7 added the command and the stop signal: without them a release of a stock image (redis
// started with a password) would come back running the image's own CMD. Version 8 added the
// schedules: a boks that drops them would leave cron running the jobs of the release rolled back from.
// Version 9 lets a port carry a path, a path rewrite and header changes: a boks that drops them
// would route a rolled-back release's paths to the whole host, without its header rules.
// Version 10 added the ports published on private addresses of the host (listen): a boks that drops
// them would bring a database back unreachable from the servers of its clients.
const FormatVersion = 10

// Snapshot is what a release ran: the image and the digest actually pulled, its ports with their
// routes (hosts, TLS, the certificate's domains), volumes, network and environment file — enough
// to run it again without consulting the current config.
type Snapshot struct {
	Version int           `json:"version"`
	ID      string        `json:"id"`
	App     string        `json:"app"`
	Image   string        `json:"image"`
	Tag     string        `json:"tag"`
	Digest  string        `json:"digest,omitempty"`
	Ports   []config.Port `json:"ports"`
	Volumes []string      `json:"volumes"`
	TLS     bool          `json:"tls"`
	// CertDomains are the domains of the certificate the routes were deployed with; a host they
	// cover was routed at that certificate rather than at the proxy's automatic HTTPS.
	CertDomains []string `json:"cert_domains,omitempty"`
	// Networks are the networks the container joined, the one it was started on first, with the
	// aliases it answered to in each. Empty before version 3.
	Networks []config.Network `json:"networks,omitempty"`
	// Uses are the apps the release reached, each on its own network, named in Networks after the
	// app's own. Empty before version 4.
	Uses []string `json:"uses,omitempty"`
	// Network is the network every app shared before version 3, which ran the container on it; a
	// newer snapshot leaves it empty and names its networks in Networks.
	Network string `json:"network,omitempty"`
	EnvPath string `json:"env_path,omitempty"`
	// Memory is the hard limit the release ran with, in the config's format; empty is none.
	Memory string `json:"memory,omitempty"`
	// Replace is the replace mode the release itself asks for — its config's, with the shape filled
	// in, so an app without routes records stop-first. It is not how the release was put in place:
	// a release deployed over a stop-first one was put in place stop-first and may still record
	// overlap. Empty in a version 1 snapshot.
	Replace string `json:"replace,omitempty"`
	// Healthcheck is the health check the config gave the container; nil when it ran with the image's
	// own, and before version 5.
	Healthcheck *config.Healthcheck `json:"healthcheck,omitempty"`
	// Files are the files mounted read-only into the container, each kept on the server under
	// FilesDir of this release. Empty before version 6.
	Files []File `json:"files,omitempty"`
	// Command is the CMD the config gave the container, and StopSignal what `docker stop` sent it;
	// empty when the release ran with the image's own, and before version 7.
	Command    []string `json:"command,omitempty"`
	StopSignal string   `json:"stop_signal,omitempty"`
	// Schedules are the jobs cron runs in the serving copy; their commands are kept under JobsDir of
	// this release. Empty when it had none, and before version 8.
	Schedules []config.Schedule `json:"schedules,omitempty"`
	// Listen are the container's ports published on private addresses of the host. Empty when it
	// published none, and before version 10.
	Listen []config.Listen `json:"listen,omitempty"`
	// Previous is the release that was serving when this one was deployed: where a rollback
	// without an id returns, and what Prune keeps. Empty for a first deploy, and in snapshots
	// written before the field.
	Previous  string    `json:"previous,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// File is one file a release mounted: Name in the release's FilesDir, read by the container at Target.
type File struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// Entry is one line of the operation journal. Started without Finished is the state that used to
// be invisible: a deploy that died between switching routes and recording the release.
type Entry struct {
	Op         string    `json:"op"`
	Action     string    `json:"action,omitempty"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to,omitempty"`
	StartedAt  time.Time `json:"started_at,omitzero"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	Result     string    `json:"result,omitempty"`
}

// Reference is what to run: the digest when it was recorded, because a tag can be overwritten and
// then means a different image than the one this release actually ran.
func (s Snapshot) Reference() string {
	if s.Digest != "" {
		return s.Image + "@" + s.Digest
	}
	return s.Image + ":" + s.Tag
}

func Dir(app string) string { return ".boks/" + app }

// EnvPath is where the environment file of release id lives. One owner for the name: the deploy
// writes it there and Prune deletes it from there.
func EnvPath(app, id string) string      { return path.Join(Dir(app), id+".env") }
func snapshotPath(app, id string) string { return path.Join(Dir(app), "releases", id+".json") }

// FilesDir holds the files release id mounts. One owner for the name, as for EnvPath.
func FilesDir(app, id string) string { return path.Join(Dir(app), "files", id) }

// JobsDir holds the commands of release id's schedules, one file per job.
func JobsDir(app, id string) string { return path.Join(Dir(app), "jobs", id) }

// ServingPath names the release that serves and its container, on one line written in one atomic
// step: a scheduled job reads both together. `current` alone cannot say which container that is —
// a rollback restores a release under its old id in a container of a new name.
func ServingPath(app string) string { return path.Join(Dir(app), "serving") }

// SetServing records that release id serves from container.
func SetServing(ctx context.Context, r remote.Runner, app, id, container string) error {
	return remote.UploadAtomic(ctx, r, []byte(id+" "+container+"\n"), ServingPath(app))
}
func currentPath(app string) string { return path.Join(Dir(app), "current") }
func journalPath(app string) string { return path.Join(Dir(app), "journal.jsonl") }

// Save writes a snapshot. The write is atomic because a half-written snapshot is worse than a
// missing one: rollback would run something that never existed.
func Save(ctx context.Context, r remote.Runner, s Snapshot) error {
	s.Version = FormatVersion
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
	// A newer format has fields this binary would silently drop — a replace mode among them, and
	// running a stop-first release with overlap puts two writers on one volume.
	if s.Version > FormatVersion {
		return nil, fmt.Errorf("release %s of %s was recorded by a newer boks (snapshot format %d, this one reads up to %d): upgrade boks",
			id, app, s.Version, FormatVersion)
	}
	return &s, nil
}

// IDs lists the releases kept on the server, oldest first. A release is named
// <app>-<tag>-<unix seconds>, and only the trailing number says how old it is: sorting the names
// as text would order them by tag, and Prune would then delete the release just deployed whenever
// its tag happens to sort first (git short SHAs, v9 before v10).
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
	sort.SliceStable(ids, func(i, j int) bool {
		ai, bi := deployedAt(ids[i]), deployedAt(ids[j])
		if ai != bi {
			return ai < bi
		}
		return ids[i] < ids[j]
	})
	return ids, nil
}

// deployedAt is the unix time at the end of a release name; a name without one sorts as oldest.
func deployedAt(id string) int64 {
	i := strings.LastIndexByte(id, '-')
	if i < 0 {
		return -1
	}
	n, err := strconv.ParseInt(id[i+1:], 10, 64)
	if err != nil {
		return -1
	}
	return n
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

// Previous is the release a rollback without an id returns to: the one that was serving when the
// current release was deployed. Deploy order is not that once a rollback has happened: after
// v1, v2, v3 and a rollback to v2, a deploy of v4 is made over v2, and its rollback must reach v2,
// not v3, which was left for a reason. A rollback keeps the restored release's own snapshot, so a
// second one goes on to the release before it. A snapshot newer than current (a deploy that saved
// it and was cut before moving current) is not "before" it; with no recorded current there is no
// previous either.
func Previous(ctx context.Context, r remote.Runner, app string) (string, error) {
	ids, err := IDs(ctx, r, app)
	if err != nil {
		return "", err
	}
	current, err := Current(ctx, r, app)
	if err != nil || !slices.Contains(ids, current) {
		return "", err
	}
	return predecessor(ctx, r, app, ids, current)
}

// predecessor is the release id was deployed over, as its snapshot names it. A snapshot that names
// none — written before the field, or a first deploy — falls back to deploy order. A predecessor no
// longer kept is no predecessor: a rollback to it could not be reproduced.
func predecessor(ctx context.Context, r remote.Runner, app string, ids []string, id string) (string, error) {
	s, err := Load(ctx, r, app, id)
	if err != nil {
		return "", err
	}
	prev := s.Previous
	if prev == "" {
		if i := slices.Index(ids, id); i > 0 {
			prev = ids[i-1]
		}
	}
	if !slices.Contains(ids, prev) {
		return "", nil
	}
	return prev, nil
}

// Prune keeps `keep` snapshots with their env files and mounted files: first the releases a rollback walks back
// through from the current one, then the newest of the rest. Age alone is not enough once a
// rollback has happened: after v1, v2, v3, two rollbacks to v1 and a deploy of v4, the newest
// three are v2, v3 and v4, and pruning by age would delete v1 — the release v4 was deployed over
// and the one its rollback has to reach. It runs after a deploy succeeds, so the release just
// recorded is current and always kept; the caller names it, having just written it.
//
// It returns the snapshots it removed, read before their files went: the image a removed release
// ran is the caller's to remove, and once the snapshot is gone nothing says which image that was.
// A snapshot that cannot be read stays, so the next prune comes back to it; one that reads but is
// damaged goes, naming no image.
func Prune(ctx context.Context, r remote.Runner, app, current string, keep int) ([]Snapshot, error) {
	ids, err := IDs(ctx, r, app)
	if err != nil || len(ids) <= keep {
		return nil, err
	}
	kept := map[string]bool{}
	for id := current; slices.Contains(ids, id) && !kept[id] && len(kept) < keep; {
		kept[id] = true
		if id, err = predecessor(ctx, r, app, ids, id); err != nil {
			return nil, err
		}
	}
	for i := len(ids) - 1; i >= 0 && len(kept) < keep; i-- {
		kept[ids[i]] = true
	}
	var removed []Snapshot
	for _, id := range ids {
		if kept[id] {
			continue
		}
		out, err := r.Run(ctx, "cat", snapshotPath(app, id))
		if err != nil {
			return removed, fmt.Errorf("release %s of %s: %w", id, app, err)
		}
		var s Snapshot
		if json.Unmarshal([]byte(out), &s) != nil {
			s = Snapshot{}
		}
		s.ID, s.App = id, app
		if _, err := r.Run(ctx, "rm", "-rf", snapshotPath(app, id), EnvPath(app, id), FilesDir(app, id), JobsDir(app, id)); err != nil {
			return removed, err
		}
		removed = append(removed, s)
	}
	return removed, nil
}

// Recorded is what the releases recorded on a server run, every app's together: the image:tag
// references and the digests. An image one of them names is a rollback target of some app, and
// many apps can share one image repository, differing only by tag.
type Recorded struct {
	Refs    map[string]bool
	Digests map[string]bool
}

// RecordedImages reads every snapshot on the server, of every app. A read that fails, or a
// snapshot that does not parse, is an error rather than a shorter answer: the caller removes
// images on the strength of nobody naming them.
func RecordedImages(ctx context.Context, r remote.Runner) (Recorded, error) {
	out, err := r.Run(ctx, "find", ".boks", "-mindepth", "3", "-maxdepth", "3", "-path", ".boks/*/releases/*.json",
		"-type", "f", "-exec", "cat", "{}", "+")
	if err != nil {
		return Recorded{}, fmt.Errorf("read the releases recorded on the server: %w", err)
	}
	rec := Recorded{Refs: map[string]bool{}, Digests: map[string]bool{}}
	dec := json.NewDecoder(strings.NewReader(out))
	for {
		var s struct{ Image, Tag, Digest string }
		if err := dec.Decode(&s); err == io.EOF {
			return rec, nil
		} else if err != nil {
			return Recorded{}, fmt.Errorf("read the releases recorded on the server: %w", err)
		}
		if s.Image != "" && s.Tag != "" {
			rec.Refs[s.Image+":"+s.Tag] = true
		}
		if s.Digest != "" {
			rec.Digests[s.Digest] = true
		}
	}
}

// Begin records that an operation is under way, before the app's containers or routes change
// (pulling the image and booting the proxy come earlier: they change nothing a later run would have
// to undo). Finish closes it. A journal that ends on a `started` line is the evidence that a deploy was cut short,
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
