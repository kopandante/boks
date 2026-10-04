package deploy

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// admitLock is the one lock every app on a server shares, unlike the deploy lock, which is per app.
// The memory check of a deploy is only as good as what it can see, and two deploys of different apps
// checking at once would each see the memory the other is about to take. A symlink is created
// atomically and carries its owner in its target; an app name cannot contain a dot, so the path
// cannot be some app's deploy lock.
const admitLock = "/tmp/boks.admit.lock"

// defaultAdmitWait is how long a deploy waits for another one to finish admitting its container. A
// stop-first admission lasts until the new copy is healthy, so it is minutes, not seconds.
const defaultAdmitWait = 5 * time.Minute

// memoryReserve is what the check keeps free for what is not an app container: the proxy, dockerd,
// sshd, the kernel's own growth. It is a starting policy, not a measured sufficient margin.
const memoryReserve = 256 << 20

// admission is a held admission lock. Every deploy takes it, with or without a memory limit: one
// without a limit still starts a container between another deploy's check and its start.
type admission struct {
	r     remote.Runner
	log   io.Writer
	token string
	held  bool
}

// admit takes the server's admission lock, waiting for another deploy to finish with it. The token
// is this run's alone, so a run whose lock was cleared by hand and taken by another cannot later
// remove the lock that is no longer its own.
func admit(ctx context.Context, r remote.Runner, log io.Writer, app string, o Options) (*admission, error) {
	token := app + "." + strconv.FormatInt(o.Now().UnixNano(), 10)
	wait := o.AdmitWait
	if wait <= 0 {
		wait = defaultAdmitWait
	}
	poll := o.Poll
	if poll <= 0 {
		poll = time.Second
	}
	deadline := time.Now().Add(wait)
	waiting, vanished := "", 0
	for {
		_, err := r.Run(ctx, "ln", "-sn", token, admitLock)
		if err == nil {
			return &admission{r: r, log: log, token: token, held: true}, nil
		}
		held, _ := r.Run(ctx, "sh", "-c", "readlink "+admitLock+" 2>/dev/null || true")
		// The link may be this run's own: `ln` succeeded and only its answer was lost on the way back.
		if strings.TrimSpace(held) == token {
			return &admission{r: r, log: log, token: token, held: true}, nil
		}
		owner := ownerApp(strings.TrimSpace(held))
		// The caller holds this app's deploy lock, so a lock this app holds under another token is
		// a leftover of an earlier run whose release did not get through: it is taken back.
		if owner == app {
			fmt.Fprintf(log, "taking back the admission lock an earlier run of %s left behind\n", app)
			best(ctx, r, log, "sh", "-c", "[ \"$(readlink "+admitLock+")\" = "+remote.Quote(strings.TrimSpace(held))+" ] && rm -f "+admitLock+" || true")
			continue
		}
		// No lock to wait for, and still `ln` fails: what fails is the server, not a wait, and saying
		// so after a few tries beats saying it after five minutes. A lock let go of between the two
		// calls reads the same way once, so once is not enough.
		if owner == "" {
			if vanished++; vanished >= 3 {
				return nil, fmt.Errorf("could not take the admission lock %s: %w", admitLock, err)
			}
		} else {
			vanished = 0
		}
		if owner != "" && owner != waiting {
			fmt.Fprintf(log, "waiting for the deploy of %s to finish admitting its container on this server\n", owner)
			waiting = owner
		}
		if time.Now().After(deadline) {
			if owner == "" {
				return nil, fmt.Errorf("could not take the admission lock %s: %w", admitLock, err)
			}
			// Not having let go in this long does not prove the owner died, so the lock is not taken over.
			return nil, fmt.Errorf("the deploy of %s has held the admission lock %s for over %s; "+
				"if no deploy of %s is running, `boks unlock` in that app clears it", owner, admitLock, wait, owner)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// ownerApp is the app named in a lock token.
func ownerApp(token string) string {
	app, _, _ := strings.Cut(token, ".")
	return app
}

// release gives the lock back if this run still holds it. It is safe to call more than once.
func (a *admission) release(ctx context.Context) {
	if a == nil || !a.held {
		return
	}
	a.held = false
	script := "[ \"$(readlink " + admitLock + ")\" = " + remote.Quote(a.token) + " ] && rm -f " + admitLock + " || true"
	best(context.WithoutCancel(ctx), a.r, a.log, "sh", "-c", script)
}

// unlockAdmission removes the admission lock when app holds it, and reports whether it did.
func unlockAdmission(ctx context.Context, r remote.Runner, app string) (bool, error) {
	out, err := r.Run(ctx, "sh", "-c", "case \"$(readlink "+admitLock+" 2>/dev/null)\" in "+app+".*) rm -f "+admitLock+" && echo freed;; esac")
	return strings.TrimSpace(out) == "freed", err
}

// checkMemory is the preliminary memory check: will the new copy's limit fit on this server? It is
// conservative and still not a guarantee against OOM — a container without a limit can grow past
// anything measured here, and so can the host's own processes.
//
// What is free is MemAvailable, less what running containers with a limit may still grow into (one
// admitted a moment ago has not taken its memory yet, and MemAvailable alone would hand it to the
// next deploy), less the reserve. In stop-first the copies about to be stopped give back what they
// use, and their own growth no longer counts; in overlap the old copy keeps running beside the new
// one, growth included. replacing names those copies, nil in overlap.
func checkMemory(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, replacing []string) error {
	need, err := config.MemoryBytes(cfg.Memory)
	if err != nil || need == 0 {
		return err
	}
	// Use first, MemAvailable after it: a container that grows between the two readings is then
	// counted twice (in what it may still take, measured low, and in MemAvailable, measured after)
	// rather than not at all.
	running, err := containerMemory(ctx, r)
	if err != nil {
		return fmt.Errorf("preliminary memory check: %w", err)
	}
	avail, err := memAvailable(ctx, r)
	if err != nil {
		return fmt.Errorf("preliminary memory check: %w", err)
	}
	var promised, freed int64
	for _, c := range running {
		if slices.Contains(replacing, c.name) {
			freed += c.used
			continue
		}
		if c.limit > c.used {
			promised += c.limit - c.used
		}
	}
	free := avail + freed - promised - memoryReserve
	terms := fmt.Sprintf("MemAvailable %s + %s used by the copies being stopped − %s other containers may still grow into − %s reserve",
		size(avail), size(freed), size(promised), size(memoryReserve))
	if need > free {
		return fmt.Errorf("preliminary memory check: %s needs %s but %s is free (%s); this is a preliminary check, not a guarantee against OOM; "+
			"lower `memory`, or free memory on the server", cfg.App, cfg.Memory, size(max(free, 0)), terms)
	}
	fmt.Fprintf(log, "memory: %s of %s free by the preliminary check (%s)\n", cfg.Memory, size(free), terms)
	return nil
}

// memAvailable reads MemAvailable from /proc/meminfo, in bytes.
func memAvailable(ctx context.Context, r remote.Runner) (int64, error) {
	out, err := r.Run(ctx, "cat", "/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("reading /proc/meminfo: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, "MemAvailable:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 2 && f[1] == "kB" {
			if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil {
				return kb << 10, nil
			}
		}
		return 0, fmt.Errorf("unreadable MemAvailable line %q", line)
	}
	return 0, fmt.Errorf("/proc/meminfo has no MemAvailable")
}

// usage is a running container's memory: its limit (0 for none) and what it uses now.
type usage struct {
	name        string
	limit, used int64
}

// containerMemory lists the running containers with their limits and use, matched by id. A container
// docker stats does not report counts as using nothing, which is the conservative side: its whole
// limit is still to come, and a copy being stopped gives back nothing.
func containerMemory(ctx context.Context, r remote.Runner) ([]usage, error) {
	out, err := containerLimits(ctx, r)
	if err != nil {
		return nil, err
	}
	var list []usage
	byID := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("unreadable container limit %q", line)
		}
		limit, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unreadable container limit %q", line)
		}
		byID[f[0]] = len(list)
		list = append(list, usage{name: strings.TrimPrefix(f[1], "/"), limit: limit})
	}
	out, err = r.Run(ctx, "docker", "stats", "--no-stream", "--no-trunc", "--format", "{{.ID}}\t{{.MemUsage}}")
	if err != nil {
		return nil, fmt.Errorf("reading container memory use: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		id, mem, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		i, known := byID[id]
		if !known {
			continue
		}
		used, _, _ := strings.Cut(mem, " / ")
		// docker prints `--` for a container whose stats it has none of (one stuck restarting). Its use
		// stays unknown, which counts as nothing: its whole limit is still to come.
		if strings.TrimSpace(used) == "--" {
			continue
		}
		n, err := parseSize(used)
		if err != nil {
			return nil, fmt.Errorf("unreadable memory use %q of %s: %w", mem, list[i].name, err)
		}
		list[i].used = n
	}
	return list, nil
}

// containerLimits lists the running containers with their limits. Listing and inspecting are two
// calls, and another app's deploy may remove a container in between — it retires its old copies
// after it has let go of admission — which fails the inspect for a container that no longer uses
// anything. That is asked again, a few times, before it counts as a failure.
func containerLimits(ctx context.Context, r remote.Runner) (string, error) {
	var err error
	for range 3 {
		var out string
		if out, err = r.Run(ctx, "docker", "ps", "-q", "--no-trunc"); err != nil {
			return "", fmt.Errorf("listing running containers: %w", err)
		}
		ids := strings.Fields(out)
		if len(ids) == 0 {
			return "", nil
		}
		if out, err = r.Run(ctx, append([]string{"docker", "container", "inspect", "--format", "{{.Id}}\t{{.Name}}\t{{.HostConfig.Memory}}"}, ids...)...); err == nil {
			return out, nil
		}
	}
	return "", fmt.Errorf("reading container limits: %w", err)
}

// sizeUnits are the suffixes docker stats prints: binary on Linux, decimal elsewhere.
var sizeUnits = map[string]float64{
	"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
	"kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
}

// parseSize reads a size as docker stats prints it, such as 155.3MiB.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(c rune) bool { return (c < '0' || c > '9') && c != '.' })
	if i <= 0 {
		return 0, fmt.Errorf("not a size")
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	unit, ok := sizeUnits[s[i:]]
	if err != nil || !ok {
		return 0, fmt.Errorf("not a size")
	}
	return int64(n * unit), nil
}

// size prints bytes in MiB, the unit memory limits are usually written in.
func size(n int64) string {
	return strconv.FormatInt(n>>20, 10) + "MiB"
}
