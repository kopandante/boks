package deploy

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

// Scheduled jobs run from the server's own cron, through one small script boks keeps on the server.
// Not a scheduler container: that would be one more process on a small box, holding the Docker
// socket, and a container's labels do not say which copy of an app is the one that serves. Cron
// fires the script; the script finds the serving copy and the release's command, and runs it there.

// runnerPath is the script cron calls, `sh boks-job <app> <job>`. Cron runs it through `sh`, so it
// needs no execute bit: the script is shared by every app on the server, and a rewrite that lands
// before a separate chmod — or a run cut between the two — would stop the jobs of all of them.
const runnerPath = ".boks/bin/boks-job"

// runner finds the copy that serves from release.ServingPath — the release and its container,
// written together after the release is recorded — and runs that release's command for the job in
// it. It skips, and says why in the job's log, rather than guess: while a deploy of the app holds its
// lock (the serving copy is about to change), when the release has no such job (cron still carries a
// line of the release before), when the copy is not running, and while the previous run of the same
// job is still going. The command reaches the container on stdin, so nothing in it is ever quoted by
// a shell or by cron (whose `%` would otherwise end the line). A log past 1 MB is moved to `.log.1` when
// the next run starts, so the log keeps at most two files; one run's own output is not cut short.
const runner = `#!/bin/sh
# boks-job <app> <job> — written by boks; runs a scheduled job in the copy of <app> that serves now.
app=$1 job=$2
d="$HOME/.boks/$app"
log="$d/jobs/$job.log"
mkdir -p "$d/jobs"
if [ -f "$log" ] && [ "$(wc -c < "$log")" -gt 1048576 ]; then mv "$log" "$log.1"; fi
exec >> "$log" 2>&1
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
if [ -d "/tmp/boks-$app.lock" ]; then echo "$(ts) skip: a deploy of $app is in progress"; exit 0; fi
read -r rel c < "$d/serving" || { echo "$(ts) skip: no serving release recorded"; exit 0; }
f="$d/jobs/$rel/$job.sh"
[ -f "$f" ] || { echo "$(ts) skip: release $rel has no job $job"; exit 0; }
[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || { echo "$(ts) skip: $c is not running"; exit 0; }
exec 9> "$d/jobs/$job.lock"
flock -n 9 || { echo "$(ts) skip: the previous run of $job is still going"; exit 0; }
echo "$(ts) start release=$rel container=$c"
docker exec -i "$c" sh -s < "$f"
rc=$?
echo "$(ts) end exit=$rc"
`

// checkCron refuses, before anything changes, an app with schedules on a server without cron or
// flock: the release would deploy and its jobs would silently never run.
func checkCron(ctx context.Context, r remote.Runner, cfg *config.Config) error {
	if len(cfg.Schedules) == 0 {
		return nil
	}
	out, err := r.Run(ctx, "sh", "-c", "command -v crontab >/dev/null && command -v flock >/dev/null && echo yes || echo no")
	if err != nil {
		return fmt.Errorf("checking for cron on the server: %w", err)
	}
	if strings.TrimSpace(out) != "yes" {
		return fmt.Errorf("%s has schedules, and this server has no crontab or flock: install cron (apt-get install cron) and deploy again; "+
			"nothing was changed", cfg.App)
	}
	return nil
}

// writeJobs keeps each job's command under the release's own directory, so a later deploy never
// changes what an earlier release runs and a rollback finds its own commands.
func writeJobs(ctx context.Context, r remote.Runner, app, id string, schedules []config.Schedule) error {
	for _, s := range schedules {
		if err := remote.UploadAtomic(ctx, r, []byte(s.Command+"\n"), path.Join(release.JobsDir(app, id), s.Name+".sh")); err != nil {
			return err
		}
	}
	return nil
}

// cronBlock is the app's lines in the crontab, between markers that name the app, so they are
// replaced as a whole and the lines of other apps and of the operator stay as they are.
func cronBlock(app string, schedules []config.Schedule) string {
	if len(schedules) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# boks:%s begin\n", app)
	for _, s := range schedules {
		fmt.Fprintf(&b, "%s sh $HOME/%s %s %s\n", strings.Join(strings.Fields(s.Cron), " "), runnerPath, app, s.Name)
	}
	fmt.Fprintf(&b, "# boks:%s end\n", app)
	return b.String()
}

// applySchedules brings the crontab in line with the release that now serves: the runner is
// (re)written, and the app's block replaced — or removed when the release has no schedules. The
// block is also kept on the server beside the app's releases, which is how an app that never had
// schedules costs one cheap call and nothing else. It runs after the release is recorded, so a
// failure here leaves the release serving and is reported for the next deploy to fix, not taken for
// a failed deploy.
func applySchedules(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	blockPath := path.Join(release.Dir(cfg.App), "crontab")
	b := remote.Quote(blockPath)
	strip := "{ crontab -l 2>/dev/null || true; } | sed -e " + remote.Quote("/^# boks:"+cfg.App+" begin$/") + "," +
		remote.Quote("/^# boks:"+cfg.App+" end$/") + "d > " + b + ".new"
	block := cronBlock(cfg.App, cfg.Schedules)
	if block == "" {
		// Nothing to schedule: remove the app's block only if an earlier release left one.
		script := "[ -s " + b + " ] || exit 0; command -v crontab >/dev/null || { : > " + b + "; exit 0; }; " +
			strip + " && crontab " + b + ".new && rm -f " + b + ".new && : > " + b
		if _, err := r.Run(ctx, "sh", "-c", script); err != nil {
			return fmt.Errorf("removing the schedules of the previous release from the crontab: %w", err)
		}
		return nil
	}
	if err := remote.UploadAtomic(ctx, r, []byte(runner), runnerPath); err != nil {
		return err
	}
	if err := remote.UploadAtomic(ctx, r, []byte(block), blockPath); err != nil {
		return err
	}
	if _, err := r.Run(ctx, "sh", "-c", strip+" && cat "+b+" >> "+b+".new && crontab "+b+".new && rm -f "+b+".new"); err != nil {
		return fmt.Errorf("updating the crontab: %w", err)
	}
	fmt.Fprintf(log, "cron: %d job(s) of %s scheduled\n", len(cfg.Schedules), cfg.App)
	return nil
}

// jobsPresent checks, before a rollback changes anything, that the commands of the release's
// schedules are still on the server; without them its jobs would be skipped from then on.
func jobsPresent(ctx context.Context, r remote.Runner, app, id string, schedules []config.Schedule) error {
	if len(schedules) == 0 {
		return nil
	}
	var paths []string
	for _, s := range schedules {
		paths = append(paths, remote.Quote(path.Join(release.JobsDir(app, id), s.Name+".sh")))
	}
	out, err := r.Run(ctx, "sh", "-c", "for f in "+strings.Join(paths, " ")+"; do [ -f \"$f\" ] || { echo \"$f\"; exit 0; }; done; echo present")
	if err != nil {
		return fmt.Errorf("checking the jobs of release %s: %w", id, err)
	}
	if out = strings.TrimSpace(out); out != "present" {
		return fmt.Errorf("a job of release %s is gone (%s): it was pruned or removed, so this release cannot be reproduced; deploy the tag again instead", id, out)
	}
	return nil
}
