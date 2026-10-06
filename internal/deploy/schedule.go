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

// Scheduled jobs run from the server's own cron, through one small script boks keeps beside each app.
// Not a scheduler container: that would be one more process on a small box, holding the Docker
// socket, and a container's labels do not say which copy of an app is the one that serves. Cron
// fires the script; the script finds the serving copy and the release's command, and runs it there.

// runnerPath is the script cron calls, `sh boks-job <app> <job>`. Each app has its own copy, written
// under the app's deploy lock, and cron runs it through `sh`: a deploy of one app never rewrites what
// the jobs of another are running, and a rewrite needs no separate chmod to become runnable.
func runnerPath(app string) string { return path.Join(release.Dir(app), "boks-job") }

// cronLock serializes edits of the crontab, which every app on the server shares: deploys of two apps
// hold different app locks, and the server's admission lock is let go before the release is recorded.
const cronLock = ".boks/crontab.lock"

// runner finds the copy that serves from release.ServingPath — the release and its container,
// written together after the release is recorded — and runs that release's command for the job in
// it. It skips, and says why in the job's log, rather than guess: while the previous run of the same
// job is still going, while a deploy of the app holds its lock (the serving copy is about to change),
// when the release has no such job (cron still carries a line of the release before), and when the
// copy is not running. The command reaches the container on stdin, so nothing in it is ever quoted by
// a shell or by cron (whose `%` would otherwise end the line).
//
// The log is bounded: a log past 1 MB moves to `.log.1` when the next run starts — under the job's
// lock, so a run that fires while another is going never moves the log that one writes — and one
// run keeps at most 1 MiB of its own output. The rest is read to the end and counted, not cut off:
// a job whose output pipe closed would get SIGPIPE and stop, and the exit status logged is the
// job's, not that of whatever cut the output. The kept part goes through dd a byte at a time, so it
// reaches the log as the job writes it, as it did before the cap (head would hold it in its stdio
// buffer until the job ends, and a hung job's last words are what the log is for); the byte at a
// time costs about a second of CPU per MiB, only when a run writes that much. The pipe's writer is opened before the command file:
// a file pruned since the check then fails the run, where the other way round the reader would wait
// for a writer forever, holding the job's lock.
const runner = `#!/bin/sh
# boks-job <app> <job> — written by boks; runs a scheduled job in the copy of <app> that serves now.
app=$1 job=$2
d="$HOME/.boks/$app"
log="$d/jobs/$job.log"
mkdir -p "$d/jobs"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
exec 9> "$d/jobs/$job.lock"
flock -n 9 || { echo "$(ts) skip: the previous run of $job is still going" >> "$log"; exit 0; }
if [ -f "$log" ] && [ "$(wc -c < "$log")" -gt 1048576 ]; then mv "$log" "$log.1"; fi
exec >> "$log" 2>&1
if [ -d "/tmp/boks-$app.lock" ]; then echo "$(ts) skip: a deploy of $app is in progress"; exit 0; fi
read -r rel c < "$d/serving" || { echo "$(ts) skip: no serving release recorded"; exit 0; }
f="$d/jobs/$rel/$job.sh"
[ -f "$f" ] || { echo "$(ts) skip: release $rel has no job $job"; exit 0; }
[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] || { echo "$(ts) skip: $c is not running"; exit 0; }
out="$d/jobs/$job.out"
rm -f "$out"
mkfifo -m 600 "$out" || { echo "$(ts) skip: cannot make $out"; exit 0; }
trap 'rm -f "$out"' EXIT
echo "$(ts) start release=$rel container=$c"
{ dd bs=1 count=1048576 2>/dev/null; n=$(wc -c); if [ "$n" -gt 0 ]; then echo; echo "$(ts) output past 1 MiB dropped: about $n more bytes"; fi; } < "$out" &
reader=$!
docker exec -i "$c" sh -s > "$out" 2>&1 < "$f"
rc=$?
wait "$reader"
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
		fmt.Fprintf(&b, "%s sh $HOME/%s %s %s\n", strings.Join(strings.Fields(s.Cron), " "), runnerPath(app), app, s.Name)
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
	lock := "mkdir -p .boks && exec 9>> " + cronLock + " && flock 9"
	block := cronBlock(cfg.App, cfg.Schedules)
	if block == "" {
		// Nothing to schedule: remove the app's block only if an earlier release left one. A server
		// without flock never had an app with schedules (checkCron) that could edit the crontab alongside.
		script := "[ -s " + b + " ] || exit 0; command -v crontab >/dev/null || { : > " + b + "; exit 0; }; " +
			"{ ! command -v flock >/dev/null || { " + lock + "; }; } && " +
			strip + " && crontab " + b + ".new && rm -f " + b + ".new && : > " + b
		if _, err := r.Run(ctx, "sh", "-c", script); err != nil {
			return fmt.Errorf("removing the schedules of the previous release from the crontab: %w", err)
		}
		return nil
	}
	if err := remote.UploadAtomic(ctx, r, []byte(runner), runnerPath(cfg.App)); err != nil {
		return err
	}
	if err := remote.UploadAtomic(ctx, r, []byte(block), blockPath); err != nil {
		return err
	}
	if _, err := r.Run(ctx, "sh", "-c", lock+" && "+strip+" && cat "+b+" >> "+b+".new && crontab "+b+".new && rm -f "+b+".new"); err != nil {
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
