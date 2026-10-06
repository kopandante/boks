package deploy

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

// The runner is a shell script, so it is run, not read: under sh, with docker and flock stood in
// by scripts on PATH, against a home directory laid out the way a deploy leaves it.
func runRunner(t *testing.T, app string, setup func(home, bin string)) string {
	t.Helper()
	home, bin := t.TempDir(), t.TempDir()
	write := func(p, body string, mode os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	// docker: `inspect` answers from $RUNNING, `exec -i <c> sh -s` runs the script here and records the container.
	write(filepath.Join(bin, "docker"), `#!/bin/sh
case "$1" in
  inspect) echo "${RUNNING:-true}" ;;
  exec) echo "exec in $3" >> "$HOME/execs"; sh -s ;;
esac
`, 0o755)
	// flock: only the non-blocking lock of the descriptor the runner opened is a skip, not a queue.
	write(filepath.Join(bin, "flock"), "#!/bin/sh\n[ \"$*\" = \"-n 9\" ] || { echo \"flock called as: $*\"; exit 2; }\nexit ${FLOCK_RC:-0}\n", 0o755)
	write(filepath.Join(home, runnerPath), runner, 0o755)
	if setup != nil {
		setup(home, bin)
	}
	cmd := exec.Command("sh", filepath.Join(home, runnerPath), app, "tick")
	cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+bin+":/usr/bin:/bin")
	for _, kv := range []string{"RUNNING", "FLOCK_RC"} {
		if v, ok := os.LookupEnv("T_" + kv); ok {
			cmd.Env = append(cmd.Env, kv+"="+v)
		}
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runner failed: %v\n%s", err, out)
	}
	log, _ := os.ReadFile(filepath.Join(home, ".boks", app, "jobs", "tick.log"))
	execs, _ := os.ReadFile(filepath.Join(home, "execs"))
	return string(log) + "--execs--\n" + string(execs)
}

func serve(home, app, rel, container, cmd string) {
	d := filepath.Join(home, ".boks", app)
	os.MkdirAll(filepath.Join(d, "jobs", rel), 0o755)
	os.WriteFile(filepath.Join(d, "serving"), []byte(rel+" "+container+"\n"), 0o600)
	if cmd != "" {
		os.WriteFile(filepath.Join(d, "jobs", rel, "tick.sh"), []byte(cmd+"\n"), 0o600)
	}
}

// The job runs in the serving container, and its exit status — not that of the line that logs it —
// is what the log reports.
func TestRunnerRunsTheJobInTheServingCopyAndLogsItsExit(t *testing.T) {
	out := runRunner(t, "rjob1", func(home, _ string) { serve(home, "rjob1", "r-2", "c-new", "echo hello; exit 3") })
	if !strings.Contains(out, "start release=r-2 container=c-new") || !strings.Contains(out, "hello") ||
		!strings.Contains(out, "end exit=3") || !strings.Contains(out, "exec in c-new") {
		t.Errorf("want the job run in c-new and its exit 3 logged:\n%s", out)
	}
}

// Each reason not to run is a logged skip, and nothing is executed.
func TestRunnerSkipsWithAReason(t *testing.T) {
	cases := map[string]struct {
		setup func(home, bin string)
		env   map[string]string
		want  string
	}{
		"no serving line":                {func(home, _ string) {}, nil, "no serving release recorded"},
		"job not in the serving release": {func(home, _ string) { serve(home, "rjob2", "r-1", "c", "") }, nil, "release r-1 has no job tick"},
		"copy not running":               {func(home, _ string) { serve(home, "rjob2", "r-1", "c", "true") }, map[string]string{"T_RUNNING": "false"}, "c is not running"},
		"previous run going":             {func(home, _ string) { serve(home, "rjob2", "r-1", "c", "true") }, map[string]string{"T_FLOCK_RC": "1"}, "still going"},
	}
	for name, c := range cases {
		for k, v := range c.env {
			t.Setenv(k, v)
		}
		out := runRunner(t, "rjob2", c.setup)
		if !strings.Contains(out, "skip: ") || !strings.Contains(out, c.want) || strings.Contains(out, "exec in") {
			t.Errorf("%s: want a skip naming %q and no exec:\n%s", name, c.want, out)
		}
		for k := range c.env {
			os.Unsetenv(k)
		}
	}
}

// While a deploy of the app holds its lock the serving copy is about to change: skip.
func TestRunnerSkipsDuringADeploy(t *testing.T) {
	lock := "/tmp/boks-rjob3.lock"
	if err := os.Mkdir(lock, 0o755); err != nil {
		t.Skip("cannot create the deploy lock: ", err)
	}
	defer os.Remove(lock)
	out := runRunner(t, "rjob3", func(home, _ string) { serve(home, "rjob3", "r-1", "c", "true") })
	if !strings.Contains(out, "skip: a deploy of rjob3 is in progress") || strings.Contains(out, "exec in") {
		t.Errorf("want a skip during the deploy:\n%s", out)
	}
}

// local runs the commands boks sends to a server on this machine, in a home directory of its own and
// with only the given PATH: the shell boks writes is run, not compared as text.
type local struct{ home, path string }

func (l local) cmd(ctx context.Context, args []string) *exec.Cmd {
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Dir, c.Env = l.home, []string{"HOME=" + l.home, "PATH=" + l.path}
	return c
}

func (l local) Run(ctx context.Context, args ...string) (string, error) {
	out, err := l.cmd(ctx, args).Output()
	return strings.TrimSpace(string(out)), err
}

func (l local) Pipe(ctx context.Context, content []byte, args ...string) (string, error) {
	c := l.cmd(ctx, args)
	c.Stdin = bytes.NewReader(content)
	out, err := c.Output()
	return strings.TrimSpace(string(out)), err
}

func stub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// A server needs both crontab and flock: without either the jobs would never run.
func TestCheckCronNeedsCrontabAndFlock(t *testing.T) {
	cfg := &config.Config{App: "c", Schedules: []config.Schedule{{Name: "j", Cron: "* * * * *", Command: "true"}}}
	for name, tools := range map[string][]string{"none": nil, "crontab only": {"crontab"}, "flock only": {"flock"}, "both": {"crontab", "flock"}} {
		bin := t.TempDir()
		for _, tool := range tools {
			stub(t, bin, tool, "exit 0\n")
		}
		// sh itself is found by this process; the script sees the stubs alone.
		err := checkCron(context.Background(), local{t.TempDir(), bin}, cfg)
		if (err == nil) != (name == "both") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// The app's block replaces its earlier one and leaves the operator's lines and other apps' blocks
// as they were; a release without schedules removes the block, and once it is gone cron is left alone.
func TestApplySchedulesEditsOnlyTheAppsBlock(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	// crontab: -l prints the installed table (fails when there is none), a file argument installs it.
	stub(t, bin, "crontab", `echo "$*" >> "$HOME/crontab.calls"
if [ "$1" = -l ]; then cat "$HOME/installed" 2>/dev/null; exit $?; fi
cp "$1" "$HOME/installed"
`)
	r := local{home, bin + ":/usr/bin:/bin"}
	installed := func() string { b, _ := os.ReadFile(filepath.Join(home, "installed")); return string(b) }
	before := "MAILTO=\"\"\n0 1 * * * /usr/local/bin/backup\n# boks:other begin\n* * * * * sh $HOME/.boks/bin/boks-job other x\n# boks:other end\n" +
		"# boks:app begin\n0 0 * * * sh $HOME/.boks/bin/boks-job app gone\n# boks:app end\n"
	if err := os.WriteFile(filepath.Join(home, "installed"), []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	// The block on the server says an earlier release left one.
	if err := os.MkdirAll(filepath.Join(home, ".boks", "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(home, ".boks", "app", "crontab"), []byte("# boks:app begin\n# boks:app end\n"), 0o600)
	cfg := &config.Config{App: "app", Schedules: []config.Schedule{{Name: "warm", Cron: "*/4  * * * *", Command: "true"}}}
	if err := applySchedules(context.Background(), r, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	want := "MAILTO=\"\"\n0 1 * * * /usr/local/bin/backup\n# boks:other begin\n* * * * * sh $HOME/.boks/bin/boks-job other x\n# boks:other end\n" +
		"# boks:app begin\n*/4 * * * * sh $HOME/.boks/bin/boks-job app warm\n# boks:app end\n"
	if got := installed(); got != want {
		t.Errorf("installed crontab:\n%s\nwant:\n%s", got, want)
	}
	if b, err := os.ReadFile(filepath.Join(home, runnerPath)); err != nil || string(b) != runner {
		t.Errorf("the runner must be on the server: %v", err)
	}

	cfg.Schedules = nil
	if err := applySchedules(context.Background(), r, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if got, want := installed(), "MAILTO=\"\"\n0 1 * * * /usr/local/bin/backup\n# boks:other begin\n* * * * * sh $HOME/.boks/bin/boks-job other x\n# boks:other end\n"; got != want {
		t.Errorf("after a release without schedules:\n%s\nwant:\n%s", got, want)
	}
	calls, _ := os.ReadFile(filepath.Join(home, "crontab.calls"))
	if err := applySchedules(context.Background(), r, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(home, "crontab.calls")); string(again) != string(calls) {
		t.Errorf("with no block left, cron must not be touched: %q", strings.TrimPrefix(string(again), string(calls)))
	}
}

// A server whose user has no crontab yet gets one with just the app's block.
func TestApplySchedulesOnAnEmptyCrontab(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	stub(t, bin, "crontab", `if [ "$1" = -l ]; then echo "no crontab for $USER" >&2; exit 1; fi
cp "$1" "$HOME/installed"
`)
	cfg := &config.Config{App: "app", Schedules: []config.Schedule{{Name: "warm", Cron: "0 3 * * *", Command: "true"}}}
	if err := applySchedules(context.Background(), local{home, bin + ":/usr/bin:/bin"}, io.Discard, cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(home, "installed"))
	if want := "# boks:app begin\n0 3 * * * sh $HOME/.boks/bin/boks-job app warm\n# boks:app end\n"; string(b) != want {
		t.Errorf("installed crontab %q, want %q", b, want)
	}
}

// A log past 1 MB is moved aside before the run writes to it, so a chatty job cannot fill the disk.
func TestRunnerRotatesALargeLog(t *testing.T) {
	big := strings.Repeat("x", 1048577)
	out := runRunner(t, "rjob4", func(home, _ string) {
		serve(home, "rjob4", "r-1", "c", "echo fresh")
		os.WriteFile(filepath.Join(home, ".boks", "rjob4", "jobs", "tick.log"), []byte(big), 0o600)
		t.Cleanup(func() {
			old, _ := os.ReadFile(filepath.Join(home, ".boks", "rjob4", "jobs", "tick.log.1"))
			if string(old) != big {
				t.Errorf("the old log must be kept as tick.log.1 (%d bytes)", len(old))
			}
		})
	})
	if strings.Contains(out, "xxx") || !strings.Contains(out, "fresh") {
		t.Errorf("want the run in a fresh log:\n%.200s", out)
	}
}

// A rollback is refused when any one of the release's commands is gone, the last one included.
func TestJobsPresentChecksEveryCommand(t *testing.T) {
	home := t.TempDir()
	r := local{home, "/usr/bin:/bin"}
	jobs := []config.Schedule{{Name: "a"}, {Name: "b"}}
	dir := filepath.Join(home, ".boks", "app", "jobs", "r-1")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "a.sh"), []byte("true\n"), 0o600)
	if err := jobsPresent(context.Background(), r, "app", "r-1", jobs); err == nil || !strings.Contains(err.Error(), "b.sh") {
		t.Errorf("want a refusal naming b.sh, got %v", err)
	}
	os.WriteFile(filepath.Join(dir, "b.sh"), []byte("true\n"), 0o600)
	if err := jobsPresent(context.Background(), r, "app", "r-1", jobs); err != nil {
		t.Errorf("all commands are there: %v", err)
	}
}
