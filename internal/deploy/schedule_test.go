package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	write(filepath.Join(bin, "flock"), "#!/bin/sh\nexit ${FLOCK_RC:-0}\n", 0o755)
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
