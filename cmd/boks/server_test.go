package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const policyRead = "sh -c if [ -f '.boks/_server/policy.json' ]"

// Every server is asked before any changes: b has moved past the file's revision, so a is not
// touched either — a refusal halfway down the list would leave the fleet on two policies. No
// boks.yml is read: server.yml belongs to the server.
func TestServerApplyAsksEveryServerFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte("servers: [a, b]\nrevision: 4\nbots:\n  block:\n    - {name: crawlers, user_agent: gptbot}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &recorder{server: server{policyRead: "present\n{\"revision\":3,\"floor\":3}"}}
	b := &recorder{server: server{policyRead: "present\n{\"revision\":5,\"floor\":5}"}}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	var errw strings.Builder
	if code := run([]string{"-f", filepath.Join(dir, "missing-boks.yml"), "server", "apply", path}, io.Discard, &errw); code != 1 {
		t.Fatalf("want a refusal, got %d", code)
	}
	if !strings.Contains(errw.String(), "b: server.yml is revision 4, but this server has applied up to 5") {
		t.Errorf("want b named: %s", errw.String())
	}
	if a.ran("ln -sn") || len(a.stdin) > 0 {
		t.Errorf("a was changed before b was asked: %v", a.calls)
	}
}

// A rollback asks every server too: b joined the fleet after revision 4, so a is not rolled back to it.
func TestServerRollbackAsksEveryServerFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte("servers: [a, b]\nrevision: 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hist := "sh -c if [ -f '.boks/_server/history/4.json' ]"
	a := &recorder{server: server{policyRead: "present\n{\"revision\":5,\"floor\":5}", hist: "present\n{\"revision\":4}"}}
	b := &recorder{server: server{policyRead: "present\n{\"revision\":5,\"floor\":5}"}}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	var errw strings.Builder
	if code := run([]string{"server", "rollback", path, "4"}, io.Discard, &errw); code != 1 {
		t.Fatalf("want a refusal, got %d", code)
	}
	if !strings.Contains(errw.String(), "b: this server never applied revision 4") {
		t.Errorf("want b named: %s", errw.String())
	}
	if a.ran("ln -sn") || len(a.stdin) > 0 {
		t.Errorf("a was changed before b was asked: %v", a.calls)
	}
}

// The docker check after usermod and the proxy boot go through a login of their own — past the run's
// shared connection and past a ControlMaster in ~/.ssh/config — since only a new login has the group
// usermod just added; the server is read over the shared one. The new login is one connection shared
// by every call after it, not one per call, which an SSH rate limit (ufw's `limit`) would cut off.
func TestServerInstallAsksDockerInANewLogin(t *testing.T) {
	for _, mux := range []string{"", "0"} {
		dir := t.TempDir()
		t.Chdir(dir)
		facts := "user=deploy\nuid=1000\nsudo=yes\nos=ubuntu\nversion=24.04\nsystemd=yes\nmigratereq=yes\ndockerd=yes\ncrontab=yes\n" +
			"flock=yes\ndockerenabled=enabled\ncronactive=active\ndockerup=yes\napi=1.47\nswarm=inactive\nrunning=1\n"
		log := filepath.Join(dir, "calls")
		script := "#!/bin/sh\nprintf '%s\\n' \"$*\" | tr '\\n' ' ' >> " + log + "\necho >> " + log + "\n" +
			"case \"$*\" in *'id -un'*) cat " + filepath.Join(dir, "facts") + " ;; esac\nexit 0\n"
		for name, body := range map[string]string{"facts": facts, "ssh": script, "server.yml": "servers: [h]\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		t.Setenv("BOKS_SSH_MUX", mux)
		run([]string{"server", "install", "server.yml"}, io.Discard, io.Discard)
		b, _ := os.ReadFile(log)
		socket := func(c string) string {
			_, rest, ok := strings.Cut(c, "-o ControlPath=")
			if !ok {
				return ""
			}
			path, _, _ := strings.Cut(rest, " ")
			return path
		}
		var run, login string
		logins := map[string]bool{}
		after := false
		for _, c := range strings.Split(string(b), "\n") {
			switch {
			case strings.Contains(c, " h 'sudo' '-n' 'usermod' '-aG' 'docker' 'deploy'"):
				run, after = socket(c), true
			case strings.Contains(c, " h 'docker' 'info'"):
				login = socket(c)
				fallthrough
			case after && strings.Contains(c, " h 'docker' "):
				logins[socket(c)] = true
			}
		}
		if mux == "0" {
			// Nothing shared: each call is a login of its own, past ~/.ssh/config's ControlMaster too.
			if login != "none" || len(logins) != 1 || !logins["none"] {
				t.Errorf("BOKS_SSH_MUX=0: docker over %q, logins %v; calls:\n%s", login, logins, b)
			}
			continue
		}
		if run == "" || run == "none" || login == "" || login == "none" || login == run || len(logins) != 1 {
			t.Errorf("usermod over %q, docker over %q, calls after it over %v; calls:\n%s", run, login, logins, b)
		}
	}
}

// Install asks every server before it changes any: b cannot take boks, so a is not touched either.
func TestServerInstallAsksEveryServerFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte("servers: [a, b]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	facts := "user=root\nuid=0\nos=ubuntu\nversion=24.04\nsystemd=yes\nmigratereq=yes\nflock=yes\ncrontab=yes\ncandidate=29.1.3\n"
	a := &recorder{server: server{"sh -c S=": facts}}
	b := &recorder{server: server{"sh -c S=": strings.Replace(facts, "os=ubuntu", "os=fedora", 1)}}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	var errw strings.Builder
	if code := run([]string{"server", "install", path}, io.Discard, &errw); code != 1 {
		t.Fatalf("want a refusal, got %d", code)
	}
	if !strings.Contains(errw.String(), "b: fedora") {
		t.Errorf("want b named: %s", errw.String())
	}
	// a's package index may be refreshed by its check — nothing boks answers for — but nothing else.
	installed := false
	for _, c := range a.calls {
		installed = installed || strings.HasSuffix(c, " apt-get install -y -q --no-install-recommends docker.io")
	}
	if a.ran("ln -sn") || installed || len(a.stdin) > 0 {
		t.Errorf("a was changed before b was asked: %v", a.calls)
	}
}
