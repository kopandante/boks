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
// usermod just added; the server is read over the shared one.
func TestServerInstallAsksDockerInANewLogin(t *testing.T) {
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
	t.Setenv("BOKS_SSH_MUX", "")
	run([]string{"server", "install", "server.yml"}, io.Discard, io.Discard)
	b, _ := os.ReadFile(log)
	var usermod, docker, read bool
	for _, c := range strings.Split(string(b), "\n") {
		alone := strings.Contains(c, "-o ControlMaster=no -o ControlPath=none h ")
		switch {
		case strings.Contains(c, " h 'sudo' '-n' 'usermod' '-aG' 'docker' 'deploy'"):
			usermod = !alone
		case strings.Contains(c, " h 'docker' 'info'"):
			docker = alone
			if !alone {
				t.Errorf("docker asked over a shared connection: %s", c)
			}
		case strings.Contains(c, "id -un"):
			read = !alone && strings.Contains(c, "ControlMaster=auto")
		}
	}
	if !usermod || !docker || !read {
		t.Errorf("usermod %v, docker in a new login %v, read shared %v; calls:\n%s", usermod, docker, read, b)
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
