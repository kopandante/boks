package main

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kopandante/boks/internal/config"
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
	for _, mux := range []string{"", "0", "nodir"} {
		dir := t.TempDir()
		t.Chdir(dir)
		facts := "user=deploy\nuid=1000\nsudo=yes\nos=ubuntu\nversion=24.04\nsystemd=yes\nmigratereq=yes\ndockerd=yes\ncrontab=yes\n" +
			"flock=yes\ndockerenabled=enabled\ncronactive=active\ncronenabled=enabled\ndockerup=yes\napi=1.47\nswarm=inactive\nrunning=1\n"
		log := filepath.Join(dir, "calls")
		script := "#!/bin/sh\nprintf '%s\\n' \"$*\" | tr '\\n' ' ' >> " + log + "\necho >> " + log + "\n" +
			"case \"$*\" in *'id -un'*) cat " + filepath.Join(dir, "facts") + " ;; esac\nexit 0\n"
		for name, body := range map[string]string{"facts": facts, "ssh": script, "server.yml": "servers: [h]\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		t.Setenv("BOKS_SSH_MUX", strings.TrimSuffix(mux, "nodir"))
		old := socketRoot
		if mux == "nodir" {
			socketRoot = filepath.Join(dir, "missing")
		}
		// The fake answers no proxy boot, so the run ends in an error after docker info; what is
		// checked is the connections up to there.
		run([]string{"server", "install", "server.yml"}, io.Discard, io.Discard)
		socketRoot = old
		b, _ := os.ReadFile(log)
		socket := func(c string) string {
			_, rest, ok := strings.Cut(c, "-o ControlPath=")
			if !ok {
				return ""
			}
			path, _, _ := strings.Cut(rest, " ")
			return path
		}
		calls := strings.Split(strings.TrimSpace(string(b)), "\n")
		usermod, docker := -1, -1
		for i, c := range calls {
			if strings.Contains(c, " h 'sudo' '-n' 'usermod' '-aG' 'docker' 'deploy'") {
				usermod = i
			}
			if strings.Contains(c, " h 'docker' 'info'") && docker < 0 {
				docker = i
			}
		}
		if usermod < 0 || docker < usermod {
			t.Fatalf("usermod at %d, docker info at %d; calls:\n%s", usermod, docker, b)
		}
		shared, login := socket(calls[usermod]), socket(calls[docker])
		// Every call after usermod goes through one login; none goes through it before usermod —
		// a connection opened then would keep the groups the user had before it.
		logins := map[string]bool{}
		for i, c := range calls {
			if !strings.Contains(c, " h ") {
				continue
			}
			if i < usermod && socket(c) == login && login != "none" {
				t.Errorf("the new login used before usermod: %s", c)
			}
			if i > usermod && !strings.HasSuffix(c, " -O exit h") && socket(c) != shared {
				logins[socket(c)] = true
			}
		}
		if mux != "" {
			// Nothing shared — turned off, or no directory for sockets: each call is a login of its
			// own, past ~/.ssh/config's ControlMaster too, and the install still goes through.
			if login != "none" || len(logins) != 1 {
				t.Errorf("%q: docker over %q, logins %v; calls:\n%s", mux, login, logins, b)
			}
			continue
		}
		if shared == "" || shared == "none" || login == "" || login == "none" || login == shared || len(logins) != 1 {
			t.Errorf("usermod over %q, docker over %q, calls after it over %v; calls:\n%s", shared, login, logins, b)
		}
		// The login is closed and its directory removed, as the run's own.
		if !strings.Contains(string(b), "-o ControlPath="+login+" -O exit h") {
			t.Errorf("the new login is not closed; calls:\n%s", b)
		}
		if _, err := os.Stat(filepath.Dir(login)); !os.IsNotExist(err) {
			t.Errorf("want the login's socket directory removed: %v", err)
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

// The policy carries server.yml's trusted proxies as ranges, an address alone as its own.
func TestPolicyOfCarriesTheTrustedProxies(t *testing.T) {
	sc, err := config.ParseServer([]byte("servers: [a]\nrevision: 1\ntrusted_proxies: [87.228.113.239, 10.1.2.3/16]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(policyOf(sc).TrustedProxies, " "); got != "87.228.113.239/32 10.1.0.0/16" {
		t.Errorf("trusted proxies: %s", got)
	}
	sc, err = config.ParseServer([]byte("servers: [a]\nrevision: 1\n"))
	if err != nil || policyOf(sc).TrustedProxies != nil {
		t.Errorf("want none without the field: %v", err)
	}
}

// The firewall step runs after the policy is on every server, and on every server whatever fails: a's
// firewall cannot be read, b's is still changed, and the error names a.
func TestServerApplyKeepsTheHairpinOnEveryServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(path, []byte("servers: [a, b]\nrevision: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	firewall := `sh -c S=""; [ "$(id -u)" = 0 ]`
	chains := `{"nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input", "policy": "drop"}}]}`
	facts := "nft=yes\nuid=0\nroot=yes\nchains=" + base64.StdEncoding.EncodeToString([]byte(chains)) + "\nenabled=enabled\n"
	var seq []string
	a := &recorder{server: server{firewall: "garbage"}, seq: &seq, name: "a"}
	b := &recorder{server: server{firewall: facts}, seq: &seq, name: "b"}
	fleet(t, map[string]*recorder{"a": a, "b": b}, time.Now)
	var errw strings.Builder
	if code := run([]string{"server", "apply", path}, io.Discard, &errw); code != 1 {
		t.Fatalf("want a failure, got %d: %s", code, errw.String())
	}
	if !strings.Contains(errw.String(), "a: could not read the server's firewall") || strings.Contains(errw.String(), "b:") {
		t.Errorf("want a named, b not: %s", errw.String())
	}
	if !b.ran("sh /usr/local/lib/boks/hairpin.sh") || !b.ran("systemctl daemon-reload") {
		t.Errorf("want b's firewall changed: %v", b.calls)
	}
	// Fleet-wide: the last policy written, on either server, comes before the first firewall read.
	lastPolicy, firstFirewall := -1, -1
	for i, c := range seq {
		_, cmd, _ := strings.Cut(c, " ")
		if strings.Contains(cmd, "mv '.boks/_server/policy.json.") || strings.Contains(cmd, "'.boks/_server/policy.json'") && strings.Contains(cmd, " mv ") {
			lastPolicy = i
		}
		if strings.HasPrefix(cmd, firewall) && firstFirewall < 0 {
			firstFirewall = i
		}
	}
	if lastPolicy < 0 || firstFirewall < lastPolicy {
		t.Errorf("want every policy written before any firewall is read: %v", seq)
	}
}
