package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// oldBoks is the boks of format 7 every app's CI pinned before the gate; gateBoks the one of format 8
// they pin until the fleet's pin is raised past the deny.
const (
	oldBoks  = "09b6657"
	gateBoks = "e57f5b7"
)

// local is a server in a directory: its commands run there, and docker answers that no proxy runs,
// so a reload is the applied config written — what a server whose proxy is stopped does.
type dirServer struct{ dir string }

func (l dirServer) Run(ctx context.Context, args ...string) (string, error) {
	return l.Pipe(ctx, nil, args...)
}

func (l dirServer) Pipe(ctx context.Context, in []byte, args ...string) (string, error) {
	if args[0] == "docker" {
		return "", nil
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir, cmd.Stdin = l.dir, bytes.NewReader(in)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// oldDeploy is the routing step of a deploy by boks@09b6657 — its own internal/proxy, built from its
// commit — setting an app's routes on the server in dir: the step that reads every fragment and the
// marker, and refuses a format newer than its own.
const oldDeploy = `package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/kopandante/boks/internal/proxy"
)

type local struct{ dir string }

func (l local) Run(ctx context.Context, args ...string) (string, error) { return l.Pipe(ctx, nil, args...) }

func (l local) Pipe(ctx context.Context, in []byte, args ...string) (string, error) {
	if args[0] == "docker" {
		return "", nil
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir, cmd.Stdin = l.dir, bytes.NewReader(in)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func main() {
	routes := []proxy.Route{{Host: os.Args[3], Dial: os.Args[2] + ":3000", TLS: true}}
	if _, err := proxy.SetRoutes(context.Background(), local{os.Args[1]}, io.Discard, os.Args[2], routes); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
`

// buildOld builds oldDeploy inside boks@rev's own tree, from this repository's history.
func buildOld(t *testing.T, rev string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds boks@" + rev)
	}
	if err := exec.Command("git", "cat-file", "-e", rev+"^{commit}").Run(); err != nil {
		t.Skipf("boks@%s is not in this clone's history: %v", rev, err)
	}
	src := t.TempDir()
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	// From the top: run in a subdirectory, git archive takes that subdirectory alone.
	archive := exec.Command("git", "archive", rev)
	archive.Dir = strings.TrimSpace(string(top))
	untar := exec.Command("tar", "-x", "-C", src)
	pipe, _ := archive.StdoutPipe()
	untar.Stdin = pipe
	if err := untar.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Run(); err != nil {
		t.Fatal(err)
	}
	if err := untar.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "cmd", "olddeploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "cmd", "olddeploy", "main.go"), []byte(oldDeploy), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "olddeploy")
	build := exec.Command("go", "build", "-o", bin, "./cmd/olddeploy")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building boks@%s: %v\n%s", rev, err, out)
	}
	return bin
}

// A fleet on two pins at once (R4, AC4, AC10): this boks applies a policy without a gate and deploys
// on the server, and boks@09b6657 deploys after it as before; a policy with a gate turns 09b6657 away,
// loudly and before it changes anything, while this boks still deploys; a rollback to a revision
// without the gate lets 09b6657 in again at once, no app deployed anew.
func TestOldBoksAndTheGate(t *testing.T) {
	old := buildOld(t, oldBoks)
	node := dirServer{t.TempDir()}
	ctx := context.Background()
	oldDeploys := func(app string) (string, bool) {
		out, err := exec.Command(old, node.dir, app, app+".example.com").CombinedOutput()
		return string(out), err == nil
	}
	if _, err := SetRoutes(ctx, node, io.Discard, "shop", []Route{{Host: "shop.example.com", Dial: "shop:3000", TLS: true}}); err != nil {
		t.Fatal(err)
	}
	plain := Policy{Revision: 1, Floor: 1, Block: []BotBlock{{Name: "crawlers", UserAgent: "(?i)gptbot"}}}
	if err := SetPolicy(ctx, node, io.Discard, plain); err != nil {
		t.Fatal(err)
	}
	if out, ok := oldDeploys("blog"); !ok {
		t.Fatalf("boks@%s on a server without a gate: %s", oldBoks, out)
	}

	gate := Policy{Revision: 2, Floor: 2, Block: plain.Block,
		Gate:        json.RawMessage(`{"groups":[{"name":"shop","app":"shop","mode":"log","secret_env":"SHOP_SECRET"}]}`),
		GateSecrets: map[string][]string{"SHOP_SECRET": {strings.Repeat("s", 32)}}}
	if err := SetPolicy(ctx, node, io.Discard, gate); err != nil {
		t.Fatal(err)
	}
	applied, _ := os.ReadFile(filepath.Join(node.dir, Dir, "caddy.json"))
	out, ok := oldDeploys("wiki")
	if ok || !strings.Contains(out, "update boks before changing this server") {
		t.Errorf("boks@%s on a server with a gate: want a refusal naming the update, got %v %s", oldBoks, ok, out)
	}
	if _, err := os.Stat(filepath.Join(node.dir, Dir, "routes", "wiki.json")); err == nil {
		t.Errorf("boks@%s wrote its fragment before refusing", oldBoks)
	}
	if now, _ := os.ReadFile(filepath.Join(node.dir, Dir, "caddy.json")); !bytes.Equal(now, applied) || !bytes.Contains(now, []byte("boks_gate")) {
		t.Errorf("boks@%s changed the applied config", oldBoks)
	}
	if _, err := SetRoutes(ctx, node, io.Discard, "docs", []Route{{Host: "docs.example.com", Dial: "docs:3000", TLS: true}}); err != nil {
		t.Errorf("this boks on a server with a gate: %v", err)
	}

	back, _, err := History(ctx, node, 1)
	if err != nil {
		t.Fatal(err)
	}
	back.Floor = 2
	if err := SetPolicy(ctx, node, io.Discard, back); err != nil {
		t.Fatal(err)
	}
	if out, ok := oldDeploys("wiki"); !ok {
		t.Errorf("boks@%s after a rollback to a revision without the gate: %s", oldBoks, out)
	}
}

// The same three steps for the deny and boks@e57f5b7, the boks of format 8 the fleet pins: on a server
// whose policy has a gate and no deny it deploys; a policy with a deny turns it away before it changes
// anything — it would read the policy without the deny and reload the config with the denied address
// let in — while this boks still deploys; a rollback to the revision without the deny lets it in again.
func TestOldBoksAndTheDeny(t *testing.T) {
	old := buildOld(t, gateBoks)
	node := dirServer{t.TempDir()}
	ctx := context.Background()
	oldDeploys := func(app string) (string, bool) {
		out, err := exec.Command(old, node.dir, app, app+".example.com").CombinedOutput()
		return string(out), err == nil
	}
	if _, err := SetRoutes(ctx, node, io.Discard, "shop", []Route{{Host: "shop.example.com", Dial: "shop:3000", TLS: true}}); err != nil {
		t.Fatal(err)
	}
	ban := &Ban{Duration: "24h", Rules: []BanRule{{Name: "all", Limit: 1500, Window: "1m", Class: "all"}}}
	gate := Policy{Revision: 1, Floor: 1, Ban: ban,
		Gate:        json.RawMessage(`{"groups":[{"name":"shop","app":"shop","mode":"log","secret_env":"SHOP_SECRET"}]}`),
		GateSecrets: map[string][]string{"SHOP_SECRET": {strings.Repeat("s", 32)}}}
	if err := SetPolicy(ctx, node, io.Discard, gate); err != nil {
		t.Fatal(err)
	}
	if out, ok := oldDeploys("blog"); !ok {
		t.Fatalf("boks@%s on a server with a gate and no deny: %s", gateBoks, out)
	}

	deny := gate
	deny.Revision, deny.Floor = 2, 2
	withDeny := *ban
	withDeny.DenyRanges = []string{"89.167.100.21/32"}
	deny.Ban = &withDeny
	if err := SetPolicy(ctx, node, io.Discard, deny); err != nil {
		t.Fatal(err)
	}
	applied, _ := os.ReadFile(filepath.Join(node.dir, Dir, "caddy.json"))
	out, ok := oldDeploys("wiki")
	if ok || !strings.Contains(out, "update boks before changing this server") {
		t.Errorf("boks@%s on a server with a deny: want a refusal naming the update, got %v %s", gateBoks, ok, out)
	}
	if now, _ := os.ReadFile(filepath.Join(node.dir, Dir, "caddy.json")); !bytes.Equal(now, applied) || !bytes.Contains(now, []byte("deny_ranges")) {
		t.Errorf("boks@%s changed the applied config", gateBoks)
	}
	if _, err := SetRoutes(ctx, node, io.Discard, "docs", []Route{{Host: "docs.example.com", Dial: "docs:3000", TLS: true}}); err != nil {
		t.Errorf("this boks on a server with a deny: %v", err)
	}

	back, _, err := History(ctx, node, 1)
	if err != nil {
		t.Fatal(err)
	}
	back.Floor = 2
	if err := SetPolicy(ctx, node, io.Discard, back); err != nil {
		t.Fatal(err)
	}
	if out, ok := oldDeploys("wiki"); !ok {
		t.Errorf("boks@%s after a rollback to a revision without the deny: %s", gateBoks, out)
	}
}
