package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/proxy"
)

// gatePolicy is revision rev with one group for shop, in mode and site_gate as given; mode "" is no gate.
func gatePolicy(rev int, mode, siteGate string) proxy.Policy {
	p := proxy.Policy{Revision: rev, Floor: rev}
	if mode != "" {
		p.Gate = json.RawMessage(fmt.Sprintf(`{"groups":[{"name":"shop","app":"shop","mode":%q,"site_gate":%q,"secret_env":"SHOP_SECRET"}]}`, mode, siteGate))
	}
	return p
}

// The matrix of current × target: a group whose site no longer checks the token (site_gate off) may
// only go to enforce with site_gate off; anything else — log, off, site_gate on, no group, no gate — is
// refused without --force, for apply and rollback alike. A group whose site still checks goes anywhere
// (plan §5 boks 5, S7, T2).
func TestCheckGateTransition(t *testing.T) {
	type state struct{ mode, siteGate string }
	targets := []state{{"", ""}, {"off", "on"}, {"log", "on"}, {"enforce", "on"}, {"enforce", "off"}}
	for _, cur := range []state{{"", ""}, {"log", "on"}, {"enforce", "on"}, {"enforce", "off"}} {
		for _, next := range targets {
			err := CheckGateTransition(gatePolicy(5, cur.mode, cur.siteGate), gatePolicy(6, next.mode, next.siteGate), false)
			refused := cur.siteGate == "off" && next != (state{"enforce", "off"})
			if (err != nil) != refused {
				t.Errorf("%v -> %v: %v, want refused=%v", cur, next, err, refused)
			}
			if refused && (!strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), "shop")) {
				t.Errorf("%v -> %v: the refusal names the app and the way out: %v", cur, next, err)
			}
			if err := CheckGateTransition(gatePolicy(5, cur.mode, cur.siteGate), gatePolicy(6, next.mode, next.siteGate), true); err != nil {
				t.Errorf("%v -> %v with --force: %v", cur, next, err)
			}
		}
	}
	// Groups are matched by app, not by name.
	renamed := gatePolicy(6, "enforce", "off")
	renamed.Gate = json.RawMessage(strings.Replace(string(renamed.Gate), `"name":"shop"`, `"name":"shop-2"`, 1))
	if err := CheckGateTransition(gatePolicy(5, "enforce", "off"), renamed, false); err != nil {
		t.Errorf("a group renamed, same app: %v", err)
	}
	other := gatePolicy(6, "enforce", "off")
	other.Gate = json.RawMessage(strings.Replace(string(other.Gate), `"app":"shop"`, `"app":"blog"`, 1))
	if err := CheckGateTransition(gatePolicy(5, "enforce", "off"), other, false); err == nil {
		t.Error("the same name on another app: taken")
	}
}

// The check runs again under the admission lock, against the policy read there: an apply or a rollback
// that passed its early check while another run turned a group's site gate off is still refused, and
// writes nothing (T6).
func TestGateTransitionUnderTheLock(t *testing.T) {
	f := serverFake(t, gatePolicy(7, "enforce", "off"))
	if err := ApplyServer(context.Background(), f, io.Discard, gatePolicy(8, "log", "on"), fixed); err == nil || !strings.Contains(err.Error(), "site_gate off") {
		t.Errorf("apply: want the refusal from under the lock, got %v", err)
	}
	if _, wrote := f.uploads[policyFile]; wrote {
		t.Errorf("apply wrote the policy: %s", f.uploads[policyFile])
	}
	hist, _ := json.Marshal(gatePolicy(6, "", ""))
	f.out["sh -c if [ -f '.boks/_server/history/6.json' ]"] = "present\n" + string(hist)
	if err := RollbackServer(context.Background(), f, io.Discard, 6, fixed); err == nil || !strings.Contains(err.Error(), "no gate group") {
		t.Errorf("rollback: want the refusal from under the lock, got %v", err)
	}
	if err := CheckServerRollback(context.Background(), f, 6, false); err == nil {
		t.Error("the early check of the rollback: taken")
	}
	if _, wrote := f.uploads[policyFile]; wrote {
		t.Errorf("rollback wrote the policy: %s", f.uploads[policyFile])
	}
	forced := fixed
	forced.Force = true
	if err := CheckGateTransition(gatePolicy(7, "enforce", "off"), gatePolicy(6, "", ""), forced.Force); err != nil {
		t.Errorf("--force: %v", err)
	}
}

// A gate the proxy's image cannot run — ban8 knows no boks_gate — is refused before anything changes,
// with the handlers themselves as the probe, secrets on its input; an app the gate names that has no
// routes on the server is refused too.
func TestCheckApplyRefusesAGateTheProxyCannotRun(t *testing.T) {
	const ban8, gate1 = "ghcr.io/kopandante/boks-caddy:2.11.7-fp0aab84d-ban8", "ghcr.io/kopandante/boks-caddy:2.11.7-fp0aab84d-ban8-gate1"
	validate := func(image string) string {
		return "docker run --rm -i --network none --entrypoint caddy " + image + " validate --config /dev/stdin"
	}
	secret := strings.Repeat("s", 32)
	next := gatePolicy(2, "log", "on")
	next.GateSecrets = map[string][]string{"SHOP_SECRET": {secret}}

	f := serverFake(t, proxy.Policy{Revision: 1, Floor: 1})
	if err := CheckApply(context.Background(), f, next, false); err == nil || !strings.Contains(err.Error(), "shop has no routes on this server") {
		t.Errorf("want an app without routes refused: %v", err)
	}
	f.out[frags] = `7
{"app": "shop", "routes": [{"host": "shop.example.com", "dial": "shop:1", "tls": true}]}`
	f.out[proxyImage] = ban8
	f.fail[validate(ban8)] = errors.New(`exit status 1: loading module 'boks_gate': unknown module: http.handlers.boks_gate`)
	if err := CheckApply(context.Background(), f, next, false); err == nil || !strings.Contains(err.Error(), "the proxy runs "+ban8) ||
		!strings.Contains(err.Error(), "refuses the gate") || !strings.Contains(err.Error(), "boks proxy upgrade") {
		t.Errorf("want ban8 refused: %v", err)
	}
	probe := f.stdin[validate(ban8)]
	if !strings.Contains(probe, `"handler":"boks_gate"`) || !strings.Contains(probe, secret) || strings.Contains(probe, "secret_env") {
		t.Errorf("want the handler with its secret as the probe: %s", probe)
	}
	if strings.Contains(strings.Join(f.calls, "\n"), secret) {
		t.Errorf("a secret on a command line")
	}
	f.out[proxyImage] = gate1
	if err := CheckApply(context.Background(), f, next, false); err != nil {
		t.Errorf("want the image with the gate taken: %v", err)
	}
	// A secret neither the apply nor the server has stops the apply here, not halfway down the list.
	next.GateSecrets = nil
	if err := CheckApply(context.Background(), f, next, false); err == nil || !strings.Contains(err.Error(), "SHOP_SECRET") {
		t.Errorf("want the missing secret named: %v", err)
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 {
		t.Errorf("want nothing written: %v %v", f.uploads, f.appends)
	}
}

// The early checks of apply and rollback, on every server before any changes, hold the transition and
// the image's check too; --force lifts the transition alone (T2).
func TestEarlyChecksHoldTheGate(t *testing.T) {
	f := serverFake(t, gatePolicy(7, "enforce", "off"))
	if err := CheckApply(context.Background(), f, gatePolicy(8, "log", "on"), false); err == nil || !strings.Contains(err.Error(), "site_gate off") {
		t.Errorf("apply: want the transition refused before any changes, got %v", err)
	}
	if err := CheckApply(context.Background(), f, gatePolicy(8, "log", "on"), true); err == nil || strings.Contains(err.Error(), "site_gate off") ||
		!strings.Contains(err.Error(), "shop has no routes") {
		t.Errorf("apply --force: want past the transition, to the image's check, got %v", err)
	}
	f = serverFake(t, gatePolicy(7, "", ""))
	hist, _ := json.Marshal(gatePolicy(6, "log", "on"))
	f.out["sh -c if [ -f '.boks/_server/history/6.json' ]"] = "present\n" + string(hist)
	if err := CheckServerRollback(context.Background(), f, 6, false); err == nil || !strings.Contains(err.Error(), "shop has no routes") {
		t.Errorf("rollback to a gate: want the image's check before any changes, got %v", err)
	}
	if len(f.uploads) > 0 || len(f.appends) > 0 {
		t.Errorf("want nothing written: %v %v", f.uploads, f.appends)
	}
}

// The policy the check under the lock judges is the one read there: a run whose early check saw the
// group's site still checking, while another run turned its site gate off before this one took the
// lock, is refused all the same (T6).
func TestGateTransitionReadsThePolicyUnderTheLock(t *testing.T) {
	off, _ := json.Marshal(gatePolicy(7, "enforce", "off"))
	for _, c := range []struct {
		name string
		run  func(f *fake) error
	}{
		{"apply", func(f *fake) error {
			return ApplyServer(context.Background(), f, io.Discard, gatePolicy(8, "log", "on"), fixed)
		}},
		{"rollback", func(f *fake) error { return RollbackServer(context.Background(), f, io.Discard, 6, fixed) }},
	} {
		f := serverFake(t, gatePolicy(7, "enforce", "on"))
		hist, _ := json.Marshal(gatePolicy(6, "", ""))
		f.out["sh -c if [ -f '.boks/_server/history/6.json' ]"] = "present\n" + string(hist)
		f.onRun = func(cmd string) {
			if strings.HasPrefix(cmd, "ln -sn ") && strings.Contains(cmd, "/tmp/boks.admit.lock") {
				f.out[policyRead] = "present\n" + string(off)
			}
		}
		if err := c.run(f); err == nil || !strings.Contains(err.Error(), "site_gate off") && !strings.Contains(err.Error(), "no gate group") {
			t.Errorf("%s: want the refusal from the policy read under the lock, got %v", c.name, err)
		}
		if _, wrote := f.uploads[policyFile]; wrote {
			t.Errorf("%s wrote the policy: %s", c.name, f.uploads[policyFile])
		}
	}
}
