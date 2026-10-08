package deploy

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kopandante/boks/internal/config"
)

const hairpinRead = "sh -c " + hairpinFacts

// nftChains is `nft -j list chains` of a host like hb-*: Docker's iptables-nft tables, and the host's
// own inet filter whose input and forward drop by default.
const nftChains = `{"nftables": [{"metainfo": {"version": "1.1.3"}},
 {"chain": {"family": "ip", "table": "nat", "name": "PREROUTING", "handle": 5, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}},
 {"chain": {"family": "ip", "table": "filter", "name": "DOCKER", "handle": 1}},
 {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 8, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
 {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
 {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
 {"chain": {"family": "inet", "table": "filter", "name": "output", "handle": 3, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}]}`

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// firewallFacts is hairpinFacts' answer on a server with chains as nft lists them, nftables.service
// enabled or not, and boks's script and drop-in as given ("" for none).
func firewallFacts(uid, chains string, enabled bool, script, dropIn string) string {
	en := "disabled"
	if enabled {
		en = "enabled"
	}
	facts := "nft=yes\nuid=" + uid + "\nroot=yes\nchains=" + b64(chains) + "\nenabled=" + en + "\nscript=" + b64(script) + "\ndropin=" + b64(dropIn) + "\n"
	// systemd has read the drop-in when it is there: a test of one written and not read says so itself.
	if dropIn != "" {
		facts += "loaded=/etc/systemd/system/nftables.service.d/90-keep-docker.conf " + hairpinDropIn + "\n"
	}
	return facts
}

// Only input chains that drop by default get the rule: not forward, not one that accepts, not
// Docker's; an INPUT that iptables manages is the owner's, and so is one whose name boks does not write.
func TestReadHairpinPicksTheInputChainsThatDrop(t *testing.T) {
	chains := strings.Replace(nftChains, `]}`, `,
 {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}},
 {"chain": {"family": "ip6", "table": "fw", "name": "in", "hook": "input", "policy": "drop"}},
 {"chain": {"family": "inet", "table": "fw", "name": "open", "hook": "input", "policy": "accept"}},
 {"chain": {"family": "inet", "table": "odd table", "name": "in", "hook": "input", "policy": "drop"}},
 {"chain": {"family": "inet", "table": "0fw", "name": "-in", "hook": "input", "policy": "drop"}},
 {"chain": {"family": "bridge", "table": "br", "name": "in", "hook": "input", "policy": "drop"}}]}`, 1)
	f := newFake()
	f.out[hairpinRead] = firewallFacts("0", chains, true, "", "")
	h, err := readHairpin(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(chainNames(h.chains), ","); got != "inet filter input,ip6 fw in" {
		t.Errorf("chains: %s", got)
	}
	if len(h.iptables) != 1 || h.iptables[0].String() != "ip filter INPUT" {
		t.Errorf("iptables' chain: %v", h.iptables)
	}
	if len(h.odd) != 2 || h.odd[0].Table != "odd table" || h.odd[1].Table != "0fw" {
		t.Errorf("odd: %v", h.odd)
	}
	if !h.persist || h.sudo != nil {
		t.Errorf("want nftables.service seen and no sudo for root: %+v", h)
	}
}

// An answer that is not the facts — empty, cut short — is an error, not "no firewall".
func TestReadHairpinRefusesAnAnswerItCannotRead(t *testing.T) {
	for _, out := range []string{"", "root=yes\n", "nft=yes\nuid=0\nroot=yes\nchains=%%%\n"} {
		f := newFake()
		f.out[hairpinRead] = out
		if _, err := readHairpin(context.Background(), f); err == nil {
			t.Errorf("%q: want an error", out)
		}
	}
}

// Where nftables.service loads the firewall, the script and the drop-in are written, systemd reloads,
// and the script runs from its file — the one the unit runs after every load.
func TestEnsureHairpinKeepsTheRuleThroughTheUnit(t *testing.T) {
	f := newFake()
	f.out[hairpinRead] = firewallFacts("0", nftChains, true, "", "")
	f.out["sh "+hairpinScript] = "inserted into inet filter input"
	var log strings.Builder
	if err := EnsureHairpin(context.Background(), f, &log, fixed); err != nil {
		t.Fatal(err)
	}
	script := f.uploads[hairpinScript]
	// The rule itself: a container's connection, from any bridge boks makes, to the proxy's ports on any
	// of the server's own addresses — and nothing wider.
	if hairpinRule != `iifname "br-*" tcp dport { 80, 443 } fib daddr type local accept comment "boks hairpin"` {
		t.Errorf("rule: %s", hairpinRule)
	}
	if !strings.Contains(script, "nft list chain inet filter input | grep -qF 'comment \"boks hairpin\"' || { nft 'insert rule inet filter input "+hairpinRule+"'") ||
		strings.Contains(script, "forward") {
		t.Errorf("want the rule inserted into inet filter input only: %s", script)
	}
	if f.uploads[hairpinDropIn] != hairpinDropInBody || !strings.Contains(hairpinDropInBody, "ExecReload=-/bin/sh "+hairpinScript) ||
		!strings.Contains(hairpinDropInBody, "ExecStartPost=-/bin/sh "+hairpinScript) {
		t.Errorf("drop-in: %q", f.uploads[hairpinDropIn])
	}
	reload, run := f.callAt("systemctl daemon-reload"), f.callAt("sh "+hairpinScript)
	if reload < 0 || run < reload || f.writeIndex(hairpinDropIn, "[Service]") < 0 {
		t.Errorf("want the files, a daemon-reload, then the script: %v", f.calls)
	}
	// Under the server's admission lock, as every change of what the server's apps share.
	if take, give := f.callAt(admitTake(proxyHolder)), f.callAt(admitGive(proxyHolder)); take < 0 || take > f.callAt(hairpinRead) || give < run {
		t.Errorf("want the step under the admission lock: %v", f.calls)
	}
	if !strings.Contains(log.String(), "firewall: inserted into inet filter input") || strings.Contains(log.String(), "warning") {
		t.Errorf("log: %s", log.String())
	}
}

// The second apply finds both files as it would write them: nothing is written and systemd is not
// reloaded, but the script runs — the rule may be gone since.
func TestEnsureHairpinAgainWritesNothing(t *testing.T) {
	f := newFake()
	f.out[hairpinRead] = firewallFacts("0", nftChains, true, hairpinScriptFor([]nftChain{{Family: "inet", Table: "filter", Name: "input"}}), hairpinDropInBody)
	if err := EnsureHairpin(context.Background(), f, &strings.Builder{}, fixed); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) > 0 || f.callAt("systemctl") >= 0 || f.callAt("sh "+hairpinScript) < 0 {
		t.Errorf("want only the script run: %v", f.calls)
	}
}

// A run cut between writing the drop-in and daemon-reload left the file and a unit that never read it:
// the next one reloads systemd though the file is as it would write it.
func TestEnsureHairpinReloadsADropInSystemdNeverRead(t *testing.T) {
	f := newFake()
	script := hairpinScriptFor([]nftChain{{Family: "inet", Table: "filter", Name: "input"}})
	f.out[hairpinRead] = strings.Replace(firewallFacts("0", nftChains, true, script, hairpinDropInBody), " "+hairpinDropIn, "", 1)
	if err := EnsureHairpin(context.Background(), f, &strings.Builder{}, fixed); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) > 0 || f.callAt("systemctl daemon-reload") < 0 || f.callAt("sh "+hairpinScript) < f.callAt("systemctl daemon-reload") {
		t.Errorf("want a daemon-reload, then the script, and nothing written: %v", f.calls)
	}
}

// Without nftables.service nothing would put the rule back: it is inserted once, nothing is written,
// and the log says so.
func TestEnsureHairpinWithoutTheUnitSaysSo(t *testing.T) {
	f := newFake()
	f.out[hairpinRead] = firewallFacts("1000", nftChains, false, "", "")
	var log strings.Builder
	if err := EnsureHairpin(context.Background(), f, &log, fixed); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) > 0 || f.callAt("sudo -n systemctl") >= 0 {
		t.Errorf("want nothing written: %v", f.calls)
	}
	if f.callAt("sudo -n sh -c #!/bin/sh") < 0 {
		t.Errorf("want the script run through sudo for a user that is not root: %v", f.calls)
	}
	if !strings.Contains(log.String(), "nftables.service is not enabled") {
		t.Errorf("log: %s", log.String())
	}
}

// A user that is not root writes the files through sudo too.
func TestEnsureHairpinWritesThroughSudo(t *testing.T) {
	f := newFake()
	f.out[hairpinRead] = firewallFacts("1000", nftChains, true, "", "")
	if err := EnsureHairpin(context.Background(), f, &strings.Builder{}, fixed); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sudo -n sh -c mkdir -p \"$(dirname '" + hairpinScript, "sudo -n sh -c mkdir -p \"$(dirname '" + hairpinDropIn,
		"sudo -n systemctl daemon-reload", "sudo -n sh " + hairpinScript} {
		if f.callAt(want) < 0 {
			t.Errorf("want %q: %v", want, f.calls)
		}
	}
}

// What boks cannot change is said, and nothing is touched: no nft, no root, iptables' INPUT, no chain
// that drops.
func TestEnsureHairpinLeavesWhatItCannotChange(t *testing.T) {
	iptables := `{"nftables": [{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}}]}`
	for _, c := range []struct{ facts, want string }{
		{"nft=no\n", "no nft on this server"},
		{"nft=yes\nuid=1000\nroot=no\n", "no root or `sudo -n`"},
		{firewallFacts("0", iptables, true, "", ""), "ip filter INPUT drops by default and is iptables', which boks does not edit: containers here do not reach the proxy on this server's own addresses until it has `iptables -I INPUT"},
		{firewallFacts("0", `{"nftables": []}`, true, "", ""), "no nft input chain drops by default"},
	} {
		f := newFake()
		f.out[hairpinRead] = c.facts
		var log strings.Builder
		if err := EnsureHairpin(context.Background(), f, &log, fixed); err != nil {
			t.Fatal(err)
		}
		if len(f.calls) != 3 || f.calls[0] != admitTake(proxyHolder) || f.calls[1] != hairpinRead || f.calls[2] != admitGive(proxyHolder) || len(f.writes) > 0 {
			t.Errorf("%q: want the facts read under the lock and nothing else: %v", c.facts, f.calls)
		}
		if !strings.Contains(log.String(), c.want) {
			t.Errorf("%q: want %q in %s", c.facts, c.want, log.String())
		}
	}
}

// A script that could not insert the rule fails the step.
func TestEnsureHairpinFailsWhenTheRuleIsNotPut(t *testing.T) {
	f := newFake()
	f.out[hairpinRead] = firewallFacts("0", nftChains, true, "", "")
	f.fail["sh "+hairpinScript] = errors.New("exit status 1")
	if err := EnsureHairpin(context.Background(), f, &strings.Builder{}, fixed); err == nil || !strings.Contains(err.Error(), "putting the hairpin rule") {
		t.Errorf("want the failure: %v", err)
	}
}

// The script itself, run by sh against a stand-in nft: it inserts the rule into a chain without it,
// leaves a chain that has it, and fails for a chain that is gone — once per chain, run twice.
func TestHairpinScriptInsertsOnce(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "rules")
	nft := "#!/bin/sh\ncase \"$1\" in\n" +
		"list) [ \"$5\" = gone ] && exit 1; grep -F \"$3 $4 $5 \" " + state + " 2>/dev/null; exit 0 ;;\n" +
		"*) set -f; set -- $1; [ \"$5\" = gone ] && exit 1; echo \"$3 $4 $5 comment \\\"boks hairpin\\\"\" >> " + state + " ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(nft), 0o755); err != nil {
		t.Fatal(err)
	}
	script := hairpinScriptFor([]nftChain{{Family: "inet", Table: "filter", Name: "input"}, {Family: "ip", Table: "fw", Name: "in"}})
	run := func() (string, error) {
		cmd := exec.Command("sh", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run()
	if err != nil || strings.Count(out, "inserted into") != 2 {
		t.Fatalf("first run: %v %s", err, out)
	}
	if out, err = run(); err != nil || strings.Contains(out, "inserted") {
		t.Fatalf("second run inserted again: %v %s", err, out)
	}
	rules, _ := os.ReadFile(state)
	if strings.Count(string(rules), "\n") != 2 {
		t.Errorf("want one rule per chain: %s", rules)
	}
	gone := hairpinScriptFor([]nftChain{{Family: "inet", Table: "filter", Name: "gone"}})
	cmd := exec.Command("sh", "-c", gone)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if err := cmd.Run(); err == nil {
		t.Errorf("want a chain that is gone to fail the script")
	}
}

const (
	proxyImageID = "docker inspect -f {{.Image}} boks-proxy"
	routeGet     = "ip -4 route get 1.1.1.1"
	hairpinRun   = "docker run --rm --pull never --network boks-web"
)

func hairpinConfig(t *testing.T, tls bool, hosts ...string) *config.Config {
	t.Helper()
	cfg := &config.Config{App: "web", TLS: tls}
	for i, h := range hosts {
		cfg.Ports = append(cfg.Ports, config.Port{Name: "p" + itoa(i), Port: 3000 + i, Host: h})
	}
	return cfg
}

// hairpinFake is a server leaving by 203.0.113.7 whose probe container prints out.
func hairpinFake(out string) *fake {
	f := newFake()
	f.out[proxyImageID] = "sha256:abc"
	f.out[routeGet] = "1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.7 uid 0\n    cache"
	f.out[hairpinRun] = out
	return f
}

// One container on the app's network, from the image the proxy runs, asks for every TLS host — sent to
// the server's own address, whatever DNS says, by the host's name; a wildcard is not asked. Any answer
// of the proxy passes: a status, a TLS alert for a host without a certificate yet.
func TestCheckHairpinAsksEveryTLSHost(t *testing.T) {
	f := hairpinFake(hairpinMark + "https://a.example.com/\nConnecting to a.example.com (203.0.113.7:443)\n  HTTP/1.1 404 Not Found\n" +
		hairpinMark + "https://xn--e1afmkfd.xn--p1ai/\nConnecting to xn--e1afmkfd.xn--p1ai (203.0.113.7:443)\n" +
		"20AD:error:0A000438:SSL routines:ssl3_read_bytes:tlsv1 alert internal error:ssl/record/rec_layer_s3.c:918:SSL alert number 80\n")
	var log strings.Builder
	cfg := hairpinConfig(t, true, "a.example.com", "*.example.com", "A.example.com", "пример.рф")
	if err := CheckHairpin(context.Background(), f, &log, cfg); err != nil {
		t.Fatal(err)
	}
	run := f.calls[f.callAt(hairpinRun)]
	want := hairpinRun + " --add-host a.example.com:203.0.113.7 --add-host xn--e1afmkfd.xn--p1ai:203.0.113.7 --entrypoint sh sha256:abc -c " +
		"echo 'boks-hairpin https://a.example.com/'; timeout 20 wget --no-check-certificate -S -O /dev/null -T 5 'https://a.example.com/' 2>&1; " +
		"echo 'boks-hairpin https://xn--e1afmkfd.xn--p1ai/'; timeout 20 wget --no-check-certificate -S -O /dev/null -T 5 'https://xn--e1afmkfd.xn--p1ai/' 2>&1; true"
	if run != want || strings.Count(strings.Join(f.calls, "\n"), "docker run") != 1 {
		t.Errorf("want one container for both hosts:\n%s\ngot %v", want, f.calls)
	}
	if !strings.Contains(log.String(), "hairpin: https://a.example.com/ answers a container on boks-web at 203.0.113.7") {
		t.Errorf("log: %s", log.String())
	}
}

// A host that does not answer fails the check, named with what the container got for it; a host that
// answered is not named.
func TestCheckHairpinFailsLoudly(t *testing.T) {
	f := hairpinFake(hairpinMark + "https://a.example.com/\nConnecting to a.example.com (203.0.113.7:443)\nwget: download timed out\n" +
		hairpinMark + "https://b.example.com/\nConnecting to b.example.com (203.0.113.7:443)\n  HTTP/1.1 200 OK\n")
	err := CheckHairpin(context.Background(), f, &strings.Builder{}, hairpinConfig(t, true, "a.example.com", "b.example.com"))
	if err == nil || !strings.Contains(err.Error(), "https://a.example.com/: Connecting to a.example.com (203.0.113.7:443) wget: download timed out") ||
		strings.Contains(err.Error(), "b.example.com") || !strings.Contains(err.Error(), "at 203.0.113.7") || !strings.Contains(err.Error(), "`boks server apply`") {
		t.Errorf("want a named, b not: %v", err)
	}
	// A host the output says nothing about — the container cut short — has not answered either.
	f = hairpinFake(hairpinMark + "https://a.example.com/\n  HTTP/1.1 200 OK\n")
	if err := CheckHairpin(context.Background(), f, &strings.Builder{}, hairpinConfig(t, true, "a.example.com", "b.example.com")); err == nil ||
		!strings.Contains(err.Error(), "https://b.example.com/") {
		t.Errorf("want b named: %v", err)
	}
}

// A server whose address cannot be read is an error, and nothing is run.
func TestCheckHairpinNeedsTheServersAddress(t *testing.T) {
	for _, route := range []string{"", "unreachable", "1.1.1.1 dev eth0 src fe80::1"} {
		f := hairpinFake("")
		f.out[routeGet] = route
		if err := CheckHairpin(context.Background(), f, &strings.Builder{}, hairpinConfig(t, true, "a.example.com")); err == nil || f.callAt("docker run") >= 0 {
			t.Errorf("%q: want an error before any probe: %v %v", route, err, f.calls)
		}
	}
}

// An app without TLS, or without a host a name can point at this server — none, a wildcard, an address —
// asks nothing.
func TestCheckHairpinWithoutTLSAsksNothing(t *testing.T) {
	for _, cfg := range []*config.Config{hairpinConfig(t, false, "a.example.com"), hairpinConfig(t, true), hairpinConfig(t, true, "*.example.com"),
		hairpinConfig(t, true, "203.0.113.9")} {
		f := newFake()
		if err := CheckHairpin(context.Background(), f, &strings.Builder{}, cfg); err != nil || len(f.calls) > 0 {
			t.Errorf("want nothing asked: %v %v", err, f.calls)
		}
	}
}

func TestProxyAnswered(t *testing.T) {
	for out, want := range map[string]bool{
		"  HTTP/1.1 308 Permanent Redirect":                      true,
		"...:SSL alert number 80\nssl_client: SSL_connect":       true,
		"wget: download timed out":                               false,
		"wget: can't connect to remote host: Connection refused": false,
		"wget: bad address 'a.example.com'":                      false,
		"":                                                       false,
	} {
		if got := proxyAnswered(out); got != want {
			t.Errorf("%q: want %v", out, want)
		}
	}
}

// After a rollback the hosts asked for are the restored release's — its ports, under today's tls — not
// today's config's; an app without tls reads nothing.
func TestCheckRolledBackHairpinAsksTheRestoredHosts(t *testing.T) {
	f := hairpinFake(hairpinMark + "https://old.example.com/\n  HTTP/1.1 200 OK\n")
	f.out["sh -c cat '.boks/web/current'"] = "web-v1-1\n"
	f.out["cat .boks/web/releases/web-v1-1.json"] = `{"id":"web-v1-1","app":"web","image":"ghcr.io/x/web","tag":"v1",` +
		`"ports":[{"name":"web","port":3000,"host":"old.example.com"}]}`
	if err := CheckRolledBackHairpin(context.Background(), f, &strings.Builder{}, hairpinConfig(t, true, "new.example.com")); err != nil {
		t.Fatal(err)
	}
	if run := f.calls[f.callAt(hairpinRun)]; !strings.Contains(run, "--add-host old.example.com:203.0.113.7") || strings.Contains(run, "new.example.com") {
		t.Errorf("want the restored release's host asked: %s", run)
	}
	// A release that cannot be read is an error, and nothing is run.
	f = hairpinFake("")
	f.out["sh -c cat '.boks/web/current'"] = "web-v1-1\n"
	f.fail["cat .boks/web/releases/web-v1-1.json"] = errors.New("No such file")
	if err := CheckRolledBackHairpin(context.Background(), f, &strings.Builder{}, hairpinConfig(t, true, "new.example.com")); err == nil ||
		!strings.Contains(err.Error(), "reading the restored release for the hairpin check") || f.callAt("docker run") >= 0 {
		t.Errorf("want an error before any probe: %v %v", err, f.calls)
	}
	f = newFake()
	if err := CheckRolledBackHairpin(context.Background(), f, &strings.Builder{}, hairpinConfig(t, false, "new.example.com")); err != nil || len(f.calls) > 0 {
		t.Errorf("want nothing asked without tls: %v %v", err, f.calls)
	}
}

// hairpinStatusRead is the start of the status's read of the rule, after the facts.
const hairpinStatusRead = "sh -c PATH=\"$PATH:/usr/sbin:/sbin\"\nif nft list chain"

// The status line for each state of the rule: in every chain and kept, gone from a chain (a `nft -f` past
// the unit) with the way back, kept by nothing, the unit off, and what boks cannot read or change.
func TestHairpinStatusSaysWhereTheRuleIs(t *testing.T) {
	input := []nftChain{{Family: "inet", Table: "filter", Name: "input"}}
	two := strings.Replace(nftChains, `]}`, `,
 {"chain": {"family": "ip6", "table": "fw", "name": "in", "hook": "input", "policy": "drop"}}]}`, 1)
	kept := firewallFacts("0", nftChains, true, hairpinScriptFor(input), hairpinDropInBody)
	iptables := `{"nftables": [{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}}]}`
	for _, c := range []struct {
		name, facts, rule string
		want              []string
	}{
		{"kept", kept, "has inet filter input", []string{"firewall: hairpin rule in inet filter input, kept by nftables.service"}},
		{"gone", kept, "lacks inet filter input", []string{"! firewall: inet filter input drops by default without boks's hairpin rule: " +
			"containers here do not reach the proxy on this server's own addresses; `boks server apply` puts it back"}},
		{"one of two", firewallFacts("0", two, true, hairpinScriptFor([]nftChain{input[0], {Family: "ip6", Table: "fw", Name: "in"}}), hairpinDropInBody),
			"has inet filter input\nlacks ip6 fw in", []string{"! firewall: ip6 fw in drops by default without boks's hairpin rule", "firewall: hairpin rule in inet filter input, kept"}},
		{"never applied", firewallFacts("0", nftChains, true, "", ""), "lacks inet filter input", []string{"! firewall: inet filter input drops by default without boks's hairpin rule: " +
			"containers here do not reach the proxy on this server's own addresses; `boks server apply` puts it back"}},
		{"kept by nothing", firewallFacts("0", nftChains, true, hairpinScriptFor(input), ""), "has inet filter input",
			[]string{"! firewall: hairpin rule in inet filter input, but nftables.service would not put it back after a reload: `boks server apply` writes"}},
		{"not read by systemd", strings.Replace(kept, " "+hairpinDropIn, "", 1), "has inet filter input",
			[]string{"! firewall: hairpin rule in inet filter input, but nftables.service would not put it back"}},
		{"old script", firewallFacts("0", two, true, hairpinScriptFor(input), hairpinDropInBody), "has inet filter input\nhas ip6 fw in",
			[]string{"! firewall: hairpin rule in inet filter input, ip6 fw in, but " + hairpinScript + " is not the one `boks server apply` writes"}},
		// A drop chain added since the last apply: the old script still keeps the rule in the first; only the
		// new one is named without it, and the script is named as not the one apply writes now.
		{"new chain", firewallFacts("0", two, true, hairpinScriptFor(input), hairpinDropInBody), "has inet filter input\nlacks ip6 fw in",
			[]string{"! firewall: ip6 fw in drops by default without boks's hairpin rule", "! firewall: hairpin rule in inet filter input, but " + hairpinScript + " is not"}},
		{"script and drop-in", firewallFacts("0", nftChains, true, "", ""), "has inet filter input",
			[]string{"! firewall: hairpin rule in inet filter input, but nftables.service would not put it back"}},
		{"unit off", firewallFacts("0", nftChains, false, "", ""), "has inet filter input", []string{"firewall: hairpin rule in inet filter input; nftables.service is not enabled"}},
		{"no nft", "nft=no\n", "", []string{"firewall: no nft on this server"}},
		{"no root", "nft=yes\nuid=1000\nroot=no\n", "", []string{"! firewall: no root or `sudo -n`"}},
		{"iptables", firewallFacts("0", iptables, true, "", ""), "", []string{"! firewall: ip filter INPUT drops by default and is iptables'"}},
		{"nothing drops", firewallFacts("0", `{"nftables": []}`, true, "", ""), "", []string{"firewall: no nft input chain drops by default; boks's hairpin rule has none to go into"}},
		{"unreadable", "garbage", "", []string{"! firewall: could not read the server's firewall"}},
		{"no answer", kept, "", []string{"! firewall: reading boks's hairpin rule: no answer for inet filter input"}},
	} {
		f := newFake()
		f.out[hairpinRead] = c.facts
		f.out[hairpinStatusRead] = c.rule
		lines := HairpinStatus(context.Background(), f)
		got := strings.Join(lines, "\n")
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: want %q in\n%s", c.name, w, got)
			}
		}
		if len(lines) != len(c.want) {
			t.Errorf("%s: want %d lines:\n%s", c.name, len(c.want), got)
		}
		if len(f.writes) > 0 || len(f.uploads) > 0 || f.has("systemctl daemon-reload") || f.has("sh "+hairpinScript) || f.has(admitTake(proxyHolder)) {
			t.Errorf("%s: want nothing changed and no lock: %v", c.name, f.calls)
		}
	}
	// A user that is not root reads the rule through sudo.
	f := newFake()
	f.out[hairpinRead] = firewallFacts("1000", nftChains, true, "", "")
	HairpinStatus(context.Background(), f)
	if !f.has("sudo -n " + hairpinStatusRead) {
		t.Errorf("want the rule read through sudo: %v", f.calls)
	}
}

// The status's read of the rule itself, run by sh against the stand-in nft of TestHairpinScriptInsertsOnce:
// a chain without the rule lacks it, the script puts it in, and the chain has it.
func TestHairpinStatusReadsTheRuleTheScriptPuts(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "rules")
	nft := "#!/bin/sh\ncase \"$1\" in\n" +
		"list) grep -F \"$3 $4 $5 \" " + state + " 2>/dev/null; exit 0 ;;\n" +
		"*) set -f; set -- $1; echo \"$3 $4 $5 comment \\\"boks hairpin\\\"\" >> " + state + " ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(nft), 0o755); err != nil {
		t.Fatal(err)
	}
	input := []nftChain{{Family: "inet", Table: "filter", Name: "input"}}
	local := &shell{path: dir + ":" + os.Getenv("PATH"), facts: firewallFacts("0", nftChains, true, hairpinScriptFor(input), hairpinDropInBody)}
	if got := strings.Join(HairpinStatus(context.Background(), local), "\n"); !strings.Contains(got, "! firewall: inet filter input drops by default without") {
		t.Fatalf("before the script: %s", got)
	}
	cmd := exec.Command("sh", "-c", hairpinScriptFor(input))
	cmd.Env = append(os.Environ(), "PATH="+local.path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script: %v %s", err, out)
	}
	if got := strings.Join(HairpinStatus(context.Background(), local), "\n"); !strings.Contains(got, "firewall: hairpin rule in inet filter input") || strings.Contains(got, "!") {
		t.Errorf("after the script: %s", got)
	}
}

// shell answers the firewall's facts as given and runs every other command with sh on this machine.
type shell struct{ path, facts string }

func (s *shell) Run(ctx context.Context, args ...string) (string, error) {
	if strings.Join(args, " ") == hairpinRead {
		return s.facts, nil
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "PATH="+s.path)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *shell) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return s.Run(ctx, args...)
}
