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
	return "nft=yes\nuid=" + uid + "\nroot=yes\nchains=" + b64(chains) + "\nenabled=" + en + "\nscript=" + b64(script) + "\ndropin=" + b64(dropIn) + "\n"
}

// Only input chains that drop by default get the rule: not forward, not one that accepts, not
// Docker's; an INPUT that iptables manages is the owner's, and so is one whose name boks does not write.
func TestReadHairpinPicksTheInputChainsThatDrop(t *testing.T) {
	chains := strings.Replace(nftChains, `]}`, `,
 {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}},
 {"chain": {"family": "ip6", "table": "fw", "name": "in", "hook": "input", "policy": "drop"}},
 {"chain": {"family": "inet", "table": "fw", "name": "open", "hook": "input", "policy": "accept"}},
 {"chain": {"family": "inet", "table": "odd table", "name": "in", "hook": "input", "policy": "drop"}},
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
	if len(h.odd) != 1 || h.odd[0].Table != "odd table" {
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
	if err := EnsureHairpin(context.Background(), f, &log); err != nil {
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
	if !strings.Contains(log.String(), "firewall: inserted into inet filter input") || strings.Contains(log.String(), "warning") {
		t.Errorf("log: %s", log.String())
	}
}

// The second apply finds both files as it would write them: nothing is written and systemd is not
// reloaded, but the script runs — the rule may be gone since.
func TestEnsureHairpinAgainWritesNothing(t *testing.T) {
	f := newFake()
	f.out[hairpinRead] = firewallFacts("0", nftChains, true, hairpinScriptFor([]nftChain{{Family: "inet", Table: "filter", Name: "input"}}), hairpinDropInBody)
	if err := EnsureHairpin(context.Background(), f, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) > 0 || f.callAt("systemctl") >= 0 || f.callAt("sh "+hairpinScript) < 0 {
		t.Errorf("want only the script run: %v", f.calls)
	}
}

// Without nftables.service nothing would put the rule back: it is inserted once, nothing is written,
// and the log says so.
func TestEnsureHairpinWithoutTheUnitSaysSo(t *testing.T) {
	f := newFake()
	f.out[hairpinRead] = firewallFacts("1000", nftChains, false, "", "")
	var log strings.Builder
	if err := EnsureHairpin(context.Background(), f, &log); err != nil {
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
	if err := EnsureHairpin(context.Background(), f, &strings.Builder{}); err != nil {
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
		{firewallFacts("0", `{"nftables": []}`, true, "", ""), ""},
	} {
		f := newFake()
		f.out[hairpinRead] = c.facts
		var log strings.Builder
		if err := EnsureHairpin(context.Background(), f, &log); err != nil {
			t.Fatal(err)
		}
		if len(f.calls) != 1 || len(f.writes) > 0 {
			t.Errorf("%q: want the facts read and nothing else: %v", c.facts, f.calls)
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
	if err := EnsureHairpin(context.Background(), f, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "putting the hairpin rule") {
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
	hairpinRun   = "docker run --rm --pull never --network boks-web --entrypoint sh sha256:abc -c wget --no-check-certificate -S -O /dev/null -T 5 'https://"
)

func hairpinConfig(t *testing.T, tls bool, hosts ...string) *config.Config {
	t.Helper()
	cfg := &config.Config{App: "web", TLS: tls}
	for i, h := range hosts {
		cfg.Ports = append(cfg.Ports, config.Port{Name: "p" + itoa(i), Port: 3000 + i, Host: h})
	}
	return cfg
}

// Each TLS host is asked from a container on the app's network, by the image the proxy runs; any
// answer of the proxy passes — a status, a TLS alert for a host without a certificate yet.
func TestCheckHairpinAsksEveryTLSHost(t *testing.T) {
	f := newFake()
	f.out[proxyImageID] = "sha256:abc"
	f.out[hairpinRun+"a.example.com/'"] = "Connecting to a.example.com (1.2.3.4:443)\n  HTTP/1.1 404 Not Found"
	f.out[hairpinRun+"xn--e1afmkfd.xn--p1ai/'"] = "Connecting to xn--e1afmkfd.xn--p1ai (1.2.3.4:443)\n" +
		"20AD:error:0A000438:SSL routines:ssl3_read_bytes:tlsv1 alert internal error:ssl/record/rec_layer_s3.c:918:SSL alert number 80"
	var log strings.Builder
	cfg := hairpinConfig(t, true, "a.example.com", "*.example.com", "A.example.com", "пример.рф")
	if err := CheckHairpin(context.Background(), f, &log, cfg); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(f.calls, "\n"), "docker run --rm"); n != 2 {
		t.Errorf("want one probe per host, none for the wildcard: %v", f.calls)
	}
	if !strings.Contains(log.String(), "hairpin: https://a.example.com/ answers a container on boks-web") {
		t.Errorf("log: %s", log.String())
	}
}

// A host that does not answer fails the check, named with what the container got, and every host is
// still asked.
func TestCheckHairpinFailsLoudly(t *testing.T) {
	f := newFake()
	f.out[proxyImageID] = "sha256:abc"
	f.out[hairpinRun+"a.example.com/'"] = "Connecting to a.example.com (1.2.3.4:443)\nwget: download timed out"
	f.out[hairpinRun+"b.example.com/'"] = "Connecting to b.example.com (1.2.3.4:443)\n  HTTP/1.1 200 OK"
	err := CheckHairpin(context.Background(), f, &strings.Builder{}, hairpinConfig(t, true, "a.example.com", "b.example.com"))
	if err == nil || !strings.Contains(err.Error(), "https://a.example.com/: Connecting to a.example.com (1.2.3.4:443) wget: download timed out") ||
		strings.Contains(err.Error(), "b.example.com") || !strings.Contains(err.Error(), "`boks server apply`") {
		t.Errorf("want a named, b not: %v", err)
	}
}

// An app without TLS, or without hosts, asks nothing.
func TestCheckHairpinWithoutTLSAsksNothing(t *testing.T) {
	for _, cfg := range []*config.Config{hairpinConfig(t, false, "a.example.com"), hairpinConfig(t, true)} {
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
