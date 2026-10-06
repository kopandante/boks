package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// swap is a server for an upgrade: answers by command prefix, failures by prefix, every call kept.
type swap struct {
	out   map[string]string
	fail  map[string]error
	calls []string
}

func newSwap(current string) *swap {
	return &swap{fail: map[string]error{}, out: map[string]string{
		"docker ps -a --filter name=^boks-proxy$": "running\tcaddy",
		"sh -c docker inspect -f":                 current,
		"sh -c cd '.boks/_proxy' && pwd -P":       "/home/u/.boks/_proxy",
		"docker exec boks-proxy cat /proc/sys":    "1",
	}}
}

func (s *swap) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	s.calls = append(s.calls, cmd)
	for p, err := range s.fail {
		if strings.HasPrefix(cmd, p) {
			return "", err
		}
	}
	best := ""
	for p := range s.out {
		if strings.HasPrefix(cmd, p) && len(p) > len(best) {
			best = p
		}
	}
	if best == "" {
		if strings.HasPrefix(cmd, "sh -c if [ -f ") {
			return "absent", nil
		}
		return "", nil
	}
	return s.out[best], nil
}

func (s *swap) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) { return s.Run(ctx, args...) }

func (s *swap) at(prefix string) int {
	for i, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

const newImage = "caddy:2.12.0-alpine"

func quick(t *testing.T) {
	w, p := answerWait, answerPoll
	answerWait, answerPoll = 50*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { answerWait, answerPoll = w, p })
}

// Everything that can refuse runs before the stop; then the old proxy is set aside, the new one made
// from the new image, put on the routes' networks, started and checked, and only then is the old one
// removed.
func TestUpgradeChecksFirstThenSwaps(t *testing.T) {
	s := newSwap("caddy:2.11.7-alpine")
	var log strings.Builder
	if err := Upgrade(context.Background(), s, &log, newImage); err != nil {
		t.Fatal(err)
	}
	order := []string{"sh -c for d in /tmp/boks-*.lock", "docker pull " + newImage, "docker run --rm", "docker stop boks-proxy",
		"docker rename boks-proxy boks-proxy.old", "docker create --name boks-proxy", "docker start boks-proxy",
		"docker exec boks-proxy wget", "docker exec boks-proxy cat /proc/sys", "docker rm -v boks-proxy.old"}
	last := -1
	for _, p := range order {
		i := s.at(p)
		if i <= last {
			t.Fatalf("want %q after the step before it:\n%s", p, strings.Join(s.calls, "\n"))
		}
		last = i
	}
	if !strings.Contains(s.calls[s.at("docker run --rm")], newImage+" caddy validate --config /etc/boks/caddy.json") ||
		!strings.Contains(s.calls[s.at("docker create")], " "+newImage+" caddy run") {
		t.Errorf("want the new image asked and created:\n%s", strings.Join(s.calls, "\n"))
	}
}

// Each refusal before the stop leaves the proxy untouched.
func TestUpgradeRefusesBeforeTheStop(t *testing.T) {
	cases := map[string]func(*swap){
		"already runs": func(s *swap) { s.out["sh -c docker inspect -f"] = newImage },
		"a deploy is in progress": func(s *swap) {
			s.out["sh -c for d in /tmp/boks-*.lock"] = "/tmp/boks-demo.lock"
		},
		"refuses the proxy's config": func(s *swap) { s.fail["docker run --rm"] = errors.New("loading config: unknown module") },
		"was not touched":            func(s *swap) { s.fail["docker pull"] = errors.New("manifest unknown") },
		"left from an upgrade":       func(s *swap) { s.out["sh -c docker ps -aq --filter name=^boks-proxy.old$"] = "abc" },
		"no proxy":                   func(s *swap) { s.out["docker ps -a --filter name=^boks-proxy$"] = "" },
		"not the Caddy":              func(s *swap) { s.out["docker ps -a --filter name=^boks-proxy$"] = "running\t" },
	}
	for want, setup := range cases {
		s := newSwap("caddy:2.11.7-alpine")
		setup(s)
		var log strings.Builder
		err := Upgrade(context.Background(), s, &log, newImage)
		if want == "already runs" {
			if err != nil || !strings.Contains(log.String(), want) {
				t.Errorf("%s: %v %s", want, err, log.String())
			}
		} else if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want the refusal, got %v", want, err)
		}
		if s.at("docker stop") >= 0 {
			t.Errorf("%s: the proxy was stopped:\n%s", want, strings.Join(s.calls, "\n"))
		}
	}
}

// A new proxy that does not answer is removed, and the old one put back and started.
func TestUpgradePutsTheOldProxyBack(t *testing.T) {
	quick(t)
	s := newSwap("caddy:2.11.7-alpine")
	s.fail["docker exec boks-proxy wget"] = errors.New("connection refused")
	var log strings.Builder
	err := Upgrade(context.Background(), s, &log, newImage)
	if err == nil || !strings.Contains(err.Error(), "caddy:2.11.7-alpine serves again") {
		t.Fatalf("want the failure and the old proxy back, got %v", err)
	}
	rm, mv, start := s.at("docker rm -f boks-proxy"), s.at("docker rename boks-proxy.old boks-proxy"), -1
	for i := len(s.calls) - 1; i >= 0; i-- {
		if s.calls[i] == "docker start boks-proxy" {
			start = i
			break
		}
	}
	if rm < 0 || mv < rm || start < mv || s.at("docker rm -v boks-proxy.old") >= 0 {
		t.Errorf("want the new one removed, the old renamed back and started, and kept:\n%s", strings.Join(s.calls, "\n"))
	}
}

// A boot leaves a running proxy alone whatever the config names, but says so.
func TestBootNamesAnotherImage(t *testing.T) {
	s := newSwap("caddy:2.11.7-alpine")
	var log strings.Builder
	if err := Boot(context.Background(), s, &log, newImage); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "and the config names "+newImage+"; `boks proxy upgrade` replaces it") {
		t.Errorf("want the other image named: %s", log.String())
	}
	if s.at("docker stop") >= 0 || s.at("docker create") >= 0 {
		t.Errorf("a boot replaced the running proxy:\n%s", strings.Join(s.calls, "\n"))
	}
}
