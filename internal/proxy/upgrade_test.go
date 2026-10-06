package proxy

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// box is a container on the swap server.
type box struct{ state, image, kind string }

// swap is a server for an upgrade that keeps its containers, so that each step acts on what the ones
// before it left: docker's name filter is a regular expression, as docker reads it. fail refuses a
// command by prefix and does nothing; lost does it and then fails, as a reply lost over SSH would.
// only refuses by prefix while the container under the proxy's name is made from newImage. slow
// makes the proxy's stop fail in its reply while docker is still at it: the container goes on
// running, a start meanwhile does nothing, and the stop lands after it — or with the next stop. Every
// other command answers by its longest prefix in out.
type swap struct {
	boxes    map[string]box
	out      map[string]string
	fail     map[string]error
	only     map[string]error
	lost     map[string]bool
	slow     bool
	stopping bool
	calls    []string
}

const (
	oldImage = "caddy:2.11.7-alpine"
	newImage = "caddy:2.12.0-alpine"
)

// newSwap is a server whose Caddy runs current and routes one app, web, whose copy is on boks-web.
func newSwap(current string) *swap {
	return &swap{
		boxes: map[string]box{Container: {"running", current, Kind}},
		fail:  map[string]error{}, only: map[string]error{}, lost: map[string]bool{},
		out: map[string]string{
			"sh -c cd '.boks/_proxy' && pwd -P":    "/home/u/.boks/_proxy",
			"sh -c for f in '.boks/_proxy/routes'": `{"app":"web","routes":[{"host":"web.example.com","dial":"web-v1:80"}]}`,
			"sh -c out=$(docker container inspect": "web|boks-web ",
			"sh -c if [ -f ":                       "absent",
		},
	}
}

var filterArg = regexp.MustCompile(`^docker ps -a --filter name=(\S+) --format (.*)$`)

func (s *swap) Run(_ context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	s.calls = append(s.calls, cmd)
	for p, err := range s.fail {
		if strings.HasPrefix(cmd, p) {
			return "", err
		}
	}
	for p, err := range s.only {
		if strings.HasPrefix(cmd, p) && s.boxes[Container].image == newImage {
			return "", err
		}
	}
	if s.slow && cmd == "docker stop "+Container && !s.stopping {
		s.stopping = true
		return "", errors.New("connection lost")
	}
	if s.stopping && cmd == "docker start "+Container {
		s.stopping = false
		b := s.boxes[Container]
		b.state = "exited"
		s.boxes[Container] = b
		return "", nil
	}
	s.stopping = s.stopping && cmd != "docker stop "+Container
	out, err := s.act(cmd, args)
	for p := range s.lost {
		if strings.HasPrefix(cmd, p) {
			return "", errors.New("connection lost")
		}
	}
	return out, err
}

func (s *swap) act(cmd string, args []string) (string, error) {
	p := s.boxes[Container]
	switch {
	case filterArg.MatchString(cmd):
		m := filterArg.FindStringSubmatch(cmd)
		re := regexp.MustCompile(m[1])
		for _, n := range slices.Sorted(maps.Keys(s.boxes)) {
			if re.MatchString(n) {
				if m[2] == "{{.Names}}" {
					return n, nil
				}
				return s.boxes[n].state + "\t" + s.boxes[n].kind, nil
			}
		}
		return "", nil
	case strings.HasPrefix(cmd, "sh -c docker inspect -f"):
		return s.boxes[Container].image, nil
	case strings.HasPrefix(cmd, "docker stop "):
		if b, ok := s.boxes[args[2]]; ok {
			b.state = "exited"
			s.boxes[args[2]] = b
		}
	case strings.HasPrefix(cmd, "docker rename "):
		b, ok := s.boxes[args[2]]
		if _, taken := s.boxes[args[3]]; !ok || taken {
			return "", errors.New("rename refused")
		}
		delete(s.boxes, args[2])
		s.boxes[args[3]] = b
	case strings.HasPrefix(cmd, "docker create --name "+Container):
		if _, taken := s.boxes[Container]; taken {
			return "", errors.New("name in use")
		}
		s.boxes[Container] = box{"created", args[len(args)-5], Kind}
	case strings.HasPrefix(cmd, "docker start "):
		b, ok := s.boxes[args[2]]
		if !ok {
			return "", errors.New("no such container")
		}
		b.state = "running"
		s.boxes[args[2]] = b
	case strings.HasPrefix(cmd, "docker rm "):
		delete(s.boxes, args[len(args)-1])
	case strings.HasPrefix(cmd, "docker container ls -a --filter name=^"+Container+"$"):
		return "boks", nil
	case strings.HasPrefix(cmd, "docker exec "+Container+" "):
		if p.state != "running" {
			return "", errors.New("not running")
		}
		if strings.Contains(cmd, "/proc/sys/") {
			return "1", nil
		}
	}
	best := ""
	for k := range s.out {
		if strings.HasPrefix(cmd, k) && len(k) > len(best) {
			best = k
		}
	}
	return s.out[best], nil
}

func (s *swap) Pipe(ctx context.Context, _ []byte, args ...string) (string, error) {
	return s.Run(ctx, args...)
}

func (s *swap) at(prefix string) int {
	for i, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// upgrade runs Upgrade to newImage; begin is recorded among the calls as BEGIN <from>.
func (s *swap) upgrade(t *testing.T) (string, error) {
	t.Helper()
	var log strings.Builder
	err := Upgrade(context.Background(), s, &log, newImage, func(from string) error {
		s.calls = append(s.calls, "BEGIN "+from)
		if err, ok := s.fail["BEGIN"]; ok {
			return err
		}
		return nil
	})
	return log.String(), err
}

func quick(t *testing.T) {
	w, p := answerWait, answerPoll
	answerWait, answerPoll = 50*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { answerWait, answerPoll = w, p })
}

// Everything that can refuse runs before begin, and begin before the stop; then the old proxy is set
// aside, the new one made from the new image, put on the routes' networks before it starts, checked,
// and only then is the old one removed.
func TestUpgradeChecksFirstThenSwaps(t *testing.T) {
	s := newSwap(oldImage)
	if _, err := s.upgrade(t); err != nil {
		t.Fatal(err)
	}
	order := []string{"sh -c for d in /tmp/boks-*.lock", "docker pull " + newImage, "docker run --rm", "BEGIN " + oldImage,
		"docker stop boks-proxy", "docker rename boks-proxy boks-proxy.old", "docker create --name boks-proxy",
		"docker network connect boks-web boks-proxy", "docker start boks-proxy", "docker exec boks-proxy wget",
		"docker exec boks-proxy cat /proc/sys", "docker rm -v boks-proxy.old"}
	last := -1
	for _, p := range order {
		i := s.at(p)
		if i <= last {
			t.Fatalf("want %q after the step before it:\n%s", p, strings.Join(s.calls, "\n"))
		}
		last = i
	}
	if !strings.Contains(s.calls[s.at("docker run --rm")], newImage+" caddy validate --config /etc/boks/caddy.json") {
		t.Errorf("want the config asked of the new image:\n%s", strings.Join(s.calls, "\n"))
	}
	if want := map[string]box{Container: {"running", newImage, Kind}}; !maps.Equal(s.boxes, want) {
		t.Errorf("want the new proxy alone, running: %v", s.boxes)
	}
}

// Each refusal before the stop leaves the proxy untouched and opens nothing in the journal.
func TestUpgradeRefusesBeforeTheStop(t *testing.T) {
	cases := map[string]func(*swap){
		"a deploy is in progress": func(s *swap) {
			s.out["sh -c for d in /tmp/boks-*.lock"] = "/tmp/boks-demo.lock"
		},
		"refuses the proxy's config": func(s *swap) { s.fail["docker run --rm"] = errors.New("loading config: unknown module") },
		"was not touched":            func(s *swap) { s.fail["docker pull"] = errors.New("manifest unknown") },
		"left from an upgrade":       func(s *swap) { s.boxes[asideName] = box{"exited", oldImage, Kind} },
		"no proxy":                   func(s *swap) { delete(s.boxes, Container) },
		"not the Caddy":              func(s *swap) { s.boxes[Container] = box{"running", "basecamp/kamal-proxy", ""} },
		"but is exited":              func(s *swap) { s.boxes[Container] = box{"exited", newImage, Kind} },
	}
	for want, setup := range cases {
		s := newSwap(oldImage)
		setup(s)
		before := maps.Clone(s.boxes)
		if _, err := s.upgrade(t); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want the refusal, got %v", want, err)
		}
		if s.at("docker stop") >= 0 || s.at("BEGIN") >= 0 || !maps.Equal(s.boxes, before) {
			t.Errorf("%s: the proxy was touched or the journal opened:\n%s", want, strings.Join(s.calls, "\n"))
		}
	}
	// A running proxy of the image asked for: nothing to do, and nothing journaled.
	s := newSwap(newImage)
	if log, err := s.upgrade(t); err != nil || !strings.Contains(log, "already runs") || s.at("BEGIN") >= 0 || s.at("docker pull") >= 0 {
		t.Errorf("already runs: %v %s\n%s", err, log, strings.Join(s.calls, "\n"))
	}
	// A journal that cannot be opened stops the upgrade before the stop.
	s = newSwap(oldImage)
	s.fail["BEGIN"] = errors.New("disk full")
	if _, err := s.upgrade(t); err == nil || !strings.Contains(err.Error(), "not touched") || s.at("docker stop") >= 0 {
		t.Errorf("begin failed: want a refusal before the stop, got %v\n%s", err, strings.Join(s.calls, "\n"))
	}
}

// A swap cut after the new proxy was made, before it started, leaves a proxy of the asked-for image
// under the proxy's name and the old one aside: that is the cut swap named, not "already runs".
func TestUpgradeNamesACutSwapOfTheSameImage(t *testing.T) {
	s := newSwap(newImage)
	s.boxes[Container] = box{"created", newImage, Kind}
	s.boxes[asideName] = box{"exited", oldImage, Kind}
	if _, err := s.upgrade(t); err == nil || !strings.Contains(err.Error(), "left from an upgrade") {
		t.Fatalf("want the cut swap named, got %v", err)
	}
}

// boks-proxy.old is a name, not a pattern: a container whose name differs in the dot does not block.
func TestUpgradeIgnoresALookalikeOfTheSetAsideName(t *testing.T) {
	s := newSwap(oldImage)
	s.boxes["boks-proxy-old"] = box{"running", "nginx", ""}
	if _, err := s.upgrade(t); err != nil {
		t.Fatalf("an unrelated boks-proxy-old blocked the upgrade: %v", err)
	}
	if _, ok := s.boxes["boks-proxy-old"]; !ok {
		t.Error("the unrelated container was removed")
	}
}

// Whatever step of the swap fails — or fails only in its reply, docker having acted — the old proxy
// ends up running under its name, the new one gone, and the error says the old one serves.
func TestUpgradePutsTheOldProxyBack(t *testing.T) {
	quick(t)
	cases := map[string]func(*swap){
		"the new one does not answer": func(s *swap) { s.only["docker exec boks-proxy wget"] = errors.New("connection refused") },
		"the new one does not start":  func(s *swap) { s.only["docker start boks-proxy"] = errors.New("port is allocated") },
		"create fails":                func(s *swap) { s.fail["docker create"] = errors.New("no space left") },
		"a network does not connect":  func(s *swap) { s.fail["docker network connect"] = errors.New("network not found") },
		"the stop fails":              func(s *swap) { s.fail["docker stop"] = errors.New("timeout") },
		"the stop's reply is lost":    func(s *swap) { s.lost["docker stop"] = true },
		"the stop is still under way": func(s *swap) { s.slow = true },
		"the rename fails":            func(s *swap) { s.fail["docker rename boks-proxy boks-proxy.old"] = errors.New("refused") },
		"the rename's reply is lost":  func(s *swap) { s.lost["docker rename boks-proxy boks-proxy.old"] = true },
	}
	for name, setup := range cases {
		s := newSwap(oldImage)
		setup(s)
		_, err := s.upgrade(t)
		if err == nil || !strings.Contains(err.Error(), oldImage+" serves again") {
			t.Errorf("%s: want the failure and the old proxy back, got %v", name, err)
		}
		if want := map[string]box{Container: {"running", oldImage, Kind}}; !maps.Equal(s.boxes, want) {
			t.Errorf("%s: want the old proxy alone, running: %v\n%s", name, s.boxes, strings.Join(s.calls, "\n"))
		}
	}
}

// When the old proxy cannot be put back either — or is put back and does not answer — the error says
// so, and does not claim it serves.
func TestUpgradeSaysWhenThePutBackFails(t *testing.T) {
	quick(t)
	cases := map[string]func(*swap){
		"the rename back fails": func(s *swap) {
			s.only["docker exec boks-proxy wget"] = errors.New("connection refused")
			s.fail["docker rename boks-proxy.old boks-proxy"] = errors.New("refused")
		},
		"the old one does not answer": func(s *swap) { s.fail["docker exec boks-proxy wget"] = errors.New("connection refused") },
	}
	for name, setup := range cases {
		s := newSwap(oldImage)
		setup(s)
		_, err := s.upgrade(t)
		if err == nil || !strings.Contains(err.Error(), "putting the old proxy back failed too") || strings.Contains(err.Error(), "serves again") ||
			!strings.Contains(err.Error(), "the new proxy failed") {
			t.Errorf("%s: want the failed put-back named, got %v", name, err)
		}
	}
}

// A boot leaves a running proxy alone whatever the config names, but says so.
func TestBootNamesAnotherImage(t *testing.T) {
	s := newSwap(oldImage)
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
	s = newSwap(newImage)
	log.Reset()
	if err := Boot(context.Background(), s, &log, newImage); err != nil || strings.Contains(log.String(), "warning") {
		t.Errorf("the image the config names: want no warning, got %v %s", err, log.String())
	}
}
