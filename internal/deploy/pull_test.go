package deploy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// Every test of the package pauses a millisecond between pulls, not two minutes: a pull a test fails on
// the way to the registry is tried again, as on a server. TestPullPauseEndsWithTheRun sets its own.
func init() { pullPause = time.Millisecond }

// pullsUntil is a server whose `docker pull` fails with err for the first n pulls and then answers.
func pullsUntil(n int, err error) (*fake, *int) {
	f := newFake()
	pulls := 0
	f.onRun = func(cmd string) {
		if strings.HasPrefix(cmd, "docker pull ") {
			pulls++
			if pulls <= n {
				f.fail["docker pull "] = err
			} else {
				delete(f.fail, "docker pull ")
			}
		}
	}
	return f, &pulls
}

var handshake = errors.New(`docker pull: exit status 1: Error response from daemon: Get "https://registry.depot.dev/v2/": net/http: TLS handshake timeout`)

// A pull the registry's network failed is made again after the pause, pullTries in all; a deploy goes
// on once one comes through (todo#437, boks#150).
func TestPullTriesAgainWhenTheRegistryDoesNotAnswer(t *testing.T) {
	f, pulls := pullsUntil(2, handshake)
	var log strings.Builder
	if err := pull(context.Background(), f, &log, "ghcr.io/x/y:v2", true, nil); err != nil {
		t.Fatal(err)
	}
	if *pulls != 3 || strings.Count(log.String(), "trying again") != 2 || !strings.Contains(log.String(), "(3 of 3)") {
		t.Errorf("%d pulls: %s", *pulls, log.String())
	}

	// An error over several lines, as the login's is, still makes one line of the log with its retry.
	f, _ = pullsUntil(1, errors.New(handshake.Error()+"\nnothing was changed on this server"))
	log.Reset()
	if err := pull(context.Background(), f, &log, "ghcr.io/x/y:v2", true, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "TLS handshake timeout; nothing was changed on this server); trying again") {
		t.Errorf("the retry is not on the line of its cause: %s", log.String())
	}

	f, pulls = pullsUntil(1, handshake)
	if err := Run(context.Background(), f, io.Discard, parse(t, onePort), "v2", fixed); err != nil {
		t.Fatalf("deploy after one pull lost: %v", err)
	}
	if *pulls != 2 {
		t.Errorf("deploy: %d pulls", *pulls)
	}
}

// Three tries lost refuse, saying so; an answer of the registry — a token refused, an image not there —
// and any other error refuse at the first pull.
func TestPullRefusesWhatTryingAgainWouldNotChange(t *testing.T) {
	f, pulls := pullsUntil(9, handshake)
	err := pull(context.Background(), f, io.Discard, "ghcr.io/x/y:v2", true, nil)
	if err == nil || *pulls != pullTries || !strings.Contains(err.Error(), "failed on the network 3 times") || !strings.Contains(err.Error(), "TLS handshake timeout") {
		t.Errorf("%d pulls: %v", *pulls, err)
	}
	for _, msg := range []string{
		"Error response from daemon: Head \"https://registry.depot.dev/v2/p/manifests/v2\": unauthorized: authentication required",
		"Error response from daemon: manifest for ghcr.io/x/y:v2 not found: manifest unknown",
		"Error response from daemon: pull access denied for y, repository does not exist",
		"write /var/lib/docker/tmp: no space left on device",
		// An answer that came over a slow link is still an answer.
		"unauthorized: authentication required after i/o timeout",
		"Error response from daemon: manifest for ghcr.io/x/y:v2 not found: manifest unknown after unexpected EOF",
	} {
		f, pulls := pullsUntil(9, errors.New(msg))
		if err := pull(context.Background(), f, io.Discard, "ghcr.io/x/y:v2", true, nil); err == nil || *pulls != 1 {
			t.Errorf("%q: %d pulls: %v", msg, *pulls, err)
		}
	}
}

// The pause ends with the deploy: a run cancelled while it waits to try again stops at once.
func TestPullPauseEndsWithTheRun(t *testing.T) {
	p := pullPause
	pullPause = time.Hour
	t.Cleanup(func() { pullPause = p })
	f, pulls := pullsUntil(9, handshake)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := pull(ctx, f, io.Discard, "ghcr.io/x/y:v2", true, nil)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || *pulls != 1 || time.Since(start) > 5*time.Second {
		t.Errorf("%d pulls in %s: %v", *pulls, time.Since(start), err)
	}
}

// The words of docker that are the network and are tried again, and those that are an answer and are
// not (boks#153).
func TestRegistryDownWords(t *testing.T) {
	for msg, want := range map[string]bool{
		`Get "https://registry.depot.dev/v2/": net/http: TLS handshake timeout`:                                          true,
		`Get "https://registry.depot.dev/v2/": dial tcp 34.1.2.3:443: connect: connection timed out`:                     true,
		`Get "https://registry.depot.dev/v2/": dial tcp 34.1.2.3:443: connect: connection refused`:                       true,
		`dial tcp 34.1.2.3:443: connect: no route to host`:                                                               true,
		`dial tcp [2600::1]:443: connect: network is unreachable`:                                                        true,
		`Get "https://registry.depot.dev/v2/": dial tcp: lookup registry.depot.dev on 127.0.0.53:53: server misbehaving`: true,
		`Get "https://registry.depot.dev/v2/p/blobs/sha256:ab": EOF`:                                                     true,
		`received unexpected HTTP status: 502 Bad Gateway`:                                                               true,
		`received unexpected HTTP status: 503 Service Unavailable`:                                                       true,
		`unknown: 504 Gateway Timeout`:                                                                                   true,
		`Get "https://registry.depot.dev/v2/": context deadline exceeded`:                                                true,
		`Get "https://registry.depot.dev/v2/": dial tcp: lookup registry.depot.dev on 127.0.0.53:53: no such host`:       false,
		`lookup regsitry.depot.dev: no such host after connection refused`:                                               false,
		`Head "https://registry.depot.dev/v2/p/manifests/v2": unauthorized: authentication required`:                     false,
		`manifest for ghcr.io/x/y:v2 not found: manifest unknown`:                                                        false,
		`pull access denied for y, repository does not exist`:                                                            false,
		// Neither a digest nor a port nor a word that holds the letters or the numbers.
		`write /var/lib/docker/tmp/sha256:5031a0eofb: no space left on device`:                    false,
		`failed to register layer: write /usr/share/nginx/html/503.html: no space left on device`: false,
		`read tcp 10.0.0.2:51234->34.1.2.3:443: read: unexpected EOF`:                             true,
		`invalid reference format: registry.depot.dev:5030/p`:                                     false,
		`exec format error: GEOF`: false,
	} {
		if got := registryDown(errors.New(msg)); got != want {
			t.Errorf("%q: %v, want %v", msg, got, want)
		}
	}
}

// A 502, 503 or 504 is the network only with the reason HTTP gives it: the number alone may be the
// user's tag or port, which the error names (boks#156).
func TestRegistryDownNotTheTag(t *testing.T) {
	for _, msg := range []string{
		"pull registry.depot.dev/p/app:503 from registry.depot.dev: sh: exit status 1: failed to register layer: no space left on device",
		"pull registry.depot.dev/p/app:1.0.502 from registry.depot.dev: sh: exit status 1: toomanyrequests: retry later",
		`docker: exit status 1: failed to resolve reference "ghcr.io/x/app:503": unexpected status from HEAD request to https://ghcr.io/v2/x/app/manifests/503: 403 Forbidden`,
		"pull reg.example:504/app:v1 from reg.example:504: sh: exit status 1: no matching manifest for linux/arm64",
	} {
		if registryDown(errors.New(msg)) {
			t.Errorf("%q: tried again for the number of the tag or port", msg)
		}
	}
	for _, msg := range []string{
		"pull registry.depot.dev/p/app:503 from registry.depot.dev: sh: exit status 1: received unexpected HTTP status: 502 Bad Gateway",
		`unexpected status from GET request to https://ghcr.io/v2/x/app/manifests/503: 503 Service Unavailable`,
		"unknown: 504 Gateway Time-out",
	} {
		if !registryDown(errors.New(msg)) {
			t.Errorf("%q: not tried again", msg)
		}
	}
}
