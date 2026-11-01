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
