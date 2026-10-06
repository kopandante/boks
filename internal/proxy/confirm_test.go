package proxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// lost is a server whose reload succeeds or fails as told — and when it fails, Caddy may have taken
// the config anyway: live is what its admin API answers then.
type lost struct {
	*disk
	reloadErr error
	takes     bool   // a failed reload went through all the same
	live      string // what Caddy runs; "" makes the admin API fail
}

func (l *lost) Run(ctx context.Context, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(cmd, reloadNext):
		l.calls = append(l.calls, cmd)
		if l.takes || l.reloadErr == nil {
			l.live = l.files[Dir+"/caddy.next.json"]
		}
		return "", l.reloadErr
	case strings.HasPrefix(cmd, "docker exec boks-proxy wget -q -O - "):
		l.calls = append(l.calls, cmd)
		if l.live == "" {
			return "", errors.New("connection refused")
		}
		return strings.TrimSpace(l.live), nil
	}
	return l.disk.Run(ctx, args...)
}

func lostServer(t *testing.T) *lost {
	t.Helper()
	l := &lost{disk: newDisk()}
	if _, err := SetRoutes(context.Background(), l, io.Discard, "demo", []Route{{Host: "demo.example.com", Dial: "demo-old:3000", TLS: true}}); err != nil {
		t.Fatal(err)
	}
	return l
}

// A switch whose reload answer was lost while Caddy took the config goes on as if the answer had
// come: Caddy runs the new routes, so they are recorded as applied.
func TestAReloadWhoseAnswerWasLostIsConfirmedByCaddy(t *testing.T) {
	l := lostServer(t)
	l.reloadErr, l.takes = errors.New("connection reset"), true
	var log strings.Builder
	reloaded, err := SetRoutes(context.Background(), l, &log, "demo", web)
	if err != nil || !reloaded || !strings.Contains(log.String(), "answer was lost, but Caddy runs") {
		t.Fatalf("want the reload confirmed, got %v %v %s", reloaded, err, log.String())
	}
	want, _ := Config(Policy{}, []Fragment{{App: "demo", Routes: web}})
	if l.files[Dir+"/caddy.json"] != string(want) {
		t.Errorf("want the new config recorded as applied")
	}
}

// A failed reload that left Caddy on the config it had says so for certain.
func TestAFailedReloadThatLeftTheOldConfigSaysSo(t *testing.T) {
	l := lostServer(t)
	l.live = l.files[Dir+"/caddy.json"]
	l.reloadErr = errors.New("connection reset")
	_, err := SetRoutes(context.Background(), l, io.Discard, "demo", web)
	if err == nil || !strings.Contains(err.Error(), "Caddy still runs the config it had") {
		t.Errorf("want the old config named, got %v", err)
	}
}

// The double failure accepted for C1: the switch's answer is lost, and so is the put-back's. Caddy
// runs the put-back routes, so the put-back is confirmed and the caller's cleanup goes on.
func TestAPutBackWhoseAnswerWasLostIsConfirmedToo(t *testing.T) {
	l := lostServer(t)
	l.reloadErr, l.takes = errors.New("connection reset"), true
	old := []Route{{Host: "demo.example.com", Dial: "demo-old:3000", TLS: true}}
	if err := RestoreRoutes(context.Background(), l, io.Discard, "demo", old); err != nil {
		t.Errorf("want the put-back confirmed, got %v", err)
	}
}

// When Caddy cannot be asked, the message claims neither outcome — and a certificate reload is never
// confirmed by the config: the paths did not change, the files behind them did.
func TestUnconfirmedReloadsSayNeither(t *testing.T) {
	l := lostServer(t)
	l.reloadErr, l.live = errors.New("connection reset"), ""
	if _, err := SetRoutes(context.Background(), l, io.Discard, "demo", web); err == nil || !strings.Contains(err.Error(), "may have been lost") {
		t.Errorf("want the uncertain message without an admin API, got %v", err)
	}
	c := lostServer(t)
	c.live = c.files[Dir+"/caddy.json"]
	c.reloadErr = errors.New("connection reset")
	if err := Reload(context.Background(), c); err == nil {
		t.Error("a certificate reload must not be confirmed by an unchanged config")
	}
}
