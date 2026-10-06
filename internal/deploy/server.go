package deploy

// The server's own policy (server.yml): applied, rolled back and reported per server, under the
// admission lock every run that reloads the proxy takes.

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/release"
	"github.com/kopandante/boks/internal/remote"
)

// serverJournal is the journal the server's runs keep, as an app keeps its own: release.Dir of it is
// proxy.ServerDir, out of every app's namespace.
const serverJournal = "_server"

// CheckRevision says whether a server running cur takes a policy of revision next — and refuses
// before anything changes: the next edit is the one after the highest revision the server ever applied,
// and the revision it runs, with the same policy, is a run to repeat. A server that never applied a
// policy takes any revision, as a server joining the fleet must.
func CheckRevision(cur, next proxy.Policy) error {
	switch {
	case next.Revision == cur.Revision && proxy.SamePolicy(cur, next):
		return nil
	case cur.Floor == 0 || next.Revision == cur.Floor+1:
		return nil
	case next.Revision <= cur.Floor:
		return fmt.Errorf("server.yml is revision %d, but this server has applied up to %d and runs %d: "+
			"an older file, or another edit made from the same revision; nothing was changed", next.Revision, cur.Floor, cur.Revision)
	}
	return fmt.Errorf("server.yml is revision %d, but this server takes %d next: a revision grows by one; nothing was changed",
		next.Revision, cur.Floor+1)
}

// ApplyServer makes next the server's policy, when CheckRevision lets it.
func ApplyServer(ctx context.Context, r remote.Runner, log io.Writer, next proxy.Policy, o Options) error {
	return withServer(ctx, r, log, o, "server apply", func(cur proxy.Policy) (proxy.Policy, error) {
		if err := CheckRevision(cur, next); err != nil {
			return next, err
		}
		next.Floor = max(cur.Floor, next.Revision)
		return next, nil
	})
}

// CheckApply asks a server, before anything changes on any server of the file, whether it takes next.
func CheckApply(ctx context.Context, r remote.Runner, next proxy.Policy) error {
	if _, err := policyProxy(ctx, r); err != nil {
		return err
	}
	cur, err := proxy.ReadPolicy(ctx, r)
	if err != nil {
		return err
	}
	return CheckRevision(cur, next)
}

// RollbackServer puts back the policy of an earlier revision from the server's history. The floor
// stays: a file of a revision the rollback undid is still refused, and the next edit is the one
// after the highest ever applied.
func RollbackServer(ctx context.Context, r remote.Runner, log io.Writer, rev int, o Options) error {
	return withServer(ctx, r, log, o, "server rollback", func(cur proxy.Policy) (proxy.Policy, error) {
		p, err := policyOfRevision(ctx, r, rev)
		if err != nil {
			return p, err
		}
		p.Revision, p.Floor = rev, cur.Floor
		return p, nil
	})
}

// CheckServerRollback asks a server, before anything changes on any server of the file, whether it has rev
// to go back to: a server that joined the fleet later never applied it.
func CheckServerRollback(ctx context.Context, r remote.Runner, rev int) error {
	if _, err := policyProxy(ctx, r); err != nil {
		return err
	}
	_, err := policyOfRevision(ctx, r, rev)
	return err
}

func policyOfRevision(ctx context.Context, r remote.Runner, rev int) (proxy.Policy, error) {
	p, ok, err := proxy.History(ctx, r, rev)
	if err == nil && !ok {
		err = fmt.Errorf("this server never applied revision %d; nothing was changed", rev)
	}
	return p, err
}

// policyProxy says whether the server's proxy runs. A policy is refused where kamal-proxy still serves:
// it would be written for a Caddy that is not there and reported applied while no request is filtered.
// Where no proxy runs yet, the policy is what Caddy loads when it starts.
func policyProxy(ctx context.Context, r remote.Runner) (running bool, err error) {
	state, kind, err := proxy.State(ctx, r)
	if err != nil {
		return false, err
	}
	if state != "" && kind != proxy.Kind {
		return false, fmt.Errorf("%w; nothing was changed", proxy.NotCaddy())
	}
	return state == "running", nil
}

// withServer runs one change of the server's policy: under the admission lock, between a journal
// entry's start and its close, with the previous entry reported if a run left it open.
func withServer(ctx context.Context, r remote.Runner, log io.Writer, o Options, action string, decide func(proxy.Policy) (proxy.Policy, error)) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	adm, err := admit(ctx, r, log, proxyHolder, o)
	if err != nil {
		return err
	}
	defer adm.release(ctx)
	running, err := policyProxy(ctx, r)
	if err != nil {
		return err
	}
	cur, err := proxy.ReadPolicy(ctx, r)
	if err != nil {
		return err
	}
	next, err := decide(cur)
	if err != nil {
		return err
	}
	op, err := beginServer(ctx, r, log, o, action, strconv.Itoa(cur.Revision), strconv.Itoa(next.Revision))
	if err != nil {
		return err
	}
	if err := proxy.SetPolicy(ctx, r, log, next); err != nil {
		finish(ctx, r, log, serverJournal, op, "failed", o.Now())
		return err
	}
	finish(ctx, r, log, serverJournal, op, "ok", o.Now())
	fmt.Fprintf(log, "server policy: revision %d (%d blocks, %d allows)\n", next.Revision, len(next.Block), len(next.Allow))
	if !running {
		fmt.Fprintf(log, "  %s is not running on this server: nothing is filtered until it starts and loads this policy\n", proxy.Container)
	}
	return nil
}

// beginServer opens an entry in the server's journal, and closes as abandoned the one a cut run left
// open: `boks server status` names the newest open entry, and one left open would be named forever.
func beginServer(ctx context.Context, r remote.Runner, log io.Writer, o Options, action, from, to string) (string, error) {
	if open, err := release.Unfinished(ctx, r, serverJournal); err == nil && open != nil {
		fmt.Fprintf(log, "warning: %s started %s and never finished; this run replaces it\n", open.Action, open.StartedAt.Format(time.RFC3339))
		finish(ctx, r, log, serverJournal, open.Op, "abandoned", o.Now())
	}
	return release.Begin(ctx, r, serverJournal, action, from, to, o.Now())
}

// ServerStatus is what a server applies, and the run that changed it and never finished, if any.
func ServerStatus(ctx context.Context, r remote.Runner) (proxy.Policy, *release.Entry, error) {
	p, err := proxy.ReadPolicy(ctx, r)
	if err != nil {
		return p, nil, err
	}
	open, err := release.Unfinished(ctx, r, serverJournal)
	return p, open, err
}
