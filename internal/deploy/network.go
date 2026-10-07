package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/proxy"
	"github.com/kopandante/boks/internal/remote"
)

// inventoryTries is how many times the container listing is asked before a failure stands.
const inventoryTries = 3

// box is a container on the server, with the names it answers to on each network it is attached to.
type box struct {
	name string
	// owner is the app that labelled it, or the container itself when no app did: two containers boks
	// did not start are not one owner.
	owner string
	// base are the names docker gives it on every network: its own, its hostname, its short id.
	base []string
	// nets are the networks it is attached to, with the aliases (and, on a Docker that reports them,
	// the DNS names) it has on each.
	nets map[string][]string
	// running and health are its state: health is healthy, unhealthy or starting, and empty for an
	// image without a HEALTHCHECK.
	running bool
	health  string
	// ports are the ports docker publishes on the host for it, by container port (`6379/tcp`).
	ports map[string][]binding
}

func (b box) on(network string) bool {
	_, ok := b.nets[network]
	return ok
}

// answers reports whether b, on network, answers to name. Docker's DNS ignores case, so a name
// matches whatever its case.
func (b box) answers(network, name string) bool {
	return b.on(network) && (hasName(b.base, name) || hasName(b.nets[network], name))
}

func hasName(names []string, name string) bool {
	return slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) })
}

// boxFormat prints one JSON object per container, so names and labels that hold tabs, spaces or
// quotes still parse.
//
// The health is read with index, not as .State.Health: `.Id` is no field of docker's Go type (that
// is ID), so the CLI runs the template over the raw JSON instead, where a container without a
// HEALTHCHECK has no Health key at all — and a field lookup of a missing key fails the whole
// inspect (docker 29.8, boks-lab, 2026-10-04: every deploy refused on a server holding one such
// container). index answers a missing key with nothing.
const boxFormat = `{"id":{{json .Id}},"name":{{json .Name}},"hostname":{{json .Config.Hostname}},` +
	`"labels":{{json .Config.Labels}},"networks":{{json .NetworkSettings.Networks}},` +
	`"ports":{{json (index .HostConfig "PortBindings")}},"running":{{json .State.Running}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}""{{end}}}`

// inventory lists every container on the server, stopped ones too: a stopped copy comes back with
// its aliases. All of them rather than those docker's network filter returns, which is documented
// for running containers; a small server has few. A container removed between the listing and the
// inspect — another app retiring its old copy, which no lock of this deploy keeps out — fails the
// call; it is asked again, and a listing that keeps failing is a refusal to guess, not an answer that
// there is no conflict.
func inventory(ctx context.Context, r remote.Runner) ([]box, error) {
	script := "ids=$(docker ps -aq --no-trunc) || exit 1; " +
		`[ -z "$ids" ] || exec docker inspect --format ` + remote.Quote(boxFormat) + " $ids"
	var out string
	var err error
	for try := 0; try < inventoryTries; try++ {
		if out, err = r.Run(ctx, "sh", "-c", script); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("listing the containers on the server: %w", err)
	}
	var bs []box
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var c struct {
			ID, Name, Hostname, Health string
			Running                    bool
			Labels                     map[string]string
			Networks                   map[string]struct{ Aliases, DNSNames []string }
			Ports                      map[string][]binding
		}
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return nil, fmt.Errorf("reading the containers on the server: %w", err)
		}
		b := box{name: strings.TrimPrefix(c.Name, "/"), owner: c.Labels["boks.app"], nets: map[string][]string{},
			running: c.Running, health: c.Health, ports: c.Ports}
		if b.owner == "" {
			b.owner = unlabelled(b.name)
		}
		b.base = []string{b.name, c.Hostname, c.ID[:min(12, len(c.ID))]}
		for n, e := range c.Networks {
			b.nets[n] = append(slices.Clone(e.Aliases), e.DNSNames...)
		}
		bs = append(bs, b)
	}
	return bs, nil
}

// checkNetworks refuses, changing nothing, a container that could not be told apart on its network.
// Docker gives one name to as many containers as ask for it and answers it with all of them, so
// whoever reaches the app by name would land on either at random: a name the new container brings
// (its own, its alias) must not be one that a container of another owner answers to there. The
// app's own copies are not in the way — overlap runs two under one alias on purpose. A routed app is
// joined there by the proxy too, with the names it already has. The network itself must be this
// app's, or one boks has yet to make: another's network under its name would put the app among
// containers it was never meant to see. An empty name is not checked: a fleet rollback asks before
// the container's name is known.
//
// It is asked before anything changes and again once the server's admission is held, because what
// runs on the server can change while a deploy pulls or waits; it says whether the network has to
// be made.
func checkNetworks(ctx context.Context, r remote.Runner, cfg *config.Config, name string) (bool, error) {
	n := cfg.Networks()[0]
	owner, exists, err := networkOwner(ctx, r, n.Name)
	if err != nil {
		return false, err
	}
	if exists && owner != cfg.App {
		// It may be the network apps shared before this boks (an old `network:` value such as
		// boks-test), with the proxy and other apps on it: removing it would cut them off.
		return false, fmt.Errorf("network %s exists but was not made by boks for %s (its boks.app label is %q), and it may "+
			"be one other containers use, such as the network apps shared before: rename the app, or remove the network "+
			"only once `docker network inspect %s` shows nothing on it; nothing was changed", n.Name, cfg.App, owner, n.Name)
	}
	boxes, err := inventory(ctx, r)
	if err != nil {
		return false, err
	}
	mine := append([]string{name}, n.Aliases...)
	if err := taken(boxes, n.Name, cfg.App, mine); err != nil {
		return false, err
	}
	// The ports published on the host are asked with the names, for the same reason: what runs on the
	// server can change while a deploy pulls or waits.
	if err := checkListen(ctx, r, cfg, boxes); err != nil {
		return false, err
	}
	for i, dep := range cfg.Uses {
		if err := checkUse(ctx, r, cfg, name, dep, cfg.Networks()[i+1], boxes); err != nil {
			return false, err
		}
	}
	if len(cfg.Ports) == 0 {
		return !exists, nil
	}
	// The proxy's names: those it has, or only its own name when it is yet to be started.
	theirs, proxyOwner := []string{proxy.Container}, unlabelled(proxy.Container)
	if i := slices.IndexFunc(boxes, func(b box) bool { return b.name == proxy.Container }); i >= 0 {
		if boxes[i].on(n.Name) {
			return !exists, nil // already there, and checked above as one of the boxes
		}
		theirs, proxyOwner = boxes[i].base, boxes[i].owner
	}
	if err := taken(boxes, n.Name, proxyOwner, theirs); err != nil {
		return false, err
	}
	for _, nm := range mine {
		if nm != "" && hasName(theirs, nm) {
			return false, nameTaken(nm, n.Name, proxy.Container, proxyOwner, cfg.App)
		}
	}
	return !exists, nil
}

// checkUse refuses, changing nothing, to put the container among an app it uses unless that app is
// there to be reached: deployed by a boks that gives it its own network, every running copy that
// answers to its name healthy, and no container of another owner answering to that name as well. A
// consumer reaches it by alias, past the proxy, so the image's own HEALTHCHECK is the only evidence
// that it answers, and an image without one is refused rather than taken on trust. The container's
// own name must be free on that network too. Its network is never made here: an app that does not
// have one is not deployed.
func checkUse(ctx context.Context, r remote.Runner, cfg *config.Config, name, dep string, n config.Network, boxes []box) error {
	refuse := func(why string, a ...any) error {
		return fmt.Errorf("uses: %s: "+why+"; nothing was changed", append([]any{dep}, a...)...)
	}
	owner, exists, err := networkOwner(ctx, r, n.Name)
	switch {
	case err != nil:
		return err
	case !exists:
		return refuse("network %s does not exist, so %s is not deployed on this server by this boks: deploy it first", n.Name, dep)
	case owner != dep:
		return refuse("network %s was not made by boks for %s (its boks.app label is %q)", n.Name, dep, owner)
	}
	serving := 0
	for _, b := range boxes {
		if !b.answers(n.Name, dep) {
			continue
		}
		if b.owner != dep {
			return nameTaken(dep, n.Name, b.name, b.owner, dep)
		}
		if !b.running {
			continue
		}
		switch b.health {
		case "healthy":
			serving++
		case "":
			return refuse("%s has no HEALTHCHECK: %s reaches it by name, past the proxy, so only the container's own health check "+
				"says it answers — add a healthcheck block to its boks.yml (or a HEALTHCHECK to its image) and deploy it again", b.name, cfg.App)
		default:
			return refuse("its copy %s is %s, and %s reaching %s by name could land on it", b.name, b.health, cfg.App, dep)
		}
	}
	if serving == 0 {
		return refuse("no running copy answers to %s on %s", dep, n.Name)
	}
	return taken(boxes, n.Name, cfg.App, []string{name})
}

// taken refuses names that a container of another owner already answers to on network.
func taken(boxes []box, network, owner string, names []string) error {
	for _, nm := range names {
		for _, b := range boxes {
			if nm != "" && b.owner != owner && b.answers(network, nm) {
				return nameTaken(nm, network, b.name, b.owner, owner)
			}
		}
	}
	return nil
}

// unlabelled is the owner of a container no app labelled: the container itself, since two of them
// are not one owner.
func unlabelled(name string) string { return "container " + name }

func nameTaken(name, network, holder, owner, joining string) error {
	return fmt.Errorf("%s answers to %s on network %s and belongs to %s, not to %s: "+
		"two owners of one name would split its traffic between them, so nothing was changed",
		holder, name, network, owner, joining)
}

// networkOwner reads the `boks.app` label of a network and whether it exists. Only docker's own
// answer that the network is not there counts as absence; any other failure is an error, or a
// dropped connection would read as a network to create.
func networkOwner(ctx context.Context, r remote.Runner, network string) (string, bool, error) {
	q := remote.Quote(network)
	out, err := r.Run(ctx, "sh", "-c", "out=$(docker network inspect --format '{{json .Labels}}' "+q+" 2>&1) && echo \"$out\" || "+
		"case \"$out\" in *'No such network'*|*'network '*' not found'*) echo absent;; *) echo \"$out\" >&2; exit 1;; esac")
	if err != nil {
		return "", false, fmt.Errorf("checking network %s: %w", network, err)
	}
	out = strings.TrimSpace(out)
	if out == "absent" {
		return "", false, nil
	}
	var labels map[string]string
	if err := json.Unmarshal([]byte(out), &labels); err != nil {
		return "", false, fmt.Errorf("checking network %s: %w", network, err)
	}
	return labels["boks.app"], true, nil
}

// makeNetwork creates the app's network, labelled as the app's, so that a later check — and the
// `boks rm` to come — can tell it from one that only shares its name.
func makeNetwork(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	n := cfg.Networks()[0].Name
	fmt.Fprintf(log, "creating network %s\n", n)
	_, err := r.Run(ctx, "docker", "network", "create", "--label", "boks.app="+cfg.App, n)
	return err
}

// joinProxy puts the proxy on the app's network once the new copy runs: the proxy probes it and then
// dials it by name, and only through a network the two share. Not earlier, so a deploy that fails
// before starting anything does not leave the proxy on a network it routes nothing to. A proxy still
// on the network every app shared before keeps reaching the old copies there, so the routes answer
// until they move, and routes put back go back to a copy they can reach.
func joinProxy(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config) error {
	n := cfg.Networks()[0].Name
	on, err := proxy.On(ctx, r, n)
	if err != nil || on {
		return err
	}
	return proxy.Connect(ctx, r, log, n)
}

// leaveProxy takes the proxy off the network of an app that has no routes any more, once they are
// known to be gone: the proxy joins only the networks of the apps it routes to. Under the admission
// lock, like every change to the proxy's networks, so a proxy boot reading the routes a moment
// before they went cannot put it back. A failure costs isolation, not the deploy, and is reported;
// the next deploy without routes tries again.
func leaveProxy(ctx context.Context, r remote.Runner, log io.Writer, cfg *config.Config, o Options) {
	n := cfg.Networks()[0].Name
	adm, err := admit(ctx, r, log, cfg.App, o)
	if err == nil {
		defer adm.release(ctx)
		var on bool
		if on, err = proxy.On(ctx, r, n); err == nil && on {
			err = proxy.Disconnect(ctx, r, log, n)
		}
	}
	if err != nil {
		fmt.Fprintf(log, "warning: the proxy may still be on network %s: %v\n", n, err)
	}
}
