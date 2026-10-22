package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/kopandante/boks/internal/remote"
)

// Shape is what of the proxy container the server's policy decides, and only a new container can
// change: the egress port it publishes beside 80 and 443, and the server's hosts file it resolves
// names through.
type Shape struct {
	EgressPort int
	HostsFile  string
}

// ShapeOf is the container p needs.
func ShapeOf(p Policy) Shape {
	if p.Egress == nil {
		return Shape{}
	}
	return Shape{EgressPort: p.Egress.Port, HostsFile: p.Egress.HostsFile}
}

// args are the docker create options of s. The hosts file is mounted with --mount, which refuses a
// source that is not there, where -v would make a directory of it and Caddy would resolve through
// nothing. The mount holds the file's inode: whoever keeps it writes it in place, not by replacing it.
func (s Shape) args() []string {
	var a []string
	if s.EgressPort != 0 {
		p := strconv.Itoa(s.EgressPort)
		a = append(a, "-p", p+":"+p)
	}
	if s.HostsFile != "" {
		a = append(a, "--mount", "type=bind,source="+s.HostsFile+",target=/etc/hosts,readonly")
	}
	return a
}

// shapeQuery reads the published ports and the hosts file of the proxy container.
const shapeQuery = `{{range $p, $b := .HostConfig.PortBindings}}{{$p}} {{end}}|{{range .Mounts}}{{if eq .Destination "/etc/hosts"}}{{.Source}}{{end}}{{end}}`

// currentShape is the shape of the proxy container as it was created.
func currentShape(ctx context.Context, r remote.Runner) (Shape, error) {
	out, err := r.Run(ctx, "docker", "inspect", "-f", shapeQuery, Container)
	if err != nil {
		return Shape{}, fmt.Errorf("reading the proxy's ports: %w", err)
	}
	ports, hosts, _ := strings.Cut(strings.TrimSpace(out), "|")
	var s Shape
	for _, p := range strings.Fields(ports) {
		n, _ := strconv.Atoi(strings.TrimSuffix(p, "/tcp"))
		if n != 80 && n != 443 && n != 0 {
			s.EgressPort = n
		}
	}
	s.HostsFile = hosts
	return s, nil
}

// appliedShape is the shape the policy on the server needs: what every path that creates the proxy
// creates it with — a boot, an upgrade — so none drops the egress port.
func appliedShape(ctx context.Context, r remote.Runner) (Shape, error) {
	p, err := ReadPolicy(ctx, r)
	return ShapeOf(p), err
}

// Reshape makes the running proxy the container next needs, before next is applied: a port is
// published, and a file mounted, only when the container is created. It is the swap of an upgrade with
// the image the proxy runs, and refuses as that does before anything stops — plus an image without the
// forward proxy, and a config with next that the running Caddy refuses. The new container loads the
// config the proxy runs now; the caller applies next after. A proxy that is not running is left to the
// boot that starts it, which creates it in the applied shape. The caller holds the admission lock.
func Reshape(ctx context.Context, r remote.Runner, log io.Writer, next Policy) error {
	want := ShapeOf(next)
	state, kind, err := State(ctx, r)
	if err != nil || state != "running" || kind != Kind {
		return err
	}
	have, err := currentShape(ctx, r)
	if err != nil || have == want {
		return err
	}
	if err := checkAside(ctx, r); err != nil {
		return err
	}
	image, err := Image(ctx, r)
	if err != nil {
		return err
	}
	if err := CheckEgress(ctx, r, next); err != nil {
		return err
	}
	if err := checkIdle(ctx, r); err != nil {
		return err
	}
	fs, err := Fragments(ctx, r)
	if err != nil {
		return err
	}
	if err := loadSecrets(ctx, r, &next); err != nil {
		return err
	}
	if err := validate(ctx, r, next, fs); err != nil {
		return fmt.Errorf("%w; the proxy was not touched", err)
	}
	abs, err := stateDir(ctx, r)
	if err != nil {
		return err
	}
	fmt.Fprintf(log, "proxy: creating %s again for the egress port and hosts file — 80 and 443 are down until it answers\n", Container)
	return swapProxy(ctx, r, log, image, image, abs, fs, want)
}

// CheckEgress refuses, before anything changes, an egress this server cannot run: a hosts file that is
// not there or a port another container publishes — docker would refuse the new container after the
// old one stopped — a login the server keeps no password for, and a running proxy without the forward
// proxy. `server apply` and `server rollback` ask it of every server of the file before any changes,
// as they ask the revision.
func CheckEgress(ctx context.Context, r remote.Runner, p Policy) error {
	e := p.Egress
	if e == nil {
		return nil
	}
	// The proxy publishes the egress port on every address, so an app's `listen` on any one of them
	// takes it.
	holder, err := hostPortHolder(ctx, r, e.Port)
	if err != nil {
		return err
	}
	if holder != "" {
		return fmt.Errorf("egress: port %d is published on this server by %s (an app's listen, or a container outside boks), "+
			"and the proxy publishes it on every address; choose another egress port or move that one; nothing was changed", e.Port, holder)
	}
	if e.HostsFile != "" {
		out, err := r.Run(ctx, "sh", "-c", "[ -f "+remote.Quote(e.HostsFile)+" ] && echo file; true")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "file" {
			return fmt.Errorf("egress: hosts_file %s is not a file on this server; nothing was changed", e.HostsFile)
		}
	}
	if err := loadSecret(ctx, r, &p); err != nil {
		return err
	}
	return checkModule(ctx, r, "http.handlers.forward_proxy", "no forward proxy")
}

// CheckBan refuses, before anything changes, a ban the proxy's image cannot run: Caddy would refuse
// the config, and with it the reload of every deploy on the server after the apply. The image — the
// running proxy's, or a stopped one's, which the boot after the apply starts as it is: a ban changes
// nothing of its shape — validates banProbe in a container of its own. Caddy decodes a module's
// config strictly, so an image without the handler, or with one older than the fields this boks
// writes, refuses it; asking for the module alone would take the handler of format 6, which refuses
// the rules on the next reload. The probe holds deny_ranges only when p has them: an image whose
// handler predates them still runs a policy without.
func CheckBan(ctx context.Context, r remote.Runner, p Policy) error {
	if p.Ban == nil {
		return nil
	}
	state, kind, err := State(ctx, r)
	if err != nil || state == "" || kind != Kind {
		return err
	}
	image, err := Image(ctx, r)
	if err != nil {
		return err
	}
	probe, fields := banProbe, "rules and heuristics"
	if len(p.Ban.DenyRanges) > 0 {
		probe, fields = banProbeDeny, "rules, heuristics and deny_ranges"
	}
	if _, err := r.Pipe(ctx, probe, "docker", "run", "--rm", "-i", "--network", "none", "--entrypoint", "caddy", image, "validate", "--config", "/dev/stdin"); err != nil {
		verb := "runs"
		if state != "running" {
			verb = "is a stopped container of"
		}
		return fmt.Errorf("the proxy %s %s, whose Caddy refuses a ban with %s (%w); "+
			"`boks proxy upgrade` with boks's own image first, then apply again", verb, image, fields, err)
	}
	return nil
}

// banProbe is a config with every field of the ban handler this boks writes but deny_ranges, and
// nothing else Caddy would reach out for: no admin endpoint, one server no one connects to.
// banProbeDeny is it with deny_ranges, and the route's client_ip matcher.
var (
	banProbe     = probeOf(``, ``)
	banProbeDeny = probeOf(`"match":[{"client_ip":{"ranges":["198.51.100.0/24"]}}],`, `,"deny_ranges":["198.51.100.0/24"]`)
)

func probeOf(match, deny string) []byte {
	return []byte(`{"admin":{"disabled":true},"apps":{"http":{"servers":{"probe":{"listen":[":80"],"routes":[{` + match + `"handle":[` +
		`{"handler":"boks_ban","duration":"1h","rules":[{"name":"probe","limit":1,"window":"1m","class":"api","paths":["^/api/"]}],` +
		`"heuristics":{"mode":"log","cluster":{"limit":1,"window":"1m","min_addresses":2}},` +
		`"exempt_paths":["^/api/pics"],"exempt_ranges":["203.0.113.0/24"]` + deny + `}]}]}}}}}`)
}

// checkModule refuses a running proxy whose Caddy lacks module. A proxy that is not running is left to
// the boot or the upgrade that creates it from the image the config names.
func checkModule(ctx context.Context, r remote.Runner, module, lacks string) error {
	state, kind, err := State(ctx, r)
	if err != nil || state != "running" || kind != Kind {
		return err
	}
	image, err := Image(ctx, r)
	if err != nil {
		return err
	}
	mods, err := r.Run(ctx, "docker", "exec", Container, "caddy", "list-modules")
	if err != nil {
		return fmt.Errorf("asking the proxy for its modules: %w", err)
	}
	if !slices.Contains(strings.Fields(mods), module) {
		return fmt.Errorf("the proxy runs %s, which has %s; `boks proxy upgrade` with boks's own image first, then apply again", image, lacks)
	}
	return nil
}

// portsFormat prints a running container's name and the ports docker bound for it on the host, as one
// JSON object a line. NetworkSettings, not HostConfig: a range or an empty host port asked for is one
// port once bound, and the bound one is what a new `-p` collides with. Read with index, as the deploy's
// inventory reads it, so a container without the key prints null rather than failing the inspect.
const portsFormat = `{"name":{{json .Name}},"ports":{{json (index .NetworkSettings "Ports")}}}`

// hostPortHolder names a running container other than the proxy that publishes port/tcp on the host,
// on any address, or "" when none does. Read from what docker bound rather than through `docker ps
// --filter publish=`, whose match — host port or container port — this need not depend on.
func hostPortHolder(ctx context.Context, r remote.Runner, port int) (string, error) {
	script := "ids=$(docker ps -q --no-trunc) || exit 1; " +
		`[ -z "$ids" ] || exec docker inspect --format ` + remote.Quote(portsFormat) + " $ids"
	// A container removed between the listing and the inspect — a deploy retiring its old copy, which
	// nothing here keeps out — fails the call; it is asked again, as the deploy's inventory is.
	var out string
	var err error
	for try := 0; try < 3; try++ {
		if out, err = r.Run(ctx, "sh", "-c", script); err == nil {
			break
		}
	}
	if err != nil {
		return "", fmt.Errorf("asking which containers publish port %d: %w", port, err)
	}
	want := strconv.Itoa(port)
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var c struct {
			Name  string
			Ports map[string][]struct{ HostPort string }
		}
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return "", fmt.Errorf("reading which containers publish port %d: %w", port, err)
		}
		name := strings.TrimPrefix(c.Name, "/")
		if name == Container {
			continue
		}
		for spec, bs := range c.Ports {
			for _, b := range bs {
				if strings.HasSuffix(spec, "/tcp") && b.HostPort == want {
					return name, nil
				}
			}
		}
	}
	return "", nil
}

// Drift is what of the running proxy the policy on the server does not see: a container in another
// shape — a swap went through and the policy after it failed, or something other than boks made it —
// and a hosts file replaced rather than written in place, which the proxy's mount still holds the old
// copy of. Each is a line to warn with; a proxy that is not running drifts from nothing.
func Drift(ctx context.Context, r remote.Runner, p Policy) ([]string, error) {
	state, kind, err := State(ctx, r)
	if err != nil || state != "running" || kind != Kind {
		return nil, err
	}
	var out []string
	want := ShapeOf(p)
	have, err := currentShape(ctx, r)
	if err != nil {
		return nil, err
	}
	if have != want {
		out = append(out, fmt.Sprintf("the proxy publishes egress port %d and mounts hosts file %q, the policy needs %d and %q; "+
			"`boks proxy upgrade` creates it again", have.EgressPort, have.HostsFile, want.EgressPort, want.HostsFile))
	}
	if want.HostsFile != "" && have.HostsFile == want.HostsFile {
		host, err := r.Run(ctx, "stat", "-c", "%i", want.HostsFile)
		if err != nil {
			return out, err
		}
		inside, err := r.Run(ctx, "docker", "exec", Container, "stat", "-c", "%i", "/etc/hosts")
		if err != nil {
			return out, err
		}
		if strings.TrimSpace(host) != strings.TrimSpace(inside) {
			out = append(out, fmt.Sprintf("%s was replaced, not written in place: the proxy resolves through the old copy until "+
				"`docker restart %s` (80 and 443 are down meanwhile)", want.HostsFile, Container))
		}
	}
	return out, nil
}

// validate asks the running Caddy whether it takes the config p and fs make, changing nothing.
func validate(ctx context.Context, r remote.Runner, p Policy, fs []Fragment) error {
	body, err := Config(p, fs)
	if err != nil {
		return err
	}
	if err := remote.UploadAtomic(ctx, r, body, checkPath()); err != nil {
		return err
	}
	if out, err := r.Run(ctx, "docker", "exec", Container, "caddy", "validate", "--config", inProxy(checkPath())); err != nil {
		return fmt.Errorf("the proxy refuses the config: %w %s", err, strings.TrimSpace(out))
	}
	return nil
}
