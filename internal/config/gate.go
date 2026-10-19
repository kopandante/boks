package config

// server.yml `gate:`: the proxy checks the sites' API token in place of each site (proxy/gate). boks
// reads of a group only what it acts on itself — which app's hosts it covers, its mode, whether the
// site still checks, and the names of the variables its secrets come from. The rest of the group goes
// to the proxy's handler as written: its schema is Caddy's, which refuses a field it does not know at
// the reload and keeps the config it runs. A new field of the handler is then a new image and a
// revision of the policy, never a new boks.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Gate is the parsed `gate:`.
type Gate struct {
	Groups []GateGroup
	// JSON is the gate as written, for the proxy: {"groups": [...]}.
	JSON json.RawMessage
}

// GateGroup is what boks reads of one group.
type GateGroup struct {
	Name string `yaml:"name"`
	// App is the app whose hosts the group covers: those of its routes on the server, whatever they are
	// when the config is assembled — a host the app adds is under the gate without an edit here.
	App string `yaml:"app"`
	// Mode is off, log — the verdict in the proxy's access log, every request passed on — or enforce.
	Mode string `yaml:"mode"`
	// SiteGate is on while the site still checks the token itself, off once it no longer does: then a
	// failure of the proxy's handler is 503, and neither apply nor rollback leaves the group anything
	// but enforce without --force.
	SiteGate string `yaml:"site_gate"`
	// SecretEnv names the variable holding the site's API_SECRET_CURRENT; SecretEnv_PREVIOUS, when
	// set, the one being rotated out.
	SecretEnv string `yaml:"secret_env"`
	Bearer    *struct {
		// DigestsEnv names the variable holding the hex SHA-256 of the partners' tokens, comma-separated.
		DigestsEnv string `yaml:"digests_env"`
	} `yaml:"bearer"`
}

// gateWritten are the keys of a group boks writes itself into the handler, which server.yml must not:
// a secret in the file would be in the repository and the policy's history.
var gateWritten = map[string]string{
	"secrets": "the secret never goes in server.yml; secret_env names the variable it comes from",
	"hosts":   "boks writes it from the app's routes",
	"handler": "boks writes it",
}

// MinGateSecret is the sites' own floor for API_SECRET_CURRENT.
const MinGateSecret = 32

func (g *Gate) UnmarshalYAML(n *yaml.Node) error {
	var raw any
	if err := n.Decode(&raw); err != nil {
		return err
	}
	top, ok := raw.(map[string]any)
	if !ok {
		return errors.New("gate: a mapping with groups")
	}
	for k := range top {
		if k != "groups" {
			return fmt.Errorf("gate: only groups go here, not %s", k)
		}
	}
	groups, _ := top["groups"].([]any)
	for i, gr := range groups {
		m, ok := gr.(map[string]any)
		if !ok {
			return fmt.Errorf("gate.groups[%d]: a mapping", i)
		}
		for k, why := range gateWritten {
			if _, set := m[k]; set {
				return fmt.Errorf("gate.groups[%d]: %s: %s", i, k, why)
			}
		}
		if b, ok := m["bearer"].(map[string]any); ok {
			if _, set := b["digests"]; set {
				return fmt.Errorf("gate.groups[%d]: bearer.digests never go in server.yml; digests_env names the variable", i)
			}
		}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("gate: %w", err)
	}
	var parsed struct {
		Groups []GateGroup `yaml:"groups"`
	}
	if err := n.Decode(&parsed); err != nil {
		return err
	}
	g.Groups, g.JSON = parsed.Groups, b
	return nil
}

func (g *Gate) validate() error {
	if len(g.Groups) == 0 {
		return errors.New("groups: at least one")
	}
	names, apps := map[string]bool{}, map[string]string{}
	for i := range g.Groups {
		gr := &g.Groups[i]
		if !nameRe.MatchString(gr.Name) {
			return fmt.Errorf("groups[%d]: name %q must match %s", i, gr.Name, nameRe)
		}
		if names[gr.Name] {
			return fmt.Errorf("groups[%s]: the name is used twice", gr.Name)
		}
		names[gr.Name] = true
		switch {
		case gr.App == "":
			return fmt.Errorf("groups[%s]: app: required, the app whose hosts the group covers", gr.Name)
		case !nameRe.MatchString(gr.App):
			return fmt.Errorf("groups[%s]: app %q must match %s", gr.Name, gr.App, nameRe)
		case apps[gr.App] != "":
			return fmt.Errorf("groups[%s]: app %s is in two groups, %s and %s", gr.Name, gr.App, apps[gr.App], gr.Name)
		}
		apps[gr.App] = gr.Name
		if gr.Mode != "off" && gr.Mode != "log" && gr.Mode != "enforce" {
			return fmt.Errorf("groups[%s]: mode %q must be off, log or enforce", gr.Name, gr.Mode)
		}
		if gr.SiteGate == "" {
			gr.SiteGate = "on"
		}
		switch {
		case gr.SiteGate != "on" && gr.SiteGate != "off":
			return fmt.Errorf("groups[%s]: site_gate %q must be on or off", gr.Name, gr.SiteGate)
		case gr.SiteGate == "off" && gr.Mode != "enforce":
			return fmt.Errorf("groups[%s]: site_gate off goes with enforce: with the site's own check gone, only the proxy's stands", gr.Name)
		case !envNameRe.MatchString(gr.SecretEnv):
			return fmt.Errorf("groups[%s]: secret_env %q must name an environment variable (%s)", gr.Name, gr.SecretEnv, envNameRe)
		case gr.Bearer != nil && !envNameRe.MatchString(gr.Bearer.DigestsEnv):
			return fmt.Errorf("groups[%s]: bearer.digests_env %q must name an environment variable (%s)", gr.Name, gr.Bearer.DigestsEnv, envNameRe)
		}
	}
	return nil
}

// Secrets reads the gate's secrets from the environment boks runs in, by variable name: a group's
// current secret and its previous one when set, the Bearer digests. A variable not set is left out —
// the server keeps what an earlier apply gave it — while one set wrong is an error before any server
// is asked.
func (g *Gate) Secrets() (map[string][]string, error) {
	out := map[string][]string{}
	for _, gr := range g.Groups {
		cur, ok := os.LookupEnv(gr.SecretEnv)
		if ok {
			vals := []string{cur}
			if prev, ok := os.LookupEnv(gr.SecretEnv + "_PREVIOUS"); ok && prev != "" {
				vals = append(vals, prev)
			}
			for i, v := range vals {
				name := gr.SecretEnv
				if i == 1 {
					name += "_PREVIOUS"
				}
				if len(v) < MinGateSecret || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n") {
					return nil, fmt.Errorf("gate.groups[%s]: %s is shorter than %d characters or has whitespace at its ends; the sites refuse such a secret", gr.Name, name, MinGateSecret)
				}
			}
			out[gr.SecretEnv] = vals
		}
		if gr.Bearer == nil {
			continue
		}
		raw, ok := os.LookupEnv(gr.Bearer.DigestsEnv)
		if !ok {
			continue
		}
		var digests []string
		for _, d := range strings.Split(raw, ",") {
			d = strings.TrimSpace(d)
			if b, err := hex.DecodeString(d); err != nil || len(b) != 32 || strings.ToLower(d) != d {
				return nil, fmt.Errorf("gate.groups[%s]: %s: %q is not the lowercase hex of a SHA-256", gr.Name, gr.Bearer.DigestsEnv, d)
			}
			digests = append(digests, d)
		}
		out[gr.Bearer.DigestsEnv] = digests
	}
	return out, nil
}
