package config

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// ServerApp is an app of server.yml as `server apply` writes it to the servers it goes on (#154,
// stage 2): its boks.yml as written, the environment its deploy would send, and the registry's token.
type ServerApp struct {
	Name string
	// Servers are those of server.yml, in its order, that the app's boks.yml names: where it goes.
	Servers []string
	Config  []byte
	Env     []byte
	// Token is the registry's token from the environment apply runs in; "" for a public image.
	Token string
}

// LoadApps reads every app of server.yml, by name, with what goes to the servers, before any server is
// asked: a boks.yml that does not load, an environment bws does not give, a token not set would stop
// the run halfway down the list. lookup is os.LookupEnv outside tests. Without secrets — what status
// compares — neither the environment nor the token is read: no bws for a look.
func (s *Server) LoadApps(lookup func(string) (string, bool), secrets bool) ([]ServerApp, error) {
	var out []ServerApp
	for _, name := range slices.Sorted(maps.Keys(s.Apps)) {
		a, err := s.loadApp(name, lookup, secrets)
		if err != nil {
			return nil, fmt.Errorf("apps: %s: %w", name, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// AppsOn are those of apps that go on server.
func AppsOn(apps []ServerApp, server string) []ServerApp {
	var on []ServerApp
	for _, a := range apps {
		if slices.Contains(a.Servers, server) {
			on = append(on, a)
		}
	}
	return on
}

func (s *Server) loadApp(name string, lookup func(string) (string, bool), secrets bool) (ServerApp, error) {
	path := s.Apps[name]
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.dir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ServerApp{}, err
	}
	cfg, err := Load(path)
	if err != nil {
		return ServerApp{}, err
	}
	switch {
	case cfg.App != name:
		return ServerApp{}, fmt.Errorf("%s names the app %s", path, cfg.App)
	case len(cfg.Files) > 0 || cfg.Cert != nil:
		// Their paths are the operator's, relative to boks.yml; the server has neither file yet.
		return ServerApp{}, fmt.Errorf("%s: files and cert are not kept on the server yet (#154, stage 3)", path)
	}
	a := ServerApp{Name: name, Config: data}
	for _, srv := range s.Servers {
		if slices.Contains(cfg.Servers, srv) {
			a.Servers = append(a.Servers, srv)
		}
	}
	if len(a.Servers) == 0 {
		return ServerApp{}, fmt.Errorf("%s names none of the servers of server.yml", path)
	}
	if !secrets {
		return a, nil
	}
	if a.Env, err = cfg.EnvContent(); err != nil {
		return ServerApp{}, err
	}
	if cfg.Registry != nil {
		if a.Token, err = cfg.Registry.Token(lookup); err != nil {
			return ServerApp{}, err
		}
	}
	return a, nil
}
