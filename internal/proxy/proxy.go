// Package proxy drives kamal-proxy running as the container boks-proxy on a server.
package proxy

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/kopandante/boks/internal/remote"
)

const (
	Container    = "boks-proxy"
	ConfigVolume = "boks-proxy-config"
	CertsVolume  = "boks-certs"
	configPath   = "/home/kamal-proxy/.config/kamal-proxy"
)

// Service is one kamal-proxy route: host → target, with the health check the proxy
// waits for before switching traffic.
type Service struct {
	Name       string
	Target     string
	Host       string
	TLS        bool
	CertPath   string // set for a DNS-01 certificate; empty leaves TLS to kamal-proxy's autocert
	KeyPath    string
	HealthPath string
	HealthPort int
	Timeout    string
}

func ServiceName(app, port string) string {
	return app + "-" + port
}

func DeployArgs(s Service) []string {
	a := []string{"docker", "exec", Container, "kamal-proxy", "deploy", s.Name,
		"--target", s.Target, "--host", s.Host}
	if s.TLS {
		a = append(a, "--tls")
	}
	if s.CertPath != "" {
		a = append(a, "--tls-certificate-path", s.CertPath, "--tls-private-key-path", s.KeyPath)
	}
	if s.HealthPath != "" {
		a = append(a, "--health-check-path", s.HealthPath)
	}
	if s.HealthPort > 0 {
		a = append(a, "--health-check-port", strconv.Itoa(s.HealthPort))
	}
	if s.Timeout != "" {
		a = append(a, "--deploy-timeout", s.Timeout)
	}
	return a
}

func RunArgs(network, image string) []string {
	return []string{"docker", "run", "-d", "--name", Container, "--restart", "unless-stopped",
		"--network", network, "-p", "80:80", "-p", "443:443",
		"-v", ConfigVolume + ":" + configPath, "-v", CertsVolume + ":/certs", image}
}

// Boot makes sure the network exists and the proxy container is running. Idempotent.
func Boot(ctx context.Context, r remote.Runner, log io.Writer, network, image string) error {
	if err := EnsureNetwork(ctx, r, log, network); err != nil {
		return err
	}
	state, err := r.Run(ctx, "docker", "ps", "-a", "--filter", "name=^"+Container+"$", "--format", "{{.State}}")
	if err != nil {
		return err
	}
	switch state {
	case "running":
		return nil
	case "":
		fmt.Fprintf(log, "proxy: starting %s (%s)\n", Container, image)
		_, err = r.Run(ctx, RunArgs(network, image)...)
	default:
		fmt.Fprintf(log, "proxy: container is %s, starting it\n", state)
		_, err = r.Run(ctx, "docker", "start", Container)
	}
	return err
}

// EnsureNetwork creates the shared Docker network unless it already exists. Idempotent. Every app
// container is started on it, so an app that never boots the proxy (one without routes) needs it
// on its own.
func EnsureNetwork(ctx context.Context, r remote.Runner, log io.Writer, network string) error {
	if _, err := r.Run(ctx, "docker", "network", "inspect", network); err == nil {
		return nil
	}
	fmt.Fprintf(log, "creating network %s\n", network)
	_, err := r.Run(ctx, "docker", "network", "create", network)
	return err
}

func List(ctx context.Context, r remote.Runner) (string, error) {
	return r.Run(ctx, "docker", "exec", Container, "kamal-proxy", "list")
}
