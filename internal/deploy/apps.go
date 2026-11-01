package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/kopandante/boks/internal/config"
	"github.com/kopandante/boks/internal/remote"
)

// appsDir holds, for each app of server.yml, what the server's own boks deploys it from (#154, stage 2):
// its boks.yml, its environment and its registry's token, each 0600.
const appsDir = ".boks/_server/apps"

func appFile(app, name string) string { return path.Join(appsDir, app, name) }

// PutApps makes apps — those of server.yml that go on this server — the apps the server keeps: each one's
// files written, the token removed for a public image, and the directory of an app server.yml no longer
// names removed. Under the admission lock: the server's boks reads them for a deploy. Every file is
// written whole or not at all, so a cut run leaves each app's file either old or new; the next apply
// writes them all again.
func PutApps(ctx context.Context, r remote.Runner, log io.Writer, apps []config.ServerApp, o Options) error {
	adm, err := admit(ctx, r, log, proxyHolder, o)
	if err != nil {
		return err
	}
	defer adm.release(ctx)
	var names []string
	for _, a := range apps {
		names = append(names, a.Name)
		if err := putApp(ctx, r, a); err != nil {
			return fmt.Errorf("apps: %s: %w", a.Name, err)
		}
	}
	kept, err := keptApps(ctx, r)
	if err != nil {
		return err
	}
	for _, k := range kept {
		if !slices.Contains(names, k) {
			if _, err := r.Run(ctx, "rm", "-rf", path.Join(appsDir, k)); err != nil {
				return fmt.Errorf("apps: removing %s, which server.yml no longer names: %w", k, err)
			}
			fmt.Fprintf(log, "apps: %s removed\n", k)
		}
	}
	if len(names) > 0 {
		fmt.Fprintf(log, "apps: %s\n", strings.Join(names, ", "))
	}
	return nil
}

func putApp(ctx context.Context, r remote.Runner, a config.ServerApp) error {
	if err := remote.UploadAtomic(ctx, r, a.Config, appFile(a.Name, "boks.yml")); err != nil {
		return err
	}
	if err := remote.UploadAtomic(ctx, r, a.Env, appFile(a.Name, "env")); err != nil {
		return err
	}
	if a.Token == "" {
		_, err := r.Run(ctx, "rm", "-f", appFile(a.Name, "registry.token"))
		return err
	}
	return remote.UploadAtomic(ctx, r, []byte(a.Token+"\n"), appFile(a.Name, "registry.token"))
}

// keptApps are the apps the server keeps files for, by name.
func keptApps(ctx context.Context, r remote.Runner) ([]string, error) {
	out, err := r.Run(ctx, "sh", "-c", "for d in "+appsDir+"/*/; do [ -d \"$d\" ] && basename \"$d\"; done; true")
	if err != nil {
		return nil, fmt.Errorf("apps: reading what the server keeps: %w", err)
	}
	return strings.Fields(out), nil
}

// AppsDrift is how the apps the server keeps differ from apps, those server.yml puts on it: one it
// lacks, one whose boks.yml differs or has no environment, one server.yml no longer names. The
// environment is compared by presence only: comparing it would take its secrets from bws.
func AppsDrift(ctx context.Context, r remote.Runner, apps []config.ServerApp) ([]string, error) {
	kept, err := keptApps(ctx, r)
	if err != nil {
		return nil, err
	}
	var drift []string
	for _, a := range apps {
		if !slices.Contains(kept, a.Name) {
			drift = append(drift, fmt.Sprintf("app %s: not on the server; `boks server apply` writes it", a.Name))
			continue
		}
		sum := sha256.Sum256(a.Config)
		out, err := r.Run(ctx, "sh", "-c", "sha256sum "+remote.Quote(appFile(a.Name, "boks.yml"))+" 2>/dev/null | cut -d' ' -f1; "+
			"[ -f "+remote.Quote(appFile(a.Name, "env"))+" ] && echo env; true")
		if err != nil {
			return nil, err
		}
		have, env, _ := strings.Cut(out, "\n")
		if strings.TrimSpace(have) != hex.EncodeToString(sum[:]) {
			drift = append(drift, fmt.Sprintf("app %s: its boks.yml on the server differs from server.yml's", a.Name))
		}
		if strings.TrimSpace(env) != "env" {
			drift = append(drift, fmt.Sprintf("app %s: no environment on the server", a.Name))
		}
	}
	for _, k := range kept {
		if !slices.ContainsFunc(apps, func(a config.ServerApp) bool { return a.Name == k }) {
			drift = append(drift, fmt.Sprintf("app %s: on the server, and server.yml does not name it", k))
		}
	}
	return drift, nil
}
