// Package git wraps the git CLI and normalizes repository URLs so a checkout
// can be matched to the repository URL configured on an IQ application.
package git

import (
	"bytes"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

func Run(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

type Remote struct {
	Name string
	URL  string
}

// Remotes lists fetch remotes, upstream first, then origin, like gh.
func Remotes() ([]Remote, error) {
	out, err := Run("remote", "-v")
	if err != nil {
		return nil, err
	}
	var rs []Remote
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[2] != "(fetch)" || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		rs = append(rs, Remote{Name: f[0], URL: f[1]})
	}
	rank := func(n string) int {
		switch n {
		case "upstream":
			return 0
		case "origin":
			return 1
		}
		return 2
	}
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rank(rs[j].Name) < rank(rs[j-1].Name); j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
	return rs, nil
}

// RepoKey reduces a clone or browse URL to a host-independent "owner/repo"
// key, so SSH and HTTPS remotes of the same repository compare equal:
//
//	https://bitbucket.corp/scm/proj/repo.git        → proj/repo
//	ssh://git@bitbucket.corp:7999/proj/repo.git     → proj/repo
//	https://bitbucket.corp/projects/PROJ/repos/repo → proj/repo
//	git@github.com:org/repo.git                     → org/repo
func RepoKey(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if !strings.Contains(raw, "://") {
		// scp-like syntax: user@host:path
		at := strings.Index(raw, "@")
		colon := strings.Index(raw, ":")
		if colon < 0 || colon < at {
			return "", false
		}
		raw = "ssh://" + raw[:colon] + "/" + raw[colon+1:]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	parts := strings.FieldsFunc(u.Path, func(r rune) bool { return r == '/' })
	var owner, repo string
	for i, p := range parts {
		if p == "scm" && i+2 < len(parts) {
			owner, repo = parts[i+1], parts[i+2]
			break
		}
		if (p == "projects" || p == "users") && i+3 < len(parts) && parts[i+2] == "repos" {
			owner, repo = parts[i+1], parts[i+3]
			if p == "users" {
				owner = "~" + owner
			}
			break
		}
	}
	if owner == "" && len(parts) >= 2 {
		owner, repo = parts[len(parts)-2], parts[len(parts)-1]
	}
	repo = strings.TrimSuffix(repo, ".git")
	if owner == "" || repo == "" {
		return "", false
	}
	return strings.ToLower(owner + "/" + repo), true
}
