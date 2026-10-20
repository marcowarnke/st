package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcowarnke/st/internal/config"
	"github.com/marcowarnke/st/internal/git"
)

// inRepo chdirs into a fresh git repository with the given origin.
func inRepo(t *testing.T, origin string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if _, err := git.Run("init", "-q"); err != nil {
		t.Fatal(err)
	}
	if origin != "" {
		if _, err := git.Run("remote", "add", "origin", origin); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAppFromGitRemote(t *testing.T) {
	f := newFake(t)
	inRepo(t, "ssh://git@bitbucket.corp:7999/proj/my-service.git")

	out, errOut, code := run(t, "", "vuln", "list", "--json", "application", "--jq", ".[0].application")
	if code != 0 || out != "my-service\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	if n := f.count("GET /api/v2/sourceControl/"); n != 2 {
		t.Fatalf("expected one source control lookup per app, got %d", n)
	}
	data, _ := os.ReadFile(filepath.Join(config.Dir(), "apps.json"))
	if !strings.Contains(string(data), `"proj/my-service": "my-service"`) {
		t.Fatalf("cache=%s", data)
	}
	// Second run uses the cache.
	if _, _, code = run(t, "", "app", "view", "--json", "publicId"); code != 0 {
		t.Fatal("cached lookup failed")
	}
	if n := f.count("GET /api/v2/sourceControl/"); n != 3 { // +1 from app view's own repository lookup
		t.Fatalf("cache not used: %d source control requests", n)
	}

	// ST_APP and -A win over the remote.
	t.Setenv("ST_APP", "other")
	out, _, _ = run(t, "", "app", "view", "--json", "publicId", "--jq", ".publicId")
	if out != "other\n" {
		t.Fatalf("ST_APP: %q", out)
	}
}

func TestAppResolutionErrors(t *testing.T) {
	newFake(t)
	inRepo(t, "https://github.com/someone/unrelated.git")
	_, errOut, code := run(t, "", "vuln", "list")
	if code != 1 || !strings.Contains(errOut, "no IQ application has a repository URL matching someone/unrelated") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	inRepo(t, "")
	_, errOut, _ = run(t, "", "fix")
	if !strings.Contains(errOut, "not in a git repository with a remote") {
		t.Fatalf("err=%q", errOut)
	}
	_, errOut, _ = run(t, "", "vuln", "list", "-A", "nope")
	if !strings.Contains(errOut, `no application with public ID "nope"`) {
		t.Fatalf("err=%q", errOut)
	}
}

func TestPurlHelpers(t *testing.T) {
	for _, c := range [][4]string{
		{"pkg:maven/org.yaml/snakeyaml@1.26?type=jar", "org.yaml:snakeyaml", "1.26", "pkg:maven/org.yaml/snakeyaml"},
		{"pkg:npm/%40babel/core@7.0.0", "@babel/core", "7.0.0", "pkg:npm/%40babel/core"},
		{"pkg:golang/golang.org/x/net@v0.17.0", "golang.org/x/net", "v0.17.0", "pkg:golang/golang.org/x/net"},
		{"pkg:pypi/django@4.2", "django", "4.2", "pkg:pypi/django"},
	} {
		if n, v, b := purlName(c[0]), purlVersion(c[0]), purlBase(c[0]); n != c[1] || v != c[2] || b != c[3] {
			t.Errorf("%s: name=%q version=%q base=%q", c[0], n, v, b)
		}
	}
	for v, want := range map[string]int{"2.9.10.1": 2, "v1.2.3": 1, "10": 10, "3.0.0-RC1": 3} {
		if got, ok := major(v); !ok || got != want {
			t.Errorf("major(%q)=%d,%v", v, got, ok)
		}
	}
	if _, ok := major("latest"); ok {
		t.Error("major(latest) should fail")
	}
	for _, c := range []struct {
		cur, tgt string
		want     bool
	}{{"1.2.0", "1.9.0", false}, {"1.2.0", "2.0.0", true}, {"0.3.1", "0.3.9", false}, {"0.3.1", "0.4.0", true}, {"v0.17.0", "v0.23.0", true}} {
		got := breaking(&fix{f: &finding{Version: c.cur}, Target: c.tgt, Strategy: "next-no-violations"})
		if got == nil || *got != c.want {
			t.Errorf("breaking(%s → %s) = %v, want %v", c.cur, c.tgt, got, c.want)
		}
	}
}
