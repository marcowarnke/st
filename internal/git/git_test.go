package git

import "testing"

func TestRepoKey(t *testing.T) {
	for in, want := range map[string]string{
		"https://bitbucket.corp/scm/proj/repo.git":               "proj/repo",
		"https://bitbucket.corp/ctx/scm/PROJ/Repo.git":           "proj/repo",
		"ssh://git@bitbucket.corp:7999/proj/repo.git":            "proj/repo",
		"git@bitbucket.corp:proj/repo.git":                       "proj/repo",
		"https://bitbucket.corp/projects/PROJ/repos/repo/browse": "proj/repo",
		"https://bitbucket.corp/users/alice/repos/tool":          "~alice/tool",
		"https://github.com/org/repo":                            "org/repo",
		"https://user@bitbucket.corp/scm/proj/repo.git":          "proj/repo",
		"https://gitlab.corp/group/subgroup/repo.git":            "subgroup/repo",
	} {
		got, ok := RepoKey(in)
		if !ok || got != want {
			t.Errorf("RepoKey(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "not a url", "https://host/"} {
		if got, ok := RepoKey(in); ok {
			t.Errorf("RepoKey(%q) = %q; want no match", in, got)
		}
	}
}
