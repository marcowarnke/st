package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marcowarnke/st/internal/git"
	"github.com/marcowarnke/st/skills"
)

func newSkillsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skills <command>",
		Short: "Manage the agent skills shipped with st",
		Long: `st embeds agent skills that teach agents to use it:

  st          command reference and conventions
  st-upgrade  upgrade vulnerable dependencies end to end

They always match this binary's commands and flags.`,
	}
	cmd.AddCommand(newSkillsListCmd(), newSkillsInstallCmd())
	return cmd
}

func skillNames() []string {
	entries, _ := fs.ReadDir(skills.FS, ".")
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

func newSkillsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the embedded skills",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, n := range skillNames() {
				data, _ := fs.ReadFile(skills.FS, n+"/SKILL.md")
				fmt.Fprintf(stdout, "%s\t%s\n", n, frontmatter(data, "description"))
			}
			return nil
		},
	}
}

func frontmatter(data []byte, key string) string {
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// skillTarget is a directory an agent loads skills from.
type skillTarget struct {
	agent, scope, label, dir string
}

// skillAgents maps --agent values to their user and project skill
// directories (project paths are relative to the repository root).
type skillAgent struct{ name, label, user, project string }

var skillAgents = []skillAgent{
	{"claude", "Claude Code", ".claude/skills", ".claude/skills"},
	{"copilot", "GitHub Copilot", ".copilot/skills", ".github/skills"},
	{"agents", "Shared .agents (Copilot, Codex…)", ".agents/skills", ".agents/skills"},
}

// skillTargets lists every agent × scope directory; project targets only
// inside a git repository.
func skillTargets() ([]skillTarget, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	top, gitErr := git.Run("rev-parse", "--show-toplevel")
	var out []skillTarget
	for _, scope := range []string{"user", "project"} {
		for _, a := range skillAgents {
			if scope == "user" {
				out = append(out, skillTarget{a.name, scope, a.label + ", personal", filepath.Join(home, filepath.FromSlash(a.user))})
			} else if gitErr == nil {
				out = append(out, skillTarget{a.name, scope, a.label + ", this repository", filepath.Join(top, filepath.FromSlash(a.project))})
			}
		}
	}
	return out, nil
}

// skillsState summarises a directory: "not installed", "up to date" or "outdated".
func skillsState(dir string, names []string) string {
	found, current := 0, 0
	for _, n := range names {
		old, err := os.ReadFile(filepath.Join(dir, n, "SKILL.md"))
		if err != nil {
			continue
		}
		found++
		if data, _ := fs.ReadFile(skills.FS, n+"/SKILL.md"); bytes.Equal(old, data) {
			current++
		}
	}
	switch {
	case found == 0:
		return "not installed"
	case current == len(names):
		return "up to date"
	}
	return "outdated"
}

// promptTargets shows a numbered menu and parses "1,3" / "1 3" / "" (=1).
func promptTargets(targets []skillTarget, names []string) ([]skillTarget, error) {
	width := 0
	for _, t := range targets {
		width = max(width, len([]rune(t.label)))
	}
	fmt.Fprintln(stderr, "Where should the skills be installed?")
	for i, t := range targets {
		pad := strings.Repeat(" ", width-len([]rune(t.label)))
		fmt.Fprintf(stderr, "  %d. %s%s  %s %s\n", i+1, t.label, pad, tildeHome(t.dir), gray("("+skillsState(t.dir, names)+")"))
	}
	fmt.Fprintln(stderr, gray("Copilot also reads the Claude and .agents directories; one directory per scope avoids duplicates."))
	fmt.Fprint(stderr, "Choose one or more, e.g. 1,4 [1]: ")
	answer, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && answer == "" {
		return nil, errors.New("no choice made; pass --agent/--scope or --dir to install without prompting")
	}
	if answer = strings.TrimSpace(answer); answer == "" {
		answer = "1"
	}
	var out []skillTarget
	seen := map[int]bool{}
	for _, f := range strings.FieldsFunc(answer, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > len(targets) {
			return nil, fmt.Errorf("invalid choice %q: enter numbers between 1 and %d", f, len(targets))
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, targets[n-1])
		}
	}
	return out, nil
}

func tildeHome(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rest, ok := strings.CutPrefix(p, home); ok {
			return "~" + rest
		}
	}
	return p
}

func newSkillsInstallCmd() *cobra.Command {
	var project bool
	var dir string
	var agents, scopes []string
	cmd := &cobra.Command{
		Use:   "install [<skill>...]",
		Short: "Install the skills for Claude Code, GitHub Copilot and other agents",
		Long: `Write the embedded skills where your agent loads them. Without arguments all
skills are installed. Existing copies are overwritten, so re-run this after
upgrading st.

  --agent    personal (--scope user)    in the repository (--scope project)
  claude     ~/.claude/skills           .claude/skills
  copilot    ~/.copilot/skills          .github/skills
  agents     ~/.agents/skills           .agents/skills

Both flags take several values. --agent alone implies --scope user; --scope
alone implies --agent claude; --project is short for --scope project. --dir
writes to any directory.

In a terminal without any of these flags, st asks where to install, showing
whether each location is up to date. Otherwise the default is ~/.claude/skills.
GitHub Copilot also reads the Claude and .agents directories.`,
		Example: `  $ st skills install
  $ st skills install --agent copilot --scope project
  $ st skills install --agent claude,copilot --scope user,project
  $ st skills install --project st`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return skillNames(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if project {
				scopes = append(scopes, "project")
			}
			if dir != "" && (len(agents) > 0 || len(scopes) > 0) {
				return usageErr("--dir can't be combined with --agent, --scope or --project")
			}
			names := args
			if len(names) == 0 {
				names = skillNames()
			}
			for _, n := range names {
				if _, err := fs.Stat(skills.FS, n+"/SKILL.md"); err != nil {
					return fmt.Errorf("unknown skill %q; available: %s", n, strings.Join(skillNames(), ", "))
				}
			}
			var dirs []string
			switch {
			case dir != "":
				dirs = []string{dir}
			case len(agents) == 0 && len(scopes) == 0 && isTTY():
				targets, err := skillTargets()
				if err != nil {
					return err
				}
				chosen, err := promptTargets(targets, names)
				if err != nil {
					return err
				}
				for _, t := range chosen {
					dirs = append(dirs, t.dir)
				}
			default:
				var err error
				if dirs, err = selectSkillDirs(agents, scopes); err != nil {
					return err
				}
			}
			for _, d := range dirs {
				if err := installSkills(d, names); err != nil {
					return err
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&agents, "agent", nil, "Install for `agents`: {claude|copilot|agents}")
	f.StringSliceVar(&scopes, "scope", nil, "Install for `scopes`: {user|project}")
	f.BoolVar(&project, "project", false, "Install into the current repository (same as --scope project)")
	f.StringVar(&dir, "dir", "", "Install into `directory` instead")
	_ = cmd.RegisterFlagCompletionFunc("agent", cobra.FixedCompletions([]string{"claude", "copilot", "agents"}, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("scope", cobra.FixedCompletions([]string{"user", "project"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

// selectSkillDirs resolves --agent × --scope to directories.
func selectSkillDirs(agents, scopes []string) ([]string, error) {
	if len(agents) == 0 {
		agents = []string{"claude"}
	}
	if len(scopes) == 0 {
		scopes = []string{"user"}
	}
	for _, a := range agents {
		if !slices.ContainsFunc(skillAgents, func(x skillAgent) bool { return x.name == a }) {
			return nil, usageErr("invalid --agent %q: valid values are {claude|copilot|agents}", a)
		}
	}
	for _, sc := range scopes {
		if sc != "user" && sc != "project" {
			return nil, usageErr("invalid --scope %q: valid values are {user|project}", sc)
		}
	}
	targets, err := skillTargets()
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, sc := range scopes {
		matched := false
		for _, a := range agents {
			for _, t := range targets {
				if t.agent == a && t.scope == sc && !slices.Contains(dirs, t.dir) {
					dirs = append(dirs, t.dir)
					matched = true
				}
			}
		}
		if !matched && sc == "project" {
			return nil, fmt.Errorf("--scope project needs a git repository")
		}
	}
	return dirs, nil
}

func installSkills(dir string, names []string) error {
	for _, n := range names {
		data, _ := fs.ReadFile(skills.FS, n+"/SKILL.md")
		dst := filepath.Join(dir, n, "SKILL.md")
		old, err := os.ReadFile(dst)
		verb := "Installed"
		switch {
		case err == nil && bytes.Equal(old, data):
			success("%s is up to date (%s)", n, dst)
			continue
		case err == nil:
			verb = "Updated"
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
		success("%s %s (%s)", verb, n, dst)
	}
	return nil
}
