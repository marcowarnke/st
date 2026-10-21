from __future__ import annotations

import json
import os
from importlib import resources
from pathlib import Path

from .. import git, output
from ..cli import COMP_NOFILE, Command, Error, Opts, no_args
from ..output import gray, success

APP = "st"


def new_skills_cmd() -> Command:
    cmd = Command(
        "skills <command>",
        short=f"Manage the agent skills shipped with {APP}",
        long=f"""{APP} embeds agent skills that teach agents to use it:

  st          command reference and conventions
  st-upgrade  upgrade vulnerable dependencies end to end

They always match this version's commands and flags.""",
    )
    cmd.add(new_skills_list_cmd(), new_skills_install_cmd())
    return cmd


def _skills_dir():  # type: ignore[no-untyped-def]
    return resources.files(__package__.rpartition(".")[0]) / "skills"


def skill_names() -> list[str]:
    return sorted(e.name for e in _skills_dir().iterdir() if e.is_dir() and (e / "SKILL.md").is_file())


def skill_data(name: str) -> bytes | None:
    f = _skills_dir() / name / "SKILL.md"
    return f.read_bytes() if f.is_file() else None


def frontmatter(data: bytes, key: str) -> str:
    for line in data.decode("utf-8").split("\n"):
        if line.startswith(key + ":"):
            return line[len(key) + 1 :].strip()
    return ""


def new_skills_list_cmd() -> Command:
    def run(o: Opts) -> None:
        for n in skill_names():
            output.out(f"{n}\t{frontmatter(skill_data(n) or b'', 'description')}")

    return Command("list", short="List the embedded skills", args=no_args, run=run)


# --agent values and their user and project skill directories (project paths
# are relative to the repository root).
SKILL_AGENTS = [
    ("claude", "Claude Code", ".claude/skills", ".claude/skills"),
    ("copilot", "GitHub Copilot", ".copilot/skills", ".github/skills"),
    ("agents", "Shared .agents (Copilot, Codex…)", ".agents/skills", ".agents/skills"),
]


def home() -> Path:
    """os.UserHomeDir: $HOME, or %USERPROFILE% on Windows."""
    v = os.environ.get("USERPROFILE" if os.name == "nt" else "HOME")
    return Path(v) if v else Path.home()


def skill_targets() -> list[tuple[str, str, str, Path]]:
    """Every agent × scope directory as (agent, scope, label, dir); project targets only inside a git repository."""
    h = home()
    try:
        top: str | None = git.run("rev-parse", "--show-toplevel")
    except Error:
        top = None
    out = []
    for scope in ("user", "project"):
        for name, label, user, project in SKILL_AGENTS:
            if scope == "user":
                out.append((name, scope, label + ", personal", h.joinpath(*user.split("/"))))
            elif top is not None:
                out.append((name, scope, label + ", this repository", Path(top).joinpath(*project.split("/"))))
    return out


def skills_state(d: Path, names: list[str]) -> str:
    """ "not installed", "up to date" or "outdated"."""
    found = current = 0
    for n in names:
        try:
            old = (d / n / "SKILL.md").read_bytes()
        except OSError:
            continue
        found += 1
        if old == skill_data(n):
            current += 1
    if found == 0:
        return "not installed"
    if current == len(names):
        return "up to date"
    return "outdated"


def tilde_home(p: Path) -> str:
    s, h = str(p), str(home())
    if s.startswith(h):
        return "~" + s[len(h) :]
    return s


def prompt_targets(targets: list, names: list[str]) -> list:
    """A numbered menu; parses "1,3" / "1 3" / "" (=1)."""
    width = max(len(t[2]) for t in targets)
    output.err("Where should the skills be installed?")
    for i, t in enumerate(targets):
        output.err(f"  {i + 1}. {t[2].ljust(width)}  {tilde_home(t[3])} {gray('(' + skills_state(t[3], names) + ')')}")
    output.err(gray("Copilot also reads the Claude and .agents directories; one directory per scope avoids duplicates."))
    output.io.stderr.write("Choose one or more, e.g. 1,4 [1]: ")
    output.io.stderr.flush()
    answer = output.io.stdin.readline()
    if answer == "":
        raise Error("no choice made; pass --agent/--scope or --dir to install without prompting")
    answer = answer.strip() or "1"
    out, seen = [], set()
    for f in answer.replace(",", " ").split():
        try:
            n = int(f)
        except ValueError:
            n = 0
        if n < 1 or n > len(targets):
            raise Error(f"invalid choice {json.dumps(f)}: enter numbers between 1 and {len(targets)}")
        if n not in seen:
            seen.add(n)
            out.append(targets[n - 1])
    return out


def new_skills_install_cmd() -> Command:
    def run(o: Opts) -> None:
        scopes = list(o.scope) + (["project"] if o.project else [])
        if o.dir and (o.agent or scopes):
            raise Error("--dir can't be combined with --agent, --scope or --project")
        names = o.args or skill_names()
        for n in names:
            if skill_data(n) is None:
                raise Error(f"unknown skill {json.dumps(n)}; available: {', '.join(skill_names())}")
        if o.dir:
            dirs = [Path(o.dir)]
        elif not o.agent and not scopes and output.io.is_tty():
            dirs = [t[3] for t in prompt_targets(skill_targets(), names)]
        else:
            dirs = select_skill_dirs(o.agent, scopes)
        for d in dirs:
            install_skills(d, names)

    cmd = Command(
        "install [<skill>...]",
        short="Install the skills for Claude Code, GitHub Copilot and other agents",
        long=f"""Write the embedded skills where your agent loads them. Without arguments all
skills are installed. Existing copies are overwritten, so re-run this after
upgrading {APP}.

  --agent    personal (--scope user)    in the repository (--scope project)
  claude     ~/.claude/skills           .claude/skills
  copilot    ~/.copilot/skills          .github/skills
  agents     ~/.agents/skills           .agents/skills

Both flags take several values. --agent alone implies --scope user; --scope
alone implies --agent claude; --project is short for --scope project. --dir
writes to any directory.

In a terminal without any of these flags, {APP} asks where to install, showing
whether each location is up to date. Otherwise the default is ~/.claude/skills.
GitHub Copilot also reads the Claude and .agents directories.""",
        example="""  $ st skills install
  $ st skills install --agent copilot --scope project
  $ st skills install --agent claude,copilot --scope user,project
  $ st skills install --project st""",
        run=run,
        complete_args=lambda o, tc: (skill_names(), COMP_NOFILE),
    )
    cmd.flag("agent", kind="strs", help="Install for `agents`: {claude|copilot|agents}", complete=["claude", "copilot", "agents"])
    cmd.flag("scope", kind="strs", help="Install for `scopes`: {user|project}", complete=["user", "project"])
    cmd.flag("project", kind="bool", help="Install into the current repository (same as --scope project)")
    cmd.flag("dir", help="Install into `directory` instead")
    return cmd


def select_skill_dirs(agents: list[str], scopes: list[str]) -> list[Path]:
    """Resolve --agent × --scope to directories."""
    agents = agents or ["claude"]
    scopes = scopes or ["user"]
    for a in agents:
        if a not in [x[0] for x in SKILL_AGENTS]:
            raise Error(f'invalid --agent "{a}": valid values are {{claude|copilot|agents}}')
    for sc in scopes:
        if sc not in ("user", "project"):
            raise Error(f'invalid --scope "{sc}": valid values are {{user|project}}')
    targets = skill_targets()
    dirs: list[Path] = []
    for sc in scopes:
        matched = False
        for a in agents:
            for t in targets:
                if t[0] == a and t[1] == sc and t[3] not in dirs:
                    dirs.append(t[3])
                    matched = True
        if not matched and sc == "project":
            raise Error("--scope project needs a git repository")
    return dirs


def install_skills(d: Path, names: list[str]) -> None:
    for n in names:
        data = skill_data(n) or b""
        dst = d / n / "SKILL.md"
        verb = "Installed"
        try:
            old = dst.read_bytes()
            if old == data:
                success(f"{n} is up to date ({dst})")
                continue
            verb = "Updated"
        except OSError:
            pass
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        success(f"{verb} {n} ({dst})")
