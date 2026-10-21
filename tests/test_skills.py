from __future__ import annotations

import re
import subprocess
from pathlib import Path

from conftest import run, run_tty

from st.cli import Command
from st.commands.root import new_root

SKILLS = Path(__file__).resolve().parent.parent / "src" / "st" / "skills"


def find(words: list[str]) -> Command | None:
    root = new_root()
    cmd, _ = root.find(words)
    return None if cmd is root else cmd


def has_flag(c: Command, name: str) -> bool:
    if name in ("--", "-"):
        return True
    if name.startswith("--"):
        return c.find_flag(name[2:]) is not None
    return len(name) == 2 and c.find_short(name[1]) is not None


def test_skills_reference_real_flags():
    """Every `st ...` invocation in the shipped skills must use real
    subcommands, flags and --json fields, so the agent instructions can't
    drift from the CLI."""
    files = sorted(SKILLS.glob("*/SKILL.md"))
    assert len(files) >= 2
    invocation = re.compile(r"\bst ((?:app|vuln|fix|waive|status|auth|api|skills)\b[^`|\n]*)")
    flag = re.compile(r"(?:^|[\s\[])(--?[a-zA-Z][\w-]*)")
    json_fields = re.compile(r"--json ([\w,]+)")
    checked, errors = 0, []
    for file in files:
        for m in invocation.finditer(file.read_text(encoding="utf-8")):
            line = m.group(1)
            cmd = find(line.split())
            if cmd is None:
                errors.append(f"{file.parent.name}: unknown command in 'st {line}'")
                continue
            for f in flag.finditer(line):
                if not has_flag(cmd, f.group(1)):
                    errors.append(f"{file.parent.name}: {cmd.path()!r} has no flag {f.group(1)} (in 'st {line}')")
                checked += 1
            for jm in json_fields.finditer(line):
                available = cmd.find_flag("json").fields or []
                for fld in jm.group(1).split(","):
                    if fld not in available:
                        errors.append(f"{file.parent.name}: {cmd.path()!r} has no JSON field {fld!r}")
                    checked += 1
    assert not errors, "\n".join(errors)
    assert checked >= 25, f"only {checked} flags checked; regexp broken?"


def test_skills_install(tmp_path):
    d = tmp_path / "skills"
    _, err, code = run("skills", "install", "--dir", str(d))
    assert code == 0 and err.count("Installed") == 2, err
    assert (d / "st-upgrade" / "SKILL.md").read_bytes() == (SKILLS / "st-upgrade" / "SKILL.md").read_bytes()
    (d / "st" / "SKILL.md").write_text("stale", encoding="utf-8")
    _, err, _ = run("skills", "install", "--dir", str(d), "st", "st-upgrade")
    assert "Updated st" in err and "st-upgrade is up to date" in err
    _, err, code = run("skills", "install", "--dir", str(d), "nope")
    assert code != 0 and "available: st, st-upgrade" in err
    out, _, _ = run("skills", "list")
    assert out.startswith("st\tSonatype IQ Server CLI")


def sandbox(tmp_path, monkeypatch) -> tuple[Path, Path]:
    """HOME at a temp dir, cwd a fresh git repo."""
    home, repo = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(repo)
    subprocess.run(["git", "init", "-q"], check=True)
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, encoding="utf-8").stdout.strip()
    return home, Path(top)  # resolves /private/var symlinks on macOS


def installed(d: Path) -> bool:
    return (d / "st-upgrade" / "SKILL.md").is_file()


def test_skills_install_targets(tmp_path, monkeypatch):
    home, repo = sandbox(tmp_path, monkeypatch)
    # Piped, no flags: unchanged default.
    _, err, code = run("skills", "install")
    assert code == 0 and installed(home / ".claude" / "skills"), err
    _, err, code = run("skills", "install", "--agent", "copilot,agents", "--scope", "user,project")
    assert code == 0, err
    for d in [home / ".copilot" / "skills", home / ".agents" / "skills", repo / ".github" / "skills", repo / ".agents" / "skills"]:
        assert installed(d), d
    assert not installed(repo / ".claude" / "skills"), "claude project dir written without being asked"
    _, err, code = run("skills", "install", "--project")
    assert code == 0 and installed(repo / ".claude" / "skills"), err
    _, err, code = run("skills", "install", "--agent", "cursor")
    assert code != 0 and "invalid --agent" in err
    _, err, code = run("skills", "install", "--dir", "x", "--project")
    assert code != 0 and "can't be combined" in err
    monkeypatch.chdir(home)
    _, err, code = run("skills", "install", "--scope", "project")
    assert code != 0 and "needs a git repository" in err


def test_skills_install_prompt(tmp_path, monkeypatch):
    home, repo = sandbox(tmp_path, monkeypatch)
    (home / ".claude" / "skills" / "st").mkdir(parents=True)
    (home / ".claude" / "skills" / "st" / "SKILL.md").write_text("old", encoding="utf-8")
    _, err, code = run_tty("skills", "install", stdin="2, 5\n")
    assert code == 0, err
    for want in [
        "1. Claude Code, personal",
        "~/.claude/skills (outdated)",
        "2. GitHub Copilot, personal",
        "~/.copilot/skills (not installed)",
        "5. GitHub Copilot, this repository",
        "Choose one or more",
    ]:
        assert want.replace("/", "\\") in err or want in err, (want, err)
    assert installed(home / ".copilot" / "skills") and installed(repo / ".github" / "skills"), err
    assert not installed(home / ".claude" / "skills"), "unchosen target written"
    # Enter = 1 (Claude, personal).
    _, _, code = run_tty("skills", "install", stdin="\n")
    assert code == 0 and installed(home / ".claude" / "skills")
    _, err, code = run_tty("skills", "install", stdin="9\n")
    assert code != 0 and "between 1 and 6" in err
    _, err, code = run_tty("skills", "install", stdin="")
    assert code != 0 and "no choice made" in err
