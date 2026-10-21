"""Wraps the git CLI and normalizes repository URLs so a checkout can be
matched to the repository URL configured on an IQ application."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from urllib.parse import urlsplit

from .cli import Error


def run(*args: str) -> str:
    try:
        p = subprocess.run(["git", *args], capture_output=True, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise Error(f"git {' '.join(args)}: git not found on PATH") from None
    if p.returncode != 0:
        msg = p.stderr.decode("utf-8", "replace").strip() or f"exit status {p.returncode}"
        raise Error(f"git {' '.join(args)}: {msg}")
    return p.stdout.decode("utf-8", "replace").rstrip("\n").replace("\r\n", "\n")


@dataclass
class Remote:
    name: str
    url: str


def remotes() -> list[Remote]:
    """Fetch remotes, upstream first, then origin, like gh."""
    out = run("remote", "-v")
    rs: list[Remote] = []
    seen = set()
    for line in out.split("\n"):
        f = line.split()
        if len(f) < 3 or f[2] != "(fetch)" or f[0] in seen:
            continue
        seen.add(f[0])
        rs.append(Remote(f[0], f[1]))
    rank = {"upstream": 0, "origin": 1}
    rs.sort(key=lambda r: rank.get(r.name, 2))
    return rs


def repo_key(raw: str) -> str | None:
    """Reduce a clone or browse URL to a host-independent "owner/repo" key, so
    SSH and HTTPS remotes of the same repository compare equal:

        https://bitbucket.corp/scm/proj/repo.git        → proj/repo
        ssh://git@bitbucket.corp:7999/proj/repo.git     → proj/repo
        https://bitbucket.corp/projects/PROJ/repos/repo → proj/repo
        git@github.com:org/repo.git                     → org/repo
    """
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        # scp-like syntax: user@host:path
        at, colon = raw.find("@"), raw.find(":")
        if colon < 0 or colon < at:
            return None
        raw = "ssh://" + raw[:colon] + "/" + raw[colon + 1 :]
    try:
        u = urlsplit(raw)
        if not u.netloc:
            return None
    except ValueError:
        return None
    parts = [p for p in u.path.split("/") if p]
    owner = repo = ""
    for i, p in enumerate(parts):
        if p == "scm" and i + 2 < len(parts):
            owner, repo = parts[i + 1], parts[i + 2]
            break
        if p in ("projects", "users") and i + 3 < len(parts) and parts[i + 2] == "repos":
            owner, repo = parts[i + 1], parts[i + 3]
            if p == "users":
                owner = "~" + owner
            break
    if not owner and len(parts) >= 2:
        owner, repo = parts[-2], parts[-1]
    repo = repo.removesuffix(".git")
    if not owner or not repo:
        return None
    return (owner + "/" + repo).lower()
