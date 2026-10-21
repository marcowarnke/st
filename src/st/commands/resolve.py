"""Session setup and application/report resolution."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .. import config, git, iq, output
from ..cli import COMP_NOFILE, Command, Error, ExitError, Opts
from .common import parse_time


class Session(iq.Client):
    """An authenticated client plus the host key it belongs to."""

    host = ""

    def abs_url(self, u: str) -> str:
        """Resolve the server-relative links IQ returns ("ui/links/…")."""
        if not u or "://" in u:
            return u
        return self.url(u)


def new_iq(base_url: str, user: str, password: str) -> Session:
    """Create a client; ST_DEBUG=1 logs every request to stderr."""
    c = Session(base_url, user, password)
    if os.environ.get("ST_DEBUG"):
        c.debug = output.io.stderr
    return c


def client_for(host: str) -> Session:
    cfg = config.Config.load()
    try:
        key, h = cfg.resolve(host)
    except Error as e:
        raise ExitError(4, e) from e
    c = new_iq(h.base_url, h.user, h.token)
    c.host = key
    return c


def add_app_flag(cmd: Command) -> None:
    """Register -A/--app with completion of application public IDs."""
    cmd.flag("app", "A", help="Application public ID (default: ST_APP, else matched from the git remote)", complete=complete_apps)


def complete_apps(o: Opts, to_complete: str) -> tuple[list[str], int]:
    try:
        c = client_for("")
        c.timeout = 5
        apps = c.applications()
    except Exception:
        return [], COMP_NOFILE
    return [f"{a.get('publicId', '')}\t{a.get('name', '')}" for a in apps], COMP_NOFILE


def resolve_app(c: Session, flag: str) -> dict:
    """-A, ST_APP, then the IQ application whose source control repository URL
    matches a git remote of the checkout."""
    if not flag:
        flag = os.environ.get("ST_APP", "")
    if flag:
        return c.application(flag)
    try:
        remotes = git.remotes()
    except Error:
        remotes = []
    keys: list[str] = []
    for r in remotes:
        k = git.repo_key(r.url)
        if k and k not in keys:
            keys.append(k)
    if not keys:
        raise Error("not in a git repository with a remote; pass -A/--app PUBLIC_ID or set ST_APP")
    cache = load_app_cache()
    for k in keys:
        app_id = cache.get(c.host, {}).get(k)
        if app_id:
            try:
                return c.application(app_id)
            except Error:
                pass
    by_repo = scan_repositories(c)
    cache[c.host] = {k: ids[0] for k, ids in by_repo.items() if len(ids) == 1}
    save_app_cache(cache)
    for k in keys:
        ids = by_repo.get(k, [])
        if len(ids) == 1:
            return c.application(ids[0])
        if len(ids) > 1:
            raise Error(f"several applications use repository {k} ({', '.join(sorted(ids))}); pass -A/--app")
    raise Error(f"no IQ application has a repository URL matching {', '.join(keys)}; pass -A/--app PUBLIC_ID or set ST_APP")


def scan_repositories(c: Session) -> dict[str, list[str]]:
    """Map repository keys to application public IDs by reading every
    application's source control configuration."""
    apps = c.applications()
    out: dict[str, list[str]] = {}
    first_err: list[BaseException] = []

    def one(a: dict) -> tuple[dict, Any, BaseException | None]:
        try:
            return a, c.source_control(a.get("id", "")), None
        except Exception as e:
            return a, None, e

    with ThreadPoolExecutor(8) as pool:
        for a, sc, e in pool.map(one, apps):
            if e is not None:
                first_err.append(e)
                continue
            if sc is None:
                continue
            k = git.repo_key(sc.get("repositoryUrl") or "")
            if k:
                out.setdefault(k, []).append(a.get("publicId", ""))
    if first_err and not out:
        raise Error(f"reading source control configuration: {first_err[0]}") from first_err[0]
    return out


def app_cache_path() -> Any:
    """The repository → application map is cached per host in apps.json, since
    building it costs one request per application."""
    return config.config_dir() / "apps.json"


def load_app_cache() -> dict[str, dict[str, str]]:
    try:
        m = json.loads(app_cache_path().read_text(encoding="utf-8"))
        return m if isinstance(m, dict) else {}
    except (OSError, ValueError):
        return {}


def save_app_cache(m: dict) -> None:
    try:
        config.config_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
        data = json.dumps({h: dict(sorted(v.items())) for h, v in sorted(m.items())}, indent=2) + "\n"
        fd = os.open(app_cache_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
    except OSError:
        pass


def pick_report(c: Session, app: dict, stage: str) -> dict:
    """The report for --stage; by default build, else the most recently evaluated stage."""
    reports = c.reports(app.get("id", ""))
    if not reports:
        raise Error(f"application {app.get('publicId', '')} has not been evaluated yet (no reports)")
    want = stage or "build"
    for r in reports:
        if r.get("stage") == want:
            return r
    if stage:
        stages = ", ".join(r.get("stage", "") for r in reports)
        raise Error(f"application {app.get('publicId', '')} has no {stage} report; available stages: {stages}")
    latest = reports[0]
    for r in reports:
        a, b = parse_time(r.get("evaluationDate", "")), parse_time(latest.get("evaluationDate", ""))
        if a is not None and (b is None or a > b):
            latest = r
    return latest


def stage_flag(cmd: Command) -> None:
    cmd.flag("stage", "s", help="Report stage: {" + "|".join(iq.STAGES) + "} (default: build, else the latest)", complete=iq.STAGES)
