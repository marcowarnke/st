from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta

from .. import iq
from ..cli import Command, Error, Opts, exact_args
from ..output import add_json_flags, pick, success
from .resolve import add_app_flag, client_for, resolve_app, stage_flag
from .vuln import load_scan

# Waivers always expire: 7 days unless --expires says otherwise, at most 90.
DEFAULT_WAIVER_DAYS = 7
MAX_WAIVER_DAYS = 90

# now is swappable for tests; it returns an aware datetime.
now: Callable[[], datetime] = lambda: datetime.now().astimezone()  # noqa: E731


def add_days(t: datetime, n: int) -> datetime:
    """Calendar days in t's time zone (Go's AddDate). The UTC offset is kept,
    so across a DST change the result is off by an hour at most."""
    return (t.replace(tzinfo=None) + timedelta(days=n)).replace(tzinfo=t.tzinfo)


def parse_expiry(s: str) -> datetime:
    """Accept "<N>d", "<N>w" or a date (YYYY-MM-DD, end of that day in local
    time) and return when the waiver expires."""
    t0 = now()
    bad = Error(f"invalid --expires {json.dumps(s)}: use e.g. 7d, 2w or a date (YYYY-MM-DD)")
    if s.endswith("d") or s.endswith("w"):
        try:
            n = int(s[:-1], 10)
        except ValueError:
            raise bad from None
        if n <= 0:
            raise bad
        if s.endswith("w"):
            n *= 7
        exp = add_days(t0, n)
    else:
        try:
            d = datetime.strptime(s, "%Y-%m-%d")
        except ValueError:
            raise bad from None
        if len(s) != 10:
            raise bad
        exp = d.replace(tzinfo=t0.tzinfo) + timedelta(hours=24) - timedelta(milliseconds=1)
    if not exp > t0:
        raise Error(f"--expires {s} is in the past")
    if exp > add_days(t0, MAX_WAIVER_DAYS):
        raise Error(f"--expires {s} is too far out: waivers expire within {MAX_WAIVER_DAYS} days at most")
    return exp


def waiver_time(t: datetime) -> str:
    """The waiver API's timestamp format, Go layout "2006-01-02T15:04:05.000-0700"."""
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}" + t.strftime("%z")


def new_waive_cmd() -> Command:
    def run(o: Opts) -> None:
        comment = o.comment.strip()
        if not comment:
            raise Error("--comment is required: say why the risk is accepted")
        expiry = parse_expiry(o.expires)
        scope = iq.WAIVE_ALL_VERSIONS if o.all_versions else iq.WAIVE_EXACT_COMPONENT
        c = client_for("")
        app = resolve_app(c, o.app)
        s = load_scan(c, app, o.stage, False)
        arg = o.args[0]
        matched = [f for f in s.findings if f.matches(arg)]
        if not matched:
            raise Error(f"{arg} has no unwaived security violations in {app.get('publicId', '')}'s {s.report.get('stage', '')} report")
        if len(matched) > 1:
            raise Error(f"{arg} matches {len(matched)} components; pass the package URL of one:\n  " + "\n  ".join(f.purl for f in matched))
        f = matched[0]
        vs = [v for v in f.violations if not o.policy or v["policy"].lower() == o.policy.lower()]
        if not vs:
            raise Error(f"{f.name} has no unwaived {o.policy} violation")
        for v in vs:
            if not v["id"]:
                raise Error(f"IQ Server reported no policy violation ID for {f.name}; this IQ version may not support waivers over the API")
        req = {"comment": comment, "expiryTime": waiver_time(expiry), "matcherStrategy": scope}
        out = []
        created: list[str] = []
        for v in vs:
            if not o.dry_run:
                try:
                    c.create_waiver(app.get("id", ""), v["id"], req)
                except Error as e:
                    err = Error(f"waiving {v['policy']} violation of {f.name}: {e}")
                    err.__cause__ = e
                    if not created:
                        raise err from e
                    # Earlier waivers exist now; report them so they aren't created twice.
                    if exp.enabled():
                        exp.write(out)
                    raise Error(
                        f"{err}\n{len(created)} of {len(vs)} waivers were created before this failure "
                        f"({', '.join(created)}); don't create them again"
                    ) from err
                created.append(v["policy"])
            if exp.enabled():
                out.append(
                    pick(
                        {
                            "application": app.get("publicId", ""),
                            "component": f.purl,
                            "violationId": v["id"],
                            "policy": v["policy"],
                            "threatLevel": v["threatLevel"],
                            "scope": scope,
                            "expiresAt": req["expiryTime"],
                            "comment": comment,
                            "dryRun": o.dry_run,
                        },
                        exp.fields,
                    )
                )
                continue
            verb = "Would waive" if o.dry_run else "Waived"
            what = f"{f.name} (all versions)" if o.all_versions else f"{f.name}@{f.version}"
            success(
                f"{verb} {v['policy']} violation (threat {v['threatLevel']}) of {what} in {app.get('publicId', '')} "
                f"until {expiry.strftime('%Y-%m-%d')}"
            )
        if exp.enabled():
            exp.write(out)

    cmd = Command(
        "waive <purl> | <name>",
        short="Waive a component's security policy violations for a limited time",
        long="""Create IQ Server waivers for the unwaived security policy violations of one
component in the application. This is the only st command that changes
anything on the server.

Only waive when a person has decided to accept the risk (false positive,
vulnerable code not reachable, fix scheduled); prefer an upgrade (st fix).
Agents: never waive on your own initiative.

--comment is required and is stored with the waiver: say why the risk is
accepted. Waivers always expire: after 7 days by default, at most 90 days
(--expires 30d, 4w or a date). They cover this version of the component
only, unless --all-versions.

The component is a package URL (with or without version) or a name
("group:artifact" for Maven, the package name elsewhere), and must select
exactly one component. --policy restricts it to one policy's violation.
--dry-run shows what would be waived.

Needs the "Waive Policy Violations" permission in IQ Server.""",
        example="""  $ st waive pkg:maven/org.yaml/snakeyaml@1.26 --comment "SafeConstructor only; untrusted YAML never parsed" --dry-run
  $ st waive lodash --comment "Fix ships in PR #42" --expires 14d
  $ st waive com.fasterxml.jackson.core:jackson-databind --policy Security-High --comment "…" --json violationId,expiresAt""",
        args=exact_args(1),
        run=run,
    )
    add_app_flag(cmd)
    stage_flag(cmd)
    cmd.flag("comment", "m", help="Why the risk is accepted (required)")
    cmd.flag(
        "expires",
        default=f"{DEFAULT_WAIVER_DAYS}d",
        help=f"When the waiver expires: `<N>d`, <N>w or YYYY-MM-DD (at most {MAX_WAIVER_DAYS} days)",
    )
    cmd.flag("policy", help="Only waive this policy's violation")
    cmd.flag("all-versions", kind="bool", help="Waive for every version of the component, not just this one")
    cmd.flag("dry-run", kind="bool", help="Show what would be waived without changing anything")
    exp = add_json_flags(
        cmd, ["application", "comment", "component", "dryRun", "expiresAt", "policy", "scope", "threatLevel", "violationId"]
    )
    return cmd
