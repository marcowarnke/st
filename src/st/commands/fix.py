from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .. import iq, output
from ..cli import Command, Error, ExitError, Opts, cause, maximum_args
from ..output import Struct, TabWriter, add_json_flags, gray, pick, red, truncate, yellow
from .common import ago, first_non_empty
from .resolve import Session, add_app_flag, client_for, resolve_app, stage_flag
from .root import EXIT_NO_REMEDIATION
from .vuln import Finding, Scan, is_vuln_id, load_scan, purl_base, purl_name, purl_version, threat_color

# Strategies in order of preference. Golden versions first (no violations,
# no breaking API changes), then the nearest version without violations,
# then the nearest one that merely stops failing the stage. The
# "-with-dependencies" variants also require the version's own dependencies
# to be clean.
STRATEGIES = [
    "recommended-non-breaking-with-dependencies",
    "recommended-non-breaking",
    "next-no-violations-with-dependencies",
    "next-no-violations",
    "next-non-failing-with-dependencies",
    "next-non-failing",
]


def complete_strategy(strategy: str) -> bool:
    """Whether a strategy clears every policy violation, not only the ones that fail the stage."""
    return not strategy.startswith("next-non-failing")


@dataclass
class Fix:
    f: Finding
    available: bool = False
    strategy: str = ""
    target: str = ""
    target_purl: str = ""
    direct: bool | None = None
    parents: list[dict] = field(default_factory=list)  # name, purl, current, target, targetPurl
    breaking: bool | None = None
    err: str = ""

    def how(self) -> str:
        """What to change: the component itself, or a parent."""
        if not self.available:
            return "no remediation"
        for p in self.parents:
            if p["target"]:
                return f"via {p['name']} {first_non_empty(p['current'], '?')} → {p['target']}"
        if self.direct is False:
            return "transitive"
        if self.direct is None:
            return "unknown"
        return "direct"


def parent_fix(name: str, purl: str = "", current: str = "", target: str = "", target_purl: str = "") -> dict:
    return Struct(name=name, purl=purl, current=current, target=target, targetPurl=target_purl)


def remediate(c: Session, s: Scan, f: Finding, prefer: list[str]) -> Fix:
    """Ask IQ for version changes and pick the preferred one."""
    x = Fix(f=f, direct=f.direct)
    if f.identifier is None:
        x.err = "IQ Server reported no component identifier for this component"
        return x
    try:
        changes = c.remediation(s.app.get("id", ""), s.report.get("stage", ""), f.identifier)
    except Error as e:
        api = cause(e, iq.APIError)
        if api is not None and api.status in (401, 403):
            raise
        x.err = str(e)
        return x
    by_type: dict[str, dict] = {}
    for ch in changes:
        comp = (ch.get("data") or {}).get("component") or {}
        v = iq.identifier_version(comp.get("componentIdentifier")) or purl_version(comp.get("packageUrl") or "")
        if not v or v == f.version or ch.get("type") in by_type:
            continue  # IQ returns the current version when it already satisfies the strategy
        by_type[ch.get("type", "")] = ch
    for st in prefer:
        ch = by_type.get(st)
        if ch is None:
            continue
        comp = (ch.get("data") or {}).get("component") or {}
        x.available, x.strategy = True, st
        x.target_purl = comp.get("packageUrl") or ""
        x.target = first_non_empty(iq.identifier_version(comp.get("componentIdentifier")), purl_version(x.target_purl))
        if ch.get("directDependency") is not None:
            x.direct = bool(ch["directDependency"])
        for dd in ch.get("directDependencyData") or []:
            dc = dd.get("component") or {}
            tp = dc.get("packageUrl") or ""
            p = parent_fix(
                purl_name(tp),
                target=first_non_empty(iq.identifier_version(dc.get("componentIdentifier")), purl_version(tp)),
                target_purl=tp,
            )
            for cur in f.parents:
                if purl_base(cur) == purl_base(tp):
                    p["purl"], p["current"] = cur, purl_version(cur)
            x.parents.append(p)
        break
    if not x.parents and x.direct is False:
        x.parents = [parent_fix(purl_name(cur), cur, purl_version(cur)) for cur in f.parents]
    if x.available:
        x.breaking = breaking(x)
    return x


def breaking(x: Fix) -> bool | None:
    """False for golden versions, else whether the major version of what gets
    bumped changes; None if versions aren't numeric."""
    if x.strategy.startswith("recommended-non-breaking"):
        return False
    cur, tgt = x.f.version, x.target
    for p in x.parents:
        if p["target"] and p["current"]:
            cur, tgt = p["current"], p["target"]
            break
    a, b = major(cur), major(tgt)
    if a is None or b is None:
        return None
    return a != b or (a == 0 and minor(cur) != minor(tgt))  # 0.x minors break by convention


def version_part(v: str, i: int) -> int | None:
    """The i-th numeric dot-separated part of a version."""
    parts = v.removeprefix("v").removeprefix("V").split(".")
    if i >= len(parts):
        return None
    p = parts[i]
    end = next((k for k, ch in enumerate(p) if not ch.isdigit() or not ch.isascii()), len(p))
    p = p[:end]
    return int(p) if p else None


def major(v: str) -> int | None:
    return version_part(v, 0)


def minor(v: str) -> int:
    return version_part(v, 1) or 0


def manifest_hint(x: Fix) -> str:
    """Where the change goes for the ecosystem."""
    f = x.f
    transitive = x.direct is False
    parent_known = any(p["target"] for p in x.parents)
    if transitive and parent_known:
        return "transitive: bump the parent dependency listed in parents to its target version"
    name = f.name
    if f.format == "maven":
        if transitive:
            return (
                f"transitive: find the path with `mvn dependency:tree -Dincludes={name}` or "
                f"`gradle dependencyInsight --dependency {name[name.rfind(':') + 1 :]}`; bump the parent, or pin the "
                "version in <dependencyManagement> (Maven) / a constraints block (Gradle)"
            )
        return "pom.xml or build.gradle: update the version (it may be set by a property, a BOM or dependencyManagement)"
    if f.format == "npm":
        if transitive:
            return (
                f'transitive: `npm why {name}` shows the path; bump the parent, or add an "overrides" (npm) / '
                '"resolutions" (yarn) entry; then refresh the lockfile'
            )
        return "package.json: update the version range, then refresh the lockfile"
    if f.format == "golang":
        return f"`go get {name}@v{x.target.removeprefix('v')} && go mod tidy`"
    if f.format == "pypi":
        if transitive:
            return f"transitive: `pipdeptree -r -p {name}` shows the path; bump the parent or add a constraint"
        return "requirements.txt / pyproject.toml: update the pinned version, then refresh the lockfile"
    if f.format == "nuget":
        if transitive:
            return "transitive: bump the parent, or add a direct <PackageReference> at the target version"
        return "*.csproj / Directory.Packages.props: update the PackageReference version"
    if transitive:
        return "transitive: bump the parent dependency or pin the version in the package manager's override mechanism"
    return "update the dependency version in the manifest"


FIX_FIELDS = [
    "application",
    "available",
    "breaking",
    "complete",
    "current",
    "dependency",
    "direct",
    "error",
    "format",
    "manifestHint",
    "name",
    "parents",
    "purl",
    "reportUrl",
    "resolves",
    "stage",
    "strategy",
    "target",
    "targetPurl",
    "threatLevel",
]


def fix_json(s: Scan, x: Fix, fields: list[str]) -> dict:
    dep = "unknown" if x.direct is None else ("direct" if x.direct else "transitive")
    return pick(
        {
            "application": s.app.get("publicId", ""),
            "available": x.available,
            "breaking": x.breaking,
            "complete": x.available and complete_strategy(x.strategy),
            "current": x.f.version,
            "dependency": dep,
            "direct": x.direct,
            "error": x.err,
            "format": x.f.format,
            "manifestHint": manifest_hint(x),
            "name": x.f.name,
            "parents": x.parents,
            "purl": x.f.purl,
            "reportUrl": s.report_url,
            "resolves": x.f.cves if x.available else [],
            "stage": s.report.get("stage", ""),
            "strategy": x.strategy,
            "target": x.target,
            "targetPurl": x.target_purl,
            "threatLevel": x.f.threat_level,
        },
        fields,
    )


def new_fix_cmd() -> Command:
    def run(o: Opts) -> None:
        for st in o.strategy:
            if st not in STRATEGIES:
                raise Error(f"invalid --strategy {json.dumps(st)}: valid values are\n  " + "\n  ".join(STRATEGIES))
        prefer = o.strategy or STRATEGIES
        c = client_for("")
        app = resolve_app(c, o.app)
        s = load_scan(c, app, o.stage, o.include_waived)
        arg = o.args[0] if o.args else ""
        targets = []
        for f in s.findings:
            if f.threat_level < o.min_threat:
                continue
            if arg and not ((is_vuln_id(arg) and f.has_cve(arg)) or (not is_vuln_id(arg) and f.matches(arg))):
                continue
            targets.append(f)
        if arg and not targets:
            raise Error(f"{arg} has no security violations in {app.get('publicId', '')}'s {s.report.get('stage', '')} report")
        with ThreadPoolExecutor(4) as pool:
            futures = [pool.submit(remediate, c, s, f, prefer) for f in targets]
        errs = [fu.exception() for fu in futures if fu.exception() is not None]
        if errs:
            if len(errs) == 1:
                raise errs[0]
            raise Error("\n".join(str(e) for e in errs)) from errs[0]
        fixes = [fu.result() for fu in futures]
        missing = sum(1 for x in fixes if not x.available)
        if exp.enabled():
            exp.write([fix_json(s, x, exp.fields) for x in fixes])
        else:
            print_fixes(s, fixes)
        if missing:
            raise ExitError(EXIT_NO_REMEDIATION, f"{missing} of {len(fixes)} components have no remediation")

    cmd = Command(
        "fix [<purl> | <name> | <vulnerability-id>]",
        short="Find the version upgrade that fixes vulnerable components",
        long="""Ask IQ Server which version to upgrade each vulnerable component to, and say
how to apply it. st fix only reads; it never edits files.

Without arguments, every component with an (unwaived) security violation in
the latest report is covered. A package URL (with or without version), a
component name ("group:artifact" for Maven, the package name elsewhere), or
a vulnerability ID (CVE-…, sonatype-…) narrows it down.

The target version is IQ's remediation, preferring in this order:
  recommended-non-breaking-with-dependencies  golden version, deps clean too
  recommended-non-breaking                    golden version
  next-no-violations-with-dependencies        nearest clean version, deps clean too
  next-no-violations                          nearest version without violations
  next-non-failing-with-dependencies          nearest version that passes the stage
  next-non-failing                            (may leave non-failing violations)
--strategy changes the order or restricts it.

For transitive dependencies, "parents" names the direct dependency to bump
(and its target version, where IQ knows it: Maven). Otherwise manifestHint
says how to find the path or pin the version.

Fields: "complete" is false when the chosen strategy only stops the stage
failing; "breaking" is false for golden versions, true when the major
version of what you bump changes, null when unknown.

Exit status 9 when some components have no remediation (IQ knows no fixed
version, or the request failed: see "error").""",
        example="""  $ st fix
  $ st fix pkg:maven/com.fasterxml.jackson.core/jackson-databind
  $ st fix CVE-2022-42003 --json name,current,target,strategy,parents,manifestHint
  $ st fix --strategy next-no-violations,next-non-failing""",
        args=maximum_args(1),
        run=run,
    )
    add_app_flag(cmd)
    stage_flag(cmd)
    cmd.flag("strategy", kind="strs", help="Remediation `strategies` to use, in order of preference", complete=STRATEGIES)
    cmd.flag("min-threat", kind="int", help="Only components with a threat level of at least `N` (0-10)")
    cmd.flag("include-waived", kind="bool", help="Include components whose violations are all waived")
    exp = add_json_flags(cmd, FIX_FIELDS)
    return cmd


def print_fixes(s: Scan, fixes: list[Fix]) -> None:
    if not output.io.is_tty():
        for x in fixes:
            output.out(f"{x.f.purl}\t{x.f.version}\t{x.target}\t{x.how()}\t{x.strategy}\t{','.join(x.f.cve_ids())}")
        return
    output.out(
        f"\nRemediation for {len(fixes)} components in {s.app.get('publicId', '')} "
        f"({s.report.get('stage', '')}, evaluated {ago(s.report.get('evaluationDate', ''))})\n"
    )
    if not fixes:
        return
    tw = TabWriter()
    tw.line("THREAT", "COMPONENT", "UPGRADE", "HOW", "STRATEGY")
    notes = []
    for x in fixes:
        upgrade = x.f.version + " → " + first_non_empty(x.target, "–")
        strategy = x.strategy
        if x.breaking:
            strategy += yellow(" ⚠ major bump")
        how = x.how()
        if not x.available:
            how = red(how)
        tw.line(threat_color(x.f.threat_level, str(x.f.threat_level)), truncate(x.f.name, 50), upgrade, how, strategy)
        if x.err:
            notes.append(f"{x.f.name}: {x.err}")
        elif x.available and x.direct is False and not x.how().startswith("via"):
            notes.append(f"{x.f.name}: {manifest_hint(x)}")
    tw.flush()
    for n in notes:
        output.out(f"\n{gray(n)}", end="")
    if notes:
        output.out()
