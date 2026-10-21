from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from .. import iq, output
from ..cli import Command, Error, Opts, exact_args, no_args
from ..output import Struct, TabWriter, add_json_flags, bold, gray, pick, red, truncate, yellow
from .common import ago, first_non_empty
from .resolve import Session, add_app_flag, client_for, pick_report, resolve_app, stage_flag


def new_vuln_cmd() -> Command:
    cmd = Command("vuln <command>", short="List and view vulnerabilities", aliases=["vulnerability"])
    cmd.add(new_vuln_list_cmd(), new_vuln_view_cmd())
    return cmd


@dataclass
class Finding:
    """A component with security policy violations in a report."""

    hash: str = ""
    purl: str = ""
    name: str = ""
    format: str = ""
    version: str = ""
    identifier: dict | None = None
    direct: bool | None = None  # None: IQ didn't say
    parents: list[str] = field(default_factory=list)
    threat_level: int = 0
    policies: list[str] = field(default_factory=list)
    waived: bool = False  # every security violation is waived
    cves: list[dict] = field(default_factory=list)
    violations: list[dict] = field(default_factory=list)  # unwaived security violations

    def dependency(self) -> str:
        if self.direct is None:
            return "unknown"
        return "direct" if self.direct else "transitive"

    def cve_ids(self) -> list[str]:
        return [c["id"] for c in self.cves]

    def matches(self, arg: str) -> bool:
        """Whether a component argument (purl with or without version or
        qualifiers, or name) selects the finding."""
        if arg.startswith("pkg:"):
            if purl_type(arg) != purl_type(self.purl):
                return False
            if purl_version(arg) == "":
                return purl_base(arg) == purl_base(self.purl)
            return purl_without_qualifiers(arg) == purl_without_qualifiers(self.purl)
        name, _, version = arg.partition("@")
        return name.lower() == self.name.lower() and (version == "" or version == self.version)

    def has_cve(self, vid: str) -> bool:
        return any(c["id"].lower() == vid.lower() for c in self.cves)


@dataclass
class Scan:
    """The security view of one application report."""

    app: dict
    report: dict
    report_url: str
    findings: list[Finding] = field(default_factory=list)


def cve(vid: str, severity: float, threat_category: str = "", status: str = "", url: str = "") -> dict:
    """One vulnerability on a component."""
    d: dict[str, Any] = Struct(id=vid, severity=severity)
    if threat_category:
        d["threatCategory"] = threat_category
    if status:
        d["status"] = status
    if url:
        d["url"] = url
    return d


VULN_REASON = re.compile(r"(?i)security vulnerability (\S+) with severity ([\d.]+)")


def load_scan(c: Session, app: dict, stage: str, include_waived: bool) -> Scan:
    """Join the policy report (violations, threat levels) with the raw report
    (CVE details, dependency data) by component hash."""
    return load_scan_with(c, app, stage, include_waived, True)


def load_scan_with(c: Session, app: dict, stage: str, include_waived: bool, with_raw: bool) -> Scan:
    """Read the raw report only if with_raw, or if the policy report lacks
    dependency data for a component with security violations (older IQ
    versions). Without it, CVE details come only from the violation reasons."""
    rep = pick_report(c, app, stage)
    public_id, rid = app.get("publicId", ""), iq.report_id(rep)
    raw: list[dict] = []
    if with_raw:
        with ThreadPoolExecutor(2) as pool:
            pf = pool.submit(c.policy_report, public_id, rid)
            rf = pool.submit(c.raw_report, public_id, rid)
            pexc, rexc = pf.exception(), rf.exception()
            if pexc is not None:
                raise pexc
            if rexc is not None:
                raise rexc
            policy, raw = pf.result(), rf.result()
    else:
        policy = c.policy_report(public_id, rid)
        if missing_dependency_data(policy):
            raw = c.raw_report(public_id, rid)
    raw_by_hash = {r.get("hash", ""): r for r in raw}
    s = Scan(app, rep, c.abs_url(rep.get("reportHtmlUrl", "")))
    for pc in policy.get("components") or []:
        sec = [v for v in pc.get("violations") or [] if iq.is_security(v)]
        active = any(not v.get("waived") for v in sec)
        if not sec or (not active and not include_waived):
            continue
        f = Finding(hash=pc.get("hash", ""), purl=pc.get("packageUrl") or "", identifier=pc.get("componentIdentifier"), waived=not active)
        rc = raw_by_hash.get(pc.get("hash", ""))
        if rc is not None:
            f.purl = f.purl or rc.get("packageUrl") or ""
            if f.identifier is None:
                f.identifier = rc.get("componentIdentifier")
        dep = pc.get("dependencyData")
        if dep is None and rc is not None:
            dep = rc.get("dependencyData")
        if dep is not None:
            f.direct = bool(dep.get("directDependency"))
            f.parents = list(dep.get("parentComponentPurls") or [])
        if f.identifier is not None:
            f.format = f.identifier.get("format") or ""
        f.name, f.version = purl_name(f.purl), purl_version(f.purl)
        if not f.name:
            f.name = first_non_empty(pc.get("displayName") or "", f.hash)
        if not f.version:
            f.version = iq.identifier_version(f.identifier)
        if not f.format:
            f.format = purl_type(f.purl)
        # CVEs named by the violations, enriched with the raw report's data.
        issues = {}
        if rc is not None:
            for i in (rc.get("securityData") or {}).get("securityIssues") or []:
                issues[i.get("reference", "")] = i
        seen = set()
        for v in sec:
            if v.get("waived") and active:
                continue
            level = int(v.get("policyThreatLevel") or 0)
            f.threat_level = max(f.threat_level, level)
            if not v.get("waived"):
                f.violations.append(Struct(id=v.get("policyViolationId") or "", policy=v.get("policyName") or "", threatLevel=level))
            if v.get("policyName", "") not in f.policies:
                f.policies.append(v.get("policyName") or "")
            for con in v.get("constraints") or []:
                for cond in con.get("conditions") or []:
                    m = VULN_REASON.search(cond.get("conditionReason") or "")
                    if m is None or m.group(1) in seen:
                        continue
                    seen.add(m.group(1))
                    try:
                        sev = float(m.group(2))
                    except ValueError:
                        sev = 0.0
                    x = cve(m.group(1), sev)
                    if m.group(1) in issues:
                        i = issues[m.group(1)]
                        x = cve(
                            m.group(1), i.get("severity") or 0, i.get("threatCategory") or "", i.get("status") or "", i.get("url") or ""
                        )
                    f.cves.append(x)
        if not f.cves:  # conditions without a parseable reason: list what the raw report has
            for i in issues.values():
                if str(i.get("status", "")).lower() != "not applicable":
                    f.cves.append(
                        cve(
                            i.get("reference") or "",
                            i.get("severity") or 0,
                            i.get("threatCategory") or "",
                            i.get("status") or "",
                            i.get("url") or "",
                        )
                    )
        f.cves.sort(key=lambda x: (-x["severity"], x["id"]))
        s.findings.append(f)
    s.findings.sort(key=lambda f: (-f.threat_level, f.name))
    return s


def missing_dependency_data(p: dict) -> bool:
    for pc in p.get("components") or []:
        for v in pc.get("violations") or []:
            if iq.is_security(v) and pc.get("dependencyData") is None:
                return True
    return False


# purl helpers. "pkg:maven/g/a@1.0?type=jar" → type "maven", base
# "pkg:maven/g/a", name "g:a", version "1.0".


def purl_split(p: str) -> tuple[str, str, str]:
    p = p.removeprefix("pkg:")
    m = re.search(r"[?#]", p)
    if m:
        p = p[: m.start()]
    typ, _, path = p.partition("/")
    version = ""
    i = path.rfind("@")
    if i > 0:
        path, version = path[:i], path[i + 1 :]
    return typ, path, _unescape(version)


def _unescape(s: str) -> str:
    try:
        return unquote(s, errors="strict")
    except UnicodeDecodeError:
        return s


def purl_type(p: str) -> str:
    return purl_split(p)[0]


def purl_version(p: str) -> str:
    return purl_split(p)[2]


def purl_base(p: str) -> str:
    t, path, _ = purl_split(p)
    return f"pkg:{t}/{path}"


def purl_without_qualifiers(p: str) -> str:
    m = re.search(r"[?#]", p)
    return p[: m.start()] if m else p


def purl_name(p: str) -> str:
    if not p:
        return ""
    t, path, _ = purl_split(p)
    path = _unescape(path)
    if t == "maven":
        return path.replace("/", ":")
    return path


def is_vuln_id(s: str) -> bool:
    u = s.upper()
    return u.startswith("CVE-") or u.startswith("SONATYPE-") or u.startswith("GHSA-")


FINDING_FIELDS = [
    "application",
    "componentIdentifier",
    "cves",
    "dependency",
    "direct",
    "format",
    "hash",
    "name",
    "parents",
    "policies",
    "purl",
    "reportUrl",
    "stage",
    "threatLevel",
    "version",
    "violations",
    "waived",
]


def finding_json(s: Scan, f: Finding, fields: list[str]) -> dict:
    return pick(
        {
            "application": s.app.get("publicId", ""),
            "componentIdentifier": identifier_json(f.identifier),
            "cves": f.cves,
            "dependency": f.dependency(),
            "direct": f.direct,
            "format": f.format,
            "hash": f.hash,
            "name": f.name,
            "parents": f.parents,
            "policies": f.policies or None,
            "purl": f.purl,
            "reportUrl": s.report_url,
            "stage": s.report.get("stage", ""),
            "threatLevel": f.threat_level,
            "version": f.version,
            "violations": f.violations,
            "waived": f.waived,
        },
        fields,
    )


def identifier_json(ci: dict | None) -> Struct | None:
    """IQ's {format, coordinates} component key."""
    if ci is None:
        return None
    return Struct(format=ci.get("format") or "", coordinates=ci.get("coordinates"))


OMIT = object()


def _structs(items: list | None, **fields: Any) -> list | None:
    """Keep only the fields the Go version decoded, in its order; fields maps
    each name to its zero value (OMIT: left out when empty)."""
    if items is None:
        return None
    out = []
    for x in items:
        st = Struct()
        for k, zero in fields.items():
            v = x.get(k)
            if zero is OMIT and not v:
                continue
            st[k] = zero if v is None else v
        out.append(st)
    return out


def threat_color(level: int, s: str) -> str:
    if level >= 8:
        return red(s)
    if level >= 4:
        return yellow(s)
    return gray(s)


def new_vuln_list_cmd() -> Command:
    def run(o: Opts) -> None:
        if o.direct and o.transitive:
            raise Error("--direct and --transitive are mutually exclusive")
        c = client_for("")
        app = resolve_app(c, o.app)
        s = load_scan(c, app, o.stage, o.include_waived)
        rows: list[Finding] = []
        for f in s.findings:
            if (
                f.threat_level < o.min_threat
                or (o.direct and f.dependency() != "direct")
                or (o.transitive and f.dependency() != "transitive")
                or (o.cve and not f.has_cve(o.cve))
            ):
                continue
            rows.append(f)
            if o.limit > 0 and len(rows) >= o.limit:
                break
        if exp.enabled():
            exp.write([finding_json(s, f, exp.fields) for f in rows])
            return
        print_findings(s, rows)

    cmd = Command(
        "list",
        short="List components with security policy violations",
        long="""List the components of an application that violate a security policy in its
latest report, highest threat level first. One row per component, with the
vulnerabilities (CVE or sonatype-* IDs) that cause the violations.

The application comes from -A, ST_APP, or the IQ application whose source
control repository URL matches a git remote of the current checkout. The
report is the build stage's by default (else the most recent); see --stage.

Waived violations are left out unless --include-waived.

"dependency" is direct, transitive or unknown (IQ didn't report it);
"parents" are the direct dependencies that pull a transitive one in.""",
        example="""  $ st vuln list
  $ st vuln list --min-threat 8 --direct
  $ st vuln list -A my-service --stage release --json name,version,cves --jq '.[].name'""",
        args=no_args,
        run=run,
    )
    add_app_flag(cmd)
    stage_flag(cmd)
    cmd.flag("min-threat", kind="int", help="Only components with a threat level of at least `N` (0-10)")
    cmd.flag("direct", kind="bool", help="Only direct dependencies")
    cmd.flag("transitive", kind="bool", help="Only transitive dependencies")
    cmd.flag("cve", help="Only components affected by vulnerability `ID`")
    cmd.flag("include-waived", kind="bool", help="Include components whose violations are all waived")
    cmd.flag("limit", "L", kind="int", help="Maximum number of components to list")
    exp = add_json_flags(cmd, FINDING_FIELDS)
    return cmd


def print_findings(s: Scan, rows: list[Finding]) -> None:
    if not output.io.is_tty():
        for f in rows:
            output.out(f"{f.threat_level}\t{f.purl}\t{f.dependency()}\t{','.join(f.cve_ids())}\t{','.join(f.policies)}")
        return
    output.out(
        f"\nShowing {len(rows)} vulnerable components in {s.app.get('publicId', '')} "
        f"({s.report.get('stage', '')}, evaluated {ago(s.report.get('evaluationDate', ''))})\n"
    )
    if not rows:
        return
    tw = TabWriter()
    tw.line("THREAT", "COMPONENT", "VERSION", "DEPENDENCY", "VULNERABILITIES")
    for f in rows:
        ids, more = f.cve_ids(), ""
        if len(ids) > 3:
            ids, more = ids[:3], f" +{len(f.cves) - 3}"
        dep = f.dependency() + (" (waived)" if f.waived else "")
        tw.line(threat_color(f.threat_level, str(f.threat_level)), truncate(f.name, 50), f.version, gray(dep), " ".join(ids) + gray(more))
    tw.flush()
    output.out(f"\n{gray(s.report_url)}")


VULN_FIELDS = [
    "advisories",
    "categories",
    "cwes",
    "description",
    "detection",
    "detectionType",
    "explanation",
    "id",
    "kev",
    "link",
    "recommendation",
    "researchType",
    "rootCauses",
    "score",
    "severityScores",
    "source",
    "vector",
    "vulnIds",
    "vulnerableVersionRanges",
]


def vuln_json(v: dict, fields: list[str]) -> dict:
    m: dict[str, Any] = {
        "advisories": _structs(v.get("advisories"), referenceType="", url=""),
        "categories": v.get("categories"),
        "description": v.get("description", ""),
        "detection": v.get("detectionMarkdown", ""),
        "detectionType": v.get("detectionType", ""),
        "explanation": v.get("explanationMarkdown", ""),
        "id": v.get("identifier", ""),
        "link": v.get("vulnerabilityLink", ""),
        "recommendation": v.get("recommendationMarkdown", ""),
        "researchType": v.get("researchType", ""),
        "rootCauses": _structs(v.get("rootCauses"), listOfPaths=None, versionRange=""),
        "severityScores": _structs(v.get("severityScores"), source="", score=0, vector=OMIT),
        "vulnIds": v.get("vulnIds"),
        "vulnerableVersionRanges": v.get("vulnerableVersionRanges"),
        "cwes": [],
        "kev": False,
        "score": None,
        "vector": "",
        "source": "",
    }
    if v.get("weakness"):
        m["cwes"] = ["CWE-" + str(c.get("id", "")).removeprefix("CWE-") for c in v["weakness"].get("cweIds") or []] or None
    if v.get("kevData"):
        m["kev"] = bool(v["kevData"].get("isKev"))
    if v.get("mainSeverity"):
        m["score"], m["vector"] = v["mainSeverity"].get("score", 0), v["mainSeverity"].get("vector", "")
    if v.get("source"):
        m["source"] = v["source"].get("shortName", "")
    return pick(m, fields)


def new_vuln_view_cmd() -> Command:
    def run(o: Opts) -> None:
        c = client_for("")
        v = c.vulnerability(o.args[0])
        if exp.enabled():
            exp.write(vuln_json(v, exp.fields))
            return
        print_vuln(v)

    cmd = Command(
        "view <id>",
        short="View a vulnerability",
        long="""Show a vulnerability by CVE or Sonatype ID: severity, CWE, whether it is
known to be exploited (CISA KEV), the vulnerable version ranges, and
Sonatype's description, explanation and recommendation.""",
        example="""  $ st vuln view CVE-2022-42003
  $ st vuln view sonatype-2021-4682 --json vulnerableVersionRanges,recommendation""",
        args=exact_args(1),
        run=run,
    )
    exp = add_json_flags(cmd, VULN_FIELDS)
    return cmd


def print_vuln(v: dict) -> None:
    m = vuln_json(v, VULN_FIELDS)
    output.out(bold(first_non_empty(v.get("identifier", ""), "(redacted)")))
    ms = v.get("mainSeverity")
    if ms:
        score = float(ms.get("score") or 0)
        output.out(f"Severity:   {threat_color(int(score + 0.5), f'{score:.1f}')} {gray(ms.get('vector', ''))}")
    if m["cwes"]:
        output.out(f"Weakness:   {', '.join(m['cwes'])}")
    if m["kev"] is True:
        output.out(f"Exploited:  {red('yes — listed in CISA KEV')}")
    if v.get("vulnerableVersionRanges"):
        output.out(f"Vulnerable: {' '.join(v['vulnerableVersionRanges'])}")
    if v.get("vulnerabilityLink"):
        output.out(f"Link:       {v['vulnerabilityLink']}")
    for title, key in (
        ("Description", "description"),
        ("Explanation", "explanationMarkdown"),
        ("Detection", "detectionMarkdown"),
        ("Recommendation", "recommendationMarkdown"),
    ):
        body = (v.get(key) or "").strip()
        if body:
            output.out(f"\n{bold(title)}\n{body}")
    if v.get("rootCauses"):
        output.out(f"\n{bold('Root causes')}")
        for rc in v["rootCauses"]:
            output.out(f"  {rc.get('versionRange', '')}  {' › '.join(rc.get('listOfPaths') or [])}")
    if v.get("advisories"):
        output.out(f"\n{bold('Advisories')}")
        for a in v["advisories"]:
            output.out(f"  {gray(str(a.get('referenceType', '')).lower())}  {a.get('url', '')}")
