from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .. import iq, output
from ..cli import Command, Error, Opts, cause, no_args
from ..output import TabWriter, add_json_flags, cyan, gray, pick, truncate
from .common import ago
from .resolve import client_for, stage_flag
from .vuln import Scan, load_scan_with, threat_color


@dataclass
class AppStatus:
    app: dict
    scan: Scan | None = None
    err: BaseException | None = None


def new_status_cmd() -> Command:
    def run(o: Opts) -> None:
        c = client_for("")
        apps = c.applications()
        sts = [AppStatus(a) for a in apps if not o.search or o.search.lower() in (a.get("publicId", "") + " " + a.get("name", "")).lower()]

        def scan(st: AppStatus) -> None:
            try:
                st.scan = load_scan_with(c, st.app, o.stage, False, False)
            except Error as e:
                st.err = e

        with ThreadPoolExecutor(8) as pool:
            list(pool.map(scan, sts))
        for st in sts:
            api = cause(st.err, iq.APIError)
            if api is not None and api.status == 401:
                raise st.err  # type: ignore[misc]

        def threat(st: AppStatus) -> int:
            if st.scan is None or not st.scan.findings:
                return -1
            return st.scan.findings[0].threat_level

        def count(st: AppStatus) -> tuple[int, int]:
            if st.scan is None:
                return 0, 0
            hits = [f for f in st.scan.findings if f.threat_level >= o.min_threat]
            return len(hits), sum(1 for f in hits if f.dependency() == "direct")

        sts.sort(key=lambda st: (-threat(st), st.app.get("publicId", "")))
        if exp.enabled():
            rows = []
            for st in sts:
                n, d = count(st)
                m = {
                    "application": st.app.get("publicId", ""),
                    "name": st.app.get("name", ""),
                    "components": n,
                    "direct": d,
                    "threatLevel": max(threat(st), 0),
                    "stage": "",
                    "evaluationDate": "",
                    "reportUrl": "",
                    "error": "",
                }
                if st.scan is not None:
                    m["stage"], m["evaluationDate"] = st.scan.report.get("stage", ""), st.scan.report.get("evaluationDate", "")
                    m["reportUrl"] = st.scan.report_url
                if st.err is not None:
                    m["error"] = str(st.err)
                rows.append(pick(m, exp.fields))
            exp.write(rows)
            return
        tty = output.io.is_tty()
        tw = TabWriter()
        if tty:
            tw.line("APPLICATION", "THREAT", "COMPONENTS", "DIRECT", "STAGE", "EVALUATED")
        for st in sts:
            n, d = count(st)
            pid = st.app.get("publicId", "")
            if st.err is not None:
                if tty:
                    tw.line(pid, "", "", "", "", gray(truncate(str(st.err), 70)))
                else:
                    output.out(f"{pid}\t\t\t\t\terror: {st.err}")
                continue
            assert st.scan is not None
            lvl = str(max(threat(st), 0))
            rep = st.scan.report
            if not tty:
                output.out(f"{pid}\t{lvl}\t{n}\t{d}\t{rep.get('stage', '')}\t{rep.get('evaluationDate', '')}")
                continue
            tw.line(cyan(pid), threat_color(threat(st), lvl), n, d, rep.get("stage", ""), gray(ago(rep.get("evaluationDate", ""))))
        tw.flush()

    cmd = Command(
        "status",
        short="Security dashboard across all applications",
        long="""For every application you can see, count the components with unwaived
security violations in its latest report (build by default), and the
highest threat level. Applications with findings come first.

This reads the report list and the policy report of each application
(two requests per application); narrow it with -S.""",
        example="""  $ st status
  $ st status --min-threat 8 --json application,threatLevel,components""",
        args=no_args,
        run=run,
    )
    stage_flag(cmd)
    cmd.flag("search", "S", help="Only applications whose public ID or name contains `text`")
    cmd.flag("min-threat", kind="int", help="Only count components with a threat level of at least `N`")
    exp = add_json_flags(
        cmd, ["application", "components", "direct", "error", "evaluationDate", "name", "reportUrl", "stage", "threatLevel"]
    )
    return cmd
