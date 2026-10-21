from __future__ import annotations

from .. import iq, output
from ..cli import Command, Error, Opts, maximum_args, no_args
from ..output import TabWriter, add_json_flags, bold, cyan, gray, pick
from .common import ago
from .resolve import client_for, complete_apps, resolve_app


def new_app_cmd() -> Command:
    cmd = Command("app <command>", short="List and view IQ applications", aliases=["application"])
    cmd.add(new_app_list_cmd(), new_app_view_cmd())
    return cmd


APP_FIELDS = ["id", "name", "organizationId", "publicId"]


def new_app_list_cmd() -> Command:
    def run(o: Opts) -> None:
        c = client_for("")
        apps = sorted(c.applications(), key=lambda a: a.get("publicId", ""))
        rows = [a for a in apps if not o.search or o.search.lower() in (a.get("publicId", "") + " " + a.get("name", "")).lower()]
        if exp.enabled():
            exp.write(
                [
                    pick(
                        {
                            "id": a.get("id", ""),
                            "name": a.get("name", ""),
                            "organizationId": a.get("organizationId", ""),
                            "publicId": a.get("publicId", ""),
                        },
                        exp.fields,
                    )
                    for a in rows
                ]
            )
            return
        if not output.io.is_tty():
            for a in rows:
                output.out(f"{a.get('publicId', '')}\t{a.get('name', '')}\t{a.get('id', '')}")
            return
        tw = TabWriter()
        tw.line("PUBLIC ID", "NAME")
        for a in rows:
            tw.line(cyan(a.get("publicId", "")), a.get("name", ""))
        tw.flush()

    cmd = Command(
        "list",
        short="List applications",
        example="""  $ st app list
  $ st app list -S payments --json publicId --jq '.[].publicId'""",
        args=no_args,
        run=run,
    )
    cmd.flag("search", "S", help="Filter by public ID or name")
    exp = add_json_flags(cmd, APP_FIELDS)
    return cmd


APP_VIEW_FIELDS = ["baseBranch", "id", "name", "organizationId", "publicId", "reports", "repositoryUrl"]


def new_app_view_cmd() -> Command:
    def run(o: Opts) -> None:
        c = client_for("")
        app = resolve_app(c, o.args[0] if o.args else "")
        reports = c.reports(app.get("id", ""))
        if o.web:
            if not reports:
                raise Error(f"application {app.get('publicId', '')} has no reports yet")
            r = reports[0]
            for x in reports:
                if x.get("stage") == "build":
                    r = x
            output.open_browser(c.abs_url(r.get("latestReportHtmlUrl", "")))
            return
        try:
            sc = c.source_control(app.get("id", ""))
        except Error:
            sc = None  # needs extra permissions on some servers; the rest is still useful
        sc = sc or {}
        reps = [
            {
                "stage": r.get("stage", ""),
                "evaluationDate": r.get("evaluationDate", ""),
                "reportId": iq.report_id(r),
                "reportUrl": c.abs_url(r.get("reportHtmlUrl", "")),
                "latestReportUrl": c.abs_url(r.get("latestReportHtmlUrl", "")),
            }
            for r in reports
        ]
        if exp.enabled():
            exp.write(
                pick(
                    {
                        "baseBranch": sc.get("baseBranch", ""),
                        "id": app.get("id", ""),
                        "name": app.get("name", ""),
                        "organizationId": app.get("organizationId", ""),
                        "publicId": app.get("publicId", ""),
                        "reports": reps,
                        "repositoryUrl": sc.get("repositoryUrl", ""),
                    },
                    exp.fields,
                )
            )
            return
        output.out(f"{bold(app.get('name', ''))} {gray('(' + app.get('publicId', '') + ')')}")
        if sc.get("repositoryUrl"):
            line = f"Repository: {sc['repositoryUrl']}"
            if sc.get("baseBranch"):
                line += f" ({sc['baseBranch']})"
            output.out(line)
        if not reports:
            output.out("\nNo reports yet")
            return
        output.out()
        tw = TabWriter()
        tw.line("STAGE", "EVALUATED", "REPORT")
        for r in reports:
            tw.line(r.get("stage", ""), ago(r.get("evaluationDate", "")), c.abs_url(r.get("reportHtmlUrl", "")))
        tw.flush()

    cmd = Command(
        "view [<public-id>]",
        short="View an application, its repository and latest reports",
        long="""Show an application, its source control repository and its latest report
per stage. Without an argument, the application of the current checkout
(ST_APP, or matched from the git remote).""",
        example="""  $ st app view
  $ st app view my-service --json reports --jq '.reports[] | select(.stage=="build").reportUrl'""",
        args=maximum_args(1),
        run=run,
        complete_args=complete_apps,
    )
    cmd.flag("web", "w", kind="bool", help="Open the latest report in the browser")
    exp = add_json_flags(cmd, APP_VIEW_FIELDS)
    return cmd
