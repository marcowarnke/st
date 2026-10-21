"""The st command tree, following gh's (and bb's) UX."""

from __future__ import annotations

import os
import sys
import traceback

from .. import __version__, cli, config, iq, output
from ..cli import Command

# Exit codes: 1 error, 4 auth, 9 no remediation for some components.
EXIT_AUTH = 4
EXIT_NO_REMEDIATION = 9


def new_root() -> Command:
    from . import api, app, auth, fix, skills, status, vuln, waive

    root = Command(
        "st <command> <subcommand> [flags]",
        short="Sonatype IQ Server CLI",
        long="""Find vulnerable dependencies in Sonatype IQ Server (Lifecycle) and the
versions that fix them, from the command line.

Built for agents: output is plain when piped, --json/--jq everywhere, and
the target application is resolved from the git remote of the checkout.""",
        example="""  $ st vuln list
  $ st vuln view CVE-2022-42003
  $ st fix --json purl,target,strategy,parents
  $ st status""",
        version=__version__,
    )
    root.add(
        auth.new_auth_cmd(),
        app.new_app_cmd(),
        vuln.new_vuln_cmd(),
        fix.new_fix_cmd(),
        waive.new_waive_cmd(),
        status.new_status_cmd(),
        api.new_api_cmd(),
        skills.new_skills_cmd(),
    )
    cli.add_completion_command(root)
    cli.add_help_command(root)
    return root


def error_hint(err: BaseException) -> str:
    """Suggest a next step for API errors that are not self-explanatory."""
    api = cli.cause(err, iq.APIError)
    if api is None:
        return ""
    if api.status == 403:
        return "hint: the user lacks permission for this request in IQ Server; ask an IQ administrator"
    if api.status == 404:
        return (
            "hint: IQ Server has no such resource, or the endpoint does not exist in this IQ version. "
            "Check the application and its reports with `st app view`; rerun with ST_DEBUG=1 to see every request"
        )
    if api.status == 429 or api.status >= 500:
        return "hint: IQ Server is overloaded or failing; try again later, or narrow the request (e.g. `st status -S text`)"
    return ""


def _map_error(err: BaseException) -> int:
    if isinstance(err, (cli.Error, OSError)):
        output.err(str(err))
    else:
        output.err(f"st: unexpected error: {type(err).__name__}: {err}")
        if os.environ.get("ST_DEBUG"):
            traceback.print_exception(err, file=output.io.stderr)
    api = cli.cause(err, iq.APIError)
    if (api is not None and api.status == 401) or cli.cause(err, config.NoHostError) is not None:
        return EXIT_AUTH
    hint = error_hint(err)
    if hint:
        output.err(hint)
    return 1


def run(argv: list[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    return cli.run_main(new_root(), argv, _map_error)


def main() -> None:
    output.setup_streams()
    sys.exit(run())
