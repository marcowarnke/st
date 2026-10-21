from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

from .. import output
from ..cli import Command, Error, Opts, exact_args
from ..iq import path_escape
from .resolve import add_app_flag, client_for, resolve_app


def new_api_cmd() -> Command:
    def run(o: Opts) -> None:
        endpoint = o.args[0].lstrip("/")
        if not endpoint.startswith("api/") and not endpoint.startswith("rest/"):
            endpoint = "api/v2/" + endpoint
        c = client_for(o.hostname)
        if "{app" in endpoint:
            app = resolve_app(c, o.app)
            endpoint = endpoint.replace("{appId}", path_escape(app.get("id", ""))).replace("{app}", path_escape(app.get("publicId", "")))
        params = parse_fields(o.raw_field, o.field)
        method = o.method
        if not method:
            method = "POST" if params or o.input else "GET"
        method = method.upper()
        query: dict[str, Any] = {}
        body: bytes | None = None
        if o.input:
            if o.input == "-":
                body = output.read_stdin().encode("utf-8")
            else:
                with open(o.input, "rb") as f:
                    body = f.read()
            query.update({k: go_sprint(v) for k, v in params.items()})
        elif method == "GET":
            query.update({k: go_sprint(v) for k, v in params.items()})
        elif params:
            body = json.dumps(params).encode("utf-8")
        if "?" in endpoint:
            endpoint, _, qs = endpoint.partition("?")
            query.update(parse_qs(qs, keep_blank_values=True))
        headers = []
        for hv in o.header:
            if ":" not in hv:
                raise Error(f'header {json.dumps(hv)}: expected "key: value"')
            k, _, v = hv.partition(":")
            headers.append((k.strip(), v.strip()))
        resp = c.raw(method, endpoint, query, headers, body)
        if o.include:
            output.out(f"{resp.version} {resp.status} {resp.reason}")
            for k, v in resp.headers:
                output.out(f"{k}: {v}")
            output.out()
        emit(resp.body.decode("utf-8", "replace"), o.jq, o.silent)

    cmd = Command(
        "api <endpoint> [flags]",
        short="Make an authenticated IQ Server API request",
        long="""Make an authenticated HTTP request to the IQ Server REST API and print the response.

The endpoint is a path such as "api/v2/applications". Paths not starting
with "api/" or "rest/" are prefixed with "api/v2/".

The placeholders {app} (public ID) and {appId} (internal ID) are replaced
with the application of the current checkout (or -A).

The default method is GET without parameters and POST with them. Pass
-X GET to send -f/-F fields as query parameters.

-f key=value adds a string parameter; -F key=value adds a typed one
(true, false, null, integers, and @file to read a value from a file;
"@-" reads from stdin). Nested keys use key[sub]=value.

--jq needs the jq command on PATH.""",
        example="""  $ st api applications --jq '.applications[].publicId'
  $ st api reports/applications/{appId}
  $ st api -X POST components/remediation/application/{appId} --input component.json
  $ st api policies""",
        args=exact_args(1),
        run=run,
    )
    cmd.flag("method", "X", help="The HTTP method for the request")
    cmd.flag("raw-field", "f", kind="array", help="Add a string parameter in `key=value` format")
    cmd.flag("field", "F", kind="array", help="Add a typed parameter in `key=value` format")
    cmd.flag("header", "H", kind="array", help="Add a HTTP request header in `key:value` format")
    cmd.flag("input", help='The `file` to use as body for the HTTP request (use "-" to read from standard input)')
    cmd.flag("include", "i", kind="bool", help="Include HTTP response status line and headers in the output")
    cmd.flag("silent", kind="bool", help="Do not print the response body")
    cmd.flag("jq", "q", help="Query to select values from the response using jq syntax")
    cmd.flag("hostname", help="The IQ Server host for the request")
    add_app_flag(cmd)
    return cmd


def emit(raw: str, jq: str, silent: bool) -> None:
    if silent or not raw:
        return
    if jq:
        output.out(output.run_jq(jq, raw), end="")
        return
    if output.io.is_tty():
        try:
            # Like Go's json.Indent, which keeps the body's trailing whitespace.
            trailing = raw[len(raw.rstrip(" \t\r\n")) :]
            output.out(json.dumps(json.loads(raw), indent=2, ensure_ascii=False) + trailing)
            return
        except ValueError:
            pass
    output.out(raw, end="" if raw.endswith("\n") else "\n")


def go_sprint(v: Any) -> str:
    """fmt.Sprint of a parameter value."""
    if v is None:
        return "<nil>"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, dict):
        return "map[" + " ".join(f"{k}:{go_sprint(x)}" for k, x in sorted(v.items())) + "]"
    return str(v)


def parse_fields(raw: list[str], typed: list[str]) -> dict[str, Any]:
    """Build a (possibly nested) parameter map from -f and -F values."""
    out: dict[str, Any] = {}

    def add(kv: str, is_typed: bool) -> None:
        if "=" not in kv:
            raise Error(f"field {json.dumps(kv)}: expected key=value")
        k, _, v = kv.partition("=")
        val: Any = typed_value(v) if is_typed else v
        keys = k.replace("]", "").split("[")
        m = out
        for key in keys[:-1]:
            nxt = m.get(key)
            if not isinstance(nxt, dict):
                nxt = {}
                m[key] = nxt
            m = nxt
        m[keys[-1]] = val

    for kv in raw:
        add(kv, False)
    for kv in typed:
        add(kv, True)
    return out


def typed_value(v: str) -> Any:
    if v == "true":
        return True
    if v == "false":
        return False
    if v == "null":
        return None
    try:
        if v.lstrip("+-").isdigit():
            return int(v, 10)
    except ValueError:
        pass
    if v.startswith("@"):
        if v == "@-":
            data = output.read_stdin()
        else:
            with open(v[1:], encoding="utf-8") as f:
                data = f.read()
        return data.rstrip("\n")
    return v
