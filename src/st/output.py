"""Terminal I/O: swappable streams, colors, gh-style --json/--jq/--format
export, Go-compatible JSON and a port of Go's text/tabwriter."""

from __future__ import annotations

import io as _io
import json
import os
import re
import shutil
import string
import subprocess
import sys
from collections.abc import Iterable
from typing import Any


class _IO:
    """The process streams; tests replace them."""

    def __init__(self) -> None:
        self.stdin: Any = sys.stdin
        self.stdout: Any = sys.stdout
        self.stderr: Any = sys.stderr
        self.tty: bool | None = None  # None: ask the real stdout

    def is_tty(self) -> bool:
        if self.tty is not None:
            return self.tty
        try:
            return self.stdout.isatty()
        except (AttributeError, ValueError):
            return False


io = _IO()


def setup_streams() -> None:
    """UTF-8 everywhere and "\\n" line endings, as the Go binaries wrote them."""
    for name in ("stdout", "stderr"):
        s = getattr(sys, name)
        try:
            s.reconfigure(encoding="utf-8", errors="replace", newline="\n")
        except (AttributeError, ValueError):
            pass
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    io.stdin, io.stdout, io.stderr = sys.stdin, sys.stdout, sys.stderr
    if os.name == "nt":
        _enable_windows_ansi()


def _enable_windows_ansi() -> None:
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            h = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                kernel32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def out(s: str = "", end: str = "\n") -> None:
    io.stdout.write(s + end)


def err(s: str = "", end: str = "\n") -> None:
    io.stderr.write(s + end)


def read_stdin() -> str:
    return io.stdin.read()


def color_on() -> bool:
    return io.is_tty() and os.environ.get("NO_COLOR", "") == ""


def paint(code: str, s: str) -> str:
    if not color_on():
        return s
    return f"\x1b[{code}m{s}\x1b[0m"


def green(s: str) -> str:
    return paint("32", s)


def red(s: str) -> str:
    return paint("31", s)


def yellow(s: str) -> str:
    return paint("33", s)


def magenta(s: str) -> str:
    return paint("35", s)


def gray(s: str) -> str:
    return paint("90", s)


def bold(s: str) -> str:
    return paint("1", s)


def cyan(s: str) -> str:
    return paint("36", s)


def success(msg: str) -> None:
    mark = "✓"
    if io.is_tty():
        mark = green(mark)
    err(f"{mark} {msg}")


def truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def plural(n: int, unit: str) -> str:
    if n == 1:
        return "about 1 " + unit
    return f"about {n} {unit}s"


def ago_seconds(d: float) -> str:
    """Renders a duration in seconds like the Go versions' ago()."""
    hours = d / 3600
    if d < 60:
        return "less than a minute ago"
    if d < 3600:
        return plural(int(d // 60), "minute") + " ago"
    if hours < 24:
        return plural(int(hours), "hour") + " ago"
    if hours < 30 * 24:
        return plural(int(hours / 24), "day") + " ago"
    if hours < 365 * 24:
        return plural(int(hours / 24 / 30), "month") + " ago"
    return plural(int(hours / 24 / 365), "year") + " ago"


def open_browser(url: str) -> None:
    if io.is_tty():
        err(f"Opening {url} in your browser.")
    b = os.environ.get("BROWSER", "")
    if b:
        cmd = [b, url]
    elif sys.platform == "darwin":
        cmd = ["open", url]
    elif os.name == "nt":
        cmd = ["rundll32", "url.dll,FileProtocolHandler", url]
    else:
        cmd = ["xdg-open", url]
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# JSON


class Struct(dict):
    """A JSON object that keeps its key order, like a Go struct; plain dicts
    are written with sorted keys, like Go maps."""


def _go_values(v: Any) -> Any:
    """Go's JSON conventions: map keys sorted, struct fields in order, and
    integral float64s without a fraction (7.0 → 7)."""
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return int(v)
    if isinstance(v, Struct):
        return {k: _go_values(x) for k, x in v.items()}
    if isinstance(v, dict):
        return {k: _go_values(v[k]) for k in sorted(v)}
    if isinstance(v, (list, tuple)):
        return [_go_values(x) for x in v]
    return v


_GO_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029"}


def to_json(v: Any, indent: bool = False) -> str:
    v = _go_values(v)
    if indent:
        s = json.dumps(v, indent=2, ensure_ascii=False)
    else:
        s = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    # Go escapes these in strings (HTML safety); outside strings they never occur in JSON.
    return re.sub("[<>&\u2028\u2029]", lambda m: _GO_ESCAPES[m.group()], s)


def pick(m: dict[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    """Filter a map to the requested fields."""
    return {f: m.get(f) for f in fields}


def run_jq(expr: str, data: str) -> str:
    """Filter JSON text with the jq binary; strings are printed raw, other
    values as compact JSON (gh's --jq behaviour)."""
    jq = shutil.which("jq")
    if jq is None:
        from .cli import Error

        raise Error(
            "--jq needs the jq command, which was not found on PATH; install it (https://jqlang.org/download/) or use --format instead"
        )
    p = subprocess.run([jq, "-r", "-c", "-S", expr], input=data.encode("utf-8"), capture_output=True)
    if p.returncode != 0:
        from .cli import Error

        msg = p.stderr.decode("utf-8", "replace").strip().replace("\r\n", "\n")
        raise Error(msg or f"jq exited with status {p.returncode}")
    return p.stdout.decode("utf-8", "replace").replace("\r\n", "\n")


class _Formatter(string.Formatter):
    def format_field(self, value: Any, spec: str) -> str:
        return format(_plain(value), spec)

    def get_value(self, key: Any, args: Any, kwargs: Any) -> Any:
        if isinstance(key, int):
            raise KeyError(key)
        return kwargs[key]


def _plain(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return to_json(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list) and all(x is None or isinstance(x, (str, int, float, bool)) for x in v):
        return ",".join(_plain(x) for x in v)
    return to_json(v)


def format_rows(fmt: str, data: Any) -> str:
    """--format: a Python format string applied to each element of a list (or
    once to an object), one line each. Lists of plain values are joined with
    commas, objects rendered as JSON; "\\t" and "\\n" are understood."""
    from .cli import Error

    fmt = fmt.replace("\\t", "\t").replace("\\n", "\n")
    rows = data if isinstance(data, list) else [data]
    lines = []
    for row in rows:
        try:
            lines.append(_Formatter().vformat(fmt, (), row if isinstance(row, dict) else {"_": row}) + "\n")
        except KeyError as e:
            raise Error(f"--format: unknown field {e.args[0]!r}; request it with --json") from None
        except (IndexError, TypeError, ValueError, AttributeError) as e:
            raise Error(f"--format: {e}") from None
    return "".join(lines)


class Exporter:
    """gh's --json / --jq trio (with --format instead of Go's --template)."""

    def __init__(self) -> None:
        self.fields: list[str] = []
        self.jq = ""
        self.format = ""

    def enabled(self) -> bool:
        return bool(self.fields)

    def wants(self, f: str) -> bool:
        return f in self.fields

    def write(self, data: Any) -> None:
        if self.jq:
            out(run_jq(self.jq, to_json(data)), end="")
        elif self.format:
            out(format_rows(self.format, _go_values(data)), end="")
        else:
            out(to_json(data, indent=True))


FORMAT_EXAMPLE = "{name}\\t{version}"


def add_json_flags(cmd: Any, available: list[str]) -> Exporter:
    """Register --json/--jq/--format on a cli.Command; returns the exporter
    that is filled in before the command runs."""
    from .cli import Error

    exp = Exporter()
    available = sorted(available)
    f = cmd.flag("json", kind="strs", help="Output JSON with the specified `fields`")
    f.fields = available
    cmd.flag("jq", "q", help="Filter JSON output using a jq `expression` (needs the jq command)")
    cmd.flag("format", help=f"Format each JSON item with a Python format `string`, e.g. '{FORMAT_EXAMPLE}'")

    def hook(o: Any) -> None:
        exp.fields, exp.jq, exp.format = o.json, o.jq, o.format
        if (o.jq or o.format) and not o.json:
            raise Error("cannot use `--jq` or `--format` without specifying `--json`")
        if o.jq and o.format:
            raise Error("specify only one of `--jq` or `--format`")
        for fld in o.json:
            if fld not in available:
                raise Error(f"Unknown JSON field: {json.dumps(fld)}\nAvailable fields:\n  " + "\n  ".join(available))

    cmd.pre_run.insert(0, hook)
    return exp


# text/tabwriter (minwidth 0, tabwidth 4, padding 2, padchar ' ', flags 0)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _width(s: str) -> int:
    return len(_ANSI.sub("", s))


class TabWriter:
    def __init__(self, w: Any = None, padding: int = 2):
        self.w = w
        self.padding = padding
        self.buf = _io.StringIO()

    def write(self, s: str) -> None:
        self.buf.write(s)

    def line(self, *cells: Any) -> None:
        self.buf.write("\t".join(str(c) for c in cells) + "\n")

    def flush(self) -> None:
        text = self.buf.getvalue()
        self.buf = _io.StringIO()
        if not text:
            return
        trailing = text.endswith("\n")
        raw = text[:-1].split("\n") if trailing else text.split("\n")
        self.lines = [ln.split("\t") for ln in raw]
        self.widths: list[int] = []
        self.parts: list[str] = []
        self._format(0, len(self.lines))
        result = "\n".join(self.parts) + ("\n" if trailing else "")
        (self.w or io.stdout).write(result)

    def _format(self, line0: int, line1: int) -> None:
        column = len(self.widths)
        this = line0
        while this < line1:
            line = self.lines[this]
            if column >= len(line) - 1:
                this += 1
                continue
            self._write_lines(line0, this)
            line0 = this
            width = 0
            while this < line1:
                line = self.lines[this]
                if column >= len(line) - 1:
                    break
                width = max(width, _width(line[column]) + self.padding)
                this += 1
            self.widths.append(width)
            self._format(line0, this)
            self.widths.pop()
            line0 = this
        self._write_lines(line0, line1)

    def _write_lines(self, line0: int, line1: int) -> None:
        for i in range(line0, line1):
            cells = self.lines[i]
            s = []
            for j, c in enumerate(cells):
                if j < len(self.widths) and j < len(cells) - 1:
                    s.append(c + " " * (self.widths[j] - _width(c)))
                else:
                    s.append(c)
            self.parts.append("".join(s))
