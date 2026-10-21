"""Helpers shared by the commands."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .. import output

_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})$")


def parse_time(s: str) -> datetime | None:
    """Parse IQ Server timestamps ("2015-01-16T13:14:32.139-05:00", RFC 3339 or -0700 offsets)."""
    m = _TS.match(s or "")
    if not m:
        return None
    y, mo, d, h, mi, sec, frac, tz = m.groups()
    if tz == "Z":
        tzinfo = timezone.utc
    else:
        sign = -1 if tz[0] == "-" else 1
        digits = tz[1:].replace(":", "")
        tzinfo = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    micro = int((frac or "0")[:6].ljust(6, "0"))
    try:
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), micro, tzinfo)
    except ValueError:
        return None


def ago(s: str) -> str:
    """An IQ timestamp relative to now, or as-is if unparseable."""
    t = parse_time(s)
    if t is None:
        return s
    return output.ago_seconds((datetime.now(timezone.utc) - t).total_seconds())


def first_non_empty(*ss: str) -> str:
    for s in ss:
        if s:
            return s
    return ""
