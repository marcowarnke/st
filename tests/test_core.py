"""The CLI framework, output helpers and credential store."""

from __future__ import annotations

import io

import pytest

from st import cli, credstore, output
from st.cli import Command, Error


def tree() -> Command:
    root = Command("app", run=None)
    sub = Command("do [x]", aliases=["d"], run=lambda o: None, args=cli.maximum_args(2))
    sub.flag("name", "n")
    sub.flag("list", "l", kind="strs")
    sub.flag("many", "m", kind="array")
    sub.flag("verbose", "v", kind="bool")
    sub.flag("count", "c", kind="int")
    sub.flag("commit", no_opt="last")
    sub.pflag("repo", "R")
    root.add(sub)
    return root


def test_parse_like_pflag():
    root = tree()
    cmd, rest = root.find(["d", "-R", "x", "a", "--name=n1", "-vc3", "-l", "a,b", "--list", "c", "-m", "x,y", "-m", "z", "--", "-p"])
    assert cmd.name == "do"
    o = cmd.parse(rest)
    assert (o.repo, o.name, o.verbose, o.count) == ("x", "n1", True, 3)
    assert o.list == ["a", "b", "c"] and o.many == ["x,y", "z"]
    assert o.args == ["a", "-p"] and o.dash == 1
    assert o.changed("name") and not o.changed("commit")
    assert cmd.parse(["--commit"]).commit == "last"
    o = cmd.parse(["--commit", "abc"])
    assert o.commit == "last" and o.args == ["abc"]
    assert cmd.parse(["--commit=abc"]).commit == "abc"
    with pytest.raises(Error, match="unknown shorthand flag: 'z' in -vz"):
        cmd.parse(["-vz"])
    with pytest.raises(Error, match="flag needs an argument: --name"):
        cmd.parse(["--name"])
    with pytest.raises(Error, match='invalid argument "x" for "-c, --count" flag'):
        cmd.parse(["-c", "x"])


def test_tabwriter_matches_go():
    buf = io.StringIO()
    tw = output.TabWriter(buf)
    tw.write("A\tBB\tC\n")
    tw.write("aaaa\tb\tccc\n")
    tw.write("x\t\t\t\t\terr\n")
    tw.flush()
    # Same as Go's tabwriter.NewWriter(w, 0, 4, 2, ' ', 0).
    assert buf.getvalue() == "A     BB  C\naaaa  b   ccc\nx               err\n"


def test_format_rows():
    data = [{"n": 1, "t": "x", "l": ["a", "b"], "d": None, "b": True, "o": {"k": 1}}]
    assert output.format_rows("{n}\\t{t}|{l}|{d}|{b}|{o}", data) == '1\tx|a,b||true|{"k":1}\n'
    assert output.format_rows("{n:>3}", {"n": 7}) == "  7\n"
    assert output.format_rows("{o[k]}", data) == "1\n"
    with pytest.raises(Error, match="unknown field 'zz'"):
        output.format_rows("{zz}", data)


def test_go_json_numbers():
    assert output.to_json({"b": 9.0, "a": [7.5, 1]}) == '{"a":[7.5,1],"b":9}'


def test_jq_missing(monkeypatch):
    monkeypatch.setattr(output.shutil, "which", lambda name: None)
    with pytest.raises(Error, match="--jq needs the jq command"):
        output.run_jq(".", "{}")


def test_mock_keyring_semantics():
    m = credstore.Mock()
    credstore.backend = m
    try:
        credstore.set("s", "u", "p")
        assert credstore.get("s", "u") == "p"
        credstore.delete("s", "u")
        credstore.delete("s", "u")  # missing is fine
        with pytest.raises(credstore.NotFound):
            credstore.get("s", "u")
    finally:
        credstore.backend = None


def test_macos_quoting_matches_go_shellescape():
    assert credstore._shellquote("st:iq.corp") == "st:iq.corp"
    assert credstore._shellquote("it's") == "'it'\"'\"'s'"
    assert credstore._shellquote("") == "''"


def test_read_stdin_drops_byte_order_mark():
    old = output.io.stdin
    output.io.stdin = __import__("io").StringIO("﻿code:pass\n")
    try:
        assert output.read_stdin() == "code:pass\n"
    finally:
        output.io.stdin = old
