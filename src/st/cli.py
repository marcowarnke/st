"""A small command framework with cobra/pflag semantics.

It keeps the Go version's command line exactly: subcommands with aliases,
interspersed flags, -abc shorthand groups, comma-separated slice flags,
"--" (with the position remembered, like cobra's ArgsLenAtDash), the same
argument-count errors, help output, and cobra's hidden __complete protocol
for shell completion.
"""

from __future__ import annotations

import csv
import re
import sys
from collections.abc import Callable, Iterable
from typing import Any

from . import output

# Shell completion directives (cobra.ShellCompDirective).
COMP_ERROR = 1
COMP_NOSPACE = 2
COMP_NOFILE = 4
COMP_KEEP_ORDER = 32
COMP_DEFAULT = 0


class Error(Exception):
    """A user-facing error; the message is printed as is."""


class ExitError(Exception):
    """Exit with a specific code, printing err (if any) to stderr."""

    def __init__(self, code: int, err: BaseException | str | None = None):
        super().__init__(str(err) if err is not None else "")
        self.code = code
        self.err = err


class HelpRequested(Exception):
    def __init__(self, cmd: Command):
        self.cmd = cmd


def cause(err: BaseException | None, typ: type) -> Any:
    """Return the first exception of typ in err's __cause__ chain (errors.As)."""
    seen = set()
    while err is not None and id(err) not in seen:
        if isinstance(err, typ):
            return err
        seen.add(id(err))
        if isinstance(err, ExitError) and isinstance(err.err, BaseException):
            err = err.err
            continue
        err = err.__cause__
    return None


class Flag:
    """A flag. kind is bool, str, int, strs (comma-separated, repeatable)
    or array (repeatable, no splitting)."""

    def __init__(
        self,
        name: str,
        short: str = "",
        kind: str = "str",
        default: Any = None,
        help: str = "",
        no_opt: str | None = None,
        complete: Any = None,
        hidden: bool = False,
    ):
        self.name, self.short, self.kind, self.help = name, short, kind, help
        self.no_opt, self.complete, self.hidden = no_opt, complete, hidden
        self.dest = name.replace("-", "_")
        if default is None:
            default = {"bool": False, "str": "", "int": 0, "strs": [], "array": []}[kind]
        self.default = default
        self.fields: list[str] | None = None  # --json: the available fields

    def initial(self) -> Any:
        return list(self.default) if isinstance(self.default, list) else self.default

    def takes_value(self) -> bool:
        return self.kind != "bool"

    def usage(self) -> tuple[str, str]:
        """(varname, usage) like pflag.UnquoteUsage."""
        m = re.search(r"`([^`]*)`", self.help)
        if m:
            return m.group(1), self.help[: m.start()] + m.group(1) + self.help[m.end() :]
        name = {"bool": "", "str": "string", "int": "int", "strs": "strings", "array": "stringArray"}[self.kind]
        return name, self.help

    def label(self) -> str:
        return f"-{self.short}, --{self.name}" if self.short else f"--{self.name}"


class Opts:
    """Parsed flag values (as attributes), positional args and the "--" position."""

    def __init__(self, cmd: Command):
        self.cmd = cmd
        self.args: list[str] = []
        self.dash = -1
        self._changed: set[str] = set()
        for f in cmd.all_flags():
            setattr(self, f.dest, f.initial())

    def changed(self, name: str) -> bool:
        return name in self._changed

    def set(self, f: Flag, value: str | None, *, bool_value: bool | None = None) -> None:
        if f.kind == "bool":
            if value is None:
                v = True if bool_value is None else bool_value
            elif value.lower() in ("true", "1", "t"):
                v = True
            elif value.lower() in ("false", "0", "f"):
                v = False
            else:
                raise Error(f'invalid argument "{value}" for "{f.label()}" flag: strconv.ParseBool: parsing "{value}": invalid syntax')
            setattr(self, f.dest, v)
        elif f.kind == "int":
            try:
                setattr(self, f.dest, int(value, 10))
            except ValueError:
                raise Error(
                    f'invalid argument "{value}" for "{f.label()}" flag: strconv.ParseInt: parsing "{value}": invalid syntax'
                ) from None
        elif f.kind == "strs":
            items = next(csv.reader([value])) if value else []
            cur = getattr(self, f.dest) if f.name in self._changed else []
            setattr(self, f.dest, cur + items)
        elif f.kind == "array":
            cur = getattr(self, f.dest) if f.name in self._changed else []
            setattr(self, f.dest, cur + [value])
        else:
            setattr(self, f.dest, value)
        self._changed.add(f.name)


def no_args(o: Opts) -> str | None:
    if o.args:
        return f'unknown command "{o.args[0]}" for "{o.cmd.path()}"'
    return None


def exact_args(n: int) -> Callable[[Opts], str | None]:
    def check(o: Opts) -> str | None:
        if len(o.args) != n:
            return f"accepts {n} arg(s), received {len(o.args)}"
        return None

    return check


def maximum_args(n: int) -> Callable[[Opts], str | None]:
    def check(o: Opts) -> str | None:
        if len(o.args) > n:
            return f"accepts at most {n} arg(s), received {len(o.args)}"
        return None

    return check


def minimum_args(n: int) -> Callable[[Opts], str | None]:
    def check(o: Opts) -> str | None:
        if len(o.args) < n:
            return f"requires at least {n} arg(s), only received {len(o.args)}"
        return None

    return check


class Command:
    def __init__(
        self,
        use: str,
        short: str = "",
        long: str = "",
        example: str = "",
        aliases: Iterable[str] = (),
        args: Callable[[Opts], str | None] | None = None,
        run: Callable[[Opts], Any] | None = None,
        complete_args: Callable[[Opts, str], tuple[list[str], int]] | None = None,
        hidden: bool = False,
        version: str = "",
    ):
        self.use, self.short, self.long, self.example = use, short, long, example
        self.name = use.split()[0]
        self.aliases = list(aliases)
        self.args_check = args
        self.run_fn = run
        self.complete_args = complete_args
        self.hidden = hidden
        self.version = version
        self.flags: list[Flag] = []
        self.persistent: list[Flag] = []
        self.commands: list[Command] = []
        self.parent: Command | None = None
        self.pre_run: list[Callable[[Opts], None]] = []
        self.help_flag = Flag("help", "h", "bool", help=f"help for {self.name}")
        self.flags_in_use_line = True

    # building

    def flag(self, name: str, short: str = "", kind: str = "str", default: Any = None, help: str = "", **kw: Any) -> Flag:
        f = Flag(name, short, kind, default, help, **kw)
        self.flags.append(f)
        if f.name == "help":
            self.help_flag = f
        elif short == "h" and self.help_flag.short == "h":
            # -h means something else here (auth --hostname, as in gh); help stays --help.
            self.help_flag = Flag("help", "", "bool", help="Show help for command")
        return f

    def pflag(self, name: str, short: str = "", kind: str = "str", default: Any = None, help: str = "", **kw: Any) -> Flag:
        f = Flag(name, short, kind, default, help, **kw)
        self.persistent.append(f)
        return f

    def add(self, *cmds: Command) -> Command:
        for c in cmds:
            c.parent = self
            self.commands.append(c)
        return self

    # introspection

    def root(self) -> Command:
        c = self
        while c.parent is not None:
            c = c.parent
        return c

    def path(self) -> str:
        return self.name if self.parent is None else self.parent.path() + " " + self.name

    def runnable(self) -> bool:
        return self.run_fn is not None

    def visible_commands(self) -> list[Command]:
        return sorted((c for c in self.commands if not c.hidden), key=lambda c: c.name)

    def inherited_flags(self) -> list[Flag]:
        out: list[Flag] = []
        p = self.parent
        while p is not None:
            out.extend(p.persistent)
            p = p.parent
        return out

    def local_flags(self) -> list[Flag]:
        out = list(self.flags) + list(self.persistent)
        if not any(f.name == "help" for f in out):
            out.append(self.help_flag)
        if self.version and self.parent is None:
            out.append(Flag("version", "v", "bool", help=f"version for {self.name}"))
        return out

    def all_flags(self) -> list[Flag]:
        return self.local_flags() + self.inherited_flags()

    def find_flag(self, name: str) -> Flag | None:
        return next((f for f in self.all_flags() if f.name == name), None)

    def find_short(self, short: str) -> Flag | None:
        return next((f for f in self.all_flags() if f.short == short), None)

    def sub(self, name: str) -> Command | None:
        return next((c for c in self.commands if c.name == name or name in c.aliases), None)

    # parsing

    def find(self, args: list[str]) -> tuple[Command, list[str]]:
        """Walk subcommand names (skipping flags), like cobra's Find."""
        c, rest = self, list(args)
        while True:
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--":
                    return c, rest
                if a.startswith("-") and len(a) > 1:
                    i += 1 + c._value_follows(a)
                    continue
                nxt = c.sub(a)
                if nxt is None:
                    return c, rest
                c = nxt
                rest = rest[:i] + rest[i + 1 :]
                break
            else:
                return c, rest

    def _value_follows(self, a: str) -> int:
        """1 if flag argument a consumes the next argument as its value."""
        if a.startswith("--"):
            if "=" in a:
                return 0
            f = self.find_flag(a[2:])
        else:
            if len(a) != 2:
                return 0
            f = self.find_short(a[1])
        return int(f is not None and f.takes_value() and f.no_opt is None)

    def parse(self, args: list[str], lenient: bool = False) -> Opts:
        o = Opts(self)
        i = 0
        while i < len(args):
            a = args[i]
            i += 1
            if a == "--":
                o.dash = len(o.args)
                o.args.extend(args[i:])
                break
            if not a.startswith("-") or a == "-":
                o.args.append(a)
                continue
            try:
                if a.startswith("--"):
                    name, eq, value = a[2:].partition("=")
                    f = self.find_flag(name)
                    if f is None:
                        raise Error(f"unknown flag: --{name}")
                    if f.kind == "bool":
                        o.set(f, value if eq else None)
                    elif eq:
                        o.set(f, value)
                    elif f.no_opt is not None:
                        o.set(f, f.no_opt)
                    elif i < len(args):
                        o.set(f, args[i])
                        i += 1
                    else:
                        raise Error(f"flag needs an argument: --{name}")
                    continue
                shorts = a[1:]
                j = 0
                while j < len(shorts):
                    ch = shorts[j]
                    f = self.find_short(ch)
                    if f is None:
                        raise Error(f"unknown shorthand flag: '{ch}' in {a}")
                    rest = shorts[j + 1 :]
                    if f.kind == "bool":
                        if rest.startswith("="):
                            o.set(f, rest[1:])
                            break
                        o.set(f, None)
                        j += 1
                        continue
                    if rest:
                        o.set(f, rest[1:] if rest.startswith("=") else rest)
                    elif f.no_opt is not None:
                        o.set(f, f.no_opt)
                    elif i < len(args):
                        o.set(f, args[i])
                        i += 1
                    else:
                        raise Error(f"flag needs an argument: '{ch}' in -{ch}")
                    break
            except Error:
                if not lenient:
                    raise
        return o


# Execution


def execute(root: Command, argv: list[str]) -> None:
    """Parse argv and run the selected command. Raises Error/ExitError."""
    if argv and argv[0] == "__complete":
        complete(root, argv[1:])
        return
    cmd, rest = root.find(argv)
    try:
        o = cmd.parse(rest)
    except Error as e:
        msg = str(e)
        f = cmd.find_flag("json")
        if msg == "flag needs an argument: --json" and f is not None and f.fields is not None:
            raise Error("Specify one or more comma-separated fields for `--json`:\n  " + "\n  ".join(f.fields)) from None
        raise
    if getattr(o, "help", False):
        output.out(help_text(cmd), end="")
        return
    if cmd.parent is None and cmd.version and getattr(o, "version", False):
        output.out(f"{cmd.name} version {cmd.version}")
        return
    if not cmd.runnable():
        if o.args and cmd.parent is None:
            raise Error(f'unknown command "{o.args[0]}" for "{cmd.path()}"')
        output.out(help_text(cmd), end="")  # as cobra does, also for unknown subcommands below the root
        return
    if cmd.args_check is not None:
        msg = cmd.args_check(o)
        if msg:
            raise Error(msg)
    for hook in cmd.pre_run:
        hook(o)
    cmd.run_fn(o)


# Help


def _flag_usages(flags: list[Flag]) -> str:
    lines = []
    maxlen = 0
    for f in sorted((f for f in flags if not f.hidden), key=lambda f: f.name):
        line = f"  -{f.short}, --{f.name}" if f.short else f"      --{f.name}"
        varname, usage = f.usage()
        if varname:
            line += " " + varname
        if f.no_opt is not None:
            line += f'[="{f.no_opt}"]' if f.kind == "str" else f"[={f.no_opt}]"
        sidx = len(line)
        maxlen = max(maxlen, sidx)
        if f.default not in ("", 0, False, [], None):
            d = f.default
            if f.kind == "strs" or f.kind == "array":
                d = "[" + ",".join(d) + "]"
            usage += f' (default "{d}")' if f.kind == "str" else f" (default {d})"
        lines.append((line, usage))
    return "\n".join(line + " " * (maxlen - len(line) + 3) + usage for line, usage in lines)


def help_text(cmd: Command) -> str:
    parts = []
    text = (cmd.long or cmd.short).rstrip()
    if text:
        parts.append(text + "\n\n")
    usage = "Usage:"
    if cmd.runnable():
        use = cmd.use if cmd.parent is None else cmd.parent.path() + " " + cmd.use
        if "[flags]" not in use and cmd.flags_in_use_line:
            use += " [flags]"
        usage += "\n  " + use
    subs = cmd.visible_commands()
    if subs:
        usage += f"\n  {cmd.path()} [command]"
    if cmd.aliases:
        usage += "\n\nAliases:\n  " + ", ".join([cmd.name] + cmd.aliases)
    if cmd.example:
        usage += "\n\nExamples:\n" + cmd.example
    if subs:
        width = max([11] + [len(c.name) for c in subs])  # cobra's minimum name padding
        usage += "\n\nAvailable Commands:" + "".join(f"\n  {c.name.ljust(width)} {c.short}" for c in subs)
    local = [f for f in cmd.local_flags() if not f.hidden]
    if local:
        usage += "\n\nFlags:\n" + _flag_usages(local)
    inherited = [f for f in cmd.inherited_flags() if not f.hidden]
    if inherited:
        usage += "\n\nGlobal Flags:\n" + _flag_usages(inherited)
    if subs:
        usage += f'\n\nUse "{cmd.path()} [command] --help" for more information about a command.'
    parts.append(usage + "\n")
    return "".join(parts)


def add_help_command(root: Command) -> None:
    def run(o: Opts) -> None:
        c, rest = root.find(o.args)
        if rest:
            raise Error(f"Unknown help topic {rest!r}")
        output.out(help_text(c), end="")

    root.add(
        Command(
            "help [command]",
            short="Help about any command",
            long="Help provides help for any command in the application.\n"
            f"Simply type {root.name} help [path to command] for full details.",
            run=run,
        )
    )


# Completion


def complete(root: Command, args: list[str]) -> None:
    """cobra's __complete: print candidates ("value\\tdescription") and ":<directive>"."""
    if not args:
        args = [""]
    to_complete = args[-1]
    cmd, rest = root.find(args[:-1])
    o = cmd.parse(rest, lenient=True)
    items: list[str] = []
    directive = COMP_DEFAULT
    flag: Flag | None = None
    prefix = ""
    if to_complete.startswith("--") and "=" in to_complete:
        name, _, value = to_complete[2:].partition("=")
        flag = cmd.find_flag(name)
        prefix, to_complete = f"--{name}=", value
    elif rest and o.dash < 0 and _pending_value_flag(cmd, rest[-1]) is not None:
        flag = _pending_value_flag(cmd, rest[-1])
    try:
        if flag is not None:
            if flag.complete is None:
                directive = COMP_DEFAULT
            elif callable(flag.complete):
                items, directive = flag.complete(o, to_complete)
            else:
                items, directive = list(flag.complete), COMP_NOFILE
            items = [prefix + i for i in items]
        elif to_complete.startswith("-") and o.dash < 0:
            # cobra: inherited flags first, then the command's own, each sorted
            ordered = sorted(cmd.inherited_flags(), key=lambda f: f.name) + sorted(cmd.local_flags(), key=lambda f: f.name)
            for f in ordered:
                if f.hidden:
                    continue
                long = "--" + f.name
                if long.startswith(to_complete):
                    items.append(f"{long}\t{f.help}")
                if f.short and to_complete == "-":
                    items.append(f"-{f.short}\t{f.help}")
            directive = COMP_NOFILE
        elif cmd.visible_commands() and not o.args:
            for c in cmd.visible_commands():
                if c.name.startswith(to_complete):
                    items.append(f"{c.name}\t{c.short}")
            directive = COMP_NOFILE
        elif cmd.complete_args is not None:
            items, directive = cmd.complete_args(o, to_complete)
    except Exception:  # completion must never break the shell
        items, directive = [], COMP_NOFILE
    for i in items:
        output.out(i)
    output.out(f":{directive}")
    output.err(f"Completion ended with directive: {directive_names(directive)}")


def directive_names(d: int) -> str:
    names = [
        n
        for bit, n in ((1, "Error"), (2, "NoSpace"), (4, "NoFileComp"), (8, "FilterFileExt"), (16, "FilterDirs"), (32, "KeepOrder"))
        if d & bit
    ]
    return ", ".join("ShellCompDirective" + n for n in names or ["Default"])


def _pending_value_flag(cmd: Command, last: str) -> Flag | None:
    """The flag whose value is being completed when last is "--flag" or "-f"."""
    if last.startswith("--") and "=" not in last:
        f = cmd.find_flag(last[2:])
    elif last.startswith("-") and not last.startswith("--") and len(last) >= 2:
        f = cmd.find_short(last[-1])
        # in a group like -dR only the last flag can take the next argument
        if f is not None and len(last) > 2 and any(cmd.find_short(ch) is None or cmd.find_short(ch).takes_value() for ch in last[1:-1]):
            f = None
    else:
        return None
    if f is None or not f.takes_value() or f.no_opt is not None:
        return None
    return f


def add_completion_command(root: Command) -> None:
    name = root.name
    cmd = Command(
        "completion",
        short="Generate the autocompletion script for the specified shell",
        long=f"Generate the autocompletion script for {name} for the specified shell.\n"
        "See each sub-command's help for details on how to use the generated script.",
    )
    shells = {
        "bash": f"""Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

\tsource <({name} completion bash)

To load completions for every new session, execute once:

#### Linux:

\t{name} completion bash > /etc/bash_completion.d/{name}

#### macOS:

\t{name} completion bash > $(brew --prefix)/etc/bash_completion.d/{name}

You will need to start a new shell for this setup to take effect.
""",
        "zsh": f"""Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

\techo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

\tsource <({name} completion zsh)

To load completions for every new session, execute once:

#### Linux:

\t{name} completion zsh > "${{fpath[1]}}/_{name}"

#### macOS:

\t{name} completion zsh > $(brew --prefix)/share/zsh/site-functions/_{name}

You will need to start a new shell for this setup to take effect.
""",
        "fish": f"""Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

\t{name} completion fish | source

To load completions for every new session, execute once:

\t{name} completion fish > ~/.config/fish/completions/{name}.fish

You will need to start a new shell for this setup to take effect.
""",
        "powershell": f"""Generate the autocompletion script for powershell.

To load completions in your current shell session:

\t{name} completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.
""",
    }
    for shell, long in shells.items():

        def run(o: Opts, shell: str = shell) -> None:
            output.out(completion_script(name, shell, not o.no_descriptions), end="")

        sub = Command(shell, short=f"Generate the autocompletion script for {shell}", long=long, args=no_args, run=run)
        sub.flags_in_use_line = shell != "bash"
        sub.flag("no-descriptions", kind="bool", help="disable completion descriptions")
        cmd.add(sub)
    root.add(cmd)


def completion_script(name: str, shell: str, descriptions: bool = True) -> str:
    fn = "_" + re.sub(r"\W", "_", name)
    if shell == "bash":
        return f"""# bash completion for {name}
{fn}() {{
    local cur=${{COMP_WORDS[COMP_CWORD]}} out directive
    out=$("{name}" __complete "${{COMP_WORDS[@]:1:COMP_CWORD-1}}" "$cur" 2>/dev/null) || return
    directive=${{out##*:}}
    out=${{out%:*}}
    local IFS=$'\\n'
    COMPREPLY=()
    local line
    for line in $out; do
        line=${{line%%$'\\t'*}}
        [[ -z $line || $line != "$cur"* ]] && continue
        COMPREPLY+=("$line")
    done
    (( directive & 2 )) && compopt -o nospace 2>/dev/null
    (( directive & 32 )) && compopt -o nosort 2>/dev/null
    if (( ${{#COMPREPLY[@]}} == 0 && (directive & 4) == 0 )); then
        compopt -o default 2>/dev/null
    fi
}}
complete -o bashdefault -F {fn} {name}
"""
    if shell == "zsh":
        desc = "1" if descriptions else ""
        return f"""#compdef {name}
# zsh completion for {name}
{fn}() {{
    local -a words_before completions descs
    local out directive line value desc
    words_before=("${{(@)words[2,CURRENT-1]}}")
    out=$("{name}" __complete "${{words_before[@]}}" "${{words[CURRENT]}}" 2>/dev/null) || return 1
    directive=${{${{out##*:}}%%$'\\n'*}}
    for line in "${{(@f)out}}"; do
        [[ $line == :* || -z $line ]] && continue
        value=${{line%%$'\\t'*}}
        desc=${{line#*$'\\t'}}
        [[ $desc == $line ]] && desc=""
        completions+=("${{value//:/\\\\:}}")
        if [[ -n "{desc}" && -n $desc ]]; then descs+=("${{value//:/\\\\:}}:$desc"); else descs+=("${{value//:/\\\\:}}"); fi
    done
    local -a nospace sortopt
    (( directive & 2 )) && nospace=(-S '')
    (( directive & 32 )) && sortopt=(-V)
    if (( ${{#completions}} == 0 )); then
        (( directive & 4 )) || _files
        return
    fi
    _describe $sortopt -t {name} '{name}' descs $nospace
}}
compdef {fn} {name}
"""
    if shell == "fish":
        desc_cut = "" if descriptions else " | string replace -r '\\t.*' ''"
        return f"""# fish completion for {name}
function __{fn}_complete
    set -l args (commandline -opc)[2..-1] (commandline -ct)
    set -l out ("{name}" __complete $args 2>/dev/null)
    set -l directive (string replace -r '^:' '' -- $out[-1])
    set -e out[-1]
    if test (count $out) -eq 0; and test (math "$directive % 8 - $directive % 4") -eq 0
        __fish_complete_path (commandline -ct)
        return
    end
    printf '%s\\n' $out{desc_cut}
end
complete -c {name} -f -a '(__{fn}_complete)'
"""
    if shell == "powershell":
        return f"""# powershell completion for {name}
Register-ArgumentCompleter -CommandName '{name}' -Native -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object {{ $_.ToString() }})
    if ($wordToComplete -eq '') {{ $words += '""' }} elseif ($words.Count -gt 0) {{ $words[-1] = $wordToComplete }}
    $out = @(& '{name}' __complete @words 2>$null)
    if ($out.Count -eq 0) {{ return }}
    $directive = [int]($out[-1].TrimStart(':'))
    $items = @($out | Select-Object -SkipLast 1)
    if ($items.Count -eq 0 -and ($directive -band 4) -eq 0) {{ return }}
    foreach ($item in $items) {{
        $value, $desc = $item -split "`t", 2
        if (-not $desc) {{ $desc = $value }}
        if ($value -like "$wordToComplete*") {{
            [System.Management.Automation.CompletionResult]::new($value, $value, 'ParameterValue', $desc)
        }}
    }}
}}
"""
    raise Error(f"unsupported shell {shell!r}")


def run_main(root: Command, argv: list[str] | None, map_error: Callable[[BaseException], int]) -> int:
    """Run the CLI and return the exit code. map_error prints an error and returns its code."""
    if argv is None:
        argv = sys.argv[1:]
    try:
        execute(root, argv)
        return 0
    except ExitError as e:
        if e.err is not None and str(e.err):
            output.err(str(e.err))
        return e.code
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except BaseException as e:  # noqa: BLE001 - every error becomes a message and an exit code
        return map_error(e)
