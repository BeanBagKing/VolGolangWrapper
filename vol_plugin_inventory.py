#!/usr/bin/env python3
"""Build a CSV inventory of Volatility 3 plugins and their options.

Two independent collectors are provided:

* ``api``  - imports Volatility 3 inside its own virtualenv, enumerates plugins
             via ``volatility3.framework.list_plugins()`` and renders each
             plugin's flags through the CLI's own argparse builder.  One
             process, exact fidelity, and immune to plugins that refuse to
             print ``--help`` without a required argument.
* ``help`` - shells out to ``vol --help`` and ``vol <plugin> --help`` and parses
             the text.  Slower and less precise, but depends only on the
             command-line interface.  Used automatically if ``api`` fails.

Columns are declared once, in ``build_columns()``; reorder that list to reorder
the CSV, or append a ``Column(name, getter)`` to add one.  ``--columns`` does
the same at run time without editing the file.
"""

import argparse
import ast
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

__version__ = "1.0.0"

DEFAULT_VOL_ROOT = "~/volatility3"
DEFAULT_VENV = "venv"
DEFAULT_OUTPUT = "plugins.csv"
# Written instead of DEFAULT_OUTPUT when --json is used without an explicit -o,
# so JSON never lands in a file named .csv.
DEFAULT_JSON_OUTPUT = "plugins.json"
# Conventional stand-in for stdout in an output path.
STDOUT_PATH = "-"

# Separator placed between a flag's invocation and its description.
FLAG_SEP = "    "

# How the two boolean columns are rendered.
BOOL_STYLES = {
    "python": ("True", "False"),
    "lower": ("true", "false"),
    "yesno": ("Yes", "No"),
    "binary": ("1", "0"),
}

# Namespaces that are operating systems, mapped to their display name.  A
# namespace not listed here is title-cased, so a future ``freebsd.*`` tree is
# reported as "Freebsd" rather than being silently dropped.
TARGET_SYSTEM_NAMES = {
    "windows": "Windows",
    "linux": "Linux",
    "mac": "Mac",
    "os_x": "Mac",
    "osx": "Mac",
    "freebsd": "FreeBSD",
}

# Plugins whose declared requirements do not reveal what they target.
# timeliner.Timeliner declares only its own flags and inherits image
# requirements from the plugins it invokes, so the capability rule cannot see
# them.  Entries naming a plugin that no longer exists are simply ignored.
TARGET_SYSTEM_OVERRIDES = {
    "timeliner.Timeliner": "All",
}

# A plugin that declares a ModuleRequirement needs the OS kernel symbol table,
# which is what forces symbol resolution (and, on a cold cache, a download).
# This is the exact property; "has an OS-specific name" is only a proxy for it
# and is wrong for six plugins in 2.28.2 (windows.crashinfo, the three
# windows.mftscan plugins, windows.statistics, linux.vmcoreinfo).
KERNEL_REQUIREMENT_CLASS = "ModuleRequirement"
# The call form, not a bare mention: yarascan.YaraScan names ModuleRequirement
# in a docstring without declaring one.
KERNEL_REQUIREMENT_PATTERN = re.compile(r"\bModuleRequirement\s*\(")
# Marks a plugin that was renamed; its requirements belong to the replacement.
RENAME_BASE_PATTERN = re.compile(r"\bPluginRenameClass\b")

# Package prefixes a plugin module can live under; stripping one turns an
# import path into the dotted name the framework lists a plugin by.
PLUGIN_PACKAGE_PREFIXES = ("volatility3.plugins.", "volatility3.framework.plugins.")

# Calls through which a plugin writes a file via the framework's file handler.
# A bare ``.open(`` is deliberately NOT matched: plugins that read a file
# (isfinfo.IsfInfo, windows.strings.Strings) would look like writers.
FILE_WRITE_PATTERN = re.compile(r"open_method\(|self\.open\(|FileHandlerInterface")

# Flag-name fragments that gate a plugin's file writing, so the write only
# happens when the user asks for it (--dump, --create-bodyfile).
DUMP_FLAG_PATTERN = re.compile(r"dump|extract|bodyfile", re.IGNORECASE)

# Requirement classes that mean "this plugin consumes a memory image", used to
# tell an OS-agnostic analysis plugin ("All") from a framework utility ("NA").
IMAGE_REQUIREMENT_CLASSES = {
    "TranslationLayerRequirement",
    "ModuleRequirement",
    "SymbolTableRequirement",
}


# --------------------------------------------------------------------------
# Column definitions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Column:
    """One CSV column: a header and how to derive it from a plugin record."""

    name: str
    getter: Callable[[Dict[str, Any]], Any]


def _bools(style: str):
    return BOOL_STYLES.get(style, BOOL_STYLES["python"])


def _render_bool(value: Any, style: str) -> str:
    true_text, false_text = _bools(style)
    return true_text if value else false_text


# ``style`` is injected by build_columns() so the boolean rendering stays a
# single knob rather than being hard-coded into each getter.
def build_columns(bool_style: str = "python") -> List[Column]:
    return [
        Column("FullName", lambda r: r["full_name"]),
        Column("ShortName", lambda r: r["short_name"]),
        Column("Description", lambda r: r["description"]),
        Column("TargetSystem", lambda r: r["target_system"]),
        Column("BulkSupport", lambda r: _render_bool(r["bulk_support"], bool_style)),
        Column("NeedsKernel", lambda r: _render_bool(r["needs_kernel"], bool_style)),
        Column("Deprecated", lambda r: _render_bool(r["deprecated"], bool_style)),
        Column("DeprecatedNewName", lambda r: r["deprecated_new_name"]),
        Column("AdditionalFlags", lambda r: "\n".join(r["additional_flags"])),
        Column("Usage", lambda r: r["usage"]),
    ]


# --------------------------------------------------------------------------
# Shared record helpers
# --------------------------------------------------------------------------


def collapse(text: Optional[str]) -> str:
    """Flatten any run of whitespace (including newlines) to single spaces."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def derive_target_system(full_name: str, requirement_classes: Sequence[str]) -> str:
    """Name the system a plugin targets.

    A plugin living in an OS subpackage (``windows.x.Y``, three or more dotted
    parts) is attributed to that OS.  A top-level plugin (``yarascan.YaraScan``)
    is "All" when it consumes a memory image and "NA" when it does not.
    ``TARGET_SYSTEM_OVERRIDES`` takes precedence over both.
    """
    if full_name in TARGET_SYSTEM_OVERRIDES:
        return TARGET_SYSTEM_OVERRIDES[full_name]
    parts = full_name.split(".")
    if len(parts) > 2:
        namespace = parts[0]
        return TARGET_SYSTEM_NAMES.get(namespace.lower(), namespace.title())
    if set(requirement_classes) & IMAGE_REQUIREMENT_CLASSES:
        return "All"
    return "NA"


def writes_files_unconditionally(source_matches: bool, flag_names: Sequence[str]) -> bool:
    """Does this plugin write files whenever it runs, with no flag to stop it?

    ``source_matches`` says the plugin's class body calls the framework file
    handler at all; the flag names say whether the user has a way to withhold
    it.  windows.dumpfiles.DumpFiles has no such flag -- dumping is the plugin
    -- so it writes on every run, which is what makes it unsuitable for a bulk
    pass even though it takes no required argument.
    """
    if not source_matches:
        return False
    return not any(DUMP_FLAG_PATTERN.search(name) for name in flag_names)


def segment_runs(full_name: str) -> List[Any]:
    """Every run of whole dot-separated segments, as (start, stop, text)."""
    segments = full_name.split(".")
    return [
        (start, stop, ".".join(segments[start:stop]))
        for start in range(len(segments))
        for stop in range(start + 1, len(segments) + 1)
    ]


def derive_short_names(full_names: Sequence[str]) -> Dict[str, str]:
    """Pick each plugin's shortest unambiguous common-reference name.

    Volatility resolves a plugin from any substring unique across plugin names
    -- ``[name for name in self._name_parser_map if parser_name in name]`` in
    ``cli/volargparse.py`` -- so a short name need only be a substring that no
    other plugin's full name contains.

    Candidates are runs of whole dot-separated segments rather than arbitrary
    truncations, so the result reads as a name ("malware.processghosting")
    instead of an abbreviation ("vadw"), and ranking prefers the module segment
    -- what people actually say ("pslist", not "PsList"). A plugin with no
    unambiguous substring at all keeps its full name.
    """
    names = list(full_names)

    def match_count(candidate: str) -> int:
        return sum(1 for name in names if candidate in name)

    short_names = {}
    for full_name in names:
        segments = full_name.split(".")
        module_index = max(len(segments) - 2, 0)
        best = None
        for start, stop, candidate in segment_runs(full_name):
            if match_count(candidate) != 1:
                continue
            key = (
                # The module segment is the name people use; keep it.
                0 if start <= module_index < stop else 1,
                stop - start,
                # Drop a class segment that only repeats the module name.
                0 if stop - 1 == module_index else 1,
                len(candidate),
                # On a tie, the more specific tail beats the leading namespace.
                -start,
            )
            if best is None or key < best[0]:
                best = (key, candidate)
        short_names[full_name] = best[1] if best else full_name
    return short_names


def apply_short_names(records: List[Dict[str, Any]]) -> None:
    """Fill in ShortName once the whole plugin set is known."""
    short_names = derive_short_names([record["full_name"] for record in records])
    for record in records:
        record["short_name"] = short_names[record["full_name"]]


def make_record(
    full_name: str,
    short_name: str = "",
    description: str = "",
    deprecated: bool = False,
    deprecated_new_name: str = "",
    target_system: str = "",
    additional_flags: Optional[List[str]] = None,
    usage: str = "",
    bulk_support: bool = True,
    needs_kernel: bool = False,
) -> Dict[str, Any]:
    return {
        "full_name": full_name,
        "short_name": short_name or full_name,
        "description": description,
        "deprecated": deprecated,
        "deprecated_new_name": deprecated_new_name,
        "target_system": target_system,
        "additional_flags": additional_flags or [],
        "usage": usage,
        "bulk_support": bulk_support,
        "needs_kernel": needs_kernel,
    }


# --------------------------------------------------------------------------
# Collector 1: in-process introspection of the volatility3 framework
# --------------------------------------------------------------------------

# Run by the *virtualenv's* interpreter, not by this script's.  Writes JSON to
# the path given as argv[1] so that warnings or logging on stdout/stderr can
# never corrupt the result.
PROBE_SOURCE = r'''
import argparse, ast, inspect, json, logging, os, re, sys, textwrap, warnings

warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

out_path = sys.argv[1]
# CommandLine.CLI_NAME is basename(sys.argv[0]), which is meaningless here
# because this probe is fed over stdin; the caller passes the real name.
cli_name_override = sys.argv[2] if len(sys.argv) > 2 else "vol"
# The caller owns the pattern so it is defined in exactly one place.
file_write_pattern = re.compile(sys.argv[3]) if len(sys.argv) > 3 else None
result = {"plugins": [], "import_failures": [], "framework_version": "", "errors": []}

def note(msg):
    result["errors"].append(str(msg))

import volatility3
import volatility3.plugins
import volatility3.framework as framework
from volatility3.framework import interfaces

try:
    from volatility3.framework import constants
    result["framework_version"] = getattr(constants, "PACKAGE_VERSION", "")
except Exception as exc:
    note("version: %s" % exc)

try:
    result["import_failures"] = sorted(framework.import_files(volatility3.plugins, False) or [])
except Exception as exc:
    note("import_files: %s" % exc)

plugins = framework.list_plugins()

# Reuse the CLI's own argument builder so flag spellings, metavars and
# required-ness match `vol <plugin> --help` exactly.
populate = None
cli_name = cli_name_override
try:
    from volatility3.cli import CommandLine
    populate = CommandLine.populate_requirements_argparse
except Exception as exc:
    note("cli import: %s" % exc)

parser_cls = argparse.ArgumentParser
try:
    from volatility3.cli import volargparse
    parser_cls = volargparse.HelpfulArgParser
except Exception as exc:
    note("volargparse: %s" % exc)

rename_base = None
try:
    from volatility3.framework import deprecation
    rename_base = getattr(deprecation, "PluginRenameClass", None)
except Exception as exc:
    note("deprecation: %s" % exc)

# Reverse map so a replacement class resolves to its canonical plugin name.
by_class = {}
for name, cls in plugins.items():
    by_class[cls] = name

PLUGIN_MODULE_PREFIXES = ("volatility3.plugins.", "volatility3.framework.plugins.")

def plugin_name_of(obj):
    if obj in by_class:
        return by_class[obj]
    module = getattr(obj, "__module__", "") or ""
    for prefix in PLUGIN_MODULE_PREFIXES:
        if module.startswith(prefix):
            return module[len(prefix):] + "." + obj.__qualname__
    return module + "." + obj.__qualname__ if module else obj.__qualname__

def resolve_dotted(module_name, expr):
    """Resolve a dotted expression such as ``cachedump.Cachedump`` in a module."""
    module = sys.modules.get(module_name)
    if module is None or not re.fullmatch(r"[A-Za-z_][\w.]*", expr or ""):
        return None
    obj = module
    for part in expr.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj

def replacement_name(cls):
    """Recover the ``replacement_class=`` keyword from a renamed plugin.

    The framework does not keep it as an attribute, so read it back out of the
    class statement and resolve the name in the defining module.
    """
    try:
        source = textwrap.dedent(inspect.getsource(cls))
        node = ast.parse(source).body[0]
    except Exception:
        return ""
    if not isinstance(node, ast.ClassDef):
        return ""
    for keyword in node.keywords:
        if keyword.arg not in ("replacement_class", "replacement"):
            continue
        try:
            expr = ast.unparse(keyword.value)
        except Exception:
            return ""
        target = resolve_dotted(cls.__module__, expr)
        return plugin_name_of(target) if target is not None else expr
    return ""

def wide_formatter(prog):
    # A very wide formatter keeps every option on one line, so nothing has to
    # be un-wrapped afterwards.
    return argparse.HelpFormatter(prog, max_help_position=10000, width=100000)

def render_nargs(action):
    metavar = action.metavar or (action.dest.upper() if action.dest else "")
    if isinstance(metavar, tuple):
        metavar = " ".join(str(m) for m in metavar)
    nargs = action.nargs
    if nargs == 0:
        return ""
    if nargs is None:
        return metavar
    if nargs == "?":
        return "[%s]" % metavar
    if nargs == "*":
        return "[%s ...]" % metavar
    if nargs == "+":
        return "%s [%s ...]" % (metavar, metavar)
    if isinstance(nargs, int):
        return " ".join([metavar] * nargs)
    return metavar

def invocation(formatter, action):
    try:
        return formatter._format_action_invocation(action)
    except Exception:
        joined = ", ".join(action.option_strings) or (action.dest or "")
        args = render_nargs(action)
        return (joined + " " + args).strip() if args else joined

for full_name in sorted(plugins):
    cls = plugins[full_name]
    entry = {
        "full_name": full_name,
        "description": "",
        "deprecated": False,
        "deprecated_new_name": "",
        "requirement_classes": [],
        "flags": [],
        "usage": "",
        "has_required_flag": False,
        "writes_to_disk": False,
        "error": "",
    }
    # cls.__doc__, not inspect.getdoc(): getdoc() walks the MRO and would
    # report PluginInterface's docstring for a plugin that has none, which is
    # not what `vol --help` shows.
    doc = textwrap.dedent(cls.__doc__ or "").strip()
    entry["description"] = doc.split("\n\n", 1)[0].strip()

    if file_write_pattern is not None:
        try:
            entry["writes_to_disk"] = bool(
                file_write_pattern.search(inspect.getsource(cls))
            )
        except Exception:
            pass

    is_renamed = bool(rename_base) and isinstance(cls, type) and issubclass(cls, rename_base)
    entry["deprecated"] = bool(is_renamed or "deprecat" in doc.lower())
    if is_renamed:
        entry["deprecated_new_name"] = replacement_name(cls)

    try:
        entry["requirement_classes"] = [type(r).__name__ for r in cls.get_requirements()]
    except Exception as exc:
        entry["error"] = "get_requirements: %s" % exc

    parser = parser_cls(prog="%s %s" % (cli_name, full_name), formatter_class=wide_formatter,
                        description=entry["description"], add_help=True)
    baseline = len(parser._actions)
    if populate is not None:
        try:
            populate(None, parser, cls)
        except Exception as exc:
            entry["error"] = (entry["error"] + "; " if entry["error"] else "") + "populate: %s" % exc

    formatter = parser._get_formatter()
    for action in parser._actions[baseline:]:
        entry["flags"].append({
            "invocation": invocation(formatter, action),
            "help": action.help or "",
            "required": bool(action.required),
        })
        if action.required:
            entry["has_required_flag"] = True

    try:
        entry["usage"] = parser.format_usage()
    except Exception as exc:
        entry["error"] = (entry["error"] + "; " if entry["error"] else "") + "usage: %s" % exc

    result["plugins"].append(entry)

with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(result, handle)
'''


class CollectorError(RuntimeError):
    """Raised when a collector cannot produce an inventory."""


def format_flag(invocation: str, help_text: str) -> str:
    invocation = collapse(invocation)
    help_text = collapse(help_text)
    return f"{invocation}{FLAG_SEP}{help_text}" if help_text else invocation


def clean_usage(usage: str) -> str:
    usage = collapse(usage)
    return re.sub(r"^usage:\s*", "", usage, flags=re.IGNORECASE)


def collect_via_api(paths: "Paths", verbose: bool = False) -> List[Dict[str, Any]]:
    """Enumerate plugins by importing volatility3 inside its virtualenv."""
    with tempfile.TemporaryDirectory(prefix="volinv-") as tmpdir:
        out_path = os.path.join(tmpdir, "plugins.json")
        env = dict(os.environ)
        # Make the checkout importable even when the venv has no editable install.
        env["PYTHONPATH"] = os.pathsep.join(
            [paths.vol_root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
        )
        env["PYTHONWARNINGS"] = "ignore"
        proc = subprocess.run(
            [paths.python, "-", out_path, paths.cli_name, FILE_WRITE_PATTERN.pattern],
            input=PROBE_SOURCE,
            text=True,
            capture_output=True,
            cwd=paths.vol_root,
            env=env,
        )
        if proc.returncode != 0 or not os.path.exists(out_path):
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise CollectorError(
                "framework introspection failed (exit %s): %s"
                % (proc.returncode, detail[-1] if detail else "no output")
            )
        with open(out_path, encoding="utf-8") as handle:
            payload = json.load(handle)

    if verbose:
        version = payload.get("framework_version") or "unknown"
        log(f"framework version {version}, {len(payload.get('plugins', []))} plugins")
        for failure in payload.get("import_failures", []):
            log(f"plugin import failure: {failure}")
        for err in payload.get("errors", []):
            log(f"probe warning: {err}")

    records = []
    for entry in payload.get("plugins", []):
        if verbose and entry.get("error"):
            log(f"{entry['full_name']}: {entry['error']}")
        raw_flags = entry.get("flags", [])
        flags = [format_flag(f["invocation"], f["help"]) for f in raw_flags]
        writes_files = writes_files_unconditionally(
            entry.get("writes_to_disk", False),
            # Invocations only -- never the formatted line, whose description
            # text can contain "dump" and fake a gating flag.
            [f["invocation"] for f in raw_flags],
        )
        records.append(
            make_record(
                full_name=entry["full_name"],
                description=collapse(entry.get("description")),
                deprecated=bool(entry.get("deprecated")),
                deprecated_new_name=collapse(entry.get("deprecated_new_name")),
                target_system=derive_target_system(
                    entry["full_name"], entry.get("requirement_classes", [])
                ),
                additional_flags=flags,
                usage=clean_usage(entry.get("usage", "")),
                # Bulk-safe means: runs with no arguments AND leaves no files
                # behind.  Every plugin renders a TreeGrid, so -r jsonl/csv is
                # universal and cannot be part of the test -- see the subject
                # document.
                bulk_support=not entry.get("has_required_flag") and not writes_files,
                needs_kernel=KERNEL_REQUIREMENT_CLASS
                in entry.get("requirement_classes", []),
            )
        )
    return records


# --------------------------------------------------------------------------
# Collector 2: parsing the command-line help output
# --------------------------------------------------------------------------

# Matches an option line in argparse's help: two spaces, then a dash.
OPTION_LINE = re.compile(r"^ {2}(-\S.*)$")
# Matches argparse's complaint about missing required arguments.
MISSING_ARGS = re.compile(r"the following arguments are required:\s*(.+)")
# Matches argparse rejecting a placeholder value, e.g. an empty string for an int.
INVALID_ARG = re.compile(r"argument (--[\w-]+)[^:]*: invalid")
# Matches argparse listing the values a choice option will accept.
INVALID_CHOICE = re.compile(r"invalid choice: .*?\(choose from ([^)]*)\)")
# Placeholder values tried, in order, for a required option we only want to
# get past.  An empty string suits strings and lists; "0" suits integers.
PLACEHOLDER_VALUES = ("", "0")
# Matches a plugin entry in `vol --help`'s plugin list.
PLUGIN_LINE = re.compile(r"^ {4}(\S+)(?:\s{2,}(.*))?$")


def run_vol(paths: "Paths", args: Sequence[str], timeout: int = 120) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.setdefault("PYTHONWARNINGS", "ignore")
    # Keep argparse from wrapping help text to the caller's terminal width.
    env["COLUMNS"] = "100000"
    return subprocess.run(
        [paths.vol] + list(args),
        text=True,
        capture_output=True,
        env=env,
        timeout=timeout,
    )


def satisfy_required(
    runner: Callable[[List[str]], Any], max_rounds: int = 8
) -> Any:
    """Re-invoke ``runner`` until required options stop blocking it.

    Some plugins (linux.vmaregexscan.VmaRegExScan, linux.module_extract.
    ModuleExtract) reject the command line before argparse prints anything
    useful.  The missing options are read back out of the error and retried
    with placeholder values, stepping through PLACEHOLDER_VALUES when a value
    is rejected for its type.  Returns whatever ``runner`` last returned.
    """
    chosen: Dict[str, str] = {}
    step: Dict[str, int] = {}
    result = None
    for _ in range(max_rounds):
        extra: List[str] = []
        for flag, value in chosen.items():
            extra.extend([flag, value])
        result, done, output = runner(extra)
        if done:
            return result
        progressed = False
        match = MISSING_ARGS.search(output)
        if match:
            for token in match.group(1).split():
                flag = token.strip().strip(",")
                if flag.startswith("--") and flag not in chosen:
                    chosen[flag] = PLACEHOLDER_VALUES[0]
                    step[flag] = 0
                    progressed = True
        invalid = INVALID_ARG.search(output)
        if invalid:
            flag = invalid.group(1)
            choices = INVALID_CHOICE.search(output)
            if choices and flag in chosen:
                # A choice option accepts nothing generic; take the first
                # value argparse just listed.
                first = choices.group(1).split(",")[0].strip().strip("'\"")
                if first and chosen[flag] != first:
                    chosen[flag] = first
                    progressed = True
            elif flag in chosen and step[flag] + 1 < len(PLACEHOLDER_VALUES):
                step[flag] += 1
                chosen[flag] = PLACEHOLDER_VALUES[step[flag]]
                progressed = True
        if not progressed:
            return result
    return result


def plugin_help_text(paths: "Paths", full_name: str, verbose: bool = False) -> str:
    """Return a plugin's --help, supplying placeholders for required options."""

    def attempt(extra: List[str]):
        proc = run_vol(paths, [full_name, "--help"] + extra)
        text = proc.stdout or ""
        ok = bool(OPTION_LINE.search(text) or "usage:" in text)
        return text, ok, (proc.stderr or "") + text

    text = satisfy_required(attempt) or ""
    if verbose and not text:
        log(f"{full_name}: no help text could be obtained")
    return text


def parse_plugin_help(text: str) -> Dict[str, Any]:
    """Pull the usage line and the option entries out of a plugin's --help.

    argparse wraps both the usage block and long option descriptions onto
    continuation lines, so each is rejoined before being emitted.
    """
    usage_lines: List[str] = []
    flags: List[List[str]] = []
    in_usage = False
    current: Optional[List[str]] = None
    skipping = False

    def flush():
        if current:
            flags.append(current)

    for raw in text.splitlines():
        line = raw.rstrip()
        if line.lower().startswith("usage:"):
            in_usage = True
            usage_lines.append(line)
            continue
        if in_usage:
            # A wrapped usage block continues with deep indentation.
            if line.startswith(" " * 7) and line.strip():
                usage_lines.append(line)
                continue
            in_usage = False

        match = OPTION_LINE.match(line)
        if match:
            flush()
            current, skipping = None, False
            head = match.group(1).split("  ", 1)
            invocation = head[0].strip()
            if invocation.split(",")[0].strip() in ("-h", "--help"):
                skipping = True
                continue
            current = [invocation, head[1].strip() if len(head) > 1 else ""]
            continue
        if not line.strip():
            # A blank line closes the options section.
            flush()
            current, skipping = None, False
            continue
        if (current or skipping) and line.startswith(" " * 4):
            if current:
                current[1] = collapse(f"{current[1]} {line}")
            continue
        flush()
        current, skipping = None, False
    flush()

    return {
        "usage": clean_usage(" ".join(usage_lines)),
        "flags": [format_flag(invocation, help_text) for invocation, help_text in flags],
        # Kept apart from "flags": a flag's *description* often contains the
        # word "dump" ("--virtaddr  Dump the _FILE_OBJECTs at ..."), which
        # would read as a gating flag if the formatted line were matched.
        "invocations": [invocation for invocation, _ in flags],
    }


def parse_plugin_list(text: str) -> Dict[str, str]:
    """Pull ``name -> short description`` out of ``vol --help``."""
    plugins: Dict[str, str] = {}
    started = False
    current: Optional[str] = None
    for line in text.splitlines():
        if re.match(r"^\s*Plugins\s*:?\s*$", line):
            started = True
            continue
        if not started:
            continue
        match = PLUGIN_LINE.match(line.rstrip())
        if match and re.match(r"^[A-Za-z_][\w.]*\.[A-Za-z_]\w*$", match.group(1)):
            current = match.group(1)
            plugins[current] = collapse(match.group(2))
            continue
        # A description too long for the name column continues on its own lines.
        if current and line.startswith(" " * 8) and line.strip():
            plugins[current] = collapse(f"{plugins[current]} {line}")
        elif line.strip() and not line.startswith(" "):
            current = None
    return plugins


def collect_via_help(paths: "Paths", verbose: bool = False) -> List[Dict[str, Any]]:
    """Enumerate plugins by scraping the command-line help output."""
    proc = run_vol(paths, ["--help"])
    listing = parse_plugin_list(proc.stdout or "")
    if not listing:
        raise CollectorError("could not parse a plugin list from 'vol --help'")
    if verbose:
        log(f"{len(listing)} plugins listed; querying each for options")

    records = []
    for full_name, description in sorted(listing.items()):
        parsed = parse_plugin_help(plugin_help_text(paths, full_name, verbose))
        own_source = plugin_class_source(paths, full_name)
        # File writing is the plugin's own behaviour, so it is read from the
        # plugin's own class even when that class is a rename shim.
        writes_files = writes_files_unconditionally(
            bool(FILE_WRITE_PATTERN.search(own_source)),
            parsed["invocations"],
        )

        # A rename shim declares no requirements of its own; the framework
        # copies them from the replacement, so read them from there.
        renamed = bool(RENAME_BASE_PATTERN.search(own_source))
        deprecated_new_name = ""
        requirement_source = own_source
        if renamed:
            deprecated_new_name = resolve_replacement_name(
                replacement_expression(own_source),
                listing.keys(),
                full_name,
                module_aliases(plugin_module_path(paths, full_name)),
            )
            if deprecated_new_name:
                requirement_source = (
                    plugin_class_source(paths, deprecated_new_name) or own_source
                )
        needs_kernel = bool(KERNEL_REQUIREMENT_PATTERN.search(requirement_source))
        if len(full_name.split(".")) > 2:
            target_system = derive_target_system(full_name, [])
        else:
            # No requirement objects here, so ask the CLI directly.
            marker = "TranslationLayerRequirement" if probe_needs_image(paths, full_name) else ""
            target_system = derive_target_system(full_name, [marker] if marker else [])
        usage = parsed["usage"]
        # Without the framework we can only see required flags in the usage
        # line: argparse brackets optional ones and leaves required ones bare.
        # Optional groups nest ("[--symbols [SYMBOLS ...]]"), so strip
        # brackets innermost-first until none are left.
        stripped = usage
        while True:
            collapsed_once = re.sub(r"\[[^\[\]]*\]", "", stripped)
            if collapsed_once == stripped:
                break
            stripped = collapsed_once
        required = bool(re.search(r"--[\w-]+", stripped))
        deprecated = renamed or "deprecat" in description.lower()
        records.append(
            make_record(
                full_name=full_name,
                description=description,
                deprecated=deprecated,
                deprecated_new_name=deprecated_new_name,
                target_system=target_system,
                additional_flags=parsed["flags"],
                usage=usage,
                bulk_support=not required and not writes_files,
                needs_kernel=needs_kernel,
            )
        )
    return records


def plugin_module_path(paths: "Paths", full_name: str) -> str:
    """Locate the .py file defining a plugin, from its dotted name."""
    *module_parts, _ = full_name.split(".")
    if not module_parts:
        return ""
    for package in ("volatility3/framework/plugins", "volatility3/plugins"):
        path = os.path.join(paths.vol_root, package, *module_parts) + ".py"
        if os.path.exists(path):
            return path
    return ""


def module_aliases(module_path: str) -> Dict[str, str]:
    """Map each name a module imports to the module it came from.

    Needed because a rename shim may import its replacement under an alias
    (``from ...linux.malware import tty_check as ttycheck``), so the name in
    ``replacement_class=`` is not the module's real name.
    """
    try:
        with open(module_path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
    except (OSError, SyntaxError, ValueError):
        return {}
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
    return aliases


def plugin_class_source(paths: "Paths", full_name: str) -> str:
    """Read one plugin class's source straight off disk.

    The help collector has no framework objects, so it locates the module from
    the plugin name -- everything but the last segment is the module path, the
    last is the class -- and pulls that class out with ``ast``.  A module can
    hold several plugins (linux/pagecache.py has InodePages and RecoverFs), so
    the whole file will not do.
    """
    *module_parts, class_name = full_name.split(".")
    if not module_parts:
        return ""
    for package in ("volatility3/framework/plugins", "volatility3/plugins"):
        path = os.path.join(paths.vol_root, package, *module_parts) + ".py"
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                source = handle.read()
            tree = ast.parse(source)
        except (OSError, SyntaxError, ValueError):
            return ""
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                return ast.get_source_segment(source, node) or ""
        return ""
    return ""


def replacement_expression(class_source: str) -> str:
    """Return the ``replacement_class=`` keyword of a renamed plugin's class."""
    try:
        node = ast.parse(class_source).body[0]
    except (SyntaxError, ValueError, IndexError):
        return ""
    if not isinstance(node, ast.ClassDef):
        return ""
    for keyword in node.keywords:
        if keyword.arg in ("replacement_class", "replacement"):
            try:
                return ast.unparse(keyword.value)
            except Exception:
                return ""
    return ""


def resolve_replacement_name(
    expression: str,
    known_names: Sequence[str],
    exclude: str,
    aliases: Optional[Dict[str, str]] = None,
) -> str:
    """Turn a ``module.Class`` expression into the plugin name it refers to.

    The help collector cannot import anything, so the expression is resolved
    through the defining module's own import statements, which gives the exact
    target. Matching the expression as a name suffix is only the fallback: it
    is ambiguous (``malfind.Malfind`` suffixes five different plugins) and it
    fails outright when the import was aliased.
    """
    if not expression:
        return ""
    parts = expression.split(".")
    class_name, prefix = parts[-1], ".".join(parts[:-1])

    imported = (aliases or {}).get(prefix)
    if imported:
        for package in PLUGIN_PACKAGE_PREFIXES:
            if imported.startswith(package):
                candidate = f"{imported[len(package):]}.{class_name}"
                if candidate in known_names:
                    return candidate

    matches = [
        name
        for name in known_names
        if name.endswith("." + expression) and name != exclude
    ]
    if len(matches) == 1:
        return matches[0]
    # Ambiguous: a replacement almost always lives under the same OS package.
    namespace = exclude.split(".")[0]
    same_namespace = [n for n in matches if n.split(".")[0] == namespace]
    return same_namespace[0] if len(same_namespace) == 1 else ""


def probe_needs_image(paths: "Paths", full_name: str) -> bool:
    """Ask the CLI whether a plugin needs a memory image, by running it without one.

    Only used by the help collector, which has no access to the requirement
    objects.  A plugin that consumes an image complains that no location was
    supplied; one that does not (frameworkinfo, isfinfo) simply runs.
    """

    def attempt(extra: List[str]):
        try:
            proc = run_vol(paths, ["-q", "-r", "none", full_name] + extra, timeout=60)
        except subprocess.TimeoutExpired:
            return True, True, ""
        combined = (proc.stdout or "") + (proc.stderr or "")
        if "single_location" in combined or "Unsatisfied requirement" in combined:
            return True, True, combined
        if MISSING_ARGS.search(combined) or INVALID_ARG.search(combined):
            return False, False, combined
        return False, True, combined

    result = satisfy_required(attempt)
    return True if result is None else bool(result)


# --------------------------------------------------------------------------
# Locating the installation
# --------------------------------------------------------------------------


@dataclass
class Paths:
    vol_root: str
    venv: str
    python: str
    vol: str

    @property
    def cli_name(self) -> str:
        """The name usage lines are written against, e.g. "vol"."""
        name = os.path.basename(self.vol)
        return name[:-4] if name.lower().endswith(".exe") else name


def resolve_paths(
    vol_root: str, venv: str, python: Optional[str] = None, vol: Optional[str] = None
) -> Paths:
    root = os.path.abspath(os.path.expanduser(vol_root))
    venv_expanded = os.path.expanduser(venv)
    # A bare name (the default, "venv") is taken relative to the checkout.
    venv_path = (
        venv_expanded
        if os.path.isabs(venv_expanded)
        else os.path.abspath(os.path.join(root, venv_expanded))
    )
    bindir = "Scripts" if os.name == "nt" else "bin"
    exe_suffix = ".exe" if os.name == "nt" else ""
    python_path = python or os.path.join(venv_path, bindir, "python" + exe_suffix)
    vol_path = vol or os.path.join(venv_path, bindir, "vol" + exe_suffix)
    return Paths(vol_root=root, venv=venv_path, python=python_path, vol=vol_path)


def check_paths(paths: Paths, method: str) -> List[str]:
    problems = []
    if not os.path.isdir(paths.vol_root):
        problems.append(f"volatility root not found: {paths.vol_root}")
    if method in ("auto", "api") and not os.path.exists(paths.python):
        problems.append(f"virtualenv interpreter not found: {paths.python}")
    if method in ("auto", "help") and not os.path.exists(paths.vol):
        problems.append(f"vol executable not found: {paths.vol}")
    return problems


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def log(message: str) -> None:
    print(f"[vol-inventory] {message}", file=sys.stderr)


def write_csv(records: Sequence[Dict[str, Any]], columns: Sequence[Column], stream) -> None:
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow([column.name for column in columns])
    for record in records:
        writer.writerow([column.getter(record) for column in columns])


def select_columns(columns: Sequence[Column], wanted: Optional[str]) -> List[Column]:
    if not wanted:
        return list(columns)
    available = {column.name.lower(): column for column in columns}
    chosen = []
    for name in (part.strip() for part in wanted.split(",")):
        if not name:
            continue
        column = available.get(name.lower())
        if column is None:
            raise SystemExit(
                f"unknown column {name!r}; available: "
                + ", ".join(c.name for c in columns)
            )
        chosen.append(column)
    if not chosen:
        raise SystemExit("--columns selected no columns")
    return chosen


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a CSV inventory of Volatility 3 plugins and their options.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s -o plugins.csv\n"
            "  %(prog)s --vol-root /opt/volatility3 --venv /opt/venvs/vol3\n"
            "  %(prog)s --method help --columns FullName,TargetSystem,Usage\n"
        ),
    )
    parser.add_argument(
        "--vol-root",
        default=DEFAULT_VOL_ROOT,
        metavar="PATH",
        help="Volatility 3 installation directory (default: %(default)s)",
    )
    parser.add_argument(
        "--venv",
        default=DEFAULT_VENV,
        metavar="PATH",
        help="virtualenv directory; a bare name is taken relative to --vol-root "
        "(default: %(default)s)",
    )
    parser.add_argument(
        "--python",
        metavar="PATH",
        help="interpreter to introspect with (default: <venv>/bin/python)",
    )
    parser.add_argument(
        "--vol",
        metavar="PATH",
        help="vol executable to call (default: <venv>/bin/vol)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        metavar="FILE",
        help=f"write here, or {STDOUT_PATH!r} for stdout "
        f"(default: %(default)s, or {DEFAULT_JSON_OUTPUT} with --json)",
    )
    parser.add_argument(
        "--method",
        choices=("auto", "api", "help"),
        default="auto",
        help="how to gather plugin data: framework introspection, CLI help "
        "scraping, or introspection falling back to scraping (default: %(default)s)",
    )
    parser.add_argument(
        "--columns",
        metavar="LIST",
        help="comma-separated column names, in the order to emit them",
    )
    parser.add_argument(
        "--list-columns",
        action="store_true",
        help="print the available column names and exit",
    )
    parser.add_argument(
        "--target-override",
        action="append",
        default=[],
        metavar="PLUGIN=SYSTEM",
        help="force TargetSystem for a plugin; repeatable",
    )
    parser.add_argument(
        "--bool-style",
        choices=sorted(BOOL_STYLES),
        default="python",
        help="how to render boolean columns (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON records instead of CSV (all fields, columns ignored)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="report progress on stderr"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    columns = build_columns(args.bool_style)

    for override in args.target_override:
        plugin, _, system = override.partition("=")
        if not plugin or not system:
            raise SystemExit(f"--target-override expects PLUGIN=SYSTEM, got {override!r}")
        TARGET_SYSTEM_OVERRIDES[plugin.strip()] = system.strip()

    if args.list_columns:
        for column in columns:
            print(column.name)
        return 0

    paths = resolve_paths(args.vol_root, args.venv, args.python, args.vol)
    problems = check_paths(paths, args.method)
    if problems:
        for problem in problems:
            log(problem)
        log("use --vol-root / --venv (or --python / --vol) to point at the install")
        return 2

    records: List[Dict[str, Any]] = []
    if args.method in ("auto", "api"):
        try:
            records = collect_via_api(paths, args.verbose)
        except (CollectorError, json.JSONDecodeError, OSError) as exc:
            if args.method == "api":
                log(f"introspection failed: {exc}")
                return 1
            log(f"introspection failed ({exc}); falling back to help scraping")
    if not records:
        try:
            records = collect_via_help(paths, args.verbose)
        except (CollectorError, OSError, subprocess.TimeoutExpired) as exc:
            log(f"help scraping failed: {exc}")
            return 1

    if not records:
        log("no plugins found")
        return 1

    # ShortName depends on every other plugin's name, so it is resolved once
    # the full set is in hand rather than per plugin.
    apply_short_names(records)
    records.sort(key=lambda record: record["full_name"])
    if args.verbose:
        log(f"{len(records)} plugins collected")

    selected = select_columns(columns, args.columns)
    def emit(handle):
        if args.json:
            json.dump(records, handle, indent=2)
            handle.write("\n")
        else:
            write_csv(records, selected, handle)

    destination = args.output
    if args.json and destination == DEFAULT_OUTPUT:
        destination = DEFAULT_JSON_OUTPUT

    if destination == STDOUT_PATH:
        emit(sys.stdout)
    else:
        with open(destination, "w", encoding="utf-8", newline="") as handle:
            emit(handle)
        log(f"wrote {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
