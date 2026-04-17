"""LLDB symbol and source tools: lookup, dump symtab, read source."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ._common import Tool, ToolParameter, json

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


_LOOKUP_ADDR_RE = re.compile(r"Address:\s+(\S+)\[(0x[0-9a-fA-F]+)\]")
_LOOKUP_SUMMARY_PREFIX = "Summary:"
# Trailing " + <digits>" offset suffix that lldb appends to symbol names.
_LOOKUP_OFFSET_SUFFIX_RE = re.compile(r"\s+\+\s+(\d+)\s*$")


def _parse_lookup_output(raw: str) -> list[dict[str, Any]]:
    """Parse `image lookup -rn/-n` output into structured matches.

    Symbol names can contain spaces, brackets, and operators
    (Objective-C selectors like ``-[NSApplication run]``, C++
    templates), so the parser captures everything between the module
    backtick and an optional trailing ``+ <offset>`` suffix — it does
    not stop at the first whitespace.
    """
    matches: list[dict[str, Any]] = []
    module_path: str | None = None
    addr: str | None = None
    for line in raw.splitlines():
        stripped = line.strip()
        addr_match = _LOOKUP_ADDR_RE.search(stripped)
        if addr_match:
            module_path = addr_match.group(1)
            addr = addr_match.group(2)
            continue
        if addr is None or not stripped.startswith(_LOOKUP_SUMMARY_PREFIX):
            continue
        summary = stripped[len(_LOOKUP_SUMMARY_PREFIX) :].strip()
        if "`" not in summary:
            continue
        module, remainder = summary.split("`", 1)
        offset: int | None = None
        offset_match = _LOOKUP_OFFSET_SUFFIX_RE.search(remainder)
        if offset_match:
            offset = int(offset_match.group(1))
            remainder = remainder[: offset_match.start()]
        entry: dict[str, Any] = {
            "addr": addr,
            "module": module,
            "module_path": module_path,
            "name": remainder.rstrip(),
        }
        if offset is not None:
            entry["offset"] = offset
        matches.append(entry)
        addr = None
        module_path = None
    return matches


def _lldb_lookup_symbol_handler(
    director: LLDBDirector,
    *,
    query: str,
    regex_search: bool = True,
    max_results: int = 200,
    as_json: bool = False,
) -> str:
    """Look up symbols in loaded images."""
    if regex_search:
        cmd = f"image lookup -rn '{query}'"
    else:
        cmd = f"image lookup -n '{query}'"
    out = director.execute_lldb_command(cmd)

    if as_json:
        parsed = _parse_lookup_output(out)
        limit = max_results if max_results and max_results > 0 else len(parsed)
        truncated = len(parsed) > limit
        return json.dumps(
            {
                "query": query,
                "regex": regex_search,
                "matches": parsed[:limit],
                "truncated": truncated,
            },
            indent=2,
        )

    if max_results and max_results > 0:
        lines = out.splitlines()
        if len(lines) > max_results:
            out = "\n".join(lines[:max_results] + ["... (truncated)"])
    return out


def _lldb_dump_symtab_handler(
    director: LLDBDirector,
    *,
    filter_regex: str | None = None,
    max_results: int = 400,
) -> str:
    """Dump the symbol table from loaded images."""
    out = director.execute_lldb_command("image dump symtab")
    if filter_regex:
        rx = re.compile(filter_regex, re.IGNORECASE)
        lines = [ln for ln in out.splitlines() if rx.search(ln)]
        out = "\n".join(lines)
    if max_results and max_results > 0:
        lines = out.splitlines()
        if len(lines) > max_results:
            out = "\n".join(lines[:max_results] + ["... (truncated)"])
    return out


def _lldb_read_source_handler(
    director: LLDBDirector,
    *,
    path: str,
    line: int,
    count: int = 21,
) -> str:
    """Read source file lines around a given line number."""
    p = Path(path).expanduser()
    try:
        p = p.resolve()
    except Exception:
        pass
    if not p.exists() or not p.is_file():
        return json.dumps({"error": f"file not found: {p}"}, indent=2)

    try:
        src_lines = p.read_text(errors="replace").splitlines()
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e), "path": str(p)}, indent=2)

    total = len(src_lines)
    ln = max(1, int(line))
    cnt = max(1, int(count))

    half = cnt // 2
    start = max(1, ln - half)
    end = min(total, start + cnt - 1)
    start = max(1, end - cnt + 1)

    window = []
    for idx in range(start, end + 1):
        window.append({"line": idx, "text": src_lines[idx - 1]})

    return json.dumps(
        {
            "path": str(p),
            "requested_line": ln,
            "start_line": start,
            "end_line": end,
            "lines": window,
        },
        indent=2,
    )


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_LOOKUP_SYMBOL = Tool(
    name="lldb_lookup_symbol",
    description=(
        "Look up symbols in loaded images by name or regex pattern. "
        "Searches all loaded modules for matching symbol names. "
        "Returns raw `image lookup` output by default; set as_json=True "
        "for a structured list of {addr, module, name, offset} matches "
        "suitable for kernel-debug automation."
    ),
    parameters=[
        ToolParameter(
            name="query",
            type="string",
            description="Symbol name or regex pattern to search for",
        ),
        ToolParameter(
            name="regex_search",
            type="boolean",
            description="Use regex matching (True) or exact match (False)",
            required=False,
            default=True,
        ),
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum matches (as_json) or output lines to return",
            required=False,
            default=200,
        ),
        ToolParameter(
            name="as_json",
            type="boolean",
            description=(
                "When True, parse `image lookup` output into a JSON list of "
                "{addr, module, name, offset} entries"
            ),
            required=False,
            default=False,
        ),
    ],
    handler=_lldb_lookup_symbol_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_DUMP_SYMTAB = Tool(
    name="lldb_dump_symtab",
    description=(
        "Dump the symbol table from loaded images. "
        "Returns all symbols or filters by regex pattern. Useful for identifying "
        "functions of interest for fuzzing (parsers, decoders, handlers)."
    ),
    parameters=[
        ToolParameter(
            name="filter_regex",
            type="string",
            description="Regex pattern to filter symbols (e.g., 'parse|decode')",
            required=False,
        ),
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum lines of output to return",
            required=False,
            default=400,
        ),
    ],
    handler=_lldb_dump_symtab_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_READ_SOURCE = Tool(
    name="lldb_read_source",
    description=(
        "Read source file lines around a given line number. "
        "Returns a window of source code centered on the specified line. "
        "Useful for viewing code context at crash sites or breakpoints."
    ),
    parameters=[
        ToolParameter(
            name="path",
            type="string",
            description="Absolute path to the source file",
        ),
        ToolParameter(
            name="line",
            type="integer",
            description="Line number to center the view on (1-based)",
        ),
        ToolParameter(
            name="count",
            type="integer",
            description="Total number of lines to return",
            required=False,
            default=21,
        ),
    ],
    handler=_lldb_read_source_handler,
    category="lldb",
    requires_lock=False,  # Reads from disk, not debugger state
)


SYMBOL_TOOLS = [
    LLDB_LOOKUP_SYMBOL,
    LLDB_DUMP_SYMTAB,
    LLDB_READ_SOURCE,
]

__all__ = [
    "LLDB_LOOKUP_SYMBOL",
    "LLDB_DUMP_SYMTAB",
    "LLDB_READ_SOURCE",
    "SYMBOL_TOOLS",
]
