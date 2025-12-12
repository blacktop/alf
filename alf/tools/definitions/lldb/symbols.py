"""LLDB symbol and source tools: lookup, dump symtab, read source."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from ._common import Tool, ToolParameter, json

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_lookup_symbol_handler(
    director: LLDBDirector,
    *,
    query: str,
    regex_search: bool = True,
    max_results: int = 200,
) -> str:
    """Look up symbols in loaded images."""
    if regex_search:
        cmd = f"image lookup -rn '{query}'"
    else:
        cmd = f"image lookup -n '{query}'"
    out = director.execute_lldb_command(cmd)
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
        "Returns symbol addresses and module information."
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
            description="Maximum lines of output to return",
            required=False,
            default=200,
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
