"""Symbol table helpers (currently LLDB-backed)."""

from __future__ import annotations

from ..lldb import LLDBDirector


def lookup_symbol(director: LLDBDirector, query: str, regex_search: bool = True) -> str:
    if regex_search:
        cmd = f"image lookup -rn '{query}'"
    else:
        cmd = f"image lookup -n '{query}'"
    return director.execute_lldb_command(cmd)


def dump_symtab(director: LLDBDirector, filter_regex: str | None = None) -> str:
    out = director.execute_lldb_command("image dump symtab")
    if filter_regex:
        import re

        rx = re.compile(filter_regex, re.IGNORECASE)
        out = "\n".join([ln for ln in out.splitlines() if rx.search(ln)])
    return out
