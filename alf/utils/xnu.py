"""Shared helpers for locating Apple's xnu lldbmacros.

The xnu lldbmacros package (``xnu.py`` plus a pile of support modules)
lives in one of a handful of conventional locations on developer
machines. Both ``alf doctor`` and ``LLDBDirector.load_xnu_macros`` need
to agree on the search order so the preflight check matches runtime
behavior.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

__all__ = ["lldbmacros_candidates", "find_lldbmacros"]


# Glob patterns applied under KDK roots.
_KDK_GLOB = "*/System/Library/Kernels/*.dSYM/Contents/Resources/DWARF/lldbmacros"

# Roots that may contain KDKs.
_KDK_ROOTS: tuple[Path, ...] = (
    Path("/Library/Developer/KDKs"),
    Path.home() / "Library" / "Developer" / "KDKs",
)

# Direct fallback locations.
_DIRECT_CANDIDATES: tuple[Path, ...] = (
    Path.home() / "src" / "xnu" / "tools" / "lldbmacros",
    Path.home() / "Developer" / "xnu" / "tools" / "lldbmacros",
)


def lldbmacros_candidates(explicit: str | Path | None = None) -> Iterable[Path]:
    """Yield candidate lldbmacros directories, in priority order.

    The first candidate whose ``xnu.py`` exists is the one to use.
    """
    if explicit is not None:
        p = Path(explicit).expanduser()
        if p.name == "xnu.py":
            yield p.parent
        else:
            yield p

    env = os.environ.get("ALF_XNU_LLDBMACROS")
    if env:
        yield Path(env).expanduser()

    yield from _DIRECT_CANDIDATES

    for root in _KDK_ROOTS:
        if not root.is_dir():
            continue
        try:
            yield from root.glob(_KDK_GLOB)
        except OSError:
            continue


def find_lldbmacros(explicit: str | Path | None = None) -> Path | None:
    """Return the first candidate directory whose ``xnu.py`` exists."""
    for cand in lldbmacros_candidates(explicit):
        if (cand / "xnu.py").is_file():
            return cand
    return None
