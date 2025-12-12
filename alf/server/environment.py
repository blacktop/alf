"""
Bridge the host ALF installation into LLDB's embedded Python.

LLDB on macOS uses its own Python interpreter (often from Xcode). Scripts
imported via `command script import` will not see the uv/venv site-packages
unless we explicitly extend `sys.path`.
"""

from __future__ import annotations

from pathlib import Path


def alf_sys_path_root() -> Path:
    """Return the directory that should be added to sys.path for `import alf`."""
    return Path(__file__).resolve().parents[2]


def bootstrap_header(root: str | None = None) -> str:
    """Return a Python header that makes ALF importable inside LLDB."""
    sys_root = root or str(alf_sys_path_root())
    return (
        "import os, sys\n"
        f"_ALF_ROOT = os.environ.get('ALF_PYTHONPATH', {sys_root!r})\n"
        "if _ALF_ROOT and _ALF_ROOT not in sys.path:\n"
        "    sys.path.insert(0, _ALF_ROOT)\n"
    )
