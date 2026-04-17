"""Shared helpers for locating the `lldb-dap` adapter binary."""

from __future__ import annotations

import os
import shutil
import subprocess

__all__ = ["find_lldb_dap"]


def find_lldb_dap(explicit: str | None = None) -> str:
    """Resolve an lldb-dap binary path.

    Resolution order: explicit argument → `LLDB_DAP_BIN` env var →
    `xcrun --find lldb-dap` → PATH fallback. Returns the string
    ``"lldb-dap"`` when nothing else resolves so callers can still
    attempt `subprocess.Popen` and surface a clear error.
    """
    if explicit:
        return explicit
    env_bin = os.environ.get("LLDB_DAP_BIN")
    if env_bin:
        return env_bin
    if shutil.which("xcrun"):
        try:
            out = subprocess.check_output(
                ["xcrun", "--find", "lldb-dap"], text=True
            ).strip()
            if out:
                return out
        except Exception:  # noqa: BLE001
            pass
    return shutil.which("lldb-dap") or "lldb-dap"
