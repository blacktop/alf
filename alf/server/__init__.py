"""
ALF LLDB‑MCP Server package.

This package is being refactored into dual domains:
  - `alf.server.static` for on‑disk Mach‑O analysis
  - `alf.server.runtime` for in‑process interrogation via LLDB

During the transition, legacy exports are re‑exported from
`alf.server_legacy` so existing clients keep working.
"""

from __future__ import annotations

from .app import build_mcp, main
from .lldb import LLDBDirector

__all__ = ["LLDBDirector", "build_mcp", "main"]
