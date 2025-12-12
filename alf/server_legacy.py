#!/usr/bin/env python3
"""
Legacy compatibility shim.

`alf.server` is now a package. This module preserves old import paths and
entrypoints while delegating to the refactored implementation in
`alf.server.*`.
"""

from __future__ import annotations

from .server.app import build_mcp, main
from .server.lldb import LLDBDirector

__all__ = ["LLDBDirector", "build_mcp", "main"]
