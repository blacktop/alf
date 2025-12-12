"""
ALF LLDB Backend Abstraction.

Provides abstract interface for different LLDB connection methods:
- DAP: Debug Adapter Protocol (lldb-dap) - current default
- SBAPI: Direct LLDB Python API (fastest)
- Native MCP: Native LLDB MCP protocol

Usage:
    from alf.backend import get_backend, DAPBackend

    # Get default backend (DAP)
    backend = get_backend("dap", port=12345)

    # Or explicitly create DAP backend
    backend = DAPBackend(host="127.0.0.1", port=12345)
    backend.connect()
    result = backend.launch("/path/to/binary")

    # Use SBAPI for maximum performance
    backend = get_backend("sbapi", binary="/path/to/binary")
"""

from __future__ import annotations

from .base import (
    BreakpointResult,
    LaunchResult,
    LLDBBackend,
    StackFrame,
    StopEvent,
    ThreadInfo,
)
from .dap import DAPBackend
from .factory import (
    DEFAULT_BACKEND,
    BackendType,
    check_backend_available,
    get_backend,
    list_backends,
)
from .lldb_mcp import LLDBMCPBackend

# Default ports for each backend (kept for backwards compatibility)
DEFAULT_PORTS = {
    "dap": 12345,
    "lldb_mcp": 59999,
}


__all__ = [
    # Factory
    "get_backend",
    "list_backends",
    "check_backend_available",
    "BackendType",
    "DEFAULT_BACKEND",
    "DEFAULT_PORTS",
    # Base classes
    "LLDBBackend",
    "LaunchResult",
    "StopEvent",
    "StackFrame",
    "ThreadInfo",
    "BreakpointResult",
    # Implementations
    "DAPBackend",
    "LLDBMCPBackend",
]
