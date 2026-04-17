"""Canonical LLDB tool definitions.

These are the LLDB debugging tools migrated to the canonical Tool format.
They can be registered with both MCP (via register_with_mcp) and provider APIs
(via the converters module).

Usage:
    from alf.tools.definitions.lldb import LLDB_TOOLS, LLDB_LAUNCH

    # Register all LLDB tools with MCP
    for tool in LLDB_TOOLS:
        tool.register_with_mcp(mcp, director)

    # Or register a single tool
    LLDB_LAUNCH.register_with_mcp(mcp, director)
"""

from __future__ import annotations

# Import all tools from submodules
from .crash_analysis import (
    CRASH_ANALYSIS_TOOLS,
    LLDB_CRASH_CONTEXT,
    LLDB_POLL_CRASHES,
    LLDB_STACK_HASH,
)
from .execution import (
    EXECUTION_TOOLS,
    LLDB_BREAKPOINT_DELETE,
    LLDB_BREAKPOINT_LIST,
    LLDB_CONTINUE,
    LLDB_EXECUTE,
    LLDB_REMOVE_ALL_BREAKPOINTS,
    LLDB_SET_BREAKPOINT,
    LLDB_STEP,
    LLDB_WATCHPOINT,
)
from .inspection import (
    INSPECTION_TOOLS,
    LLDB_BACKTRACE,
    LLDB_BACKTRACE_JSON,
    LLDB_DEREF,
    LLDB_DISASSEMBLE,
    LLDB_EVALUATE,
    LLDB_FRAME_SELECT,
    LLDB_FRAME_VARIABLES,
    LLDB_MEMORY_SEARCH,
    LLDB_READ_MEMORY,
    LLDB_REGISTER_READ,
    LLDB_REGISTER_WRITE,
    LLDB_THREAD_LIST,
    LLDB_THREAD_SELECT,
)
from .kernel import (
    KERNEL_TOOLS,
    LLDB_ADD_MODULE,
    LLDB_LOAD_XNU_MACROS,
    LLDB_SLIDE,
    LLDB_WRITE_MEMORY,
)
from .scripting import LLDB_SCRIPT, SCRIPTING_TOOLS
from .session import (
    LLDB_ATTACH,
    LLDB_GDB_REMOTE,
    LLDB_HELP,
    LLDB_KILL,
    LLDB_LAUNCH,
    LLDB_LOAD_CORE,
    LLDB_PROCESS_INFO,
    LLDB_STATUS,
    LLDB_TERMINATE,
    SESSION_TOOLS,
)
from .symbols import (
    LLDB_DUMP_SYMTAB,
    LLDB_LOOKUP_SYMBOL,
    LLDB_READ_SOURCE,
    SYMBOL_TOOLS,
)
from .validation import LLDB_VALIDATE_INPUT_CONTROL, VALIDATION_TOOLS

# =============================================================================
# Exported Tool List
# =============================================================================

# NOTE: LLDB_CONTINUE is defined but not included in LLDB_TOOLS because
# the MCP server version has extra functionality (crash notifications via SSE).
# It's kept as an async inline tool in app.py.

LLDB_TOOLS = [
    # Core session management
    LLDB_LAUNCH,
    LLDB_ATTACH,
    LLDB_GDB_REMOTE,
    LLDB_LOAD_CORE,
    LLDB_STATUS,
    LLDB_PROCESS_INFO,
    LLDB_HELP,
    LLDB_TERMINATE,
    LLDB_KILL,
    # Execution control
    LLDB_EXECUTE,
    # LLDB_CONTINUE - has MCP-specific crash notifications, kept inline in app.py
    LLDB_STEP,
    # Breakpoints and watchpoints
    LLDB_SET_BREAKPOINT,
    LLDB_BREAKPOINT_LIST,
    LLDB_BREAKPOINT_DELETE,
    LLDB_REMOVE_ALL_BREAKPOINTS,
    LLDB_WATCHPOINT,
    # Thread and frame management
    LLDB_THREAD_LIST,
    LLDB_THREAD_SELECT,
    LLDB_FRAME_SELECT,
    LLDB_FRAME_VARIABLES,
    # Stack and crash analysis
    LLDB_BACKTRACE,
    LLDB_BACKTRACE_JSON,
    LLDB_STACK_HASH,
    LLDB_CRASH_CONTEXT,
    LLDB_POLL_CRASHES,
    # Memory inspection
    LLDB_READ_MEMORY,
    LLDB_DEREF,
    LLDB_MEMORY_SEARCH,
    LLDB_DISASSEMBLE,
    # Register operations
    LLDB_REGISTER_READ,
    LLDB_REGISTER_WRITE,
    # Expression evaluation
    LLDB_EVALUATE,
    # Symbol lookup
    LLDB_LOOKUP_SYMBOL,
    LLDB_DUMP_SYMTAB,
    # Source inspection
    LLDB_READ_SOURCE,
    # Scripting
    LLDB_SCRIPT,
    # Kernel / remote debugging
    LLDB_ADD_MODULE,
    LLDB_SLIDE,
    LLDB_LOAD_XNU_MACROS,
    LLDB_WRITE_MEMORY,
    # Input control validation (Phase 1 dynamic tracing)
    LLDB_VALIDATE_INPUT_CONTROL,
]


__all__ = [
    # Individual tools - Core session
    "LLDB_LAUNCH",
    "LLDB_ATTACH",
    "LLDB_GDB_REMOTE",
    "LLDB_LOAD_CORE",
    "LLDB_STATUS",
    "LLDB_PROCESS_INFO",
    "LLDB_HELP",
    "LLDB_TERMINATE",
    "LLDB_KILL",
    # Individual tools - Execution control
    "LLDB_EXECUTE",
    "LLDB_CONTINUE",  # Available for non-MCP use
    "LLDB_STEP",
    # Individual tools - Breakpoints
    "LLDB_SET_BREAKPOINT",
    "LLDB_BREAKPOINT_LIST",
    "LLDB_BREAKPOINT_DELETE",
    "LLDB_REMOVE_ALL_BREAKPOINTS",
    "LLDB_WATCHPOINT",
    # Individual tools - Thread/frame
    "LLDB_THREAD_LIST",
    "LLDB_THREAD_SELECT",
    "LLDB_FRAME_SELECT",
    "LLDB_FRAME_VARIABLES",
    # Individual tools - Stack/crash
    "LLDB_BACKTRACE",
    "LLDB_BACKTRACE_JSON",
    "LLDB_STACK_HASH",
    "LLDB_CRASH_CONTEXT",
    "LLDB_POLL_CRASHES",
    # Individual tools - Memory
    "LLDB_READ_MEMORY",
    "LLDB_DEREF",
    "LLDB_MEMORY_SEARCH",
    "LLDB_DISASSEMBLE",
    # Individual tools - Registers
    "LLDB_REGISTER_READ",
    "LLDB_REGISTER_WRITE",
    # Individual tools - Evaluation
    "LLDB_EVALUATE",
    # Individual tools - Symbols
    "LLDB_LOOKUP_SYMBOL",
    "LLDB_DUMP_SYMTAB",
    # Individual tools - Source
    "LLDB_READ_SOURCE",
    # Individual tools - Scripting
    "LLDB_SCRIPT",
    # Individual tools - Kernel / remote
    "LLDB_ADD_MODULE",
    "LLDB_SLIDE",
    "LLDB_LOAD_XNU_MACROS",
    "LLDB_WRITE_MEMORY",
    # Individual tools - Input control validation
    "LLDB_VALIDATE_INPUT_CONTROL",
    # Tool lists by category
    "SESSION_TOOLS",
    "EXECUTION_TOOLS",
    "INSPECTION_TOOLS",
    "CRASH_ANALYSIS_TOOLS",
    "SYMBOL_TOOLS",
    "SCRIPTING_TOOLS",
    "KERNEL_TOOLS",
    "VALIDATION_TOOLS",
    # Combined tool list
    "LLDB_TOOLS",
]
