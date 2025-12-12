"""Canonical tool definitions for ALF.

This package contains all tool definitions organized by category:
- lldb.py: LLDB debugging tools (launch, attach, execute, etc.)
- static.py: Static analysis tools (macho parsing, symbol lookup)
- runtime.py: Runtime inspection tools (ObjC/Swift introspection)
- instrumentation.py: Fuzzing instrumentation tools (stop hooks, fork server, telemetry)

Usage:
    from alf.tools.definitions import all_tools, LLDB_TOOLS, STATIC_TOOLS

    # Get all tools
    for tool in all_tools():
        tool.register_with_mcp(mcp, director)

    # Get tools by category
    from alf.tools.definitions import get_tools_by_category
    lldb_tools = get_tools_by_category("lldb")
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schema import Tool

# Re-export tool lists for convenient access
from .instrumentation import INSTRUMENTATION_TOOLS
from .lldb import LLDB_TOOLS
from .meta import META_TOOLS
from .runtime import RUNTIME_TOOLS
from .static import STATIC_TOOLS
from .capabilities import CAPABILITY_TOOLS



def all_tools() -> list[Tool]:
    """Return all canonical tool definitions.

    Returns tools from all categories:
    - Meta tools (tool search, category listing)
    - LLDB debugging tools
    - Static analysis tools
    - Runtime inspection tools
    - Instrumentation/fuzzing tools
    """
    tools: list[Tool] = []
    tools.extend(META_TOOLS)  # Meta tools first for discoverability
    tools.extend(LLDB_TOOLS)
    tools.extend(STATIC_TOOLS)
    tools.extend(RUNTIME_TOOLS)
    tools.extend(INSTRUMENTATION_TOOLS)
    tools.extend(CAPABILITY_TOOLS)
    return tools



def get_tools_by_category(category: str) -> list[Tool]:
    """Return tools filtered by category.

    Args:
        category: Tool category ("lldb", "static", "runtime", "instrumentation")

    Returns:
        List of tools in the specified category.
    """
    return [t for t in all_tools() if t.category == category]


# Essential tools for crash analysis (minimal set to reduce context usage)
# Note: lldb_continue is NOT included because:
# 1. For crash triage, the binary has already crashed - no need to continue
# 2. The MCP version has special crash notification handling in app.py
ESSENTIAL_CRASH_TOOLS = [
    "lldb_launch",
    "lldb_crash_context",  # Most important - gets real crash data
    "lldb_execute",
    "lldb_backtrace",
    "lldb_backtrace_json",
    "lldb_disassemble",
    "lldb_read_memory",
    "lldb_register_read",
    "lldb_stack_hash",
]

# Minimal starter tools (for very small context windows)
# These are the absolute minimum + tool_search for discovery
MINIMAL_STARTER_TOOLS = [
    "lldb_launch",
    "lldb_crash_context",
    "lldb_execute",
    "tool_search",  # Meta-tool for discovering other tools
]


def get_essential_tools() -> list[Tool]:
    """Return minimal essential tools for crash analysis.

    This is a subset of tools optimized for smaller context windows.
    """
    all_t = all_tools()
    return [t for t in all_t if t.name in ESSENTIAL_CRASH_TOOLS]


def get_minimal_tools() -> list[Tool]:
    """Return absolute minimal tools for very small context windows.

    Includes only core tools + tool_search for discovering more.
    Use this for models with 4K-8K context.
    """
    all_t = all_tools()
    return [t for t in all_t if t.name in MINIMAL_STARTER_TOOLS]


def search_tools(query: str, limit: int = 5) -> list[dict[str, str]]:
    """Search for tools by keyword in name or description.

    Args:
        query: Search keyword (case-insensitive)
        limit: Maximum results to return

    Returns:
        List of dicts with tool name, description, and category.
    """
    query_lower = query.lower()
    results = []

    for tool in all_tools():
        # Search in name and description
        if query_lower in tool.name.lower() or query_lower in tool.description.lower():
            results.append(
                {
                    "name": tool.name,
                    "description": tool.description[:200],  # Truncate for context efficiency
                    "category": tool.category,
                }
            )
            if len(results) >= limit:
                break

    return results


def get_tool_by_name(name: str) -> Tool | None:
    """Get a specific tool by exact name."""
    for tool in all_tools():
        if tool.name == name:
            return tool
    return None


__all__ = [
    # Functions
    "all_tools",
    "get_tools_by_category",
    "get_essential_tools",
    "get_minimal_tools",
    "search_tools",
    "get_tool_by_name",
    # Tool lists
    "META_TOOLS",
    "LLDB_TOOLS",
    "STATIC_TOOLS",
    "RUNTIME_TOOLS",
    "INSTRUMENTATION_TOOLS",
    "CAPABILITY_TOOLS",
    "ESSENTIAL_CRASH_TOOLS",

    "MINIMAL_STARTER_TOOLS",
]
