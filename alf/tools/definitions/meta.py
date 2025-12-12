"""Meta-tools for tool discovery and context management.

These tools help models discover available tools without loading
all tool schemas into context upfront.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..schema import Tool, ToolParameter

if TYPE_CHECKING:
    pass  # No director needed for meta-tools


def _tool_search_handler(
    _context: None = None,  # Not used, but keeps signature consistent
    *,
    query: str,
    limit: int = 5,
) -> str:
    """Search for available tools by keyword."""
    from . import search_tools

    results = search_tools(query, limit=limit)
    if not results:
        return json.dumps(
            {
                "found": 0,
                "message": (
                    f"No tools found matching '{query}'. "
                    "Try broader keywords like 'memory', 'breakpoint', 'symbol', 'objc', 'macho'."
                ),
            }
        )

    return json.dumps(
        {
            "found": len(results),
            "tools": results,
            "hint": "Use these tool names directly in subsequent calls.",
        },
        indent=2,
    )


def _list_tool_categories_handler(
    _context: None = None,
) -> str:
    """List available tool categories."""
    categories = {
        "lldb": "Core LLDB debugging (launch, breakpoints, memory, registers, disassembly)",
        "static": "Static analysis (Mach-O parsing, symbols, entitlements, ObjC metadata)",
        "runtime": "Runtime inspection (ObjC classes, Swift types, live object dumps)",
        "instrumentation": "Fuzzing instrumentation (stop hooks, fork server, telemetry)",
    }
    return json.dumps(
        {
            "categories": categories,
            "hint": "Search within a category using tool_search with keywords like 'macho', 'objc', 'breakpoint', etc.",
        },
        indent=2,
    )


# Tool definitions
TOOL_SEARCH = Tool(
    name="tool_search",
    description=(
        "Search for available debugging tools by keyword. Use this to discover "
        "tools for specific tasks like 'memory', 'breakpoint', 'register', 'symbol', "
        "'objc', 'macho', 'disassemble', etc. Returns matching tool names and descriptions."
    ),
    parameters=[
        ToolParameter(
            name="query",
            type="string",
            description="Search keyword (e.g., 'memory', 'breakpoint', 'symbol', 'objc')",
        ),
        ToolParameter(
            name="limit",
            type="integer",
            description="Maximum number of results (default: 5)",
            required=False,
            default=5,
        ),
    ],
    handler=_tool_search_handler,
    category="meta",
    requires_lock=False,
)

LIST_TOOL_CATEGORIES = Tool(
    name="list_tool_categories",
    description=(
        "List all available tool categories. Use this to understand what types of tools are available before searching."
    ),
    parameters=[],
    handler=_list_tool_categories_handler,
    category="meta",
    requires_lock=False,
)

# Export all meta-tools
META_TOOLS = [TOOL_SEARCH, LIST_TOOL_CATEGORIES]
