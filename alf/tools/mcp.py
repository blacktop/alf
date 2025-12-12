"""MCP integration helpers for canonical tool definitions.

This module provides utilities for registering canonical Tool definitions
with a FastMCP server instance.

Usage:
    from mcp.server.fastmcp import FastMCP
    from alf.tools.mcp import register_all_tools, register_tools

    mcp = FastMCP("alf")
    director = LLDBDirector(...)

    # Register all canonical tools
    register_all_tools(mcp, director)

    # Or register specific tools
    from alf.tools.definitions.lldb import LLDB_LAUNCH, LLDB_EXECUTE
    register_tools(mcp, director, [LLDB_LAUNCH, LLDB_EXECUTE])
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from .schema import Tool

logger = logging.getLogger(__name__)


def register_tools(
    mcp: FastMCP,
    context: Any,
    tools: list[Tool],
) -> list[str]:
    """Register a list of canonical tools with a FastMCP instance.

    Args:
        mcp: FastMCP instance to register tools with
        context: Context object to pass to handlers (e.g., LLDBDirector)
        tools: List of Tool definitions to register

    Returns:
        List of registered tool names
    """
    registered: list[str] = []

    for tool in tools:
        try:
            tool.register_with_mcp(mcp, context)
        except Exception as e:
            # Tool registration must be reliable; failing silently makes the
            # client experience unpredictable ("Unknown tool" at runtime).
            logger.error("Failed to register tool %s: %s", tool.name, e)
            raise
        registered.append(tool.name)
        logger.debug("Registered tool: %s", tool.name)

    return registered


def register_all_tools(
    mcp: FastMCP,
    context: Any,
) -> list[str]:
    """Register all canonical tool definitions with a FastMCP instance.

    This imports and registers all tools from the definitions package.

    Args:
        mcp: FastMCP instance to register tools with
        context: Context object to pass to handlers (e.g., LLDBDirector)

    Returns:
        List of registered tool names
    """
    from .definitions import all_tools
    from .registry import ToolRegistry

    tools = all_tools()
    registered = register_tools(mcp, context, tools)

    # Also add to registry for API access
    for tool in tools:
        ToolRegistry.register(tool)

    logger.info("Registered %d canonical tools with MCP", len(registered))
    return registered


def register_tools_by_category(
    mcp: FastMCP,
    context: Any,
    category: str,
) -> list[str]:
    """Register canonical tools filtered by category.

    Args:
        mcp: FastMCP instance to register tools with
        context: Context object to pass to handlers (e.g., LLDBDirector)
        category: Tool category to filter by ("lldb", "static", "runtime", "telemetry")

    Returns:
        List of registered tool names
    """
    from .definitions import get_tools_by_category

    tools = get_tools_by_category(category)
    return register_tools(mcp, context, tools)


__all__ = [
    "register_tools",
    "register_all_tools",
    "register_tools_by_category",
]
