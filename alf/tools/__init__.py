"""Unified tool abstraction for ALF.

This module provides a provider-agnostic tool system that works with both
MCP (Model Context Protocol) and native LLM tool calling APIs.

Key Components:
- Tool: Canonical tool definition (single source of truth)
- ToolRegistry: Central registry for all tools
- ToolExecutor: Execute tools via MCP or local handlers
- AgenticLoop: Tool use loop pattern for LLM agents

Usage:
    from alf.tools import (
        Tool,
        ToolParameter,
        ToolRegistry,
        ToolExecutor,
        AgenticLoop,
        run_tool_loop,
    )

    # Define a canonical tool
    my_tool = Tool(
        name="my_tool",
        description="Does something useful",
        parameters=[
            ToolParameter(name="input", type="string", description="Input data"),
        ],
        handler=my_handler_function,
        category="lldb",
    )

    # Register with MCP server
    my_tool.register_with_mcp(mcp, director)

    # Or register with the global registry for API access
    ToolRegistry.register(my_tool)

    # Get tools for a specific provider
    anthropic_tools = ToolRegistry.for_provider("anthropic")
    openai_tools = ToolRegistry.for_provider("openai")

    # Run tool loop
    response = await run_tool_loop(
        provider=my_provider,
        messages=conversation,
        model="claude-sonnet-4-20250514",
        session=fuzz_session,
    )
"""

from .executor import ToolExecutor
from .loop import AgenticLoop, run_tool_loop
from .mcp import register_all_tools, register_tools, register_tools_by_category
from .registry import ToolRegistry, tool
from .schema import Tool, ToolCall, ToolParameter, ToolResult

__all__ = [
    # Schema
    "Tool",
    "ToolParameter",
    "ToolCall",
    "ToolResult",
    # Registry
    "ToolRegistry",
    "tool",
    # Execution
    "ToolExecutor",
    # Loop
    "AgenticLoop",
    "run_tool_loop",
    # MCP helpers
    "register_tools",
    "register_all_tools",
    "register_tools_by_category",
]
