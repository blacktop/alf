"""Tool execution engine.

Provides unified tool execution via MCP session or local handlers.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import TYPE_CHECKING, Any

from .registry import ToolRegistry
from .schema import ToolCall, ToolResult

if TYPE_CHECKING:
    from ..fuzz.session import FuzzSession
    from ..server.lldb import LLDBDirector


class ToolExecutor:
    """Execute tools via MCP session or local handlers.

    The executor provides a unified interface for tool execution that can
    work with either an MCP session (for the lldb-mcp server) or local
    function handlers (for direct API calls).

    Usage:
        # With MCP session (e.g., connecting to alf server)
        executor = ToolExecutor(session=fuzz_session)
        result = await executor.execute(tool_call)

        # With local handlers (direct execution, no MCP)
        executor = ToolExecutor(context=director)
        result = await executor.execute(tool_call)

        # Hybrid: prefer MCP, fall back to local
        executor = ToolExecutor(session=session, context=director, prefer_mcp=True)
    """

    def __init__(
        self,
        session: FuzzSession | None = None,
        context: LLDBDirector | Any | None = None,
        prefer_mcp: bool = True,
    ):
        """Initialize the executor.

        Args:
            session: Optional FuzzSession for MCP tool execution.
            context: Context object passed to local handlers (e.g., LLDBDirector).
            prefer_mcp: If True, prefer MCP execution over local handlers.
        """
        self.session = session
        self.context = context
        self.prefer_mcp = prefer_mcp

    async def execute(self, call: ToolCall) -> ToolResult:
        """Execute a tool call and return the result.

        Args:
            call: The tool call to execute.

        Returns:
            ToolResult with the execution result or error.
        """
        tool = ToolRegistry.get(call.name)

        # Check if tool exists
        if tool is None:
            # If we have a session, try MCP even for unknown tools
            if self.session:
                return await self._execute_via_mcp(call)
            return ToolResult(
                tool_call_id=call.id,
                content=f"Unknown tool: {call.name}",
                is_error=True,
            )

        # Meta tools (tool_search, list_categories) always execute locally
        if tool.category == "meta" and tool.handler:
            return await self._execute_local(call, tool.handler)

        # Decide execution path for other tools
        use_mcp = self.session is not None and self.prefer_mcp

        if use_mcp:
            return await self._execute_via_mcp(call)
        elif tool.handler:
            return await self._execute_local(call, tool.handler)
        elif self.session:
            return await self._execute_via_mcp(call)
        else:
            return ToolResult(
                tool_call_id=call.id,
                content=f"No execution path available for tool: {call.name}",
                is_error=True,
            )

    async def _execute_via_mcp(self, call: ToolCall) -> ToolResult:
        """Execute tool via MCP session.

        Args:
            call: The tool call to execute.

        Returns:
            ToolResult from MCP execution.
        """
        if not self.session:
            return ToolResult(
                tool_call_id=call.id,
                content="No MCP session available",
                is_error=True,
            )

        try:
            # Prefer structured error propagation if the session supports it.
            if hasattr(self.session, "call_tool_text"):
                text, is_error = await self.session.call_tool_text(call.name, call.arguments)  # type: ignore[attr-defined]
                result = text
                result_is_error = bool(is_error)
            else:
                result = await self.session.call_tool(call.name, call.arguments)
                result_is_error = False
            return ToolResult(
                tool_call_id=call.id,
                content=result,
                is_error=result_is_error,
            )
        except Exception as e:
            return ToolResult(
                tool_call_id=call.id,
                content=f"MCP tool execution failed: {e}",
                is_error=True,
            )

    async def _execute_local(
        self,
        call: ToolCall,
        handler: Any,
    ) -> ToolResult:
        """Execute tool via local handler function.

        Args:
            call: The tool call to execute.
            handler: The handler function to call.

        Returns:
            ToolResult from local execution.
        """
        try:
            # Determine if handler expects context as first argument
            # by checking if it has more parameters than in call.arguments
            sig = inspect.signature(handler)
            params = list(sig.parameters.keys())

            # Check if first parameter looks like a context parameter
            # (not in call arguments and not **kwargs)
            needs_context = (
                params
                and params[0] not in call.arguments
                and sig.parameters[params[0]].kind
                not in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL)
            )

            # Call handler with arguments (and context if needed)
            if asyncio.iscoroutinefunction(handler):
                if needs_context and self.context is not None:
                    result = await handler(self.context, **call.arguments)
                else:
                    result = await handler(**call.arguments)
            else:
                # Run sync function in executor to avoid blocking
                loop = asyncio.get_event_loop()
                if needs_context and self.context is not None:
                    result = await loop.run_in_executor(
                        None,
                        lambda: handler(self.context, **call.arguments),
                    )
                else:
                    result = await loop.run_in_executor(
                        None,
                        lambda: handler(**call.arguments),
                    )

            # Ensure result is string
            if not isinstance(result, str):
                import json

                try:
                    result = json.dumps(result, indent=2)
                except (TypeError, ValueError):
                    result = str(result)

            return ToolResult(
                tool_call_id=call.id,
                content=result,
                is_error=False,
            )
        except TypeError as e:
            # Likely argument mismatch
            sig = inspect.signature(handler)
            return ToolResult(
                tool_call_id=call.id,
                content=f"Invalid arguments for {call.name}: {e}. Expected: {sig}",
                is_error=True,
            )
        except Exception as e:
            return ToolResult(
                tool_call_id=call.id,
                content=f"Tool execution failed: {type(e).__name__}: {e}",
                is_error=True,
            )

    async def execute_many(
        self,
        calls: list[ToolCall],
        parallel: bool = True,
    ) -> list[ToolResult]:
        """Execute multiple tool calls.

        Args:
            calls: List of tool calls to execute.
            parallel: If True, execute calls in parallel.

        Returns:
            List of results in the same order as calls.
        """
        if parallel:
            tasks = [self.execute(call) for call in calls]
            return await asyncio.gather(*tasks)
        else:
            results = []
            for call in calls:
                result = await self.execute(call)
                results.append(result)
            return results
