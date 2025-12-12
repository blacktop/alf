"""Provider-agnostic tool schema definitions.

This module defines the core data structures for tools that work across
all LLM providers (Anthropic, OpenAI, Gemini, Ollama) and MCP.

The `Tool` class is the canonical definition that can be exported to:
- MCP/FastMCP (via to_mcp_handler / register_with_mcp)
- Anthropic API (via converters.anthropic)
- OpenAI API (via converters.openai)
- Gemini API (via converters.gemini)
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from mcp.server.fastmcp import FastMCP


@dataclass
class ToolParameter:
    """Provider-agnostic parameter definition.

    Maps to JSON Schema property definitions used by all major LLM APIs.
    """

    name: str
    type: str  # "string", "integer", "number", "boolean", "array", "object"
    description: str
    required: bool = True
    enum: list[str] | None = None
    default: Any = None
    items: dict[str, Any] | None = None  # For array types

    def to_json_schema(self) -> dict[str, Any]:
        """Convert to JSON Schema property definition."""
        schema: dict[str, Any] = {
            "type": self.type,
            "description": self.description,
        }
        if self.enum:
            schema["enum"] = self.enum
        if self.default is not None:
            schema["default"] = self.default
        if self.items and self.type == "array":
            schema["items"] = self.items
        return schema


# Type mapping from our simple types to Python types
_TYPE_MAP: dict[str, type | None] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "array": list,
    "object": dict,
}


@dataclass
class Tool:
    """Canonical tool definition usable by MCP and all LLM provider APIs.

    This is the single source of truth for tool definitions. Define a tool once
    using this class, then export it to MCP (via register_with_mcp) or provider
    APIs (via the converters module).

    Usage:
        tool = Tool(
            name="lldb_launch",
            description="Launch a binary under LLDB",
            parameters=[
                ToolParameter(name="binary", type="string", description="Path to binary"),
                ToolParameter(name="stop_on_entry", type="boolean", description="Stop at entry", required=False),
            ],
            handler=my_launch_function,
            category="lldb",
            requires_lock=True,
        )

        # Export to MCP
        tool.register_with_mcp(mcp, director)

        # Export to provider API (via converters)
        from alf.tools.converters import anthropic
        schema = anthropic.to_anthropic_schema(tool)
    """

    name: str
    description: str
    parameters: list[ToolParameter] = field(default_factory=list)
    handler: Callable[..., str | Awaitable[str]] | None = None

    # Metadata
    category: str = "lldb"  # For organization: "lldb", "static", "runtime", "telemetry"
    requires_lock: bool = True  # For MCP: wrap handler in director._lock

    def to_json_schema(self) -> dict[str, Any]:
        """Convert parameters to JSON Schema format.

        Returns a JSON Schema object definition suitable for any provider.
        """
        properties = {p.name: p.to_json_schema() for p in self.parameters}
        required = [p.name for p in self.parameters if p.required]

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def to_mcp_handler(self, context: Any = None) -> Callable[..., str]:
        """Generate a FastMCP-compatible handler function.

        Creates a function with proper type annotations using Annotated[type, Field(...)]
        that FastMCP expects. The context object (e.g., LLDBDirector) is passed to
        the handler as the first argument.

        Args:
            context: Object to pass as first argument to handler (e.g., director)

        Returns:
            A function suitable for registration with FastMCP via @mcp.tool()
        """
        if self.handler is None:
            raise ValueError(f"Tool {self.name} has no handler")

        # Import here to avoid circular imports and optional dependency
        from typing import Annotated

        from pydantic import Field

        # Build parameter annotations for the wrapper function
        annotations: dict[str, Any] = {}
        defaults: dict[str, Any] = {}

        for param in self.parameters:
            py_type = _TYPE_MAP.get(param.type, str)
            if py_type is None:
                py_type = str

            # Handle optional parameters
            if not param.required:
                py_type = py_type | None  # type: ignore[assignment]

            # Create Annotated type with Field description (FastMCP pattern)
            annotations[param.name] = Annotated[py_type, Field(description=param.description)]

            if param.default is not None:
                defaults[param.name] = param.default
            elif not param.required:
                defaults[param.name] = None

        # Build a FastMCP-friendly signature that *excludes* the injected context
        # parameter (director/_context). FastMCP uses inspect.signature() and will
        # reject handlers whose signature includes non-JSON-serializable params.
        sig_params: list[inspect.Parameter] = []
        for param in self.parameters:
            default = inspect.Parameter.empty
            if param.name in defaults:
                default = defaults[param.name]
            sig_params.append(
                inspect.Parameter(
                    param.name,
                    kind=inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=annotations.get(param.name, Any),
                )
            )
        mcp_sig = inspect.Signature(parameters=sig_params, return_annotation=str)

        # Create wrapper function
        handler = self.handler
        requires_lock = self.requires_lock

        if inspect.iscoroutinefunction(handler):
            # Async handler
            @functools.wraps(handler)
            async def async_wrapper(**kwargs: Any) -> str:
                if requires_lock and context is not None and hasattr(context, "_lock"):
                    with context._lock:
                        return await handler(context, **kwargs)  # type: ignore[misc]
                # Static/meta tools pass context=None; handlers still accept the
                # first positional parameter for signature consistency.
                return await handler(context, **kwargs)  # type: ignore[misc]

            # Override signature/annotations so FastMCP sees only tool parameters.
            async_wrapper.__signature__ = mcp_sig  # type: ignore[attr-defined]
            async_wrapper.__annotations__ = annotations
            async_wrapper.__annotations__["return"] = str
            async_wrapper.__kwdefaults__ = defaults if defaults else None
            async_wrapper.__doc__ = self.description
            async_wrapper.__name__ = self.name

            return async_wrapper
        else:
            # Sync handler
            @functools.wraps(handler)
            def sync_wrapper(**kwargs: Any) -> str:
                if requires_lock and context is not None and hasattr(context, "_lock"):
                    with context._lock:
                        return handler(context, **kwargs)  # type: ignore[return-value]
                return handler(context, **kwargs)  # type: ignore[return-value]

            # Override signature/annotations so FastMCP sees only tool parameters.
            sync_wrapper.__signature__ = mcp_sig  # type: ignore[attr-defined]
            sync_wrapper.__annotations__ = annotations
            sync_wrapper.__annotations__["return"] = str
            sync_wrapper.__kwdefaults__ = defaults if defaults else None
            sync_wrapper.__doc__ = self.description
            sync_wrapper.__name__ = self.name

            return sync_wrapper

    def register_with_mcp(self, mcp: FastMCP, context: Any = None) -> None:
        """Register this tool with a FastMCP instance.

        Args:
            mcp: FastMCP instance to register with
            context: Context object to pass to handler (e.g., LLDBDirector)
        """
        handler = self.to_mcp_handler(context)
        # Use mcp.tool() decorator to register
        mcp.tool()(handler)


@dataclass
class ToolCall:
    """Represents an LLM's request to call a tool.

    Created when parsing provider-specific tool call responses.
    The `id` field is provider-assigned and required for sending results back.
    """

    id: str  # Unique ID from LLM (required for tool_result)
    name: str  # Tool name
    arguments: dict[str, Any]  # Parsed arguments
    thought_signature: Any | None = None  # Gemini thought signature (if provided)

    @classmethod
    def from_anthropic(cls, block: Any) -> ToolCall:
        """Create from Anthropic tool_use block."""
        return cls(
            id=block.id,
            name=block.name,
            arguments=block.input if isinstance(block.input, dict) else {},
        )

    @classmethod
    def from_openai(cls, tool_call: Any) -> ToolCall:
        """Create from OpenAI tool call."""
        import json

        args = tool_call.function.arguments
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}

        return cls(
            id=tool_call.id,
            name=tool_call.function.name,
            arguments=args,
        )

    @classmethod
    def from_openai_dict(cls, tool_call: dict[str, Any]) -> ToolCall:
        """Create from OpenAI-compatible tool call dict (e.g., from LM Studio/Ollama).

        Expected format:
        {
            "id": "call_abc123",
            "type": "function",
            "function": {
                "name": "tool_name",
                "arguments": "{\"arg\": \"value\"}"  # or dict
            }
        }
        """
        import json

        func = tool_call.get("function", {})
        args = func.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}

        return cls(
            id=tool_call.get("id", ""),
            name=func.get("name", ""),
            arguments=args if isinstance(args, dict) else {},
        )

    @classmethod
    def from_gemini(cls, function_call: Any, thought_signature: Any | None = None) -> ToolCall:
        """Create from Gemini function call."""
        def _get(obj: Any, key: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        name = _get(function_call, "name", "") or ""
        args = _get(function_call, "args", None)
        if args is None:
            args = _get(function_call, "arguments", None)
        if isinstance(args, dict):
            parsed_args = args
        elif args is None:
            parsed_args = {}
        else:
            try:
                parsed_args = dict(args)
            except Exception:
                parsed_args = {}

        if thought_signature is None:
            thought_signature = _get(function_call, "thought_signature", None)
        if thought_signature is None:
            thought_signature = _get(function_call, "thoughtSignature", None)

        return cls(
            id=name,  # Gemini doesn't have explicit IDs
            name=name,
            arguments=parsed_args,
            thought_signature=thought_signature,
        )


@dataclass
class ToolResult:
    """Result of executing a tool, to send back to the LLM.

    The `tool_call_id` must match the `id` from the corresponding ToolCall.
    """

    tool_call_id: str
    content: str
    is_error: bool = False

    def to_anthropic(self) -> dict[str, Any]:
        """Convert to Anthropic tool_result format."""
        result: dict[str, Any] = {
            "type": "tool_result",
            "tool_use_id": self.tool_call_id,
            "content": self.content,
        }
        if self.is_error:
            result["is_error"] = True
        return result

    def to_openai(self) -> dict[str, Any]:
        """Convert to OpenAI tool message format."""
        return {
            "role": "tool",
            "tool_call_id": self.tool_call_id,
            "content": self.content,
        }

    def to_gemini(self) -> dict[str, Any]:
        """Convert to Gemini FunctionResponse format."""
        import json

        # Try to parse content as JSON for structured response
        try:
            response_data = json.loads(self.content)
        except (json.JSONDecodeError, TypeError):
            response_data = {"result": self.content}

        if self.is_error:
            response_data = {"error": self.content}

        return {
            "name": self.tool_call_id,  # Gemini uses name as ID
            "response": response_data,
        }
