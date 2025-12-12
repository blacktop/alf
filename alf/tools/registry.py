"""Central registry for ALF tools.

The ToolRegistry provides a single source of truth for all tool definitions,
allowing tools to be registered once and exported to any provider format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .schema import Tool

if TYPE_CHECKING:
    from collections.abc import Callable


class ToolRegistry:
    """Central registry for all ALF tools.

    Tools are registered once and can be exported to any provider's schema format.

    Usage:
        # Register a tool
        ToolRegistry.register(Tool(
            name="lldb_launch",
            description="Launch a binary",
            parameters=[...],
        ))

        # Get tools for a specific provider
        anthropic_tools = ToolRegistry.for_provider("anthropic")
        openai_tools = ToolRegistry.for_provider("openai")

        # Get a specific tool
        tool = ToolRegistry.get("lldb_launch")
    """

    _tools: dict[str, Tool] = {}
    _initialized: bool = False

    @classmethod
    def register(cls, tool: Tool) -> None:
        """Register a tool definition.

        Args:
            tool: The tool definition to register.

        Raises:
            ValueError: If a tool with the same name is already registered.
        """
        if tool.name in cls._tools:
            # Allow re-registration with same definition (for reloads)
            pass
        cls._tools[tool.name] = tool

    @classmethod
    def register_many(cls, tools: list[Tool]) -> None:
        """Register multiple tool definitions."""
        for tool in tools:
            cls.register(tool)

    @classmethod
    def get(cls, name: str) -> Tool | None:
        """Get a tool by name.

        Args:
            name: The tool name.

        Returns:
            The tool definition, or None if not found.
        """
        return cls._tools.get(name)

    @classmethod
    def all_tools(cls) -> list[Tool]:
        """Get all registered tools.

        Returns:
            List of all tool definitions.
        """
        return list(cls._tools.values())

    @classmethod
    def tool_names(cls) -> list[str]:
        """Get all registered tool names.

        Returns:
            List of tool names.
        """
        return list(cls._tools.keys())

    @classmethod
    def for_provider(cls, provider: str) -> list[dict[str, Any]]:
        """Get all tools in a provider's native schema format.

        Args:
            provider: Provider name ("anthropic", "openai", "gemini", "ollama").

        Returns:
            List of tool definitions in provider's format.

        Raises:
            ValueError: If provider is unknown.
        """
        from .converters import anthropic, gemini, openai

        converters: dict[str, Callable[[Tool], dict[str, Any]]] = {
            "anthropic": anthropic.to_anthropic_schema,
            "openai": openai.to_openai_schema,
            "gemini": gemini.to_gemini_schema,
            "google": gemini.to_gemini_schema,  # Google provider uses Gemini schema
            "ollama": openai.to_openai_schema,  # Ollama uses OpenAI format
            "lmstudio": openai.to_openai_schema,  # LM Studio uses OpenAI format
            "vllm": openai.to_openai_schema,  # vLLM uses OpenAI format
            "localai": openai.to_openai_schema,  # LocalAI uses OpenAI format
        }

        converter = converters.get(provider)
        if not converter:
            raise ValueError(f"Unknown provider: {provider}. Supported: {', '.join(converters.keys())}")

        return [converter(tool) for tool in cls._tools.values()]

    @classmethod
    def clear(cls) -> None:
        """Clear all registered tools (mainly for testing)."""
        cls._tools.clear()
        cls._initialized = False

    @classmethod
    def count(cls) -> int:
        """Get the number of registered tools."""
        return len(cls._tools)

    @classmethod
    def initialize_canonical_tools(cls) -> int:
        """Initialize the registry with all canonical tool definitions.

        This loads all tools from alf.tools.definitions and registers them.
        Call this once at startup before using the AgenticLoop.

        Returns:
            Number of tools registered.
        """
        if cls._initialized:
            return cls.count()

        from .definitions import all_tools

        tools = all_tools()
        cls.register_many(tools)
        cls._initialized = True

        return len(tools)


def tool(
    name: str | None = None,
    description: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to register a function as a tool.

    Usage:
        @tool(name="my_tool", description="Does something")
        def my_tool(arg1: str, arg2: int = 0) -> str:
            '''Optional docstring for additional description.'''
            return "result"

    Args:
        name: Tool name (defaults to function name).
        description: Tool description (defaults to docstring).

    Returns:
        Decorator function.
    """
    import inspect

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        from .schema import ToolParameter

        tool_name = name or func.__name__
        tool_desc = description or func.__doc__ or f"Execute {tool_name}"

        # Extract parameters from function signature
        sig = inspect.signature(func)
        type_hints = getattr(func, "__annotations__", {})

        parameters: list[ToolParameter] = []
        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            # Get type hint
            hint = type_hints.get(param_name)
            param_type = _python_type_to_json_schema_type(hint)

            # Get default
            has_default = param.default is not inspect.Parameter.empty
            default = param.default if has_default else None

            # Check if required (no default and not Optional)
            is_required = not has_default and not _is_optional_type(hint)

            parameters.append(
                ToolParameter(
                    name=param_name,
                    type=param_type,
                    description=f"Parameter {param_name}",  # Could extract from docstring
                    required=is_required,
                    default=default,
                )
            )

        tool_def = Tool(
            name=tool_name,
            description=tool_desc,
            parameters=parameters,
            handler=func,
        )

        ToolRegistry.register(tool_def)
        return func

    return decorator


def _python_type_to_json_schema_type(hint: Any) -> str:
    """Convert Python type hint to JSON Schema type."""
    if hint is None:
        return "string"

    # Handle Optional types
    origin = getattr(hint, "__origin__", None)
    if origin is not None:
        # Handle Union types (including Optional)
        import typing

        if origin is typing.Union:
            args = getattr(hint, "__args__", ())
            # Filter out NoneType
            non_none_args = [a for a in args if a is not type(None)]
            if non_none_args:
                return _python_type_to_json_schema_type(non_none_args[0])
        # Handle list/List
        if origin is list:
            return "array"
        # Handle dict/Dict
        if origin is dict:
            return "object"

    # Direct type mappings
    type_map = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }

    return type_map.get(hint, "string")


def _is_optional_type(hint: Any) -> bool:
    """Check if type hint is Optional (Union with None)."""
    origin = getattr(hint, "__origin__", None)
    if origin is None:
        return False

    import typing

    if origin is typing.Union:
        args = getattr(hint, "__args__", ())
        return type(None) in args

    return False
