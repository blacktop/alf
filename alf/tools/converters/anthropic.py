"""Anthropic/Claude tool schema converter.

Converts Tool to Anthropic's tool_use format as documented at:
https://docs.anthropic.com/en/docs/build-with-claude/tool-use
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..schema import Tool


def to_anthropic_schema(tool: Tool) -> dict[str, Any]:
    """Convert a Tool to Anthropic tool format.

    Anthropic's format:
    {
        "name": "tool_name",
        "description": "Tool description",
        "input_schema": {
            "type": "object",
            "properties": {
                "param1": {"type": "string", "description": "..."},
                ...
            },
            "required": ["param1", ...]
        }
    }

    Args:
        tool: The tool definition to convert.

    Returns:
        Dictionary in Anthropic's tool format.
    """
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in tool.parameters:
        prop: dict[str, Any] = {
            "type": param.type,
            "description": param.description,
        }

        if param.enum:
            prop["enum"] = param.enum

        if param.default is not None:
            prop["default"] = param.default

        if param.items and param.type == "array":
            prop["items"] = param.items

        properties[param.name] = prop

        if param.required:
            required.append(param.name)

    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
    }


def format_tool_results(results: list[Any]) -> dict[str, Any]:
    """Format tool results for Anthropic.

    Anthropic expects tool results in a user message with type "tool_result".

    Args:
        results: List of ToolResult objects.

    Returns:
        User message with tool results.
    """
    return {
        "role": "user",
        "content": [result.to_anthropic() for result in results],
    }
