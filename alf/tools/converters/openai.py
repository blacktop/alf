"""OpenAI function calling schema converter.

Converts Tool to OpenAI's function calling format as documented at:
https://platform.openai.com/docs/guides/function-calling
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..schema import Tool


def to_openai_schema(tool: Tool) -> dict[str, Any]:
    """Convert a Tool to OpenAI function calling format.

    OpenAI's format:
    {
        "type": "function",
        "function": {
            "name": "tool_name",
            "description": "Tool description",
            "parameters": {
                "type": "object",
                "properties": {
                    "param1": {"type": "string", "description": "..."},
                    ...
                },
                "required": ["param1", ...]
            }
        }
    }

    Args:
        tool: The tool definition to convert.

    Returns:
        Dictionary in OpenAI's function format.
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
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def format_tool_results(results: list[Any]) -> list[dict[str, Any]]:
    """Format tool results for OpenAI.

    OpenAI expects separate tool messages for each result.

    Args:
        results: List of ToolResult objects.

    Returns:
        List of tool messages.
    """
    return [result.to_openai() for result in results]
