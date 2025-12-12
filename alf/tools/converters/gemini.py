"""Google Gemini function calling schema converter.

Converts Tool to Gemini's function declaration format as documented at:
https://ai.google.dev/gemini-api/docs/function-calling
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..schema import Tool


def to_gemini_schema(tool: Tool) -> dict[str, Any]:
    """Convert a Tool to Gemini function declaration format.

    Gemini's format:
    {
        "name": "tool_name",
        "description": "Tool description",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "param1": {"type": "STRING", "description": "..."},
                ...
            },
            "required": ["param1", ...]
        }
    }

    Note: Gemini uses uppercase type names.

    Args:
        tool: The tool definition to convert.

    Returns:
        Dictionary in Gemini's function declaration format.
    """
    # Gemini uses uppercase type names
    type_mapping = {
        "string": "STRING",
        "integer": "INTEGER",
        "number": "NUMBER",
        "boolean": "BOOLEAN",
        "array": "ARRAY",
        "object": "OBJECT",
    }

    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in tool.parameters:
        gemini_type = type_mapping.get(param.type.lower(), "STRING")

        prop: dict[str, Any] = {
            "type": gemini_type,
            "description": param.description,
        }

        if param.enum:
            prop["enum"] = param.enum

        if param.items and param.type == "array":
            # Convert items type to Gemini format
            items = param.items.copy()
            if "type" in items:
                items["type"] = type_mapping.get(items["type"].lower(), "STRING")
            prop["items"] = items

        properties[param.name] = prop

        if param.required:
            required.append(param.name)

    return {
        "name": tool.name,
        "description": tool.description,
        "parameters": {
            "type": "OBJECT",
            "properties": properties,
            "required": required,
        },
    }


def format_tool_results(results: list[Any]) -> list[dict[str, Any]]:
    """Format tool results for Gemini.

    Gemini expects FunctionResponse parts.

    Args:
        results: List of ToolResult objects.

    Returns:
        List of FunctionResponse dictionaries.
    """
    return [result.to_gemini() for result in results]
