"""Canonical runtime inspection tool definitions.

These tools query the Objective-C and Swift runtime in a running process.
They require an active LLDB session with a stopped process.

Usage:
    from alf.tools.definitions.runtime import RUNTIME_TOOLS, RUNTIME_OBJC_CLASSES

    # Register all runtime tools with MCP
    for tool in RUNTIME_TOOLS:
        tool.register_with_mcp(mcp, director)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..schema import Tool, ToolParameter

if TYPE_CHECKING:
    from ...server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _runtime_objc_classes_handler(
    director: LLDBDirector,
    *,
    max_results: int = 200,
) -> str:
    """List Objective-C classes from the runtime (requires running process)."""
    from ...server.runtime import objc as runtime_objc

    out = runtime_objc.runtime_objc_classes(director, max_results=max_results)
    text = (out or "").strip()
    if text.lower().startswith("error") or text.lower().startswith("lldb command failed"):
        return json.dumps({"error": text}, indent=2)
    return out


def _runtime_nsobject_to_json_handler(
    director: LLDBDirector,
    *,
    address_or_expr: str,
) -> str:
    """Serialize an NSObject to JSON via the Objective-C runtime."""
    from ...server.runtime import objc as runtime_objc

    out = runtime_objc.runtime_nsobject_to_json(director, address_or_expr)
    text = (out or "").strip()
    if text.lower().startswith("error") or text.lower().startswith("lldb command failed"):
        return json.dumps({"error": text}, indent=2)
    return out


def _runtime_objc_class_dump_handler(
    director: LLDBDirector,
    *,
    class_name: str | None = None,
    address: str | None = None,
) -> str:
    """Dump full Objective-C class description to JSON."""
    from ...server.runtime import objc as runtime_objc

    out = runtime_objc.runtime_objc_class_dump(director, class_name, address)
    text = (out or "").strip()
    if text.lower().startswith("error") or "expression failed" in text.lower():
        return json.dumps({"error": text}, indent=2)
    return out


def _runtime_objc_object_dump_handler(
    director: LLDBDirector,
    *,
    address: str,
) -> str:
    """Dump an Objective-C object instance with all ivar values."""
    from ...server.runtime import objc as runtime_objc

    out = runtime_objc.runtime_objc_object_dump(director, address)
    text = (out or "").strip()
    if text.lower().startswith("error") or "expression failed" in text.lower():
        return json.dumps({"error": text}, indent=2)
    return out


# =============================================================================
# Tool Definitions
# =============================================================================


RUNTIME_OBJC_CLASSES = Tool(
    name="runtime_objc_classes",
    description=(
        "List Objective-C classes from the runtime (requires running process). "
        "Queries the ObjC runtime for all registered classes. More comprehensive "
        "than static analysis as it includes dynamically loaded classes."
    ),
    parameters=[
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum number of classes to return",
            required=False,
            default=200,
        ),
    ],
    handler=_runtime_objc_classes_handler,
    category="runtime",
    requires_lock=True,
)


RUNTIME_NSOBJECT_TO_JSON = Tool(
    name="runtime_nsobject_to_json",
    description=(
        "Serialize an NSObject to JSON via the Objective-C runtime. "
        "Recursively converts Foundation objects (NSArray, NSDictionary, NSString, etc.) "
        "to JSON. Useful for inspecting complex ObjC data structures during debugging."
    ),
    parameters=[
        ToolParameter(
            name="address_or_expr",
            type="string",
            description="Object address, register ($x0), or expression",
        ),
    ],
    handler=_runtime_nsobject_to_json_handler,
    category="runtime",
    requires_lock=True,
)


RUNTIME_OBJC_CLASS_DUMP = Tool(
    name="runtime_objc_class_dump",
    description=(
        "Dump full Objective-C class description to JSON. "
        "Returns detailed class information including methods, properties, "
        "instance variables, protocols, and superclass. Provide either name or address."
    ),
    parameters=[
        ToolParameter(
            name="class_name",
            type="string",
            description="Class name to dump (e.g., 'NSString')",
            required=False,
        ),
        ToolParameter(
            name="address",
            type="string",
            description="Class pointer address to dump",
            required=False,
        ),
    ],
    handler=_runtime_objc_class_dump_handler,
    category="runtime",
    requires_lock=True,
)


RUNTIME_OBJC_OBJECT_DUMP = Tool(
    name="runtime_objc_object_dump",
    description=(
        "Dump an Objective-C object instance with all ivar values. "
        "Returns JSON with the object's class, address, and all instance "
        "variables with their current values. Essential for state inspection."
    ),
    parameters=[
        ToolParameter(
            name="address",
            type="string",
            description="Object instance address or register ($x0)",
        ),
    ],
    handler=_runtime_objc_object_dump_handler,
    category="runtime",
    requires_lock=True,
)


# =============================================================================
# Exported Tool List
# =============================================================================


RUNTIME_TOOLS: list[Tool] = [
    RUNTIME_OBJC_CLASSES,
    RUNTIME_NSOBJECT_TO_JSON,
    RUNTIME_OBJC_CLASS_DUMP,
    RUNTIME_OBJC_OBJECT_DUMP,
]


__all__ = [
    # Individual tools
    "RUNTIME_OBJC_CLASSES",
    "RUNTIME_NSOBJECT_TO_JSON",
    "RUNTIME_OBJC_CLASS_DUMP",
    "RUNTIME_OBJC_OBJECT_DUMP",
    # Tool list
    "RUNTIME_TOOLS",
]
