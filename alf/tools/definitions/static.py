"""Canonical static analysis tool definitions.

These tools analyze Mach-O binaries and source files without requiring a running
process. They can be used for pre-analysis before debugging or independently
for binary analysis tasks.

Usage:
    from alf.tools.definitions.static import STATIC_TOOLS, MACHO_LOAD_COMMANDS

    # Register all static tools with MCP
    for tool in STATIC_TOOLS:
        tool.register_with_mcp(mcp, context=None)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..schema import Tool, ToolParameter

if TYPE_CHECKING:
    pass


# =============================================================================
# Handler Functions
# =============================================================================


def _macho_load_commands_handler(
    _context: None,
    *,
    binary_path: str,
    max_results: int = 200,
) -> str:
    """List Mach-O load commands from a binary."""
    from ...server.static import macho as static_macho

    try:
        p = static_macho.MachOParser(binary_path)
        summary = p.get_load_commands_summary()
        text = "\n".join(summary)
        if max_results > 0:
            lines = text.splitlines()
            if len(lines) > max_results:
                text = "\n".join(lines[:max_results] + ["... (truncated)"])
        return text
    except Exception as e:
        return f"Parser error: {e}"


def _macho_linked_dylibs_handler(
    _context: None,
    *,
    binary_path: str,
) -> str:
    """List dynamic libraries linked by a Mach-O binary."""
    from ...server.static import macho as static_macho

    try:
        p = static_macho.MachOParser(binary_path)
        libs = p.get_dylibs()
        return "\n".join(libs)
    except Exception as e:
        return f"Error: {e}"


def _macho_info_plist_handler(
    _context: None,
    *,
    binary_path: str,
) -> str:
    """Extract embedded Info.plist from a Mach-O binary."""
    from ...server.static import macho as static_macho

    try:
        p = static_macho.MachOParser(binary_path)
        data = p.get_section_data("__TEXT", "__info_plist")
        if data:
            return data.decode("utf-8", errors="ignore")
        return "No info_plist found."
    except Exception as e:
        return f"Error: {e}"


def _macho_entitlements_handler(
    _context: None,
    *,
    binary_path: str,
) -> str:
    """Extract code signing entitlements from a Mach-O binary."""
    from ...server.static import macho as static_macho

    try:
        p = static_macho.MachOParser(binary_path)
        ent = p.get_entitlements()
        return ent if ent else "No entitlements found."
    except Exception as e:
        return f"Error: {e}"


def _macho_list_objc_classes_handler(
    _context: None,
    *,
    binary_path: str,
    max_results: int = 200,
) -> str:
    """List Objective-C class names defined in a Mach-O binary."""
    from ...server.static import macho as static_macho

    try:
        p = static_macho.MachOParser(binary_path)
        names = p.get_objc_class_names()
        if names:
            text = "\n".join(sorted(names))
            if max_results > 0:
                lines = text.splitlines()
                if len(lines) > max_results:
                    text = "\n".join(lines[:max_results] + ["... (truncated)"])
            return text
        return "No ObjC classes found."
    except Exception as e:
        return f"Error: {e}"


def _macho_objc_segment_handler(
    _context: None,
    *,
    binary_path: str,
    max_results: int = 200,
) -> str:
    """Dump Objective-C segment metadata from a Mach-O binary."""
    from ...server.static import macho as static_macho

    return static_macho.macho_objc_segment(binary_path, max_results=max_results)


def _macho_swift_symbols_handler(
    _context: None,
    *,
    binary_path: str,
    demangle: bool = True,
    max_results: int = 200,
) -> str:
    """Extract Swift symbols from a Mach-O binary."""
    from ...server.static import macho as static_macho

    return static_macho.macho_swift_symbols(binary_path, demangle=demangle, max_results=max_results)


def _static_lookup_handler(
    _context: None,
    *,
    symbol: str,
    source_root: str | None = None,
    max_results: int = 40,
    context_lines: int = 2,
) -> str:
    """Search for a symbol or callsite in on-disk source files."""
    from ...server.static import source as static_source

    return static_source.static_lookup(
        symbol=symbol,
        source_root=source_root,
        max_results=max_results,
        context_lines=context_lines,
    )


# =============================================================================
# Tool Definitions
# =============================================================================


MACHO_LOAD_COMMANDS = Tool(
    name="macho_load_commands",
    description=(
        "List Mach-O load commands from a binary. "
        "Shows segment mappings, dylib dependencies, entry point, code signature, "
        "and other metadata. Essential for understanding binary structure."
    ),
    parameters=[
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to Mach-O binary file",
        ),
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum lines of output",
            required=False,
            default=200,
        ),
    ],
    handler=_macho_load_commands_handler,
    category="static",
    requires_lock=False,
)


MACHO_LINKED_DYLIBS = Tool(
    name="macho_linked_dylibs",
    description=(
        "List dynamic libraries linked by a Mach-O binary. "
        "Shows all dylibs the binary depends on, useful for understanding "
        "dependencies and identifying interesting frameworks to analyze."
    ),
    parameters=[
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to Mach-O binary file",
        ),
    ],
    handler=_macho_linked_dylibs_handler,
    category="static",
    requires_lock=False,
)


MACHO_INFO_PLIST = Tool(
    name="macho_info_plist",
    description=(
        "Extract embedded Info.plist from a Mach-O binary. "
        "Returns the XML property list containing bundle metadata like "
        "version, identifier, minimum OS version, and required capabilities."
    ),
    parameters=[
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to Mach-O binary file",
        ),
    ],
    handler=_macho_info_plist_handler,
    category="static",
    requires_lock=False,
)


MACHO_ENTITLEMENTS = Tool(
    name="macho_entitlements",
    description=(
        "Extract code signing entitlements from a Mach-O binary. "
        "Returns XML entitlements showing sandbox permissions, capabilities, "
        "and security exceptions. Critical for security analysis."
    ),
    parameters=[
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to Mach-O binary file",
        ),
    ],
    handler=_macho_entitlements_handler,
    category="static",
    requires_lock=False,
)


MACHO_LIST_OBJC_CLASSES = Tool(
    name="macho_list_objc_classes",
    description=(
        "List Objective-C class names defined in a Mach-O binary. "
        "Extracts class names from __objc_classlist section. Use to identify "
        "interesting classes for runtime inspection or fuzzing targets."
    ),
    parameters=[
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to Mach-O binary file",
        ),
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum number of classes to return",
            required=False,
            default=200,
        ),
    ],
    handler=_macho_list_objc_classes_handler,
    category="static",
    requires_lock=False,
)


MACHO_OBJC_SEGMENT = Tool(
    name="macho_objc_segment",
    description=(
        "Dump Objective-C segment metadata from a Mach-O binary. "
        "Shows detailed ObjC metadata including classes, categories, protocols, "
        "and their methods. More detailed than macho_list_objc_classes."
    ),
    parameters=[
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to Mach-O binary file",
        ),
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum lines of output",
            required=False,
            default=200,
        ),
    ],
    handler=_macho_objc_segment_handler,
    category="static",
    requires_lock=False,
)


MACHO_SWIFT_SYMBOLS = Tool(
    name="macho_swift_symbols",
    description=(
        "Extract Swift symbols from a Mach-O binary. "
        "Lists Swift types, functions, and metadata with optional demangling. "
        "Useful for analyzing Swift binaries and identifying attack surface."
    ),
    parameters=[
        ToolParameter(
            name="binary_path",
            type="string",
            description="Path to Mach-O binary file",
        ),
        ToolParameter(
            name="demangle",
            type="boolean",
            description="Demangle Swift symbol names",
            required=False,
            default=True,
        ),
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum symbols to return",
            required=False,
            default=200,
        ),
    ],
    handler=_macho_swift_symbols_handler,
    category="static",
    requires_lock=False,
)


STATIC_LOOKUP = Tool(
    name="static_lookup",
    description=(
        "Search for a symbol or callsite in on-disk source files. "
        "Uses static analysis to find symbol definitions and usages. "
        "Returns matches with surrounding source context."
    ),
    parameters=[
        ToolParameter(
            name="symbol",
            type="string",
            description="Symbol name to search for in source files",
        ),
        ToolParameter(
            name="source_root",
            type="string",
            description="Root directory to search (default: current dir)",
            required=False,
        ),
        ToolParameter(
            name="max_results",
            type="integer",
            description="Maximum number of matches to return",
            required=False,
            default=40,
        ),
        ToolParameter(
            name="context_lines",
            type="integer",
            description="Lines of context around each match",
            required=False,
            default=2,
        ),
    ],
    handler=_static_lookup_handler,
    category="static",
    requires_lock=False,
)


# =============================================================================
# Exported Tool List
# =============================================================================


STATIC_TOOLS: list[Tool] = [
    MACHO_LOAD_COMMANDS,
    MACHO_LINKED_DYLIBS,
    MACHO_INFO_PLIST,
    MACHO_ENTITLEMENTS,
    MACHO_LIST_OBJC_CLASSES,
    MACHO_OBJC_SEGMENT,
    MACHO_SWIFT_SYMBOLS,
    STATIC_LOOKUP,
]


__all__ = [
    # Individual tools
    "MACHO_LOAD_COMMANDS",
    "MACHO_LINKED_DYLIBS",
    "MACHO_INFO_PLIST",
    "MACHO_ENTITLEMENTS",
    "MACHO_LIST_OBJC_CLASSES",
    "MACHO_OBJC_SEGMENT",
    "MACHO_SWIFT_SYMBOLS",
    "STATIC_LOOKUP",
    # Tool list
    "STATIC_TOOLS",
]
