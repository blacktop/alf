"""LLDB scripting tool: inject Python scripts into LLDB."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._common import Tool, ToolParameter

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_script_handler(
    director: LLDBDirector,
    *,
    script: str,
    name: str | None = None,
    command: str | None = None,
    bootstrap_alf: bool = True,
) -> str:
    """Import a Python script into the LLDB scripting environment."""
    from ....server.environment import bootstrap_header

    if bootstrap_alf:
        script = bootstrap_header() + "\n\n" + script
    return director.inject_script(script, name=name, command=command)


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_SCRIPT = Tool(
    name="lldb_script",
    description=(
        "Import a Python script into the LLDB scripting environment. "
        "Injects custom Python code for advanced debugging automation. "
        "The script runs in LLDB's Python interpreter with access to lldb module. "
        "Bootstrap adds ALF to sys.path for mutation/telemetry imports."
    ),
    parameters=[
        ToolParameter(
            name="script",
            type="string",
            description="Python script source code to inject into LLDB",
        ),
        ToolParameter(
            name="name",
            type="string",
            description="Module name for the script",
            required=False,
        ),
        ToolParameter(
            name="command",
            type="string",
            description="Custom LLDB command name to register",
            required=False,
        ),
        ToolParameter(
            name="bootstrap_alf",
            type="boolean",
            description="Prepend ALF module path setup code",
            required=False,
            default=True,
        ),
    ],
    handler=_lldb_script_handler,
    category="lldb",
    requires_lock=True,
)


SCRIPTING_TOOLS = [
    LLDB_SCRIPT,
]

__all__ = [
    "LLDB_SCRIPT",
    "SCRIPTING_TOOLS",
]
