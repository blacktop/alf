"""LLDB execution control tools: continue, step, breakpoints, watchpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._common import Tool, ToolParameter

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_execute_handler(
    director: LLDBDirector,
    *,
    command: str,
) -> str:
    """Execute a raw LLDB command and return the output."""
    return director.execute_lldb_command(command)


def _lldb_continue_handler(
    director: LLDBDirector,
    *,
    thread_id: int | None = None,
    wait: bool = True,
    timeout: float | None = None,
) -> str:
    """Continue process execution after a stop."""
    return director.continue_exec(thread_id=thread_id, wait=wait, timeout=timeout)


def _lldb_step_handler(
    director: LLDBDirector,
    *,
    kind: str = "over",
    count: int = 1,
) -> str:
    """Single-step execution."""
    return director.step(kind=kind, count=count)


def _lldb_set_breakpoint_handler(
    director: LLDBDirector,
    *,
    function: str | None = None,
    address: str | None = None,
    file: str | None = None,
    line: int | None = None,
    condition: str | None = None,
    static_addr: str | None = None,
    module: str | None = None,
) -> str:
    """Set a breakpoint by function name, address, or source location.

    `static_addr`/`module` resolve a link-time address against the runtime
    module slide, which is how kernel-debug breakpoints are typically set
    (disassembly addresses don't account for KASLR).
    """
    return director.set_breakpoint(
        function=function,
        address=address,
        file=file,
        line=line,
        condition=condition,
        static_addr=static_addr,
        module=module,
    )


def _lldb_breakpoint_list_handler(
    director: LLDBDirector,
    *,
    max_lines: int = 200,
) -> str:
    """List all currently set LLDB breakpoints."""
    out = director.execute_lldb_command("breakpoint list")
    if max_lines and max_lines > 0:
        lines = out.splitlines()
        if len(lines) > max_lines:
            out = "\n".join(lines[:max_lines] + ["... (truncated)"])
    return out


def _lldb_breakpoint_delete_handler(
    director: LLDBDirector,
    *,
    breakpoint_id: int,
) -> str:
    """Delete an LLDB breakpoint by its numeric ID."""
    return director.execute_lldb_command(f"breakpoint delete {int(breakpoint_id)}")


def _lldb_remove_all_breakpoints_handler(director: LLDBDirector) -> str:
    """Remove all breakpoints from the debugger."""
    return director.execute_lldb_command("breakpoint delete -f")


def _lldb_watchpoint_handler(
    director: LLDBDirector,
    *,
    expression: str,
    watch_type: str = "write",
    size: int | None = None,
) -> str:
    """Set a watchpoint to break on memory access."""
    wt = (watch_type or "write").strip().lower()
    if wt in ("rw", "readwrite", "read_write"):
        wt = "read_write"
    elif wt in ("r", "read"):
        wt = "read"
    elif wt in ("w", "write"):
        wt = "write"
    cmd = f"watchpoint set expression -w {wt}"
    if size is not None and int(size) > 0:
        cmd += f" -s {int(size)}"
    cmd += f" -- {expression}"
    return director.execute_lldb_command(cmd)


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_EXECUTE = Tool(
    name="lldb_execute",
    description=(
        "Execute a raw LLDB command and return the output. "
        "Use this for any LLDB command not covered by specialized tools. "
        "Examples: 'bt', 'frame variable', 'image list', 'target modules'."
    ),
    parameters=[
        ToolParameter(
            name="command",
            type="string",
            description="Raw LLDB command to execute (e.g., 'bt', 'frame variable')",
        ),
    ],
    handler=_lldb_execute_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_CONTINUE = Tool(
    name="lldb_continue",
    description=(
        "Continue process execution after a stop. "
        "Resumes the debugged process. If wait=True, blocks until the process "
        "stops again (breakpoint, crash, or exit)."
    ),
    parameters=[
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread to continue (all threads if omitted)",
            required=False,
        ),
        ToolParameter(
            name="wait",
            type="boolean",
            description="Wait for process to stop before returning",
            required=False,
            default=True,
        ),
        ToolParameter(
            name="timeout",
            type="number",
            description="Timeout in seconds (None = use default)",
            required=False,
        ),
    ],
    handler=_lldb_continue_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_STEP = Tool(
    name="lldb_step",
    description=(
        "Single-step execution. "
        "'over': Execute next line, stepping over function calls. "
        "'into': Execute next line, stepping into function calls. "
        "'out': Continue until returning from current function."
    ),
    parameters=[
        ToolParameter(
            name="kind",
            type="string",
            description="Step type: 'over' (next line), 'into' (enter functions), 'out' (return from function)",
            required=False,
            default="over",
        ),
        ToolParameter(
            name="count",
            type="integer",
            description="Number of steps to execute",
            required=False,
            default=1,
        ),
    ],
    handler=_lldb_step_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_SET_BREAKPOINT = Tool(
    name="lldb_set_breakpoint",
    description=(
        "Set a breakpoint by function name, address, or source location. "
        "Specify one of: function name, address, file+line, or "
        "static_addr(+module). Optional condition makes it conditional. "
        "Use static_addr when setting breakpoints from link-time addresses "
        "in disassembly (e.g. a kernel symbol at 0xfffffe000a5ec4c8) — alf "
        "resolves the runtime slide automatically."
    ),
    parameters=[
        ToolParameter(
            name="function",
            type="string",
            description="Function name to break on (e.g., 'main', 'parse_input')",
            required=False,
        ),
        ToolParameter(
            name="address",
            type="string",
            description="Runtime memory address to break on (e.g., '0x1000')",
            required=False,
        ),
        ToolParameter(
            name="file",
            type="string",
            description="Source file path (requires line parameter)",
            required=False,
        ),
        ToolParameter(
            name="line",
            type="integer",
            description="Line number in file (requires file parameter)",
            required=False,
        ),
        ToolParameter(
            name="condition",
            type="string",
            description="Conditional expression (break only when true)",
            required=False,
        ),
        ToolParameter(
            name="static_addr",
            type="string",
            description=(
                "Link-time address; resolved to runtime via the module "
                "slide. Typical for kernel breakpoints from disassembly."
            ),
            required=False,
        ),
        ToolParameter(
            name="module",
            type="string",
            description=(
                "Module basename (e.g. 'kernel.release.vmapple') used with "
                "static_addr to pick the right slide."
            ),
            required=False,
        ),
    ],
    handler=_lldb_set_breakpoint_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_BREAKPOINT_LIST = Tool(
    name="lldb_breakpoint_list",
    description=(
        "List all currently set LLDB breakpoints. "
        "Shows breakpoint IDs, locations, hit counts, and conditions. "
        "Use the ID with lldb_breakpoint_delete to remove breakpoints."
    ),
    parameters=[
        ToolParameter(
            name="max_lines",
            type="integer",
            description="Maximum lines of output to return",
            required=False,
            default=200,
        ),
    ],
    handler=_lldb_breakpoint_list_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_BREAKPOINT_DELETE = Tool(
    name="lldb_breakpoint_delete",
    description="Delete an LLDB breakpoint by its numeric ID. Get breakpoint IDs from lldb_breakpoint_list output.",
    parameters=[
        ToolParameter(
            name="breakpoint_id",
            type="integer",
            description="Breakpoint ID to delete (from lldb_breakpoint_list)",
        ),
    ],
    handler=_lldb_breakpoint_delete_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_REMOVE_ALL_BREAKPOINTS = Tool(
    name="lldb_remove_all_breakpoints",
    description=(
        "Remove all breakpoints from the debugger. "
        "Useful for clearing state before setting up a new debugging scenario."
    ),
    parameters=[],
    handler=_lldb_remove_all_breakpoints_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_WATCHPOINT = Tool(
    name="lldb_watchpoint",
    description=(
        "Set a watchpoint to break on memory access. "
        "Useful for tracking memory corruption, detecting unintended writes, "
        "or finding where a variable gets modified. Breaks when the watched "
        "memory region is accessed according to watch_type."
    ),
    parameters=[
        ToolParameter(
            name="expression",
            type="string",
            description="Address or expression to watch (e.g., '&myvar', '0x1000')",
        ),
        ToolParameter(
            name="watch_type",
            type="string",
            description="Type: 'write', 'read', or 'read_write'",
            required=False,
            default="write",
        ),
        ToolParameter(
            name="size",
            type="integer",
            description="Number of bytes to watch (default: variable size)",
            required=False,
        ),
    ],
    handler=_lldb_watchpoint_handler,
    category="lldb",
    requires_lock=True,
)


EXECUTION_TOOLS = [
    LLDB_EXECUTE,
    # LLDB_CONTINUE - has MCP-specific crash notifications, kept inline in app.py
    LLDB_STEP,
    LLDB_SET_BREAKPOINT,
    LLDB_BREAKPOINT_LIST,
    LLDB_BREAKPOINT_DELETE,
    LLDB_REMOVE_ALL_BREAKPOINTS,
    LLDB_WATCHPOINT,
]

__all__ = [
    "LLDB_EXECUTE",
    "LLDB_CONTINUE",
    "LLDB_STEP",
    "LLDB_SET_BREAKPOINT",
    "LLDB_BREAKPOINT_LIST",
    "LLDB_BREAKPOINT_DELETE",
    "LLDB_REMOVE_ALL_BREAKPOINTS",
    "LLDB_WATCHPOINT",
    "EXECUTION_TOOLS",
]
