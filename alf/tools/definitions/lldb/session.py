"""LLDB session lifecycle tools: launch, attach, terminate, status."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._common import Tool, ToolParameter, json

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_launch_handler(
    director: LLDBDirector,
    *,
    binary: str,
    crash_input: str | None = None,
    stop_on_entry: bool = False,
    extra_args: list[str] | None = None,
) -> str:
    """Launch a binary under LLDB for debugging."""
    try:
        result = director.initialize_session(
            binary,
            crash_input,
            stop_on_entry=stop_on_entry,
            extra_args=extra_args,
        )
        return json.dumps(result, indent=2)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        hint = None
        if "process exited with status -1" in msg or "no such process" in msg:
            hint = (
                "LLDB cannot launch debuggees on this host. Run `uv run alf doctor` "
                "and enable macOS Developer Mode / DevToolsSecurity."
            )
        return json.dumps({"error": msg, "hint": hint}, indent=2)


def _lldb_attach_handler(
    director: LLDBDirector,
    *,
    pid: int,
    program: str | None = None,
    wait_for: bool = False,
) -> str:
    """Attach to an already-running process by PID."""
    try:
        result = director.attach_session(int(pid), program=program, wait_for=wait_for)
        return json.dumps(result, indent=2)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)}, indent=2)


def _lldb_load_core_handler(
    director: LLDBDirector,
    *,
    core_path: str,
    program: str | None = None,
) -> str:
    """Load a core dump file for post-mortem analysis."""
    try:
        result = director.load_core_session(core_path, program=program)
        return json.dumps(result, indent=2)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)}, indent=2)


def _lldb_status_handler(director: LLDBDirector) -> str:
    """Get current LLDB session status."""
    return json.dumps(director.status(), indent=2)


def _lldb_process_info_handler(director: LLDBDirector) -> str:
    """Return current process info."""
    return director.execute_lldb_command("process info")


def _lldb_help_handler(
    director: LLDBDirector,
    *,
    command: str | None = None,
    max_lines: int = 200,
) -> str:
    """Show LLDB help for a command or general help."""
    cmd = "help" if not command else f"help {command}"
    out = director.execute_lldb_command(cmd)
    if max_lines and max_lines > 0:
        lines = out.splitlines()
        if len(lines) > max_lines:
            out = "\n".join(lines[:max_lines] + ["... (truncated)"])
    return out


def _lldb_terminate_handler(director: LLDBDirector) -> str:
    """Terminate the LLDB debugging session cleanly."""
    try:
        if director.dap_session:
            try:
                director.dap_session.request("disconnect", {"terminateDebuggee": True})
            except Exception:
                pass
        director.thread_id = None
        director.frame_id = None
        director.last_stop_event = None
        return json.dumps({"status": "terminated", "message": "Debug session terminated"}, indent=2)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)}, indent=2)


def _lldb_kill_handler(director: LLDBDirector) -> str:
    """Kill the debuggee process but keep the debug session alive."""
    return director.execute_lldb_command("process kill")


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_LAUNCH = Tool(
    name="lldb_launch",
    description=(
        "Launch a binary under LLDB for debugging. "
        "Creates a new debug session, loading the binary and optionally passing "
        "a crash input file. Returns session info including process ID and state. "
        "IMPORTANT: Call this ONCE at the start. If you get errors like 'DAP socket closed' "
        "or 'Broken pipe', the session has ended - do NOT retry, just analyze the data you have."
    ),
    parameters=[
        ToolParameter(
            name="binary",
            type="string",
            description="Path to the executable binary to debug",
        ),
        ToolParameter(
            name="crash_input",
            type="string",
            description="Path to crash input file to pass as first argument",
            required=False,
        ),
        ToolParameter(
            name="stop_on_entry",
            type="boolean",
            description="Stop at entry point instead of running to crash",
            required=False,
            default=False,
        ),
        ToolParameter(
            name="extra_args",
            type="array",
            description="Additional command-line arguments for the binary",
            required=False,
            items={"type": "string"},
        ),
    ],
    handler=_lldb_launch_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_ATTACH = Tool(
    name="lldb_attach",
    description=(
        "Attach to an already-running process by PID. "
        "Useful for debugging daemons, services, or long-running applications. "
        "Optionally provide the program path for better symbol resolution."
    ),
    parameters=[
        ToolParameter(
            name="pid",
            type="integer",
            description="Process ID of the running process to attach to",
        ),
        ToolParameter(
            name="program",
            type="string",
            description="Path to executable for symbol resolution",
            required=False,
        ),
        ToolParameter(
            name="wait_for",
            type="boolean",
            description="Wait for process with this PID to start",
            required=False,
            default=False,
        ),
    ],
    handler=_lldb_attach_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_LOAD_CORE = Tool(
    name="lldb_load_core",
    description=(
        "Load a core dump file for post-mortem analysis. "
        "Enables examination of crash state without a running process. "
        "Provide the original program path for accurate symbol resolution."
    ),
    parameters=[
        ToolParameter(
            name="core_path",
            type="string",
            description="Path to the core dump file",
        ),
        ToolParameter(
            name="program",
            type="string",
            description="Path to the executable that generated the core",
            required=False,
        ),
    ],
    handler=_lldb_load_core_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_STATUS = Tool(
    name="lldb_status",
    description=(
        "Get current LLDB session status. "
        "Returns session state including: connected, has target, process state, "
        "current thread/frame IDs, and pending crash count."
    ),
    parameters=[],
    handler=_lldb_status_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_PROCESS_INFO = Tool(
    name="lldb_process_info",
    description="Return current process info (pid/status/arch/etc).",
    parameters=[],
    handler=_lldb_process_info_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_HELP = Tool(
    name="lldb_help",
    description=(
        "Show LLDB help for a command or general help. "
        "Use to discover available commands and their syntax. "
        "Omit command parameter for overview of all LLDB commands."
    ),
    parameters=[
        ToolParameter(
            name="command",
            type="string",
            description="LLDB command to get help for (omit for general help)",
            required=False,
        ),
        ToolParameter(
            name="max_lines",
            type="integer",
            description="Maximum lines of output to return",
            required=False,
            default=200,
        ),
    ],
    handler=_lldb_help_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_TERMINATE = Tool(
    name="lldb_terminate",
    description=(
        "Terminate the LLDB debugging session cleanly. "
        "Sends disconnect to DAP and cleans up session state. "
        "Use this when done debugging to release resources."
    ),
    parameters=[],
    handler=_lldb_terminate_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_KILL = Tool(
    name="lldb_kill",
    description=(
        "Kill the debuggee process but keep the debug session alive. "
        "Use this to stop a running process without terminating the entire session. "
        "You can then launch a new target without reconnecting."
    ),
    parameters=[],
    handler=_lldb_kill_handler,
    category="lldb",
    requires_lock=True,
)


SESSION_TOOLS = [
    LLDB_LAUNCH,
    LLDB_ATTACH,
    LLDB_LOAD_CORE,
    LLDB_STATUS,
    LLDB_PROCESS_INFO,
    LLDB_HELP,
    LLDB_TERMINATE,
    LLDB_KILL,
]

__all__ = [
    "LLDB_LAUNCH",
    "LLDB_ATTACH",
    "LLDB_LOAD_CORE",
    "LLDB_STATUS",
    "LLDB_PROCESS_INFO",
    "LLDB_HELP",
    "LLDB_TERMINATE",
    "LLDB_KILL",
    "SESSION_TOOLS",
]
