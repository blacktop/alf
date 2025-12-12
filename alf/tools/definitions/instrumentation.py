"""Canonical instrumentation tool definitions for fuzzing.

These tools support in-process fuzzing via LLDB with stop hooks and fork servers.
They require an active LLDB session with a stopped process.

Usage:
    from alf.tools.definitions.instrumentation import INSTRUMENTATION_TOOLS

    # Register all instrumentation tools with MCP
    for tool in INSTRUMENTATION_TOOLS:
        tool.register_with_mcp(mcp, director)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..schema import Tool, ToolParameter

if TYPE_CHECKING:
    from ...server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_install_stop_hook_handler(
    director: LLDBDirector,
    *,
    function: str | None = None,
    address: str | None = None,
    file: str | None = None,
    line: int | None = None,
    ptr_reg: str = "x0",
    len_reg: str | None = None,
    max_size: int = 4096,
    name: str = "alf_stop_hook",
    telemetry_pipe: str | None = None,
) -> str:
    """Install an in-process mutation hook at a breakpoint for high-speed fuzzing."""
    from ...instrument.generator import generate_stop_hook
    from ...server.environment import bootstrap_header
    from ...server.telemetry import TelemetrySession

    # 0) Create FIFO telemetry channel unless user supplied one.
    session: TelemetrySession | None = None
    pipe_path = telemetry_pipe
    if not pipe_path:
        session = TelemetrySession.create(Path.cwd(), name=name)
        session.start()
        director.telemetry_sessions[name] = session
        pipe_path = str(session.pipe_path)

    # 1) Set breakpoint
    bp_out = director.set_breakpoint(function=function, address=address, file=file, line=line)
    m = re.search(r"Breakpoint\s+(\d+):", bp_out)
    bp_id = m.group(1) if m else None
    if bp_id is None:
        # Fallback: try to find any integer in output
        m2 = re.search(r"\b(\d+)\b", bp_out)
        bp_id = m2.group(1) if m2 else None

    if bp_id is None:
        return json.dumps({"error": f"failed to parse breakpoint id: {bp_out}"}, indent=2)

    # 2) Generate + import stop-hook script
    script = generate_stop_hook(
        ptr_reg=ptr_reg,
        len_reg=len_reg,
        max_size=max_size,
        name=name,
        telemetry_pipe=pipe_path,
        include_bootstrap=False,
    )
    import_info = director.inject_script(bootstrap_header() + "\n\n" + script, name=name)
    if (import_info or "").lower().startswith("error"):
        return json.dumps({"error": import_info}, indent=2)

    # 3) Bind callback to breakpoint
    cmd_out = director.execute_lldb_command(f"breakpoint command add -F {name} {bp_id}")
    text = (cmd_out or "").strip().lower()
    if text.startswith("error") or "failed" in text:
        return json.dumps({"error": cmd_out, "breakpoint": bp_out, "import": import_info}, indent=2)

    return json.dumps(
        {
            "breakpoint_id": int(bp_id),
            "breakpoint_output": bp_out,
            "import": json.loads(import_info) if import_info.strip().startswith("{") else import_info,
            "command_output": cmd_out,
            "telemetry_pipe": pipe_path,
        },
        indent=2,
    )


def _lldb_install_fork_server_handler(
    director: LLDBDirector,
    *,
    function: str | None = None,
    address: str | None = None,
    file: str | None = None,
    line: int | None = None,
    name: str = "alf_fork_server",
    telemetry_pipe: str | None = None,
    follow_mode: str = "parent",
) -> str:
    """Install a fork server at an entry point to avoid process restart overhead."""
    from ...instrument.generator import generate_fork_server
    from ...server.environment import bootstrap_header
    from ...server.telemetry import TelemetrySession

    if follow_mode:
        director.execute_lldb_command(f"settings set target.process.follow-fork-mode {follow_mode}")

    # Telemetry FIFO for parent/child events.
    session: TelemetrySession | None = None
    pipe_path = telemetry_pipe
    if not pipe_path:
        session = TelemetrySession.create(Path.cwd(), name=name)
        session.start()
        director.telemetry_sessions[name] = session
        pipe_path = str(session.pipe_path)

    bp_out = director.set_breakpoint(function=function, address=address, file=file, line=line)
    m = re.search(r"Breakpoint\s+(\d+):", bp_out)
    bp_id = m.group(1) if m else None
    if bp_id is None:
        m2 = re.search(r"\b(\d+)\b", bp_out)
        bp_id = m2.group(1) if m2 else None
    if bp_id is None:
        return json.dumps({"error": f"failed to parse breakpoint id: {bp_out}"}, indent=2)

    script = generate_fork_server(
        name=name,
        telemetry_pipe=pipe_path,
        include_bootstrap=False,
    )
    import_info = director.inject_script(bootstrap_header() + "\n\n" + script, name=name)
    if (import_info or "").lower().startswith("error"):
        return json.dumps({"error": import_info}, indent=2)

    cmd_out = director.execute_lldb_command(f"breakpoint command add -F {name} {bp_id}")
    text = (cmd_out or "").strip().lower()
    if text.startswith("error") or "failed" in text:
        return json.dumps({"error": cmd_out, "breakpoint": bp_out, "import": import_info}, indent=2)

    return json.dumps(
        {
            "breakpoint_id": int(bp_id),
            "breakpoint_output": bp_out,
            "import": json.loads(import_info) if import_info.strip().startswith("{") else import_info,
            "command_output": cmd_out,
            "telemetry_pipe": pipe_path,
            "follow_mode": follow_mode,
        },
        indent=2,
    )


def _telemetry_snapshot_handler(
    director: LLDBDirector,
    *,
    name: str | None = None,
    limit: int = 200,
) -> str:
    """Get buffered telemetry events from a stop-hook session."""
    if not director.telemetry_sessions:
        return "No telemetry sessions active."
    if name and name in director.telemetry_sessions:
        return director.telemetry_sessions[name].snapshot(limit=limit)
    # Default: most recent session by insertion order.
    last_key = next(reversed(director.telemetry_sessions))
    return director.telemetry_sessions[last_key].snapshot(limit=limit)


def _telemetry_rate_handler(
    director: LLDBDirector,
    *,
    name: str | None = None,
    window_sec: float = 5.0,
) -> str:
    """Calculate the execution rate (events/sec) for a fuzzing session."""
    if not director.telemetry_sessions:
        return "No telemetry sessions active."
    sess = director.telemetry_sessions.get(name) if name else None
    if sess is None:
        last_key = next(reversed(director.telemetry_sessions))
        sess = director.telemetry_sessions[last_key]
    return json.dumps(sess.rate(window_sec=window_sec), indent=2)


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_INSTALL_STOP_HOOK = Tool(
    name="lldb_install_stop_hook",
    description=(
        "Install an in-process mutation hook at a breakpoint for high-speed fuzzing. "
        "Sets a breakpoint and attaches an SBAPI callback that: "
        "1) Reads buffer from the specified register, "
        "2) Applies random mutation from ALF strategies, "
        "3) Writes mutated buffer back, "
        "4) Continues execution (returns False). "
        "This enables >1000 execs/sec without process restart overhead."
    ),
    parameters=[
        ToolParameter(
            name="function",
            type="string",
            description="Function name to hook (e.g., 'parse_input')",
            required=False,
        ),
        ToolParameter(
            name="address",
            type="string",
            description="Memory address to hook",
            required=False,
        ),
        ToolParameter(
            name="file",
            type="string",
            description="Source file path (requires line)",
            required=False,
        ),
        ToolParameter(
            name="line",
            type="integer",
            description="Line number in file (requires file)",
            required=False,
        ),
        ToolParameter(
            name="ptr_reg",
            type="string",
            description="Register containing buffer pointer (arm64: x0-x7)",
            required=False,
            default="x0",
        ),
        ToolParameter(
            name="len_reg",
            type="string",
            description="Register containing buffer length (optional)",
            required=False,
        ),
        ToolParameter(
            name="max_size",
            type="integer",
            description="Maximum buffer size to mutate",
            required=False,
            default=4096,
        ),
        ToolParameter(
            name="name",
            type="string",
            description="Unique name for this hook callback",
            required=False,
            default="alf_stop_hook",
        ),
        ToolParameter(
            name="telemetry_pipe",
            type="string",
            description="Path to FIFO for telemetry output",
            required=False,
        ),
    ],
    handler=_lldb_install_stop_hook_handler,
    category="instrumentation",
    requires_lock=True,
)


LLDB_INSTALL_FORK_SERVER = Tool(
    name="lldb_install_fork_server",
    description=(
        "Install a fork server at an entry point to avoid process restart overhead. "
        "For one-shot binaries, installs a callback that: "
        "1) Forks at the breakpoint, "
        "2) Parent waits for child to exit, then loops back, "
        "3) Child continues normal execution. "
        "This eliminates process startup overhead for each fuzz iteration."
    ),
    parameters=[
        ToolParameter(
            name="function",
            type="string",
            description="Function name to install at (e.g., 'main')",
            required=False,
        ),
        ToolParameter(
            name="address",
            type="string",
            description="Memory address to install at",
            required=False,
        ),
        ToolParameter(
            name="file",
            type="string",
            description="Source file path (requires line)",
            required=False,
        ),
        ToolParameter(
            name="line",
            type="integer",
            description="Line number in file (requires file)",
            required=False,
        ),
        ToolParameter(
            name="name",
            type="string",
            description="Unique name for this fork server",
            required=False,
            default="alf_fork_server",
        ),
        ToolParameter(
            name="telemetry_pipe",
            type="string",
            description="Path to FIFO for parent/child events",
            required=False,
        ),
        ToolParameter(
            name="follow_mode",
            type="string",
            description="Which process to follow after fork: 'parent' or 'child'",
            required=False,
            default="parent",
        ),
    ],
    handler=_lldb_install_fork_server_handler,
    category="instrumentation",
    requires_lock=True,
)


TELEMETRY_SNAPSHOT = Tool(
    name="telemetry_snapshot",
    description=(
        "Get buffered telemetry events from a stop-hook session. "
        "Returns mutation counts, timing data, and other metrics collected "
        "by the FIFO telemetry system during fuzzing."
    ),
    parameters=[
        ToolParameter(
            name="name",
            type="string",
            description="Hook name to get telemetry for (latest if omitted)",
            required=False,
        ),
        ToolParameter(
            name="limit",
            type="integer",
            description="Maximum number of telemetry entries to return",
            required=False,
            default=200,
        ),
    ],
    handler=_telemetry_snapshot_handler,
    category="instrumentation",
    requires_lock=True,
)


TELEMETRY_RATE = Tool(
    name="telemetry_rate",
    description=(
        "Calculate the execution rate (events/sec) for a fuzzing session. "
        "Measures how many mutations/executions occurred over the time window. "
        "Use to monitor fuzzing throughput and detect stalls."
    ),
    parameters=[
        ToolParameter(
            name="name",
            type="string",
            description="Hook name to measure (latest if omitted)",
            required=False,
        ),
        ToolParameter(
            name="window_sec",
            type="number",
            description="Time window in seconds for rate calculation",
            required=False,
            default=5.0,
        ),
    ],
    handler=_telemetry_rate_handler,
    category="instrumentation",
    requires_lock=True,
)


# =============================================================================
# Custom Script Generation
# =============================================================================


def _lldb_generate_fuzz_script_handler(
    director: LLDBDirector,
    *,
    function: str,
    registers: dict[str, str],
    buffer_reg: str = "x0",
    size_reg: str | None = None,
    size_expr: str | None = None,
    skip_conditions: list[str] | None = None,
    callback_name: str | None = None,
    include_hexdump: bool = True,
    telemetry_pipe: str | None = None,
) -> str:
    """Generate a custom, target-aware fuzzing script for native-speed execution.

    Generates custom callbacks that understand the target function's ABI
    and can apply intelligent filtering.
    """
    import time

    from ...server.environment import bootstrap_header
    from ...server.telemetry import TelemetrySession

    # Generate callback name from function if not provided
    cb_name = callback_name or f"fuzz_{function.replace(':', '_').replace('-', '_')}"

    # Set up telemetry
    pipe_path = telemetry_pipe
    session: TelemetrySession | None = None
    if not pipe_path:
        session = TelemetrySession.create(Path.cwd(), name=cb_name)
        session.start()
        director.telemetry_sessions[cb_name] = session
        pipe_path = str(session.pipe_path)

    # Build register reading code
    reg_reads = []
    reg_prints = []
    for name, desc in registers.items():
        var_name = name.replace("$", "").lower()
        reg_reads.append(f"    {var_name} = frame.FindRegister('{name.replace('$', '')}').GetValueAsUnsigned()")
        reg_prints.append(f'    print(f"\\t{desc}: {{hex({var_name})}}")')

    # Build skip conditions
    skip_code = ""
    if skip_conditions:
        conditions = " or ".join(skip_conditions)
        skip_code = f"""
    # Skip conditions (target-specific filtering)
    if {conditions}:
        print("\\tSkipping: condition not met")
        return False
"""

    # Hexdump helper
    hexdump_code = ""
    if include_hexdump:
        hexdump_code = """
COLORS = {
    'address': '\\033[33m', 'modified': '\\033[41m',
    'nonzero': '\\033[32m', 'ascii': '\\033[31m', 'reset': '\\033[0m'
}

def hexdump(addr, data, size, hl_off=None, hl_len=1):
    for off in range(0, min(len(data), size), 16):
        line = f'\\t{COLORS["address"]}0x{addr + off:016x}{COLORS["reset"]} '
        for i in range(off, min(off + 16, len(data))):
            hl = hl_off is not None and hl_off <= i < hl_off + hl_len
            c = COLORS['modified'] if hl else COLORS['nonzero'] if data[i] != 0 else ''
            line += f'{c}{data[i]:02x}{COLORS["reset"]} '
        line = line.ljust(70) + '|'
        for i in range(off, min(off + 16, len(data))):
            ch = chr(data[i]) if 32 <= data[i] < 127 else '.'
            hl = hl_off is not None and hl_off <= i < hl_off + hl_len
            c = COLORS['modified'] if hl else COLORS['ascii'] if 32 <= data[i] < 127 else ''
            line += f'{c}{ch}{COLORS["reset"]}'
        print(line + '|')
"""

    # Size expression
    if size_reg:
        size_var = size_reg.replace("$", "").lower()
        size_code = f"    size = min({size_var}, MAX_SIZE)"
    elif size_expr:
        size_code = f"    size = min({size_expr}, MAX_SIZE)"
    else:
        size_code = "    size = MAX_SIZE"

    buffer_var = buffer_reg.replace("$", "").lower()

    # Build hexdump display line
    hexdump_orig = "hexdump(ptr, memory, size)" if include_hexdump else "print(f'\\t{memory[:64].hex()}...')"
    hexdump_mod = (
        "hexdump(ptr, result.data, size, result.highlight_offset, result.highlight_length)"
        if include_hexdump
        else "print(f'\\t{bytes(result.data[:64]).hex()}...')"
    )

    # Generate the script using regular string formatting to avoid f-string escaping issues
    script_parts = [
        f'"""Auto-generated fuzzing script for {function}.',
        "",
        "Generated by ALF lldb_generate_fuzz_script tool.",
        f"Target: {function}",
        f"Buffer register: {buffer_reg}",
        f"Size: {size_reg or size_expr or 'MAX_SIZE'}",
        '"""',
        "",
        "import lldb",
        "import os",
        "import json",
        "import errno",
        "",
        "# ALF imports (mutation strategies)",
        "from alf.mut import apply_random_mutation",
        "",
        "MAX_SIZE = 4096",
        "PAC_MASK = 0x0000FFFFFFFFFFFF",
        f'TELEMETRY_PIPE = "{pipe_path}"',
    ]

    if hexdump_code:
        script_parts.append(hexdump_code)

    script_parts.extend(
        [
            "",
            f"def {cb_name}(frame, bp_loc, internal_dict):",
            f'    """Breakpoint callback for {function}."""',
            "    thread = frame.GetThread()",
            "    process = thread.GetProcess()",
            "    error = lldb.SBError()",
            "",
            "    print('\\n' + '=' * 80)",
            f"    print('{function}:')",
            "",
            "    # Read registers",
        ]
    )
    script_parts.extend(reg_reads)
    script_parts.extend(
        [
            "",
            "    # Print register values",
        ]
    )
    script_parts.extend(reg_prints)
    script_parts.append("    print()")

    if skip_code:
        script_parts.append(skip_code)

    script_parts.extend(
        [
            "    # Get buffer pointer (strip PAC bits on arm64e)",
            f"    ptr = {buffer_var} & PAC_MASK",
            size_code,
            "",
            "    if ptr == 0 or size == 0:",
            '        print("\\tSkipping: null pointer or zero size")',
            "        return False",
            "",
            "    # Read memory",
            "    memory = process.ReadMemory(ptr, size, error)",
            "    if not error.Success():",
            '        print(f"\\tFailed to read memory: {error.GetCString()}")',
            "        return False",
            "",
            '    print("\\tOriginal data:")',
            f"    {hexdump_orig}",
            "    print()",
            "",
            "    # Apply mutation",
            "    buf = bytearray(memory)",
            "    result = apply_random_mutation(buf)",
            "",
            '    print(f"\\tMutation: {result.description}")',
            "",
            "    # Write back",
            "    write_result = process.WriteMemory(ptr, bytes(result.data), error)",
            "    if not error.Success():",
            '        print(f"\\tFailed to write memory: {error.GetCString()}")',
            "        return False",
            "",
            '    print("\\tModified data:")',
            f"    {hexdump_mod}",
            "",
            "    # Emit telemetry",
            "    try:",
            "        fd = os.open(TELEMETRY_PIPE, os.O_WRONLY | os.O_NONBLOCK)",
            "        event = json.dumps({",
            '            "event": "mutation",',
            f'            "function": "{function}",',
            '            "ptr": hex(ptr),',
            '            "size": size,',
            '            "desc": result.description[:100],',
            "        })",
            '        os.write(fd, (event + "\\n").encode())',
            "        os.close(fd)",
            "    except OSError as e:",
            "        if e.errno not in (errno.EAGAIN, errno.EPIPE, errno.ENXIO):",
            '            print(f"\\tTelemetry error: {e}")',
            "",
            "    print('=' * 80 + '\\n')",
            "    return False  # Continue execution",
            "",
            "",
            "def __lldb_init_module(debugger, internal_dict):",
            '    """Called when script is imported into LLDB."""',
            "    target = debugger.GetSelectedTarget()",
            f"    bp = target.BreakpointCreateByName('{function}')",
            f'    bp.SetScriptCallbackFunction(f"{{__name__}}.{cb_name}")',
            f'    print(f"[+] Installed fuzzing hook on {function}")',
        ]
    )

    script = "\n".join(script_parts)

    # Write script to disk
    logs_dir = Path.cwd() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    script_path = logs_dir / f"fuzz_{function}_{ts}.py"

    # Prepend bootstrap header
    full_script = bootstrap_header() + "\n\n" + script
    script_path.write_text(full_script, encoding="utf-8")

    return json.dumps(
        {
            "script_path": str(script_path),
            "callback_name": cb_name,
            "function": function,
            "telemetry_pipe": pipe_path,
            "instructions": (
                f"Script generated at {script_path}. To install: lldb_execute('command script import {script_path}')"
            ),
        },
        indent=2,
    )


LLDB_GENERATE_FUZZ_SCRIPT = Tool(
    name="lldb_generate_fuzz_script",
    description=(
        "Generate a custom, target-aware fuzzing script for native-speed execution. "
        "Creates a Python script that: "
        "1) Reads registers according to the target function's ABI, "
        "2) Applies intelligent filtering based on register values, "
        "3) Mutates the buffer using ALF strategies, "
        "4) Writes back and continues. "
        "The script can be customized before installation for complex targets."
    ),
    parameters=[
        ToolParameter(
            name="function",
            type="string",
            description="Target function name (e.g., 'parse_input', 'decode_message')",
        ),
        ToolParameter(
            name="registers",
            type="object",
            description=(
                "Map of register names to descriptions. Example: {'x0': 'connection', 'x1': 'selector', 'x2': 'input'}"
            ),
        ),
        ToolParameter(
            name="buffer_reg",
            type="string",
            description="Register containing the buffer pointer to mutate",
            required=False,
            default="x0",
        ),
        ToolParameter(
            name="size_reg",
            type="string",
            description="Register containing buffer size (optional)",
            required=False,
        ),
        ToolParameter(
            name="size_expr",
            type="string",
            description="Expression for buffer size if not in a register (e.g., '1024')",
            required=False,
        ),
        ToolParameter(
            name="skip_conditions",
            type="array",
            description=("Python expressions to skip mutation. Example: ['selector in [6, 8, 9]', 'size == 0']"),
            required=False,
        ),
        ToolParameter(
            name="callback_name",
            type="string",
            description="Custom callback function name (auto-generated if omitted)",
            required=False,
        ),
        ToolParameter(
            name="include_hexdump",
            type="boolean",
            description="Include colorized hexdump output",
            required=False,
            default=True,
        ),
        ToolParameter(
            name="telemetry_pipe",
            type="string",
            description="Path to FIFO for telemetry (auto-created if omitted)",
            required=False,
        ),
    ],
    handler=_lldb_generate_fuzz_script_handler,
    category="instrumentation",
    requires_lock=True,
)


# =============================================================================
# Exported Tool List
# =============================================================================


INSTRUMENTATION_TOOLS: list[Tool] = [
    LLDB_INSTALL_STOP_HOOK,
    LLDB_INSTALL_FORK_SERVER,
    LLDB_GENERATE_FUZZ_SCRIPT,
    TELEMETRY_SNAPSHOT,
    TELEMETRY_RATE,
]


__all__ = [
    # Individual tools
    "LLDB_INSTALL_STOP_HOOK",
    "LLDB_INSTALL_FORK_SERVER",
    "LLDB_GENERATE_FUZZ_SCRIPT",
    "TELEMETRY_SNAPSHOT",
    "TELEMETRY_RATE",
    # Tool list
    "INSTRUMENTATION_TOOLS",
]
