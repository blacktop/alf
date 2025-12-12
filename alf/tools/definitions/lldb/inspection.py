"""LLDB inspection tools: backtrace, memory, registers, disassembly, threads, frames."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._common import Tool, ToolParameter, json

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_backtrace_handler(
    director: LLDBDirector,
    *,
    thread_id: int | None = None,
    count: int = 32,
) -> str:
    """Get stack backtrace for a thread."""
    try:
        effective_thread_id = thread_id if thread_id is not None else director.thread_id
        frames = director.get_backtrace(thread_id=effective_thread_id, count=count)
        if not frames:
            return "No active session or no frames"
            
        out_lines = []
        for i, frame in enumerate(frames):
            name = frame.name or "??"
            line = frame.line or 0
            src = frame.source_path or ""
            out_lines.append(f"#{i:2d} {name} at {src}:{line}")
        return "\n".join(out_lines)
    except Exception as e:  # noqa: BLE001
        return f"Backtrace failed: {e}"


def _lldb_backtrace_json_handler(
    director: LLDBDirector,
    *,
    thread_id: int | None = None,
    count: int = 32,
) -> str:
    """Get stack backtrace as structured JSON with PAC-stripped addresses."""
    from ....server.runtime.memory import strip_pac, try_parse_address

    try:
        effective_thread_id = thread_id if thread_id is not None else director.thread_id
        frames = director.get_backtrace(thread_id=effective_thread_id, count=count)
        if not frames:
            return json.dumps({"error": "No active session"}, indent=2)

        out: list[dict[str, Any]] = []
        for frame in frames:
            ip_ref = frame.instruction_pointer
            addr_int = try_parse_address(str(ip_ref)) if ip_ref else None
            pc_str = None
            if addr_int is not None:
                pc_str = f"0x{strip_pac(addr_int):x}"
            
            out.append(
                {
                    "name": frame.name or "??",
                    "pc": pc_str,
                    "file": frame.source_path,
                    "line": frame.line,
                    "column": frame.column,
                    "module": frame.module_name,
                }
            )
        return json.dumps({"frames": out}, indent=2)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)}, indent=2)


def _lldb_disassemble_handler(
    director: LLDBDirector,
    *,
    address: str = "--pc",
    count: int = 20,
) -> str:
    """Disassemble machine code at the specified address."""
    if address == "--pc":
        cmd = f"disassemble --pc --count {count}"
    else:
        addr = director.evaluate_address(address)
        start_expr = f"0x{addr:x}" if addr is not None else address
        cmd = f"disassemble --start-address {start_expr} --count {count}"
    return director.execute_lldb_command(cmd)


def _lldb_read_memory_handler(
    director: LLDBDirector,
    *,
    address: str,
    size: int = 64,
    fmt: str = "x",
) -> str:
    """Read memory at the specified address."""
    addr = director.evaluate_address(address)
    addr_expr = f"0x{addr:x}" if addr is not None else address
    cmd = f"memory read --size 1 --count {size} --format {fmt} {addr_expr}"
    return director.execute_lldb_command(cmd)


def _lldb_deref_handler(
    director: LLDBDirector,
    *,
    register_or_expr: str,
    size: int = 64,
    fmt: str = "x",
) -> str:
    """Dereference a pointer and read memory at the target address."""
    addr = director.evaluate_address(register_or_expr)
    if addr is None:
        return f"Could not parse address from '{register_or_expr}'"
    cmd = f"memory read --size 1 --count {size} --format {fmt} 0x{addr:x}"
    return director.execute_lldb_command(cmd)


def _lldb_memory_search_handler(
    director: LLDBDirector,
    *,
    pattern: str,
    start_address: str,
    size: int = 4096,
) -> str:
    """Search memory for a byte pattern."""
    out = director.memory_search(pattern, start_address, size=size)
    text = (out or "").strip().lower()
    if text.startswith("error") or "read failed" in text or "expression failed" in text:
        return json.dumps({"error": out}, indent=2)
    return out


def _lldb_register_read_handler(
    director: LLDBDirector,
    *,
    register: str | None = None,
) -> str:
    """Read CPU register values."""
    return director.register_read(register=register)


def _lldb_register_write_handler(
    director: LLDBDirector,
    *,
    register: str,
    value: str,
) -> str:
    """Write a value to a CPU register."""
    return director.register_write(register=register, value=value)


def _lldb_evaluate_handler(
    director: LLDBDirector,
    *,
    expression: str,
) -> str:
    """Evaluate an expression in the current frame context."""
    try:
        return str(director.evaluate(expression, frame_id=director.frame_id))
    except Exception as e:  # noqa: BLE001
        return f"Evaluation failed: {e}"


def _lldb_thread_list_handler(director: LLDBDirector) -> str:
    """List threads in the current target."""
    return json.dumps(director.list_threads(), indent=2)


def _lldb_thread_select_handler(
    director: LLDBDirector,
    *,
    thread_id: int,
) -> str:
    """Select a thread for subsequent operations."""
    return json.dumps(director.select_thread(int(thread_id)), indent=2)


def _lldb_frame_select_handler(
    director: LLDBDirector,
    *,
    frame_index: int = 0,
    thread_id: int | None = None,
) -> str:
    """Select a specific stack frame."""
    return json.dumps(director.select_frame(int(frame_index), thread_id=thread_id), indent=2)


def _lldb_frame_variables_handler(
    director: LLDBDirector,
    *,
    frame_index: int = 0,
    thread_id: int | None = None,
    show_globals: bool = False,
) -> str:
    """Get all local variables in the specified stack frame."""
    select_result = director.select_frame(int(frame_index), thread_id=thread_id)
    if isinstance(select_result, dict) and select_result.get("error"):
        return json.dumps(select_result, indent=2)

    cmd = "frame variable"
    if show_globals:
        cmd += " -g"
    vars_output = director.execute_lldb_command(cmd)

    return json.dumps(
        {
            "frame_index": frame_index,
            "variables": vars_output,
        },
        indent=2,
    )


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_BACKTRACE = Tool(
    name="lldb_backtrace",
    description=(
        "Get stack backtrace for a thread. "
        "Shows the call stack leading to the current location. "
        "Essential for understanding crash context and call flow."
    ),
    parameters=[
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread ID (uses current thread if omitted)",
            required=False,
        ),
        ToolParameter(
            name="count",
            type="integer",
            description="Maximum number of stack frames to return",
            required=False,
            default=32,
        ),
    ],
    handler=_lldb_backtrace_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_BACKTRACE_JSON = Tool(
    name="lldb_backtrace_json",
    description=(
        "Get stack backtrace as structured JSON with PAC-stripped addresses. "
        "Returns detailed frame information including function names, addresses, "
        "source files, and line numbers. PAC bits are stripped for accurate addresses."
    ),
    parameters=[
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread ID (uses current thread if omitted)",
            required=False,
        ),
        ToolParameter(
            name="count",
            type="integer",
            description="Maximum number of stack frames to return",
            required=False,
            default=32,
        ),
    ],
    handler=_lldb_backtrace_json_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_DISASSEMBLE = Tool(
    name="lldb_disassemble",
    description=(
        "Disassemble machine code at the specified address. "
        "Use '--pc' (default) to disassemble from the current program counter. "
        "Essential for understanding crash sites and analyzing exploit behavior."
    ),
    parameters=[
        ToolParameter(
            name="address",
            type="string",
            description="Address to disassemble from, or '--pc' for current instruction",
            required=False,
            default="--pc",
        ),
        ToolParameter(
            name="count",
            type="integer",
            description="Number of instructions to disassemble",
            required=False,
            default=20,
        ),
    ],
    handler=_lldb_disassemble_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_READ_MEMORY = Tool(
    name="lldb_read_memory",
    description=(
        "Read memory at the specified address. "
        "Supports addresses, expressions, and registers (prefix with $). "
        "Returns raw memory contents in the specified format."
    ),
    parameters=[
        ToolParameter(
            name="address",
            type="string",
            description="Memory address or register (e.g., '0x1000', '$x0', '$sp')",
        ),
        ToolParameter(
            name="size",
            type="integer",
            description="Number of bytes to read",
            required=False,
            default=64,
        ),
        ToolParameter(
            name="fmt",
            type="string",
            description="Output format: 'x' (hex), 's' (string), 'i' (instruction)",
            required=False,
            default="x",
        ),
    ],
    handler=_lldb_read_memory_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_DEREF = Tool(
    name="lldb_deref",
    description=(
        "Dereference a pointer and read memory at the target address. "
        "Evaluates the expression to get a pointer value, then reads memory "
        "at that address. Useful for examining buffer contents from registers."
    ),
    parameters=[
        ToolParameter(
            name="register_or_expr",
            type="string",
            description="Register or expression containing a pointer (e.g., '$x0', '*(int*)p')",
        ),
        ToolParameter(
            name="size",
            type="integer",
            description="Number of bytes to read at the pointed-to address",
            required=False,
            default=64,
        ),
        ToolParameter(
            name="fmt",
            type="string",
            description="Output format: 'x' (hex), 's' (string), 'i' (instruction)",
            required=False,
            default="x",
        ),
    ],
    handler=_lldb_deref_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_MEMORY_SEARCH = Tool(
    name="lldb_memory_search",
    description=(
        "Search memory for a byte pattern. "
        "Scans memory starting at the given address looking for the pattern. "
        "Useful for finding magic bytes, strings, or specific data structures."
    ),
    parameters=[
        ToolParameter(
            name="pattern",
            type="string",
            description="Byte pattern to search for (hex string or ASCII)",
        ),
        ToolParameter(
            name="start_address",
            type="string",
            description="Address or register to start searching from",
        ),
        ToolParameter(
            name="size",
            type="integer",
            description="Number of bytes to search",
            required=False,
            default=4096,
        ),
    ],
    handler=_lldb_memory_search_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_REGISTER_READ = Tool(
    name="lldb_register_read",
    description=(
        "Read CPU register values. "
        "Returns all general-purpose registers if no register specified, "
        "or the value of a specific register. ARM64 registers: x0-x28, fp, lr, sp, pc."
    ),
    parameters=[
        ToolParameter(
            name="register",
            type="string",
            description="Specific register to read (e.g., 'x0', 'pc'), or None for all",
            required=False,
        ),
    ],
    handler=_lldb_register_read_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_REGISTER_WRITE = Tool(
    name="lldb_register_write",
    description=(
        "Write a value to a CPU register. "
        "Modifies register state during debugging. Use with caution as this "
        "can affect program behavior and crash analysis."
    ),
    parameters=[
        ToolParameter(
            name="register",
            type="string",
            description="Register name to modify (e.g., 'x0', 'pc')",
        ),
        ToolParameter(
            name="value",
            type="string",
            description="Value to write (hex or decimal, e.g., '0x1000', '42')",
        ),
    ],
    handler=_lldb_register_write_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_EVALUATE = Tool(
    name="lldb_evaluate",
    description=(
        "Evaluate an expression in the current frame context. "
        "Supports C/C++/ObjC expressions, register access ($x0), pointer "
        "dereferencing, struct field access, and function calls."
    ),
    parameters=[
        ToolParameter(
            name="expression",
            type="string",
            description="Expression to evaluate (e.g., 'argc', '*(char*)$x0', 'myStruct.field')",
        ),
    ],
    handler=_lldb_evaluate_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_THREAD_LIST = Tool(
    name="lldb_thread_list",
    description="List threads in the current target.",
    parameters=[],
    handler=_lldb_thread_list_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_THREAD_SELECT = Tool(
    name="lldb_thread_select",
    description=(
        "Select a thread for subsequent stack/evaluate operations. "
        "After selecting, backtrace and evaluate operations use this thread's context."
    ),
    parameters=[
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread ID to select (from lldb_thread_list)",
        ),
    ],
    handler=_lldb_thread_select_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_FRAME_SELECT = Tool(
    name="lldb_frame_select",
    description=(
        "Select a specific stack frame for subsequent evaluate operations. "
        "Frame 0 is the top (current) frame. Higher indices go up the call stack. "
        "Variables and expressions are evaluated in the selected frame's context."
    ),
    parameters=[
        ToolParameter(
            name="frame_index",
            type="integer",
            description="Stack frame index (0 = top/current frame)",
            required=False,
            default=0,
        ),
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread ID (uses current thread if omitted)",
            required=False,
        ),
    ],
    handler=_lldb_frame_select_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_FRAME_VARIABLES = Tool(
    name="lldb_frame_variables",
    description=(
        "Get all local variables in the specified stack frame. "
        "Shows variable names, types, and values. "
        "Useful for understanding program state at a crash or breakpoint."
    ),
    parameters=[
        ToolParameter(
            name="frame_index",
            type="integer",
            description="Stack frame index (0 = top/current frame)",
            required=False,
            default=0,
        ),
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread ID (uses current thread if omitted)",
            required=False,
        ),
        ToolParameter(
            name="show_globals",
            type="boolean",
            description="Also show global variables",
            required=False,
            default=False,
        ),
    ],
    handler=_lldb_frame_variables_handler,
    category="lldb",
    requires_lock=True,
)


INSPECTION_TOOLS = [
    LLDB_BACKTRACE,
    LLDB_BACKTRACE_JSON,
    LLDB_DISASSEMBLE,
    LLDB_READ_MEMORY,
    LLDB_DEREF,
    LLDB_MEMORY_SEARCH,
    LLDB_REGISTER_READ,
    LLDB_REGISTER_WRITE,
    LLDB_EVALUATE,
    LLDB_THREAD_LIST,
    LLDB_THREAD_SELECT,
    LLDB_FRAME_SELECT,
    LLDB_FRAME_VARIABLES,
]

__all__ = [
    "LLDB_BACKTRACE",
    "LLDB_BACKTRACE_JSON",
    "LLDB_DISASSEMBLE",
    "LLDB_READ_MEMORY",
    "LLDB_DEREF",
    "LLDB_MEMORY_SEARCH",
    "LLDB_REGISTER_READ",
    "LLDB_REGISTER_WRITE",
    "LLDB_EVALUATE",
    "LLDB_THREAD_LIST",
    "LLDB_THREAD_SELECT",
    "LLDB_FRAME_SELECT",
    "LLDB_FRAME_VARIABLES",
    "INSPECTION_TOOLS",
    # Handler exported for crash_analysis module
    "_lldb_backtrace_json_handler",
]
