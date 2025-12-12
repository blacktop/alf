"""LLDB crash analysis tools: crash context, stack hash, poll crashes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._common import Tool, ToolParameter, hashlib, json
from .inspection import _lldb_backtrace_json_handler

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_stack_hash_handler(
    director: LLDBDirector,
    *,
    max_frames: int = 5,
    thread_id: int | None = None,
) -> str:
    """Compute a hash of the top stack frames for crash deduplication."""
    bt_json = _lldb_backtrace_json_handler(director, thread_id=thread_id, count=max_frames)
    try:
        obj = json.loads(bt_json)
    except Exception:
        return json.dumps({"error": bt_json}, indent=2)
    frames = obj.get("frames") if isinstance(obj, dict) else None
    if not isinstance(frames, list):
        return json.dumps({"error": obj.get("error", "invalid backtrace")}, indent=2)
    pcs = [f.get("pc") for f in frames if isinstance(f, dict) and f.get("pc")]
    pcs = pcs[: max(1, int(max_frames))]
    h = hashlib.sha256("|".join(pcs).encode()).hexdigest() if pcs else ""
    return json.dumps({"stack_hash": h, "pcs": pcs}, indent=2)


def _lldb_crash_context_handler(
    director: LLDBDirector,
    *,
    max_frames: int = 24,
    stack_bytes: int = 256,
    thread_id: int | None = None,
) -> str:
    """Get comprehensive crash context including backtrace, registers, and disassembly."""
    from ....server.runtime.memory import strip_pac, try_parse_address

    if not director.dap_session:
        return json.dumps({"error": "No active DAP session"}, indent=2)

    tid = thread_id if thread_id is not None else director.thread_id
    frames_out: list[dict[str, Any]] = []
    bt_error: str | None = None
    if tid is not None:
        try:
            resp = director.dap_session.request("stackTrace", {"threadId": tid, "levels": int(max_frames)})
            frames = resp.get("body", {}).get("stackFrames", []) or []
            for frame in frames:
                ip_ref = (
                    frame.get("instructionPointerReference")
                    or frame.get("instructionPointerAddress")
                    or frame.get("address")
                    or ""
                )
                addr_int = try_parse_address(str(ip_ref)) if ip_ref else None
                pc_str = f"0x{strip_pac(addr_int):x}" if addr_int is not None else None
                src = frame.get("source", {}) or {}
                frames_out.append(
                    {
                        "name": frame.get("name", "??"),
                        "pc": pc_str,
                        "file": src.get("path"),
                        "line": frame.get("line"),
                        "column": frame.get("column"),
                        "module": frame.get("moduleId"),
                    }
                )
        except Exception as e:  # noqa: BLE001
            bt_error = str(e)

    pcs = [f.get("pc") for f in frames_out if f.get("pc")]
    pcs_top = pcs[:5]
    stack_hash = hashlib.sha256("|".join(pcs_top).encode()).hexdigest() if pcs_top else ""

    regs = director.execute_lldb_command("register read")
    dis = director.execute_lldb_command("disassemble --pc --count 24")
    stack_dump = director.execute_lldb_command(f"memory read -fx -s1 $sp {max(0, int(stack_bytes))}")

    stop_body = (director.last_stop_event or {}).get("body", {}) if director.last_stop_event else {}

    payload: dict[str, Any] = {
        "reason": stop_body.get("reason"),
        "stop": stop_body,
        "stack_hash": stack_hash,
        "pcs": pcs_top,
        "frames": frames_out,
        "registers": regs,
        "disassemble": dis,
        "stack_bytes": stack_dump,
    }
    if bt_error:
        payload["backtrace_error"] = bt_error
    return json.dumps(payload, indent=2)


def _lldb_poll_crashes_handler(
    director: LLDBDirector,
    *,
    limit: int = 5,
) -> str:
    """Poll for newly-detected crashes since last check."""
    crashes = director.pop_pending_crashes(limit=limit)
    return json.dumps({"crashes": crashes}, indent=2)


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_STACK_HASH = Tool(
    name="lldb_stack_hash",
    description=(
        "Compute a hash of the top stack frames for crash deduplication. "
        "Generates a unique identifier based on the top N program counters. "
        "Use to identify unique crashes and avoid duplicate reports."
    ),
    parameters=[
        ToolParameter(
            name="max_frames",
            type="integer",
            description="Number of top frames to include in hash",
            required=False,
            default=5,
        ),
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread ID (uses current thread if omitted)",
            required=False,
        ),
    ],
    handler=_lldb_stack_hash_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_CRASH_CONTEXT = Tool(
    name="lldb_crash_context",
    description=(
        "Get comprehensive crash context including backtrace, registers, and disassembly. "
        "Returns a complete snapshot of the crash state: stack hash, frames, "
        "register values, disassembly at PC, and stack memory. Essential for "
        "root cause analysis and vulnerability classification."
    ),
    parameters=[
        ToolParameter(
            name="max_frames",
            type="integer",
            description="Maximum stack frames to include",
            required=False,
            default=24,
        ),
        ToolParameter(
            name="stack_bytes",
            type="integer",
            description="Bytes of stack memory to dump",
            required=False,
            default=256,
        ),
        ToolParameter(
            name="thread_id",
            type="integer",
            description="Thread ID (uses current thread if omitted)",
            required=False,
        ),
    ],
    handler=_lldb_crash_context_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_POLL_CRASHES = Tool(
    name="lldb_poll_crashes",
    description=(
        "Poll for newly-detected crashes since last check. "
        "Returns crashes deduplicated by stack hash. Use during fuzzing "
        "to collect unique crashes without stopping the campaign."
    ),
    parameters=[
        ToolParameter(
            name="limit",
            type="integer",
            description="Maximum number of crashes to return",
            required=False,
            default=5,
        ),
    ],
    handler=_lldb_poll_crashes_handler,
    category="lldb",
    requires_lock=True,
)


CRASH_ANALYSIS_TOOLS = [
    LLDB_STACK_HASH,
    LLDB_CRASH_CONTEXT,
    LLDB_POLL_CRASHES,
]

__all__ = [
    "LLDB_STACK_HASH",
    "LLDB_CRASH_CONTEXT",
    "LLDB_POLL_CRASHES",
    "CRASH_ANALYSIS_TOOLS",
]
