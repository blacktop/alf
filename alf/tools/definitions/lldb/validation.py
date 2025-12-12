"""LLDB input control validation: Phase 1 dynamic tracing for fuzzing."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ._common import Tool, ToolParameter, json

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Helper Functions
# =============================================================================


def _parse_register_hex(output: str) -> int | None:
    """Extract hex value from 'register read' output like 'x0 = 0x0000000100003f00'."""
    match = re.search(r"=\s*(0x[0-9a-fA-F]+)", output)
    if match:
        try:
            return int(match.group(1), 16)
        except ValueError:
            pass
    return None


def _looks_like_pointer(val: int) -> bool:
    """Heuristic: arm64 user pointers typically in range 0x1000 - 0x0000FFFFFFFFFFFF."""
    # Exclude NULL, small integers, and kernel addresses
    return 0x1000 <= val <= 0x0000_FFFF_FFFF_FFFF


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_validate_input_control_handler(
    director: LLDBDirector,
    *,
    function: str | None = None,
    address: str | None = None,
    marker: str,
    search_size: int = 4096,
) -> str:
    """Validate that input is accessible at a target function via arm64 argument registers.

    Requires: session launched with stop_on_entry=True.
    Workflow: set breakpoint → continue → inspect x0-x7 → search for marker.
    """
    if not function and not address:
        return json.dumps({"error": "Provide either 'function' or 'address'"}, indent=2)

    if not marker:
        return json.dumps({"error": "Provide a 'marker' pattern to search for"}, indent=2)

    # 1. Set breakpoint on target
    bp_result = director.set_breakpoint(function=function, address=address)
    if "error" in bp_result.lower():
        return json.dumps({"error": f"Failed to set breakpoint: {bp_result}"}, indent=2)

    # 2. Continue execution to hit the breakpoint
    continue_result = director.continue_exec(wait=True, timeout=30.0)
    try:
        continue_data = json.loads(continue_result)
    except Exception:
        continue_data = {"raw": continue_result}

    stop_reason = continue_data.get("reason", "")
    status = continue_data.get("status", "")

    # 3. Check we stopped (ideally at breakpoint)
    if status == "exited":
        return json.dumps(
            {
                "validated": False,
                "error": "Process exited before hitting breakpoint",
                "function": function or address,
                "marker": marker,
            },
            indent=2,
        )

    # 4. Read argument registers x0-x7
    arg_registers = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    reg_values: dict[str, int | None] = {}

    for reg in arg_registers:
        reg_output = director.register_read(register=reg)
        reg_values[reg] = _parse_register_hex(reg_output)

    # 5. For each pointer-like register, search for marker
    results: dict[str, dict[str, Any]] = {}
    found_count = 0

    for reg, val in reg_values.items():
        if val is None:
            results[reg] = {"controls_input": False, "error": "Could not read register"}
            continue

        if _looks_like_pointer(val):
            # Search memory at this address for the marker
            # Use hex address directly since we already have the value
            search_result = director.memory_search(marker, f"0x{val:x}", size=search_size)
            try:
                search_data = json.loads(search_result)
                if search_data.get("found"):
                    results[reg] = {
                        "controls_input": True,
                        "offset": search_data.get("offset", 0),
                        "address": f"0x{val:x}",
                    }
                    found_count += 1
                else:
                    results[reg] = {
                        "controls_input": False,
                        "address": f"0x{val:x}",
                        "note": "pointer, but marker not found",
                    }
            except Exception:
                # Not found or error
                if "Not found" in search_result:
                    results[reg] = {
                        "controls_input": False,
                        "address": f"0x{val:x}",
                        "note": "pointer, but marker not found",
                    }
                else:
                    results[reg] = {
                        "controls_input": False,
                        "address": f"0x{val:x}",
                        "error": search_result[:100],
                    }
        else:
            # Likely an integer value (size, flags, etc.)
            results[reg] = {
                "controls_input": False,
                "value": f"0x{val:x}",
                "interpretation": "likely integer (size/flags/fd)",
            }

    # 6. Generate interpretation
    controlling_regs = [r for r, v in results.items() if v.get("controls_input")]
    if controlling_regs:
        # Find first non-controlling register after a controlling one as potential size
        interpretation_parts = []
        for reg in controlling_regs:
            interpretation_parts.append(f"{reg} points to input buffer containing marker")

        # Look for size parameter (typically x1 if x0 is buffer, or next non-pointer)
        for i, reg in enumerate(arg_registers):
            if reg in controlling_regs:
                next_reg = arg_registers[i + 1] if i + 1 < len(arg_registers) else None
                if next_reg and not results.get(next_reg, {}).get("controls_input"):
                    next_val = reg_values.get(next_reg)
                    if next_val is not None and not _looks_like_pointer(next_val):
                        interpretation_parts.append(f"{next_reg} = {next_val} (likely size)")
                        break

        interpretation = "; ".join(interpretation_parts)
    else:
        interpretation = "Marker not found in any argument register memory"

    return json.dumps(
        {
            "validated": found_count > 0,
            "function": function or address,
            "marker": marker,
            "registers": results,
            "interpretation": interpretation,
            "stop_reason": stop_reason,
            "stop_status": status,
        },
        indent=2,
    )


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_VALIDATE_INPUT_CONTROL = Tool(
    name="lldb_validate_input_control",
    description=(
        "Validate that fuzzer input is accessible at a target function. "
        "Requires: session launched with lldb_launch(stop_on_entry=True). "
        "Sets breakpoint on target function, continues execution, then inspects "
        "arm64 argument registers (x0-x7) searching for a marker pattern. "
        "Returns which registers point to memory containing the marker, "
        "confirming the agent controls input at that function."
    ),
    parameters=[
        ToolParameter(
            name="function",
            type="string",
            description="Target function name to validate (e.g., 'parse_input')",
            required=False,
        ),
        ToolParameter(
            name="address",
            type="string",
            description="Alternative: target address instead of function name",
            required=False,
        ),
        ToolParameter(
            name="marker",
            type="string",
            description="Pattern to search for in memory (e.g., 'FUZZ_MARKER')",
        ),
        ToolParameter(
            name="search_size",
            type="integer",
            description="Bytes to search per register address",
            required=False,
            default=4096,
        ),
    ],
    handler=_lldb_validate_input_control_handler,
    category="lldb",
    requires_lock=True,
)


VALIDATION_TOOLS = [
    LLDB_VALIDATE_INPUT_CONTROL,
]

__all__ = [
    "LLDB_VALIDATE_INPUT_CONTROL",
    "VALIDATION_TOOLS",
]
