"""LLDB kernel-debugging helpers.

Tools in this module cover operations that only matter when debugging a
kernel, kext, or firmware through a gdb-remote stub (e.g. XNU under
Virtualization.framework). They wrap backend primitives that default to
`BackendUnsupportedError` so callers get a clear failure when running
against a backend that cannot service the request.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from ._common import Tool, ToolParameter, json

if TYPE_CHECKING:
    from ....server.lldb import LLDBDirector


# =============================================================================
# Handler Functions
# =============================================================================


def _lldb_add_module_handler(
    director: LLDBDirector,
    *,
    path: str,
    dsym: str | None = None,
    slide: int | None = None,
    load_addr: int | None = None,
) -> str:
    """Add a module (and optional dSYM) to the current LLDB target."""
    result = director.add_module(
        path=path,
        dsym=dsym,
        slide=int(slide) if slide is not None else None,
        load_addr=int(load_addr) if load_addr is not None else None,
    )
    return json.dumps(result, indent=2)


def _lldb_slide_handler(
    director: LLDBDirector,
    *,
    module: str | None = None,
) -> str:
    """Return the runtime slide for a loaded module."""
    return json.dumps(director.image_slide(module=module), indent=2)


def _lldb_load_xnu_macros_handler(
    director: LLDBDirector,
    *,
    path: str | None = None,
) -> str:
    """Import Apple's xnu lldbmacros into the current session."""
    return json.dumps(director.load_xnu_macros(path=path), indent=2)


def _decode_payload(data: str, encoding: str) -> bytes:
    enc = (encoding or "hex").strip().lower()
    if enc == "hex":
        cleaned = data.strip().replace(" ", "").replace(":", "").replace(",", "")
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        return bytes.fromhex(cleaned)
    if enc == "ascii":
        return data.encode("utf-8")
    if enc == "base64":
        return base64.b64decode(data)
    raise ValueError(f"unknown encoding '{encoding}'")


def _lldb_write_memory_handler(
    director: LLDBDirector,
    *,
    address: str,
    data: str,
    encoding: str = "hex",
    resume: bool = True,
) -> str:
    """Write bytes to target memory, optionally interrupting+resuming."""
    try:
        payload = _decode_payload(data, encoding)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"invalid data for encoding={encoding}: {e}"}, indent=2)
    if not payload:
        return json.dumps({"error": "empty payload"}, indent=2)
    result = director.write_memory_atomic(
        address=address,
        data=payload,
        resume=resume,
    )
    return json.dumps(result, indent=2)


# =============================================================================
# Tool Definitions
# =============================================================================


LLDB_ADD_MODULE = Tool(
    name="lldb_add_module",
    description=(
        "Add a module (executable, kernel, or kext) and optional dSYM to the "
        "current target. Required for symbol resolution when debugging a "
        "stripped release kernel — after this, name-based breakpoints work. "
        "Supply slide OR load_addr if lldb cannot infer placement."
    ),
    parameters=[
        ToolParameter(
            name="path",
            type="string",
            description="Path to the module (e.g. KDK kernel.release.vmapple)",
        ),
        ToolParameter(
            name="dsym",
            type="string",
            description="Optional path to a companion dSYM bundle",
            required=False,
        ),
        ToolParameter(
            name="slide",
            type="integer",
            description="Optional constant slide applied via `target modules load --slide`",
            required=False,
        ),
        ToolParameter(
            name="load_addr",
            type="integer",
            description="Optional explicit load address for __TEXT",
            required=False,
        ),
    ],
    handler=_lldb_add_module_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_SLIDE = Tool(
    name="lldb_slide",
    description=(
        "Return the runtime slide (load_addr - link_addr) for a loaded module. "
        "Use this to convert static disassembly addresses into runtime "
        "addresses for breakpoints and memory reads."
    ),
    parameters=[
        ToolParameter(
            name="module",
            type="string",
            description=(
                "Module basename or full path. Omit for the main/first "
                "image (usually the kernel in a gdb-remote session)."
            ),
            required=False,
        ),
    ],
    handler=_lldb_slide_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_LOAD_XNU_MACROS = Tool(
    name="lldb_load_xnu_macros",
    description=(
        "Import Apple's xnu lldbmacros so kernel inspection commands like "
        "`zprint`, `showallkmods`, `paniclog`, `whatis`, `pmap_walk` are "
        "available via lldb_execute. Auto-detects common locations when path "
        "is omitted (ALF_XNU_LLDBMACROS env, ~/src/xnu/..., KDK dSYM)."
    ),
    parameters=[
        ToolParameter(
            name="path",
            type="string",
            description=(
                "Path to the lldbmacros directory or directly to xnu.py. "
                "Optional — auto-detects if omitted."
            ),
            required=False,
        ),
    ],
    handler=_lldb_load_xnu_macros_handler,
    category="lldb",
    requires_lock=True,
)


LLDB_WRITE_MEMORY = Tool(
    name="lldb_write_memory",
    description=(
        "Write bytes to target memory. With resume=True this is an atomic "
        "interrupt → write → continue sequence — the kernel-debug pattern "
        "that keeps a running guest's network jitter to a single pause. Use "
        "resume=False when already stopped at a breakpoint."
    ),
    parameters=[
        ToolParameter(
            name="address",
            type="string",
            description=(
                "Destination address. Accepts numeric (0x...) or symbolic "
                "expressions (_smbfs_loglevel, $x0+0x10)."
            ),
        ),
        ToolParameter(
            name="data",
            type="string",
            description="Payload to write, interpreted per `encoding`",
        ),
        ToolParameter(
            name="encoding",
            type="string",
            description="Data encoding: 'hex' (default), 'ascii', or 'base64'",
            required=False,
            default="hex",
            enum=["hex", "ascii", "base64"],
        ),
        ToolParameter(
            name="resume",
            type="boolean",
            description=(
                "When True (default), interrupt a running target, write, "
                "then continue. When False, require the target to already "
                "be stopped."
            ),
            required=False,
            default=True,
        ),
    ],
    handler=_lldb_write_memory_handler,
    category="lldb",
    requires_lock=True,
)


KERNEL_TOOLS = [
    LLDB_ADD_MODULE,
    LLDB_SLIDE,
    LLDB_LOAD_XNU_MACROS,
    LLDB_WRITE_MEMORY,
]

__all__ = [
    "LLDB_ADD_MODULE",
    "LLDB_SLIDE",
    "LLDB_LOAD_XNU_MACROS",
    "LLDB_WRITE_MEMORY",
    "KERNEL_TOOLS",
]
