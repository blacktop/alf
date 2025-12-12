"""
SBAPI stop-hook templates.

Templates are plain Python strings to avoid bringing in Jinja2 for Phase 2.
"""

from __future__ import annotations

STOP_HOOK_TEMPLATE = r'''
import lldb
import json
import os

from alf.mut import apply_random_mutation

# TODO(phase2): Pre-compile/inject this hook to avoid JIT/import overhead per run.

PAC_MASK = int(os.environ.get("ALF_PAC_MASK", "0x0000ffffffffffff"), 16)

PTR_REG = "{ptr_reg}"
LEN_REG = "{len_reg}"
MAX_SIZE = {max_size}
TELEMETRY_PIPE = "{telemetry_pipe}"

_telemetry_fd = None


def _emit_telemetry(payload: str) -> None:
    """Write telemetry to FIFO in non-blocking mode; drop on EAGAIN/EPIPE."""
    global _telemetry_fd  # noqa: PLW0603
    if not TELEMETRY_PIPE:
        return
    try:
        if _telemetry_fd is None:
            _telemetry_fd = os.open(TELEMETRY_PIPE, os.O_WRONLY | os.O_NONBLOCK)
        os.write(_telemetry_fd, payload.encode("utf-8") + b"\\n")
    except BlockingIOError:
        return
    except OSError:
        try:
            if _telemetry_fd is not None:
                os.close(_telemetry_fd)
        except Exception:
            pass
        _telemetry_fd = None


def _read_reg(frame, name: str) -> int | None:
    reg = frame.FindRegister(name)
    if reg and reg.IsValid():
        try:
            return int(reg.GetValueAsUnsigned())
        except Exception:
            return None
    return None


def {name}(frame, bp_loc, internal_dict):  # noqa: ANN001
    """
    LLDB breakpoint callback.
    Mutates in-process buffer and resumes execution.
    """
    thread = frame.GetThread()
    process = thread.GetProcess()

    ptr = _read_reg(frame, PTR_REG)
    if ptr is None:
        return False
    ptr = ptr & PAC_MASK

    size = MAX_SIZE
    if LEN_REG:
        ln = _read_reg(frame, LEN_REG)
        if ln is not None and ln > 0:
            size = min(int(ln), MAX_SIZE)

    if size <= 0:
        return False

    err = lldb.SBError()
    data = process.ReadMemory(ptr, size, err)
    if not err.Success() or data is None:
        return False

    res = apply_random_mutation(data)
    process.WriteMemory(ptr, bytes(res.data), err)

    # Best-effort telemetry (do not stall fuzzing on failure).
    try:
        _emit_telemetry(
            json.dumps(
                dict(
                    event="mutation",
                    ptr=hex(ptr),
                    size=int(size),
                    desc=res.description,
                )
            )
        )
    except Exception:
        pass
    return False
'''
