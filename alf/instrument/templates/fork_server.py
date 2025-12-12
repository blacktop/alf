"""
SBAPI fork-server templates.

This is a Phase-2 performance primitive for one-shot targets.
"""

from __future__ import annotations

FORK_SERVER_TEMPLATE = r'''
import lldb
import json
import os

# TODO(phase2): fork() on macOS is fragile for complex apps (Mach ports/XPC).
# This primitive is best-effort for simple harnesses and one-shot tools.

TELEMETRY_PIPE = "{telemetry_pipe}"
_telemetry_fd = None


def _emit(payload: str) -> None:
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


def {name}(frame, bp_loc, internal_dict):  # noqa: ANN001
    """
    Fork-server breakpoint callback.

    Parent stays in this callback forever, spawning children.
    Child returns False and runs the target normally.
    """
    if internal_dict.get("alf_fork_child"):
        return False

    internal_dict["alf_fork_server"] = True

    while True:
        pid_val = frame.EvaluateExpression("(int)fork()")
        try:
            pid = int(pid_val.GetValueAsUnsigned())
        except Exception:
            _emit(json.dumps(dict(event="fork_error", error="fork eval failed")))
            return False

        if pid == 0:
            # Child path: continue into target.
            internal_dict["alf_fork_child"] = True
            return False

        # Parent: wait for child to exit/crash inside target.
        frame.EvaluateExpression("(int)waitpid(%d, 0, 0)" % pid)
        try:
            _emit(json.dumps(dict(event="child_exit", pid=int(pid))))
        except Exception:
            pass

    # Unreachable for parent.
    return False
'''
