"""Director + bootstrap tests covering kernel-debug plumbing.

Exercises:
- Actionable no-session vs session-ended errors from `lldb_execute`.
- gdb_remote session orchestration and teardown semantics.
- Slide-aware breakpoints compute runtime addresses.
- Readiness probe surfaces meaningful detail on failure.
"""

from __future__ import annotations

import socket
import subprocess
import threading

import pytest

from alf.backend.mock import MockBackend
from alf.server.app import _wait_for_port
from alf.server.lldb import LLDBDirector
from alf.tools.definitions.lldb.session import _lldb_terminate_handler


@pytest.fixture
def director() -> LLDBDirector:
    mock = MockBackend()
    return LLDBDirector(dap_host="mock", dap_port=0, backend=mock)


def test_no_session_returns_actionable_error(director: LLDBDirector) -> None:
    out = director.execute_lldb_command("register read")
    assert out.startswith("Error: No active session")
    assert "lldb_gdb_remote" in out


def test_session_ended_after_disconnect(director: LLDBDirector) -> None:
    director.gdb_remote_session(host="127.0.0.1", port=8864, target=None)
    director._backend.disconnect()
    out = director.execute_lldb_command("register read")
    # last_launch is populated, backend disconnected — use the "session ended"
    # variant (which implies: analyze what you already collected).
    assert out.startswith("Error: Session ended")


def test_gdb_remote_session_mode(director: LLDBDirector) -> None:
    result = director.gdb_remote_session(
        host="127.0.0.1", port=8864, target="/tmp/kernel"
    )
    assert result["status"] == "stopped"
    assert director.last_launch["mode"] == director._backend.SESSION_KIND_GDB_REMOTE


def test_static_addr_uses_module_slide(director: LLDBDirector) -> None:
    director.gdb_remote_session(host="127.0.0.1", port=8864, target=None)
    # MockBackend returns slide=0x100000.
    out = director.set_breakpoint(
        static_addr="0xfffffe000a5ec4c8",
        module="kernel.release.vmapple",
    )
    assert "0xfffffe000a6ec4c8" in out


def test_terminate_detaches_gdb_remote_session(director: LLDBDirector) -> None:
    director.gdb_remote_session(host="127.0.0.1", port=8864, target=None)
    result = _lldb_terminate_handler(director)
    assert '"detached": true' in result
    assert '"mode": "gdb_remote"' in result


def test_terminate_after_launch_terminates(director: LLDBDirector) -> None:
    director.initialize_session(binary="/bin/echo", crash_input="/tmp/x")
    result = _lldb_terminate_handler(director)
    assert '"detached": false' in result
    assert '"mode": "launch"' in result


def test_readiness_probe_timeout_format() -> None:
    ready, detail = _wait_for_port(
        "127.0.0.1", port=1, budget_seconds=0.2, interval_seconds=0.05
    )
    assert ready is False
    assert "timed out" in detail


def test_readiness_probe_detects_exited_child() -> None:
    # Start and immediately exit a child process with stderr.
    proc = subprocess.Popen(
        ["sh", "-c", "echo boom >&2; exit 7"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Give it a moment to terminate.
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()

    ready, detail = _wait_for_port(
        "127.0.0.1", port=1, proc=proc, budget_seconds=0.5, interval_seconds=0.05
    )
    assert ready is False
    assert "exited with code 7" in detail
    assert "boom" in detail


def test_gdb_remote_error_leaves_director_pristine(director: LLDBDirector) -> None:
    """Failed gdb-remote attach must not leave director in a half-open state."""
    from alf.backend.base import LaunchResult

    director._backend.attach_gdb_remote = lambda **_kwargs: LaunchResult(  # type: ignore[method-assign]
        status="error",
        error="adapter rejected gdb-remote attach",
        hint="confirm the stub is listening",
    )
    disconnect_called = {"n": 0}
    orig_disconnect = director._backend.disconnect

    def _counting_disconnect() -> None:
        disconnect_called["n"] += 1
        orig_disconnect()

    director._backend.disconnect = _counting_disconnect  # type: ignore[method-assign]

    result = director.gdb_remote_session(host="127.0.0.1", port=8864)
    assert result["status"] == "error"
    assert result["error"] == "adapter rejected gdb-remote attach"
    assert disconnect_called["n"] == 1
    assert not director.last_launch
    out = director.execute_lldb_command("register read")
    assert out.startswith("Error: No active session")


def test_readiness_probe_success() -> None:
    # Bind to a random free port.
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    try:
        # Accept in a thread so the caller's create_connection succeeds.
        def _accept() -> None:
            try:
                s, _ = srv.accept()
                s.close()
            except Exception:
                pass

        t = threading.Thread(target=_accept, daemon=True)
        t.start()
        ready, detail = _wait_for_port(
            "127.0.0.1", port=port, budget_seconds=1.0, interval_seconds=0.05
        )
    finally:
        srv.close()

    assert ready is True
    assert "listening on" in detail
