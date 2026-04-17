"""Tests for DAP gdb-remote attach and kernel helpers.

Uses a scripted fake DAP server (pair of TCP sockets over threads) to verify
that `DAPBackend.attach_gdb_remote` issues the documented attach config keys
and that the attach-safe disconnect honors gdb-remote session kind.
"""

from __future__ import annotations

import json
import socket
import threading
from typing import Any

import pytest

from alf.backend.dap import DAPBackend


def _read_message(sock: socket.socket, buffer: bytearray) -> dict[str, Any]:
    """Read a single DAP message from `sock`, using `buffer` for carry-over."""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("socket closed mid-header")
        buffer.extend(chunk)
    header_end = buffer.index(b"\r\n\r\n")
    header = bytes(buffer[:header_end]).decode("ascii")
    rest = bytes(buffer[header_end + 4 :])
    length = 0
    for line in header.split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
            break
    while len(rest) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("socket closed mid-payload")
        rest += chunk
    body = rest[:length]
    buffer.clear()
    buffer.extend(rest[length:])
    return json.loads(body.decode("utf-8"))


def _send_message(sock: socket.socket, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    sock.sendall(header + body)


class FakeDAP:
    """Tiny scripted DAP server good enough for one attach handshake."""

    def __init__(self) -> None:
        self._server = socket.socket()
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(1)
        self.port = self._server.getsockname()[1]
        self.requests: list[dict[str, Any]] = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._advertise_write_memory = True

    def disable_write_memory(self) -> None:
        self._advertise_write_memory = False

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        client, _ = self._server.accept()
        client.settimeout(5.0)
        buffer = bytearray()
        seq = 100

        def respond(request: dict[str, Any], body: dict[str, Any] | None = None) -> None:
            nonlocal seq
            seq += 1
            resp = {
                "seq": seq,
                "type": "response",
                "request_seq": request["seq"],
                "command": request["command"],
                "success": True,
            }
            if body is not None:
                resp["body"] = body
            _send_message(client, resp)

        def event(name: str, body: dict[str, Any] | None = None) -> None:
            nonlocal seq
            seq += 1
            evt = {"seq": seq, "type": "event", "event": name}
            if body is not None:
                evt["body"] = body
            _send_message(client, evt)

        try:
            while True:
                try:
                    msg = _read_message(client, buffer)
                except Exception:
                    break
                self.requests.append(msg)
                cmd = msg.get("command")
                if cmd == "initialize":
                    caps = {
                        "supportsConfigurationDoneRequest": True,
                        "supportsWriteMemoryRequest": self._advertise_write_memory,
                    }
                    respond(msg, caps)
                elif cmd == "attach":
                    respond(msg)
                    event("initialized")
                elif cmd == "configurationDone":
                    respond(msg)
                    event(
                        "stopped",
                        {
                            "reason": "signal",
                            "threadId": 1,
                            "allThreadsStopped": True,
                            "description": "fake stop",
                        },
                    )
                elif cmd == "stackTrace":
                    respond(
                        msg,
                        {
                            "stackFrames": [
                                {
                                    "id": 0,
                                    "name": "fake",
                                    "instructionPointerReference": "0xffffff8000000000",
                                }
                            ],
                            "totalFrames": 1,
                        },
                    )
                elif cmd == "threads":
                    respond(msg, {"threads": [{"id": 1, "name": "Thread 1"}]})
                elif cmd == "disconnect":
                    respond(msg)
                    break
                else:
                    respond(msg)
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                self._server.close()
            except Exception:
                pass


@pytest.fixture
def fake_dap() -> FakeDAP:
    dap = FakeDAP()
    dap.start()
    try:
        yield dap
    finally:
        try:
            dap._server.close()
        except Exception:
            pass
        dap._thread.join(timeout=1.0)


def test_attach_gdb_remote_sends_documented_keys(fake_dap: FakeDAP) -> None:
    backend = DAPBackend(host="127.0.0.1", port=fake_dap.port, timeout=3.0)
    result = backend.attach_gdb_remote(
        host="127.0.0.1",
        port=8864,
        target="/tmp/fake-kernel",
        arch="arm64e",
        plugin="kdp-remote",
    )
    assert result.status == "stopped", result

    attach_requests = [r for r in fake_dap.requests if r.get("command") == "attach"]
    assert len(attach_requests) == 1
    args = attach_requests[0].get("arguments", {})
    # lldb-dap's attach schema uses `gdb-remote-hostname` (not `-host`).
    assert args.get("gdb-remote-hostname") == "127.0.0.1"
    assert args.get("gdb-remote-port") == 8864
    assert args.get("program") == "/tmp/fake-kernel"

    init_commands = args.get("initCommands", [])
    assert any("target.default-arch arm64e" in cmd for cmd in init_commands)
    assert any("kdp-remote" in cmd for cmd in init_commands)

    assert backend.last_launch.get("mode") == backend.SESSION_KIND_GDB_REMOTE
    assert backend.capabilities.get("supportsWriteMemoryRequest") is True


def test_disconnect_uses_detach_for_gdb_remote(fake_dap: FakeDAP) -> None:
    backend = DAPBackend(host="127.0.0.1", port=fake_dap.port, timeout=3.0)
    backend.attach_gdb_remote(host="127.0.0.1", port=8864, target=None)

    backend.disconnect()

    disconnect_requests = [r for r in fake_dap.requests if r.get("command") == "disconnect"]
    assert len(disconnect_requests) == 1
    assert disconnect_requests[0]["arguments"] == {"terminateDebuggee": False}


def test_connected_becomes_false_after_disconnect(fake_dap: FakeDAP) -> None:
    backend = DAPBackend(host="127.0.0.1", port=fake_dap.port, timeout=3.0)
    backend.attach_gdb_remote(host="127.0.0.1", port=8864, target=None)
    assert backend.connected
    backend.disconnect()
    # `connected` reads a torn-down session as False without raising.
    assert backend.connected is False


def _build_lldb_mcp_stub(mode: str) -> tuple[Any, list[str]]:
    """Construct a real `LLDBMCPBackend` with `_lldb_command` captured.

    `__init__` does not open a socket, so constructing the real class is
    cheap and gives us the genuine `should_terminate_debuggee` helper.
    """
    from alf.backend.lldb_mcp import LLDBMCPBackend

    backend = LLDBMCPBackend()
    backend._socket = object()  # truthy sentinel
    backend._initialized = True
    backend.last_launch = {"mode": mode}

    captured: list[str] = []

    def _capture(cmd: str) -> str:
        captured.append(cmd)
        return ""

    backend._lldb_command = _capture  # type: ignore[method-assign]
    return backend, captured


def test_lldb_mcp_attach_terminate_uses_detach() -> None:
    """Regression: attach → terminate on the lldb_mcp backend must detach."""
    from alf.backend.base import LLDBBackend

    backend, captured = _build_lldb_mcp_stub(LLDBBackend.SESSION_KIND_ATTACH)
    backend.disconnect()
    assert captured == ["process detach"]


def test_lldb_mcp_launch_terminate_kills() -> None:
    from alf.backend.base import LLDBBackend

    backend, captured = _build_lldb_mcp_stub(LLDBBackend.SESSION_KIND_LAUNCH)
    backend.disconnect()
    assert captured == ["process kill"]


def test_parse_image_list_detects_unresolved_slide() -> None:
    """When both columns match, lldb hasn't resolved a slide — return None."""
    backend = DAPBackend(host="127.0.0.1", port=1, timeout=1.0)
    raw = "[  0] 0x0000000100000000 0x0000000100000000 /bin/ls\n"
    entries = backend._parse_image_list(raw)
    assert len(entries) == 1
    assert entries[0]["slide"] is None
    assert entries[0]["load_addr"] == 0x100000000
    assert entries[0]["name"] == "ls"


def test_parse_image_list_picks_real_slide() -> None:
    """Distinct columns mean the second is the slide."""
    backend = DAPBackend(host="127.0.0.1", port=1, timeout=1.0)
    raw = (
        "[  0] 0xfffffe000a5e0000 0x00000000035dc000 "
        "/Library/Developer/KDKs/KDK.kdk/kernel.release.vmapple\n"
    )
    entries = backend._parse_image_list(raw)
    assert len(entries) == 1
    assert entries[0]["slide"] == 0x35DC000
    assert entries[0]["load_addr"] == 0xFFFFFE000A5E0000
