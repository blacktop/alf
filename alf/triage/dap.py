#!/usr/bin/env python3
"""
Minimal LLDB Debug Adapter Protocol client.
Connects to lldb-dap, launches the target, waits for the crash stop,
and captures stack frames, scopes, registers, and output events into JSON.
"""

from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass, field
from typing import Any


class DAPError(RuntimeError):
    """Raised on protocol-level failures."""


@dataclass
class DAPSession:
    host: str
    port: int
    timeout: float
    sock: socket.socket = field(init=False)
    _buffer: bytes = field(default=b"", init=False)
    _seq: int = field(default=1, init=False)
    _event_queue: list[dict[str, Any]] = field(default_factory=list, init=False)
    transcript: list[dict[str, Any]] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        last_err: Exception | None = None
        for _ in range(40):
            try:
                self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                self.sock.settimeout(self.timeout)
                return
            except Exception as err:  # noqa: BLE001
                last_err = err
                time.sleep(0.25)
        raise ConnectionError(f"failed to connect to {self.host}:{self.port}") from last_err

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:  # noqa: BLE001
            pass

    @property
    def is_alive(self) -> bool:
        """Check if the socket connection is still alive."""
        try:
            # Use select with timeout 0 to check socket state without blocking
            import select

            readable, _, errored = select.select([self.sock], [], [self.sock], 0)
            if errored:
                return False
            if readable:
                # Socket is readable - either has data or is closed
                # Peek to check if it's closed (0 bytes = closed)
                data = self.sock.recv(1, socket.MSG_PEEK)
                return len(data) > 0
            return True  # Not readable, not errored = still connected
        except Exception:  # noqa: BLE001
            return False

    def _send_message(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self.sock.sendall(header + body)
        self.transcript.append({"direction": "out", "payload": payload})

    def _recv_once(self) -> dict[str, Any]:
        while True:
            header_end = self._buffer.find(b"\r\n\r\n")
            if header_end == -1:
                try:
                    chunk = self.sock.recv(4096)
                except TimeoutError as err:
                    raise TimeoutError("timed out waiting for DAP header") from err
                if not chunk:
                    raise ConnectionError("DAP socket closed unexpectedly")
                self._buffer += chunk
                continue
            header = self._buffer[:header_end].decode("ascii")
            rest = self._buffer[header_end + 4 :]
            length = None
            for line in header.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":")[1].strip())
                    break
            if length is None:
                raise DAPError(f"missing Content-Length header: {header!r}")
            while len(rest) < length:
                try:
                    chunk = self.sock.recv(4096)
                except TimeoutError as err:
                    raise TimeoutError("timed out waiting for DAP payload") from err
                if not chunk:
                    raise ConnectionError("DAP socket closed mid-packet")
                rest += chunk
            body, self._buffer = rest[:length], rest[length:]
            message = json.loads(body.decode("utf-8"))
            self.transcript.append({"direction": "in", "payload": message})
            return message

    def request(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        seq = self._seq
        self._seq += 1
        payload: dict[str, Any] = {"seq": seq, "type": "request", "command": command}
        if arguments is not None:
            payload["arguments"] = arguments
        self._send_message(payload)

        while True:
            try:
                message = self._recv_once()
            except TimeoutError as err:
                raise DAPError(f"{command} timed out waiting for response") from err
            if (
                message.get("type") == "response"
                and message.get("command") == command
                and message.get("request_seq") == seq
            ):
                if not message.get("success", True):
                    raise DAPError(f"{command} failed: {message.get('message')}")
                return message
            self._event_queue.append(message)

    def wait_for_event(self, name: str, timeout: float | None = None) -> dict[str, Any]:
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        while True:
            for idx, message in enumerate(self._event_queue):
                if message.get("type") == "event" and message.get("event") == name:
                    return self._event_queue.pop(idx)
            if time.time() > deadline:
                raise TimeoutError(f"timed out waiting for event '{name}'")
            try:
                message = self._recv_once()
            except TimeoutError as err:
                raise TimeoutError(f"timed out waiting for event '{name}'") from err
            if message.get("type") == "event" and message.get("event") == name:
                return message
            self._event_queue.append(message)

    def wait_for_events(self, names: list[str], timeout: float | None = None) -> dict[str, Any]:
        """Wait for any of the specified events.

        Returns the first matching event found.
        """
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        while True:
            # Check queue for any matching event
            for idx, message in enumerate(self._event_queue):
                if message.get("type") == "event" and message.get("event") in names:
                    return self._event_queue.pop(idx)
            if time.time() > deadline:
                raise TimeoutError(f"timed out waiting for events {names}")
            try:
                message = self._recv_once()
            except TimeoutError as err:
                raise TimeoutError(f"timed out waiting for events {names}") from err
            if message.get("type") == "event" and message.get("event") in names:
                return message
            self._event_queue.append(message)

    def drain_events(self) -> list[dict[str, Any]]:
        events = self._event_queue[:]
        self._event_queue.clear()
        return events


def collect_triage(session: DAPSession, args: argparse.Namespace) -> dict[str, Any]:
    log: dict[str, Any] = {
        "metadata": {
            "tag": args.tag,
            "binary": args.bin,
            "crash_input": args.crash,
            "host": args.host,
            "port": args.port,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        },
        "events": [],
        "responses": {},
        "details": {},
        "transcript": session.transcript,
    }

    capabilities = session.request(
        "initialize",
        {
            "clientID": "alf",
            "adapterID": "lldb",
            "pathFormat": "path",
            "linesStartAt1": True,
            "columnsStartAt1": True,
        },
    )
    log["responses"]["initialize"] = capabilities

    # lldb-dap commonly sends the `initialized` event *after* launch.
    launch_resp = session.request(
        "launch",
        {
            "program": args.bin,
            "args": ["-runs=1", args.crash],
            "stopOnEntry": False,
        },
    )
    log["responses"]["launch"] = launch_resp

    # Wait briefly for `initialized` (some adapters send it earlier, some later).
    try:
        initialized_event = session.wait_for_event("initialized", timeout=min(2.0, float(args.timeout)))
        log["events"].append(initialized_event)
    except TimeoutError:
        initialized_event = None

    try:
        configuration_done = session.request("configurationDone")
        log["responses"]["configurationDone"] = configuration_done
    except DAPError as e:
        log["responses"]["configurationDone"] = {"error": str(e)}

    # resume immediately; if already running this is harmless
    try:
        continue_resp = session.request("continue", {"threadId": 0})
        log["responses"]["continue"] = continue_resp
    except DAPError:
        pass

    stopped_event = session.wait_for_event("stopped", timeout=args.timeout)
    log["events"].append(stopped_event)

    thread_id = stopped_event.get("body", {}).get("threadId")
    if thread_id is None:
        raise DAPError("stopped event did not include threadId")

    stack_resp = session.request("stackTrace", {"threadId": thread_id, "levels": args.stack_levels})
    log["responses"]["stackTrace"] = stack_resp

    frames = stack_resp.get("body", {}).get("stackFrames", [])
    registers: dict[str, Any] = {}
    locals_dump: dict[str, Any] = {}
    scopes_dump: list[dict[str, Any]] = []

    if frames:
        frame_id = frames[0]["id"]
        scopes_resp = session.request("scopes", {"frameId": frame_id})
        log["responses"]["scopes"] = scopes_resp
        scopes = scopes_resp.get("body", {}).get("scopes", [])
        scopes_dump = scopes
        for scope in scopes:
            scope_name = scope.get("name", "")
            ref = scope.get("variablesReference")
            if not ref:
                continue
            variables_resp = session.request("variables", {"variablesReference": ref})
            data = variables_resp.get("body", {}).get("variables", [])
            if scope.get("presentationHint") == "registers" or scope_name.lower() == "registers":
                registers = data
            else:
                locals_dump[scope_name] = data
        try:
            eval_resp = session.request(
                "evaluate",
                {"expression": "memory read -fx -s1 $sp 256", "context": "repl", "frameId": frame_id},
            )
            log["responses"]["stackBytes"] = eval_resp
        except DAPError:
            pass

    log["details"]["registers"] = registers
    log["details"]["locals"] = locals_dump
    log["details"]["scopes"] = scopes_dump
    log["events"].extend(session.drain_events())

    try:
        session.request("disconnect", {"terminateDebuggee": False})
    except DAPError:
        pass

    return log


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect crash triage data via lldb-dap.")
    parser.add_argument("--host", required=True, help="lldb-dap host (usually 127.0.0.1)")
    parser.add_argument("--port", type=int, required=True, help="lldb-dap port")
    parser.add_argument("--bin", required=True, help="Absolute path to fuzz binary")
    parser.add_argument("--crash", required=True, help="Absolute path to crashing input")
    parser.add_argument("--log", required=True, help="Output JSON log path")
    parser.add_argument("--tag", default="triage", help="Tag used for metadata")
    parser.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait for key events")
    parser.add_argument("--stack-levels", type=int, default=32, help="Max stack frames to capture")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    session = DAPSession(host=args.host, port=args.port, timeout=args.timeout)
    try:
        log = collect_triage(session, args)
    finally:
        session.close()

    with open(args.log, "w", encoding="utf-8") as fp:
        json.dump(log, fp, indent=2)
        fp.write("\n")

    print(f"[+] DAP triage saved to {args.log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
