"""
LLDB DAP state machine and low-level debugger helpers.

All `lldb_*` MCP tools should be thin wrappers around this module.

This module uses the DAPBackend abstraction internally, allowing future
backends (native MCP, remote) to be substituted without changing tool code.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from ..backend import LLDBBackend
from ..backend.factory import get_backend
from ..triage.dap import DAPSession
from .runtime.memory import strip_pac, try_parse_address
from .telemetry import TelemetrySession

logger = logging.getLogger(__name__)


class LLDBDirector:
    """Stateful LLDB controller backed by lldb-dap.

    Uses DAPBackend internally for low-level debugger operations while
    providing high-level MCP tool interface and state management.
    """

    def __init__(
        self,
        dap_host: str,
        dap_port: int,
        timeout: float = 30.0,
        backend: LLDBBackend | None = None,
    ):
        self.dap_host = dap_host
        self.dap_port = dap_port
        self.timeout = timeout

        # Use provided backend or fallback to DAP
        if backend:
            self._backend = backend
        else:
            self._backend = get_backend("dap", host=dap_host, port=dap_port, timeout=timeout)

        # State tracking (sync with backend)
        self.thread_id: int | None = None
        self.frame_id: int | None = None
        self.breakpoints: list[str] = []
        self.last_launch: dict[str, Any] = {}
        self._lock = threading.Lock()

        # High-level session state
        self.last_triage: dict[str, str] = {}
        self.telemetry_sessions: dict[str, TelemetrySession] = {}
        self.last_stop_event: dict[str, Any] | None = None
        self.seen_crash_hashes: set[str] = set()
        self.pending_crashes: list[dict[str, Any]] = []

    @property
    def connected(self) -> bool:
        """Check if backend is connected."""
        return self._backend.connected

    @property
    def dap_session(self) -> DAPSession | None:
        """Access raw DAP session for operations not yet in backend abstraction.

        WARNING: This breaks the backend abstraction. Prefer adding methods to LLDBBackend.
        """
        return getattr(self._backend, "_session", None)

    def connect_dap(self) -> None:
        """Connect to lldb-dap via the backend."""
        if not self._backend.connected:
            logger.info("Connecting to debugger backend")
            self._backend.connect()

    def _refresh_frame(self) -> None:
        if not self._backend.connected or not self.thread_id:
            return
        try:
            frames = self._backend.get_backtrace(thread_id=self.thread_id, max_frames=1)
            if frames:
                self.frame_id = frames[0].id
        except Exception:  # noqa: BLE001
            pass

    def _wait_for_stopped(self, timeout: float | None = None) -> dict[str, Any] | None:
        if not self._backend.connected:
            return None
        session = self.dap_session
        if session is None:
            return None
        try:
            stopped_event = session.wait_for_event(
                "stopped", timeout=timeout if timeout is not None else self.timeout
            )
        except TimeoutError:
            return None
        self.thread_id = stopped_event.get("body", {}).get("threadId", self.thread_id)
        self._refresh_frame()
        self._record_stop_event(stopped_event)
        return stopped_event

    def _is_crash_reason(self, reason: str) -> bool:
        return self._backend.is_crash_reason(reason)

    def _compute_stack_hash(self, max_frames: int = 5) -> dict[str, Any]:
        if not self._backend.connected:
            return {"stack_hash": "", "pcs": []}

        h, pcs = self._backend.compute_stack_hash(max_frames)
        return {"stack_hash": h, "pcs": pcs}

    def _record_stop_event(self, stopped_event: dict[str, Any]) -> None:
        self.last_stop_event = stopped_event
        reason = str(stopped_event.get("body", {}).get("reason", "") or "")
        if not self._is_crash_reason(reason):
            return

        info = self._compute_stack_hash(max_frames=5)
        stack_hash = str(info.get("stack_hash") or "")
        if stack_hash and stack_hash in self.seen_crash_hashes:
            return
        if stack_hash:
            self.seen_crash_hashes.add(stack_hash)

        crash_entry: dict[str, Any] = {
            "ts": time.time(),
            "reason": reason,
            "thread_id": self.thread_id,
            "frame_id": self.frame_id,
            "stack_hash": stack_hash,
            "pcs": info.get("pcs", []),
            "stop_body": stopped_event.get("body", {}) or {},
        }
        self.pending_crashes.append(crash_entry)
        if len(self.pending_crashes) > 200:
            self.pending_crashes = self.pending_crashes[-200:]

    def _sync_from_backend(self) -> None:
        """Sync state from backend to director after backend operations."""
        self.thread_id = self._backend.thread_id
        self.frame_id = self._backend.frame_id
        self.breakpoints = list(self._backend.breakpoints)
        stop_event = getattr(self._backend, "last_stop_event", None)
        if stop_event is not None:
            # Mirror the DAP "stopped" event shape used by existing tools.
            self.last_stop_event = {
                "body": {
                    "reason": getattr(stop_event, "reason", None),
                    "threadId": getattr(stop_event, "thread_id", None),
                    "description": getattr(stop_event, "description", None),
                    "allThreadsStopped": getattr(stop_event, "all_threads_stopped", False),
                }
            }

    def _record_stop_from_backend(self) -> None:
        """Record crash info from backend's last_stop_event if it's a crash."""
        stop_event = self._backend.last_stop_event
        if not stop_event:
            return

        reason = stop_event.reason
        if not self._is_crash_reason(reason):
            return

        # Build stop event dict for existing _record_stop_event
        stopped_event = {
            "body": {
                "reason": reason,
                "threadId": stop_event.thread_id,
                "description": stop_event.description,
                "allThreadsStopped": stop_event.all_threads_stopped,
            }
        }
        self._record_stop_event(stopped_event)

    def pop_pending_crashes(self, limit: int = 5) -> list[dict[str, Any]]:
        if limit <= 0:
            out = list(self.pending_crashes)
            self.pending_crashes.clear()
            return out
        out = self.pending_crashes[:limit]
        self.pending_crashes = self.pending_crashes[limit:]
        return out

    def initialize_session(
        self,
        binary: str,
        crash_input: str,
        stop_on_entry: bool = False,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """Launch target with input and stop at entry or first exception.

        Delegates to DAPBackend.launch() for core DAP operations.
        """
        # Build args list - preserve crash input handling from original
        launch_args: list[str]
        if extra_args is None:
            launch_args = ["-runs=1", crash_input]
        else:
            # Preserve the crash input even when the caller provides custom args
            launch_args = list(extra_args)
            if crash_input and crash_input not in launch_args:
                launch_args.append(crash_input)

        # Delegate to backend
        result = self._backend.launch(
            binary=binary,
            args=launch_args,
            crash_input=crash_input,
            stop_on_entry=stop_on_entry,
        )

        # Sync state from backend
        self._sync_from_backend()
        self.last_launch = {"binary": binary, "crash_input": crash_input}

        # Record any crash stop events
        if result.status == "stopped" and result.reason:
            self._record_stop_from_backend()

        # Convert to dict for backward compatibility
        if result.status == "stopped":
            return {
                "status": "stopped",
                "thread_id": self.thread_id,
                "frame_id": self.frame_id,
                "reason": result.reason,
            }
        elif result.status == "exited":
            return {"status": "exited", "exitCode": result.exit_code}
        elif result.status == "terminated":
            return {"status": "terminated"}
        return {"status": "running"}

    def attach_session(
        self,
        pid: int,
        program: str | None = None,
        wait_for: bool = False,
    ) -> dict[str, Any]:
        """Attach to an already-running process by PID.

        Delegates to DAPBackend.attach() for core DAP operations.
        """
        result = self._backend.attach(pid=pid, program=program, wait_for=wait_for)

        # Sync state from backend
        self._sync_from_backend()
        self.last_launch = {"pid": int(pid), "program": program, "mode": "attach"}

        # Record any crash stop events
        if result.status == "stopped" and result.reason:
            self._record_stop_from_backend()

        # Convert to dict for backward compatibility
        if result.status == "stopped":
            return {
                "status": "stopped",
                "thread_id": self.thread_id,
                "frame_id": self.frame_id,
                "reason": result.reason,
            }
        elif result.status == "exited":
            return {"status": "exited", "exitCode": result.exit_code}
        elif result.status == "terminated":
            return {"status": "terminated"}
        return {"status": "running"}

    def load_core_session(self, core_path: str, program: str | None = None) -> dict[str, Any]:
        """Load a core file for post-mortem analysis.

        Delegates to DAPBackend.load_core() for core DAP operations.
        """
        result = self._backend.load_core(core_path=core_path, program=program)

        # Sync state from backend
        self._sync_from_backend()
        self.last_launch = {"core_file": core_path, "program": program, "mode": "core"}

        # Record any crash stop events
        if result.status == "stopped" and result.reason:
            self._record_stop_from_backend()

        # Convert to dict for backward compatibility
        if result.status == "stopped":
            return {
                "status": "stopped",
                "thread_id": self.thread_id,
                "frame_id": self.frame_id,
                "reason": result.reason,
            }
        return {"status": "running"}

    def list_threads(self) -> dict[str, Any]:
        """List threads in the current target, delegating to DAPBackend."""
        if not self._backend.connected:
            return {"error": "No active DAP session"}
        try:
            threads = self._backend.get_threads()
            out = [{"id": t.id, "name": t.name} for t in threads]
            return {"threads": out, "selected_thread_id": self.thread_id}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def select_thread(self, thread_id: int) -> dict[str, Any]:
        """Select a thread for subsequent stack/evaluate operations."""
        if not self._backend.connected:
            return {"error": "No active session"}
        self.thread_id = int(thread_id)
        self._refresh_frame()
        return {"selected_thread_id": self.thread_id, "frame_id": self.frame_id}

    def select_frame(self, frame_index: int = 0, thread_id: int | None = None) -> dict[str, Any]:
        """Select a specific stack frame index for subsequent evaluate operations."""
        if not self._backend.connected:
            return {"error": "No active session"}
        tid = int(thread_id) if thread_id is not None else self.thread_id
        if not tid:
            return {"error": "No active thread. Call lldb_launch/attach first."}
        try:
            idx = max(0, int(frame_index))
            frames = self._backend.get_backtrace(thread_id=tid, max_frames=max(1, idx + 1))
            if not frames:
                return {"error": "No stack frames available"}
            if idx >= len(frames):
                return {"error": f"frame_index out of range (have {len(frames)})"}
            frame = frames[idx]
            self.thread_id = tid
            self.frame_id = frame.id
            selected_frame = {
                "id": frame.id,
                "name": frame.name,
                "line": frame.line,
                "column": frame.column,
                "source": {"path": frame.source_path} if frame.source_path else None,
                "instructionPointerReference": frame.instruction_pointer,
                "moduleId": frame.module_name,
            }
            return {
                "selected_thread_id": self.thread_id,
                "frame_id": self.frame_id,
                "frame": selected_frame,
            }
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def get_backtrace(self, thread_id: int | None = None, count: int = 32) -> list[Any]:
        """Get stack backtrace from backend."""
        if not self._backend.connected:
            return []
        return self._backend.get_backtrace(thread_id=thread_id, max_frames=count)

    def evaluate(self, expression: str, frame_id: int | None = None) -> Any:
        """Evaluate expression via backend."""
        if not self._backend.connected:
            return "Error: No active session"
        return self._backend.evaluate(expression, frame_id=frame_id)

    def execute_lldb_command(self, command: str) -> str:
        if not self._backend.connected:
            return "Error: Session ended - the debug session has terminated. Analyze the data you already collected."
        return self._backend.execute_command(command)

    def continue_exec(
        self,
        thread_id: int | None = None,
        wait: bool = True,
        timeout: float | None = None,
    ) -> str:
        """Continue execution, delegating to DAPBackend."""
        if not self._backend.connected:
            return "Error: Session ended - the debug session has terminated. Analyze the data you already collected."

        try:
            stop_event = self._backend.continue_execution(
                thread_id=thread_id,
                wait=wait,
                timeout=timeout if timeout is not None else self.timeout,
            )
        except RuntimeError as e:
            return str(e)

        # Sync state from backend
        self._sync_from_backend()

        if not wait:
            return json.dumps({"status": "continued"}, indent=2)

        if not stop_event:
            return json.dumps({"status": "running"}, indent=2)

        # Record crash if applicable
        if stop_event.reason:
            self._record_stop_from_backend()

        return json.dumps(
            {
                "status": "stopped",
                "thread_id": self.thread_id,
                "frame_id": self.frame_id,
                "reason": stop_event.reason,
            },
            indent=2,
        )

    def set_breakpoint(
        self,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        condition: str | None = None,
    ) -> str:
        if not function and not address and not (file and line):
            return "Error: provide function, address, or file+line"
        parts = ["breakpoint set"]
        if function:
            parts += ["--name", function]
        if address:
            parts += ["--address", address]
        if file and line:
            parts += ["--file", file, "--line", str(line)]
        if condition:
            parts += ["--condition", condition]
        cmd = " ".join(parts)
        out = self.execute_lldb_command(cmd)
        self.breakpoints.append(cmd)
        return out

    def register_read(self, register: str | None = None) -> str:
        cmd = "register read" if not register else f"register read {register}"
        return self.execute_lldb_command(cmd)

    def register_write(self, register: str, value: str) -> str:
        return self.execute_lldb_command(f"register write {register} {value}")

    def step(self, kind: str = "over", count: int = 1) -> str:
        """Step execution, delegating to DAPBackend."""
        if not self._backend.connected or not self.thread_id:
            return "Error: No active DAP session"

        kind = kind or "over"
        reasons: list[str] = []

        # Step one at a time to collect all reasons
        for _ in range(max(1, int(count or 1))):
            try:
                stop_event = self._backend.step(kind=kind, count=1, thread_id=self.thread_id)
            except RuntimeError as e:
                return str(e)

            if not stop_event:
                break
            reasons.append(stop_event.reason or "")

        # Sync state from backend
        self._sync_from_backend()

        # Record crash if applicable
        self._record_stop_from_backend()

        return json.dumps(
            {
                "status": "stopped",
                "thread_id": self.thread_id,
                "frame_id": self.frame_id,
                "reasons": reasons,
            },
            indent=2,
        )

    def inject_script(self, script: str, name: str | None = None, command: str | None = None) -> str:
        base = (name or "alf_script").replace(" ", "_")
        logs_dir = Path.cwd() / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        script_path = logs_dir / f"{base}_{ts}.py"
        script_path.write_text(script, encoding="utf-8")
        import_out = self.execute_lldb_command(f"command script import {script_path}")
        cmd_out = self.execute_lldb_command(command) if command else None
        return json.dumps(
            {
                "script_path": str(script_path),
                "import_output": import_out,
                "command_output": cmd_out,
            },
            indent=2,
        )

    def status(self) -> dict[str, Any]:
        return {
            "binary": self.last_launch.get("binary"),
            "crash_input": self.last_launch.get("crash_input"),
            "thread_id": self.thread_id,
            "frame_id": self.frame_id,
            "breakpoints": self.breakpoints,
        }

    def source_window(self) -> str:
        if not self._backend.connected:
            return "Error: No active session"
        try:
            frames = self._backend.get_backtrace(max_frames=1)
            if not frames:
                return "No stack frames available"
            frame = frames[0]
            path = frame.source_path
            line = int(frame.line or 0)
            if path and os.path.exists(path):
                src_lines = Path(path).read_text(errors="replace").splitlines()
                start = max(0, line - 6)
                end = min(len(src_lines), line + 5)
                window = []
                for idx in range(start, end):
                    window.append(f"{idx + 1:6d}: {src_lines[idx]}")
                return "\n".join(window)
            return self.execute_lldb_command("frame info")
        except Exception as e:  # noqa: BLE001
            return f"Error loading source: {e}"

    def evaluate_address(self, expr: str) -> int | None:
        """Evaluate expr to an integer address, stripping PAC if needed."""
        out = self.execute_lldb_command(f"expression -O -- (uintptr_t)({expr})")
        addr = try_parse_address(out)
        if addr is None:
            return None
        return strip_pac(addr)

    def memory_search(self, pattern: str, start_address: str, size: int = 4096, chunk_size: int = 4096) -> str:
        """
        Search process memory for a pattern starting at an address.

        `pattern` may be:
          - a hex string (e.g. "0x414243", "41 42 43", "414243")
          - a plain ASCII string (e.g. "FUZZ_MARKER")

        Returns JSON with address/offset if found, or "Not found".
        """
        if not self._backend.connected:
            return "Error: No active DAP session"

        base_addr = self.evaluate_address(start_address)
        if base_addr is None:
            return f"Error: could not parse start_address '{start_address}'"

        pat_bytes = self._parse_pattern(pattern)
        if pat_bytes is None or not pat_bytes:
            return f"Error: invalid pattern '{pattern}'"

        remaining = max(0, int(size))
        if remaining == 0:
            return "Not found"

        chunk_size = max(256, int(chunk_size))
        scanned = 0
        tail = b""

        while scanned < remaining:
            read_len = min(chunk_size, remaining - scanned)
            addr = base_addr + scanned
            chunk, err = self._read_memory_bytes(addr, read_len)
            if chunk is None:
                return f"Error: read failed at offset {scanned}: {err}"

            data = tail + chunk
            idx = data.find(pat_bytes)
            if idx != -1:
                found_offset = scanned - len(tail) + idx
                found_addr = base_addr + found_offset
                return json.dumps(
                    {
                        "found": True,
                        "address": f"0x{found_addr:x}",
                        "offset": found_offset,
                        "pattern": pattern,
                    },
                    indent=2,
                )

            if len(pat_bytes) > 1:
                tail = data[-(len(pat_bytes) - 1) :]
            else:
                tail = b""

            scanned += read_len

        return "Not found"

    def _parse_pattern(self, pattern: str) -> bytes | None:
        """Parse pattern as hex or ASCII.

        Hex formats (interpreted as bytes):
          - "0x414243" or "0x41 42 43" → b'ABC'
          - "41 42 43" or "41:42:43" (space/colon separated pairs) → b'ABC'
          - "414243" (all hex digits, even length, no letters g-z) → b'ABC'

        Otherwise treated as UTF-8 ASCII string.
        """
        pat = (pattern or "").strip()
        if not pat:
            return None

        # Check for explicit hex prefix
        if pat.lower().startswith("0x"):
            hex_str = pat[2:].replace(" ", "").replace(":", "")
            if re.fullmatch(r"[0-9a-fA-F]+", hex_str) and len(hex_str) % 2 == 0:
                try:
                    return bytes.fromhex(hex_str)
                except ValueError:
                    pass

        # Check for space/colon-separated hex pairs like "41 42 43" or "41:42:43"
        if re.fullmatch(r"[0-9a-fA-F]{2}([ :][0-9a-fA-F]{2})+", pat):
            hex_str = pat.replace(" ", "").replace(":", "")
            try:
                return bytes.fromhex(hex_str)
            except ValueError:
                pass

        # Check for pure hex string (only 0-9, a-f, no g-z letters that indicate ASCII)
        if re.fullmatch(r"[0-9a-fA-F]+", pat) and len(pat) % 2 == 0:
            # Only treat as hex if it doesn't look like ASCII text
            # (ASCII text usually has letters beyond a-f)
            has_non_hex_letters = bool(re.search(r"[g-zG-Z]", pattern))
            if not has_non_hex_letters:
                try:
                    return bytes.fromhex(pat)
                except ValueError:
                    pass

        # Default: treat as UTF-8 string
        return pat.encode("utf-8", errors="ignore")

    def _read_memory_bytes(self, address: int, count: int) -> tuple[bytes | None, str | None]:
        """Read raw bytes via backend. Returns (bytes, error)."""
        if not self._backend.connected:
            return None, "no session"
        try:
            return self._backend.read_memory(address, count), None
        except Exception as e:
            return None, str(e)
