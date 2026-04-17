"""
DAP-based LLDB backend.

Implements the LLDBBackend interface using the Debug Adapter Protocol
to communicate with lldb-dap.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import shlex
import time
from typing import Any

from alf.utils.address import parse_address as _try_parse_address
from alf.utils.address import strip_pac as _strip_pac

from ..triage.dap import DAPError, DAPSession
from .base import (
    BreakpointResult,
    LaunchResult,
    LLDBBackend,
    StackFrame,
    StopEvent,
    ThreadInfo,
)

logger = logging.getLogger(__name__)


class DAPBackend(LLDBBackend):
    """LLDB backend using Debug Adapter Protocol (lldb-dap).

    This backend connects to lldb-dap over TCP and communicates using
    the standard Debug Adapter Protocol.

    Usage:
        backend = DAPBackend(host="127.0.0.1", port=12345)
        backend.connect()
        result = backend.launch("/path/to/binary", crash_input="/path/to/crash")
        print(f"Stopped: {result.status}")
    """

    # LLDB performance settings for faster crash triage
    # See: https://lldb.llvm.org/use/ondemand.html
    # See: PR #104874 for extended backtrace performance fix
    PERF_INIT_COMMANDS: list[str] = [
        "settings set symbols.load-on-demand true",  # 3.5x startup speedup
        "settings set symbols.enable-lldb-index-cache true",  # Cache symbols across sessions
        "settings set target.memory-module-load-level minimal",  # Minimal memory reads
    ]

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 12345,
        timeout: float = 30.0,
    ):
        """Initialize DAP backend.

        Args:
            host: lldb-dap host address.
            port: lldb-dap port.
            timeout: Default timeout for operations.
        """
        super().__init__(timeout=timeout)
        self.host = host
        self.port = port
        self._session: DAPSession | None = None

    @property
    def name(self) -> str:
        return "dap"

    @property
    def connected(self) -> bool:
        """Check if connected to lldb-dap and socket is still alive."""
        if self._session is None:
            return False
        if not self._session.is_alive:
            # Socket died - clean up the session reference
            self._session = None
            return False
        return True

    # =========================================================================
    # Connection Management
    # =========================================================================

    def connect(self) -> None:
        """Connect to lldb-dap."""
        if self._session is None:
            logger.info("Connecting to lldb-dap at %s:%s", self.host, self.port)
            self._session = DAPSession(host=self.host, port=self.port, timeout=self.timeout)

    def disconnect(self) -> None:
        """Disconnect from lldb-dap.

        Uses detach semantics (terminateDebuggee=False) for attach and
        gdb-remote sessions so a remote inferior keeps running after we
        disconnect. Launched sessions still terminate the child process.
        """
        if self._session:
            try:
                self._session.request(
                    "disconnect",
                    {"terminateDebuggee": self.should_terminate_debuggee()},
                )
            except Exception:
                pass
            self._session = None
            self.capabilities = {}

    def reset_target(self) -> bool:
        """Reset the current target without closing the DAP connection.

        This allows reusing the same lldb-dap session for multiple crashes,
        preserving symbol caches and avoiding process restart overhead.

        Returns:
            True if reset succeeded, False otherwise.
        """
        if not self._session:
            return False

        try:
            # Terminate the debuggee but keep the DAP session alive
            self._session.request("disconnect", {"terminateDebuggee": True, "restart": False})
        except Exception:
            pass

        # Reset internal state
        self.thread_id = None
        self.frame_id = None
        self.breakpoints = []
        self.last_launch = {}
        self.last_stop_event = None
        # Note: Keep seen_crash_hashes and pending_crashes for deduplication

        # Re-initialize the session for the next target
        try:
            self._handshake_initialize()
            return True
        except Exception as e:
            logger.warning("Failed to re-initialize DAP session: %s", e)
            return False

    # =========================================================================
    # Session Management
    # =========================================================================

    def _handshake_initialize(self) -> dict[str, Any]:
        """Send DAP `initialize` and cache advertised capabilities.

        Returns the response body (capabilities dict).
        """
        assert self._session is not None
        resp = self._session.request(
            "initialize",
            {
                "clientID": "lldb-mcp",
                "adapterID": "lldb",
                "pathFormat": "path",
                "linesStartAt1": True,
                "columnsStartAt1": True,
            },
        )
        caps = resp.get("body", {}) or {}
        if isinstance(caps, dict):
            self.capabilities = dict(caps)
        return self.capabilities

    def launch(
        self,
        binary: str,
        args: list[str] | None = None,
        crash_input: str | None = None,
        stop_on_entry: bool = False,
        env: dict[str, str] | None = None,
    ) -> LaunchResult:
        """Launch a binary under lldb-dap."""
        self.connect()
        assert self._session is not None

        self.last_launch = {
            "binary": binary,
            "crash_input": crash_input,
            "mode": self.SESSION_KIND_LAUNCH,
        }
        self.thread_id = None
        self.frame_id = None
        self.breakpoints = []

        self._handshake_initialize()

        # Build launch arguments
        launch_args: list[str] = []
        if args:
            launch_args.extend(args)
        else:
            launch_args.append("-runs=1")
        if crash_input:
            if crash_input not in launch_args:
                launch_args.append(crash_input)

        # Always use stopOnEntry=True to avoid lldb-dap race conditions with ASAN crashes.
        # We'll continue immediately after the entry stop to simulate stopOnEntry=False.
        launch_request: dict[str, Any] = {
            "program": binary,
            "args": launch_args,
            "stopOnEntry": True,  # Always stop on entry for reliable ASAN handling
            "initCommands": self.PERF_INIT_COMMANDS,
            "enableDisplayExtendedBacktrace": False,  # PR #104874 fix
        }
        if env:
            launch_request["env"] = env

        self._session.request("launch", launch_request)

        # Wait for initialized
        try:
            self._session.wait_for_event("initialized", timeout=min(2.0, self.timeout))
        except TimeoutError:
            pass

        # Set function breakpoints for ASAN/crash handling via DAP protocol
        # Note: DAP function breakpoints use simple symbol names, not mangled C++ names
        try:
            self._session.request(
                "setFunctionBreakpoints",
                {
                    "breakpoints": [
                        # System abort/exit (reliable fallback)
                        {"name": "abort"},
                        {"name": "_exit"},
                    ]
                },
            )
        except DAPError as e:
            logger.debug("setFunctionBreakpoints failed: %s", e)

        # Configuration done - this starts the program running
        try:
            self._session.request("configurationDone")
        except DAPError as e:
            logger.warning("configurationDone failed: %s", e)

        # Wait for entry stop
        entry_stop = self._wait_for_stopped(self.timeout)
        if not entry_stop:
            return LaunchResult(status="running")

        # Check if this is a real crash (not just SIGSTOP from stop-on-entry)
        # SIGSTOP is used for stop-on-entry, not a crash
        desc = (entry_stop.description or "").lower()
        is_entry_stop = "sigstop" in desc or entry_stop.reason == "step"

        # If the entry stop is actually a crash (e.g., immediate SIGABRT), return it
        if not is_entry_stop and self.is_crash_reason(entry_stop.reason):
            return LaunchResult(
                status="stopped",
                thread_id=self.thread_id,
                frame_id=self.frame_id,
                reason=entry_stop.reason,
            )

        # If user wanted stop_on_entry, return the entry stop
        if stop_on_entry:
            return LaunchResult(
                status="stopped",
                thread_id=self.thread_id,
                frame_id=self.frame_id,
                reason=entry_stop.reason,
            )

        # Otherwise, continue to let the program run to crash/exit
        try:
            self._session.request("continue", {"threadId": self.thread_id or 0})
        except DAPError:
            pass

        # Wait for crash or exit
        stop_event = self._wait_for_stopped(self.timeout)
        if stop_event:
            # Handle exited events (e.g., ASAN crash that exits before stop)
            if stop_event.reason == "exited":
                exit_code = stop_event.raw.get("body", {}).get("exitCode")
                return LaunchResult(
                    status="exited",
                    exit_code=exit_code,
                    reason="exited",
                )
            return LaunchResult(
                status="stopped",
                thread_id=self.thread_id,
                frame_id=self.frame_id,
                reason=stop_event.reason,
            )

        return LaunchResult(status="running")

    def attach(
        self,
        pid: int,
        program: str | None = None,
        wait_for: bool = False,
    ) -> LaunchResult:
        """Attach to a running process."""
        self.connect()
        assert self._session is not None

        self.last_launch = {
            "pid": int(pid),
            "program": program,
            "mode": self.SESSION_KIND_ATTACH,
        }
        self.thread_id = None
        self.frame_id = None
        self.breakpoints = []

        self._handshake_initialize()

        attach_args: dict[str, Any] = {
            "pid": int(pid),
            "initCommands": self.PERF_INIT_COMMANDS,
            "enableDisplayExtendedBacktrace": False,
        }
        if program:
            attach_args["program"] = str(program)
        if wait_for:
            attach_args["waitFor"] = True

        self._session.request("attach", attach_args)

        try:
            self._session.wait_for_event("initialized", timeout=min(2.0, self.timeout))
        except TimeoutError:
            pass

        try:
            self._session.request("configurationDone")
        except DAPError as e:
            logger.warning("configurationDone failed: %s", e)

        stop_event = self._wait_for_stopped(self.timeout)
        if stop_event:
            return LaunchResult(
                status="stopped",
                thread_id=self.thread_id,
                frame_id=self.frame_id,
                reason=stop_event.reason,
            )

        for event in self._session._event_queue:
            if event.get("event") == "exited":
                return LaunchResult(
                    status="exited",
                    exit_code=event.get("body", {}).get("exitCode"),
                )
            if event.get("event") == "terminated":
                return LaunchResult(status="terminated")

        return LaunchResult(status="running")

    def load_core(
        self,
        core_path: str,
        program: str | None = None,
    ) -> LaunchResult:
        """Load a core file for post-mortem analysis."""
        self.connect()
        assert self._session is not None

        self.last_launch = {
            "core_file": core_path,
            "program": program,
            "mode": self.SESSION_KIND_CORE,
        }
        self.thread_id = None
        self.frame_id = None
        self.breakpoints = []

        self._handshake_initialize()

        attach_args: dict[str, Any] = {
            "coreFile": str(core_path),
            "initCommands": self.PERF_INIT_COMMANDS,
            "enableDisplayExtendedBacktrace": False,
        }
        if program:
            attach_args["program"] = str(program)

        self._session.request("attach", attach_args)

        try:
            self._session.wait_for_event("initialized", timeout=min(2.0, self.timeout))
        except TimeoutError:
            pass

        try:
            self._session.request("configurationDone")
        except DAPError as e:
            logger.warning("configurationDone failed: %s", e)

        stop_event = self._wait_for_stopped(self.timeout)
        if stop_event:
            return LaunchResult(
                status="stopped",
                thread_id=self.thread_id,
                frame_id=self.frame_id,
                reason=stop_event.reason,
            )

        return LaunchResult(status="running")

    def attach_gdb_remote(
        self,
        host: str,
        port: int,
        target: str | None = None,
        arch: str | None = None,
        plugin: str | None = None,
    ) -> LaunchResult:
        """Attach to a gdb-remote stub via lldb-dap.

        Uses the adapter's `gdb-remote-hostname` / `gdb-remote-port` attach
        config (verified against Xcode-shipped and LLVM lldb-dap binaries).
        Surfaces the adapter error directly when the installed lldb-dap
        build does not recognize these keys.
        """
        self.connect()
        assert self._session is not None

        self.last_launch = {
            "host": host,
            "port": int(port),
            "program": target,
            "arch": arch,
            "plugin": plugin,
            "mode": self.SESSION_KIND_GDB_REMOTE,
        }
        self.thread_id = None
        self.frame_id = None
        self.breakpoints = []

        self._handshake_initialize()

        init_commands: list[str] = list(self.PERF_INIT_COMMANDS)
        if arch:
            init_commands.append(f"settings set target.default-arch {arch}")
        if plugin:
            init_commands.append(f"settings set plugin.process.gdb-remote.target {plugin}")

        attach_args: dict[str, Any] = {
            "gdb-remote-hostname": str(host),
            "gdb-remote-port": int(port),
            "initCommands": init_commands,
            "enableDisplayExtendedBacktrace": False,
        }
        if target:
            attach_args["program"] = str(target)

        try:
            self._session.request("attach", attach_args)
        except DAPError as e:
            return LaunchResult(
                status="error",
                error=str(e),
                hint=(
                    "lldb-dap rejected gdb-remote attach. Confirm the adapter "
                    "supports 'gdb-remote-hostname'/'gdb-remote-port' (Xcode 16 "
                    "command-line tools or recent LLVM) and that the stub is "
                    "listening on the requested port."
                ),
            )

        try:
            self._session.wait_for_event("initialized", timeout=min(2.0, self.timeout))
        except TimeoutError:
            pass

        try:
            self._session.request("configurationDone")
        except DAPError as e:
            logger.warning("configurationDone failed: %s", e)

        stop_event = self._wait_for_stopped(self.timeout)
        if stop_event:
            return LaunchResult(
                status="stopped",
                thread_id=self.thread_id,
                frame_id=self.frame_id,
                reason=stop_event.reason,
            )
        return LaunchResult(status="running")

    # =========================================================================
    # Kernel / remote helpers
    # =========================================================================

    # Matches `[ N ] 0x<load_addr> 0x<slide_or_file_addr> <path>` from
    # `image list -h -o -f`. lldb prints the file address in the second
    # column when no valid load address is available (no running process),
    # and the actual slide only when the process is live.
    _IMAGE_LIST_HO_RE = re.compile(
        r"^\s*\[\s*\d+\s*\]\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S.*)$"
    )

    def _parse_image_list(self, raw: str) -> list[dict[str, Any]]:
        """Parse `image list -h -o -f` output.

        Returns one dict per module with ``load_addr``, ``slide``, and
        ``path``. ``slide`` is populated only when lldb actually resolved
        one — when the second column differs from the first. When lldb
        cannot determine a slide (no running process, module unloaded)
        both columns hold the file address and ``slide`` is ``None`` so
        callers don't apply the link base as a slide.
        """
        results: list[dict[str, Any]] = []
        for line in raw.splitlines():
            m = self._IMAGE_LIST_HO_RE.match(line)
            if not m:
                continue
            load_addr = _try_parse_address(m.group(1))
            offset_col = _try_parse_address(m.group(2))
            path = m.group(3).strip()
            basename = os.path.basename(path)

            slide: int | None
            if (
                load_addr is not None
                and offset_col is not None
                and offset_col != load_addr
            ):
                slide = offset_col
            else:
                slide = None

            results.append(
                {
                    "load_addr": load_addr,
                    "slide": slide,
                    "path": path,
                    "name": basename,
                }
            )
        return results

    def add_module(
        self,
        path: str,
        dsym: str | None = None,
        slide: int | None = None,
        load_addr: int | None = None,
    ) -> dict[str, Any]:
        """Add a module (and optional dSYM) to the current target.

        Path and module-name arguments are shell-quoted so bundles like
        ``/Applications/My App.app/Contents/MacOS/My App`` load correctly.
        """
        if not self._session:
            raise RuntimeError("No active DAP session")

        outputs: list[str] = []
        quoted_path = shlex.quote(path)
        outputs.append(self.execute_command(f"target modules add {quoted_path}"))
        if dsym:
            outputs.append(
                self.execute_command(f"target symbols add {shlex.quote(dsym)}")
            )

        basename = os.path.basename(path)
        quoted_basename = shlex.quote(basename)
        if slide is not None:
            outputs.append(
                self.execute_command(
                    f"target modules load --file {quoted_basename} --slide {slide:#x}"
                )
            )
        elif load_addr is not None:
            # No explicit section: use __TEXT as the conventional default for
            # Mach-O kernels/kexts.
            outputs.append(
                self.execute_command(
                    f"target modules load --file {quoted_basename} __TEXT {load_addr:#x}"
                )
            )

        combined = "\n".join(out for out in outputs if out)
        loaded = "error" not in combined.lower()
        return {
            "module": basename,
            "path": path,
            "dsym": dsym,
            "loaded": loaded,
            "output": combined,
        }

    def get_module_slide(self, module: str | None = None) -> int | None:
        """Compute runtime ASLR/KASLR slide for a loaded module.

        Requires an attached or running target: if the module has no
        resolved load address (fresh target, not attached), the returned
        value is ``None`` rather than the file address — callers must not
        use the file address as a slide.

        When a module name is supplied, lldb filters server-side with a
        positional argument — important on kernel sessions where
        unfiltered output lists hundreds of kexts.
        """
        if not self._session:
            return None

        cmd = "image list -h -o -f"
        if module:
            cmd = f"image list -h -o -f {shlex.quote(module)}"

        raw = self.execute_command(cmd)
        entries = self._parse_image_list(raw)
        if not entries:
            return None

        picked = entries[0]
        if module:
            for entry in entries:
                if entry.get("name") == module or entry.get("path") == module:
                    picked = entry
                    break

        slide = picked.get("slide")
        return slide if isinstance(slide, int) else None

    def interrupt(self, timeout: float | None = None) -> StopEvent | None:
        """Pause the running target via DAP `pause`."""
        if not self._session:
            raise RuntimeError("No active DAP session")
        tid = self.thread_id or 0
        try:
            self._session.request("pause", {"threadId": tid})
        except DAPError as e:
            raise RuntimeError(f"pause failed: {e}") from e
        return self._wait_for_stopped(timeout)

    def write_memory(self, address: int | str, data: bytes) -> int:
        """Write bytes to target memory.

        Uses DAP `writeMemory` when the adapter advertises
        `supportsWriteMemoryRequest`; otherwise falls back to the
        REPL `memory write` command.
        """
        if not self._session:
            raise RuntimeError("No active DAP session")

        if isinstance(address, str):
            addr_int = _try_parse_address(address)
            if addr_int is None:
                # Let lldb resolve symbolic addresses via REPL fallback.
                addr_int = None
        else:
            addr_int = int(address)

        if self.capabilities.get("supportsWriteMemoryRequest") and addr_int is not None:
            payload = base64.b64encode(bytes(data)).decode("ascii")
            try:
                self._session.request(
                    "writeMemory",
                    {
                        "memoryReference": f"0x{addr_int:x}",
                        "data": payload,
                        "allowPartial": False,
                    },
                )
                return len(data)
            except DAPError as e:
                logger.debug("writeMemory request failed, falling back: %s", e)

        # REPL fallback — works for arbitrary address expressions too.
        hex_bytes = " ".join(f"0x{b:02x}" for b in data)
        if addr_int is not None:
            target_expr = f"0x{addr_int:x}"
        else:
            target_expr = str(address)
        out = self.execute_command(f"memory write {target_expr} {hex_bytes}")
        if "error" in out.lower():
            raise RuntimeError(f"memory write failed: {out.strip()}")
        return len(data)

    def is_running(self) -> bool:
        """Return True when the adapter reports the target is executing.

        Uses a fresh `process status` REPL query instead of sticky
        last_stop_event state — the latter gets set once at attach and
        stays until the next stop, which would mis-report a resumed
        target as still stopped.
        """
        if not self._session:
            return False
        try:
            status = self.execute_command("process status")
        except Exception:  # noqa: BLE001
            return False
        lowered = status.lower()
        if "stopped" in lowered or "exited" in lowered:
            return False
        if "running" in lowered:
            return True
        # Unknown state string — be conservative and assume stopped so the
        # caller does not attempt to interrupt something already halted.
        return False

    # =========================================================================
    # Execution Control
    # =========================================================================

    def continue_execution(
        self,
        thread_id: int | None = None,
        wait: bool = True,
        timeout: float | None = None,
    ) -> StopEvent | None:
        """Continue execution."""
        if not self._session:
            raise RuntimeError("No active DAP session")

        tid = thread_id if thread_id is not None else (self.thread_id or 0)
        try:
            self._session.request("continue", {"threadId": tid})
        except DAPError as e:
            raise RuntimeError(f"Continue failed: {e}") from e

        if not wait:
            return None

        return self._wait_for_stopped(timeout)

    def step(
        self,
        kind: str = "over",
        count: int = 1,
        thread_id: int | None = None,
    ) -> StopEvent | None:
        """Step execution."""
        if not self._session or not self.thread_id:
            raise RuntimeError("No active DAP session")

        cmd_map = {
            "into": "stepIn",
            "over": "next",
            "out": "stepOut",
            "instruction": "stepIn",
        }
        request_name = cmd_map.get(kind, "next")
        tid = thread_id if thread_id is not None else self.thread_id

        req_args: dict[str, Any] = {"threadId": tid}
        if kind == "instruction":
            req_args["granularity"] = "instruction"

        last_stop: StopEvent | None = None
        for _ in range(max(1, int(count or 1))):
            try:
                self._session.request(request_name, req_args)
            except DAPError as e:
                raise RuntimeError(f"Step failed: {e}") from e
            last_stop = self._wait_for_stopped()
            if not last_stop:
                break

        return last_stop

    def set_breakpoint(
        self,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        condition: str | None = None,
    ) -> BreakpointResult:
        """Set a breakpoint using LLDB command."""
        if not function and not address and not (file and line):
            return BreakpointResult(message="Error: provide function, address, or file+line")

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
        output = self.execute_command(cmd)
        self.breakpoints.append(cmd)

        # Parse output for breakpoint ID
        match = re.search(r"Breakpoint (\d+):", output)
        bp_id = int(match.group(1)) if match else None

        return BreakpointResult(
            id=bp_id,
            verified="Breakpoint" in output,
            message=output,
        )

    # =========================================================================
    # Inspection
    # =========================================================================

    def execute_command(self, command: str) -> str:
        """Execute a raw LLDB command via DAP evaluate."""
        if not self._session:
            return "Error: No active DAP session"

        try:
            args: dict[str, Any] = {
                "expression": command,
                "context": "repl",
            }
            if self.frame_id is not None:
                args["frameId"] = self.frame_id

            resp = self._session.request("evaluate", args)
            return resp.get("body", {}).get("result", "")
        except DAPError as e:
            return f"LLDB command failed: {e}"

    def get_threads(self) -> list[ThreadInfo]:
        """Get list of threads."""
        if not self._session:
            return []

        try:
            resp = self._session.request("threads")
            threads = resp.get("body", {}).get("threads", []) or []
            return [
                ThreadInfo(
                    id=t.get("id"),
                    name=t.get("name", f"Thread {t.get('id')}"),
                )
                for t in threads
            ]
        except Exception:
            return []

    def get_backtrace(
        self,
        thread_id: int | None = None,
        max_frames: int = 32,
    ) -> list[StackFrame]:
        """Get stack backtrace."""
        if not self._session:
            return []

        tid = thread_id if thread_id is not None else self.thread_id
        if not tid:
            return []

        try:
            resp = self._session.request(
                "stackTrace",
                {"threadId": tid, "levels": int(max_frames)},
            )
            frames = resp.get("body", {}).get("stackFrames", []) or []
            return [
                StackFrame(
                    id=f.get("id"),
                    name=f.get("name", ""),
                    line=f.get("line"),
                    column=f.get("column"),
                    source_path=(f.get("source") or {}).get("path"),
                    instruction_pointer=f.get("instructionPointerReference"),
                    module_name=f.get("moduleId"),
                )
                for f in frames
            ]
        except Exception:
            return []

    def read_memory(
        self,
        address: int | str,
        size: int,
    ) -> bytes:
        """Read memory at address."""
        if not self._session:
            raise MemoryError("No active DAP session")

        # Normalize address
        if isinstance(address, str):
            addr_int = _try_parse_address(address)
            if addr_int is None:
                raise MemoryError(f"Invalid address: {address}")
        else:
            addr_int = address

        try:
            resp = self._session.request(
                "readMemory",
                {"memoryReference": f"0x{addr_int:x}", "count": int(size)},
            )
            body = resp.get("body", {}) or {}
            data_field = body.get("data")

            if isinstance(data_field, str) and data_field:
                # Try base64 first
                try:
                    return base64.b64decode(data_field)
                except Exception:
                    pass
                # Try hex
                try:
                    return bytes.fromhex(data_field)
                except ValueError as err:
                    raise MemoryError("Invalid data encoding") from err

            return b""
        except DAPError as e:
            raise MemoryError(f"Read failed: {e}") from e

    def read_register(self, register: str | None = None) -> dict[str, Any]:
        """Read register(s) via LLDB command."""
        cmd = "register read" if not register else f"register read {register}"
        output = self.execute_command(cmd)

        # Parse output into dict (best effort)
        result: dict[str, Any] = {"raw": output}
        for line in output.splitlines():
            line = line.strip()
            if "=" in line:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    reg_name = parts[0].strip()
                    reg_value = parts[1].strip()
                    result[reg_name] = reg_value

        return result

    def write_register(self, register: str, value: str | int) -> bool:
        """Write to a register."""
        output = self.execute_command(f"register write {register} {value}")
        return "error" not in output.lower()

    def evaluate(
        self,
        expression: str,
        frame_id: int | None = None,
    ) -> Any:
        """Evaluate an expression."""
        if not self._session:
            raise RuntimeError("No active DAP session")

        try:
            args: dict[str, Any] = {"expression": expression}
            fid = frame_id if frame_id is not None else self.frame_id
            if fid is not None:
                args["frameId"] = fid

            resp = self._session.request("evaluate", args)
            body = resp.get("body", {})
            return body.get("result")
        except DAPError as e:
            raise RuntimeError(f"Evaluate failed: {e}") from e

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _wait_for_stopped(self, timeout: float | None = None) -> StopEvent | None:
        """Wait for a stopped, exited, or terminated event.

        For ASAN crashes, the program may exit before we get a 'stopped' event,
        so we need to watch for both stop and exit events.
        """
        if not self._session:
            return None

        try:
            # Wait for any of: stopped, exited, terminated
            event = self._session.wait_for_events(
                ["stopped", "exited", "terminated"],
                timeout=timeout if timeout is not None else self.timeout,
            )
        except TimeoutError:
            return None

        event_type = event.get("event")
        body = event.get("body", {})

        # Handle exited/terminated events - create a synthetic stop event
        if event_type in ("exited", "terminated"):
            exit_code = body.get("exitCode")
            # ASAN typically exits with code 1, treat as crash
            if exit_code and exit_code != 0:
                return StopEvent(
                    reason="exited",
                    thread_id=None,
                    frame_id=None,
                    description=f"Process exited with code {exit_code}",
                    all_threads_stopped=True,
                    raw=event,
                )
            return None

        # Handle stopped event
        self.thread_id = body.get("threadId", self.thread_id)
        self._refresh_frame()

        stop = StopEvent(
            reason=body.get("reason", ""),
            thread_id=self.thread_id,
            frame_id=self.frame_id,
            description=body.get("description"),
            all_threads_stopped=body.get("allThreadsStopped", False),
            raw=event,
        )

        self.last_stop_event = stop
        self._record_crash_if_needed(stop)

        return stop

    def _refresh_frame(self) -> None:
        """Refresh current frame ID from stack trace."""
        if not self._session or not self.thread_id:
            return

        try:
            stack_resp = self._session.request(
                "stackTrace",
                {"threadId": self.thread_id, "levels": 1},
            )
            frames = stack_resp.get("body", {}).get("stackFrames", [])
            if frames:
                self.frame_id = frames[0]["id"]
        except DAPError:
            pass

    def _record_crash_if_needed(self, stop: StopEvent) -> None:
        """Record crash event if this is a crash."""
        if not self.is_crash_reason(stop.reason):
            return

        # Compute stack hash
        stack_hash, pcs = self._compute_stack_hash(max_frames=5)
        if stack_hash and stack_hash in self.seen_crash_hashes:
            return
        if stack_hash:
            self.seen_crash_hashes.add(stack_hash)

        crash_entry: dict[str, Any] = {
            "ts": time.time(),
            "reason": stop.reason,
            "thread_id": stop.thread_id,
            "frame_id": stop.frame_id,
            "stack_hash": stack_hash,
            "pcs": pcs,
            "stop_body": stop.raw.get("body", {}),
        }
        self.pending_crashes.append(crash_entry)
        if len(self.pending_crashes) > 200:
            self.pending_crashes = self.pending_crashes[-200:]

    def _compute_stack_hash(self, max_frames: int = 5) -> tuple[str, list[str]]:
        """Compute a hash of the top stack frames for crash deduplication."""
        if not self._session or not self.thread_id:
            return "", []

        try:
            resp = self._session.request(
                "stackTrace",
                {"threadId": self.thread_id, "levels": int(max_frames)},
            )
        except Exception:
            return "", []

        frames = resp.get("body", {}).get("stackFrames", []) or []
        pcs: list[str] = []

        for frame in frames:
            ip_ref = (
                frame.get("instructionPointerReference")
                or frame.get("instructionPointerAddress")
                or frame.get("address")
                or ""
            )
            addr_int = _try_parse_address(str(ip_ref)) if ip_ref else None
            if addr_int is not None:
                pcs.append(f"0x{_strip_pac(addr_int):x}")

        pcs = pcs[: max(1, int(max_frames))]
        h = hashlib.sha256("|".join(pcs).encode()).hexdigest() if pcs else ""
        return h, pcs
