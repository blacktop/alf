"""
LLDB/DAP session management for fuzzing.

Handles spawning lldb-dap, connecting to the MCP server, and providing
a clean interface for the fuzzing agent.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import socket
import subprocess
import sys
import weakref
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

# Track all active DAP processes for cleanup on exit
_active_dap_procs: weakref.WeakSet[subprocess.Popen] = weakref.WeakSet()


def _cleanup_dap_procs() -> None:
    """Terminate any remaining DAP processes on exit."""
    for proc in list(_active_dap_procs):
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


atexit.register(_cleanup_dap_procs)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _free_port() -> int:
    """Find an available port."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return int(port)


def _find_lldb_dap(explicit: str | None = None) -> str:
    """Find lldb-dap binary."""
    if explicit:
        return explicit
    env_bin = os.environ.get("LLDB_DAP_BIN")
    if env_bin:
        return env_bin
    if shutil.which("xcrun"):
        try:
            out = subprocess.check_output(["xcrun", "--find", "lldb-dap"], text=True).strip()
            if out:
                return out
        except Exception:
            pass
    return "lldb-dap"


@dataclass
class SessionConfig:
    """Configuration for a fuzz session."""

    binary: str
    corpus_dir: str | None = None
    dap_path: str | None = None
    dap_port: int = 0  # 0 = auto
    timeout: float = 30.0
    log_level: str = "ERROR"
    keep_alive: bool = False  # Keep session alive for batch operations
    backend: str = "dap"  # "dap" or "sbapi"

    def __post_init__(self) -> None:
        self.binary = str(Path(self.binary).expanduser().resolve())
        if self.corpus_dir:
            self.corpus_dir = str(Path(self.corpus_dir).expanduser().resolve())
        if self.backend not in ("dap", "sbapi"):
            raise ValueError(f"Invalid backend: {self.backend}. Must be 'dap' or 'sbapi'")


@dataclass
class FuzzSession:
    """Manages an LLDB/DAP session for fuzzing.

    Usage:
        async with FuzzSession(binary="/path/to/bin") as session:
            result = await session.call_tool("lldb_launch", {...})
            ...

    For maximum performance, use backend="sbapi":
        async with FuzzSession(binary="/path/to/bin", backend="sbapi") as session:
            # 10-100x faster stack hashing
            ...
    """

    config: SessionConfig
    _dap_proc: subprocess.Popen[str] | None = field(default=None, repr=False)
    _mcp_session: ClientSession | None = field(default=None, repr=False)
    _context_manager: Any = field(default=None, repr=False)
    _notifications: list[dict[str, Any]] = field(default_factory=list, repr=False)
    _tools: list[str] = field(default_factory=list, repr=False)
    _sbapi_backend: Any = field(default=None, repr=False)  # SBAPIBackend when using sbapi

    def __init__(
        self,
        binary: str,
        corpus_dir: str | None = None,
        dap_path: str | None = None,
        dap_port: int = 0,
        timeout: float = 30.0,
        log_level: str = "ERROR",
        keep_alive: bool = False,
        backend: str = "dap",
    ):
        self.config = SessionConfig(
            binary=binary,
            corpus_dir=corpus_dir,
            dap_path=dap_path,
            dap_port=dap_port,
            timeout=timeout,
            log_level=log_level,
            keep_alive=keep_alive,
            backend=backend,
        )
        self._dap_proc = None
        self._mcp_session = None
        self._context_manager = None
        self._notifications = []
        self._tools = []
        self._crash_count = 0  # Track crashes analyzed in this session
        self._sbapi_backend = None

    @property
    def binary(self) -> str:
        return self.config.binary

    @property
    def notifications(self) -> list[dict[str, Any]]:
        """Crash notifications received from the MCP server."""
        return self._notifications

    @property
    def tools(self) -> list[str]:
        """Available MCP tools."""
        return self._tools

    async def __aenter__(self) -> FuzzSession:
        await self._start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self._stop()

    async def _start(self) -> None:
        """Start DAP/MCP server or SBAPI backend."""
        if self.config.backend == "sbapi":
            await self._start_sbapi()
        else:
            await self._start_dap()

    async def _start_sbapi(self) -> None:
        """Start SBAPI backend (direct LLDB Python bindings)."""
        try:
            from alf.backend.sbapi import SBAPIBackend
        except ImportError as e:
            raise RuntimeError(
                f"SBAPI backend requires LLDB Python bindings: {e}. Make sure lldb Python module is in your PYTHONPATH."
            ) from e

        self._sbapi_backend = SBAPIBackend(self.config.binary)
        # SBAPI provides these tools (subset of DAP tools)
        self._tools = [
            "lldb_launch",
            "lldb_backtrace",
            "lldb_stack_hash",
            "lldb_read_memory",
            "lldb_execute",
            "lldb_disassemble",
            "lldb_crash_context",
            "lldb_set_breakpoint",
            "lldb_continue",
            "lldb_kill",
        ]

    async def _start_dap(self) -> None:
        """Start DAP and MCP server."""
        root = _repo_root()
        dap_bin = _find_lldb_dap(self.config.dap_path)
        port = self.config.dap_port or _free_port()

        env = os.environ.copy()
        env["PYTHONPATH"] = str(root)

        # Start lldb-dap
        cmd = [dap_bin, "--port", str(port)]
        self._dap_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=env)
        # Register for cleanup on exit (in case of Ctrl+C or crash)
        _active_dap_procs.add(self._dap_proc)

        # Build MCP server params
        args = [
            "-m",
            "alf.server",
            "--dap-host",
            "127.0.0.1",
            "--dap-port",
            str(port),
            "--timeout",
            str(self.config.timeout),
            "--log-level",
            self.config.log_level,
        ]
        server_params = StdioServerParameters(command=sys.executable, args=args, env=env, cwd=str(root))

        # Connect to MCP server
        self._context_manager = stdio_client(server_params)
        read_stream, write_stream = await self._context_manager.__aenter__()

        async def logging_cb(params: types.LoggingMessageNotificationParams) -> None:
            data = params.data
            if isinstance(data, dict) and data.get("crash"):
                self._notifications.append(data)

        self._mcp_session = ClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            logging_callback=logging_cb,
            read_timeout_seconds=timedelta(seconds=float(self.config.timeout)),
        )
        await self._mcp_session.__aenter__()
        await self._mcp_session.initialize()

        # Get available tools
        tools_result = await self._mcp_session.list_tools()
        self._tools = [t.name for t in tools_result.tools]

    async def _stop(self) -> None:
        """Stop DAP/MCP server or SBAPI backend."""
        # Stop SBAPI backend if active
        if self._sbapi_backend:
            try:
                self._sbapi_backend.terminate()
            except Exception:
                pass
            self._sbapi_backend = None

        # Stop MCP session
        if self._mcp_session:
            try:
                await self._mcp_session.__aexit__(None, None, None)
            except Exception:
                pass
            self._mcp_session = None

        if self._context_manager:
            try:
                await self._context_manager.__aexit__(None, None, None)
            except Exception:
                pass
            self._context_manager = None

        if self._dap_proc and self._dap_proc.poll() is None:
            self._dap_proc.terminate()
            self._dap_proc = None

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> str:
        """Call an MCP tool and return the text result."""
        text, _is_error = await self.call_tool_text(name, arguments, timeout=timeout)
        return text

    async def call_tool_text(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> tuple[str, bool]:
        """Call an MCP tool and return (text, is_error)."""
        if not self._mcp_session:
            raise RuntimeError("Session not started")

        try:
            timeout_seconds = float(timeout) if timeout is not None else float(self.config.timeout)
            res = await self._mcp_session.call_tool(
                name,
                arguments or {},
                read_timeout_seconds=timedelta(seconds=timeout_seconds) if timeout_seconds > 0 else None,
            )
        except Exception as e:  # noqa: BLE001
            return (f"Error: tool {name} failed: {e}", True)

        is_error = getattr(res, "isError", False)

        # Collect all text/content parts
        output_parts = []
        if res.content:
            for content in res.content:
                if content.type == "text":
                    output_parts.append(content.text)
                elif content.type == "image":
                    output_parts.append(f"[Image: {content.mimeType}]")
                elif content.type == "resource":
                    output_parts.append(f"[Resource: {content.resource.uri}]")

        full_text = "\n".join(output_parts)

        if is_error:
            # If explicit error flag is set, return as error
            msg = full_text if full_text.strip() else "Unknown tool error"
            return (json.dumps({"tool": name, "error": msg}, indent=2), True)

        if full_text:
            return (full_text, False)

        if res.structuredContent is not None:
            try:
                return (json.dumps(res.structuredContent, indent=2), False)
            except Exception:
                return (str(res.structuredContent), False)

        try:
            return (json.dumps(res.model_dump(), indent=2), False)
        except Exception:
            return (str(res), False)

    async def launch(self, crash_input: str | None = None, stop_on_entry: bool = False) -> dict[str, Any]:
        """Launch the target binary.

        Args:
            crash_input: Optional input file to pass to the binary.
            stop_on_entry: Stop at entry point instead of running to crash.

        Returns:
            Launch result dict with status, error, hint fields.
        """
        # SBAPI backend: direct launch
        if self._sbapi_backend:
            result = self._sbapi_backend.launch(crash_input=crash_input, stop_on_entry=stop_on_entry)
            return {
                "status": result.status,
                "error": result.error,
                "hint": result.hint,
                "stop_reason": result.stop_reason,
            }

        # DAP backend: use MCP tools
        args: dict[str, Any] = {"binary": self.binary, "stop_on_entry": stop_on_entry}
        if crash_input:
            args["crash_input"] = crash_input

        result = await self.call_tool("lldb_launch", args)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"status": "error", "error": result}

    async def get_crash_context(self, max_frames: int = 32, stack_bytes: int = 256) -> dict[str, Any]:
        """Get detailed crash context."""
        # SBAPI backend: build context from direct API calls
        if self._sbapi_backend:
            context: dict[str, Any] = {}

            # Get backtrace
            backtrace = self._sbapi_backend.get_backtrace(max_frames=max_frames)
            context["backtrace"] = [
                {"frame": f.index, "pc": f.pc, "symbol": f.symbol or "", "module": f.module or ""} for f in backtrace
            ]

            # Get stack hash
            stack_hash, pcs = self._sbapi_backend.compute_stack_hash(max_frames=5)
            context["stack_hash"] = stack_hash
            context["stack_pcs"] = pcs

            # Get registers
            context["registers"] = self._sbapi_backend.read_registers()

            # Get stop reason
            stop = self._sbapi_backend.get_stop_reason()
            if stop:
                context["stop_reason"] = {
                    "type": stop.reason,
                    "description": stop.description or "",
                    "signal": stop.signal,
                }

            return context

        # DAP backend: use MCP tools
        result = await self.call_tool("lldb_crash_context", {"max_frames": max_frames, "stack_bytes": stack_bytes})
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": result}

    async def get_backtrace(self, count: int = 32) -> str:
        """Get stack backtrace."""
        return await self.call_tool("lldb_backtrace", {"count": count})

    async def get_registers(self) -> str:
        """Read all registers."""
        return await self.call_tool("lldb_execute", {"command": "register read"})

    async def disassemble(self, address: str = "--pc", count: int = 24) -> str:
        """Disassemble at address."""
        return await self.call_tool("lldb_disassemble", {"address": address, "count": count})

    async def set_breakpoint(
        self,
        symbol: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
    ) -> str:
        """Set a breakpoint."""
        args: dict[str, Any] = {}
        if symbol:
            args["function"] = symbol
        if address:
            args["address"] = address
        if file:
            args["file"] = file
        if line:
            args["line"] = line
        return await self.call_tool("lldb_set_breakpoint", args)

    async def continue_execution(self, wait: bool = True) -> str:
        """Continue execution."""
        return await self.call_tool("lldb_continue", {"wait": wait})

    async def install_stop_hook(
        self,
        *,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        ptr_reg: str = "x0",
        len_reg: str | None = None,
        max_size: int = 4096,
        name: str = "alf_stop_hook",
        telemetry_pipe: str | None = None,
    ) -> str:
        """Install a high-performance mutation stop-hook (server-side generator)."""
        args: dict[str, Any] = {
            "ptr_reg": ptr_reg,
            "max_size": int(max_size),
            "name": name,
        }
        if function:
            args["function"] = function
        if address:
            args["address"] = address
        if file:
            args["file"] = file
        if line is not None:
            args["line"] = int(line)
        if len_reg:
            args["len_reg"] = len_reg
        if telemetry_pipe:
            args["telemetry_pipe"] = telemetry_pipe
        return await self.call_tool("lldb_install_stop_hook", args)

    async def install_fork_server(
        self,
        *,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        name: str = "alf_fork_server",
        telemetry_pipe: str | None = None,
        follow_mode: str = "parent",
    ) -> str:
        """Install a best-effort fork server (server-side generator)."""
        args: dict[str, Any] = {
            "name": name,
            "follow_mode": follow_mode,
        }
        if function:
            args["function"] = function
        if address:
            args["address"] = address
        if file:
            args["file"] = file
        if line is not None:
            args["line"] = int(line)
        if telemetry_pipe:
            args["telemetry_pipe"] = telemetry_pipe
        return await self.call_tool("lldb_install_fork_server", args)

    async def get_stack_hash(self, frames: int = 5) -> str:
        """Get a hash of the current stack (for crash deduplication).

        This is a performance-critical method. With SBAPI backend, this is
        ~100x faster than DAP due to avoiding socket I/O overhead.
        """
        # SBAPI backend: direct hash computation (microseconds)
        if self._sbapi_backend:
            stack_hash, _pcs = self._sbapi_backend.compute_stack_hash(max_frames=frames)
            return stack_hash

        # DAP backend: use MCP tools (milliseconds due to socket I/O)
        return await self.call_tool("lldb_stack_hash", {"max_frames": frames})

    async def read_memory(self, address: str, size: int) -> str:
        """Read memory at address."""
        return await self.call_tool("lldb_read_memory", {"address": address, "size": size})

    async def execute(self, command: str) -> str:
        """Execute an LLDB command."""
        return await self.call_tool("lldb_execute", {"command": command})

    async def reset_for_next_crash(self) -> bool:
        """Reset the session for analyzing the next crash.

        This keeps the lldb-dap process running and reuses symbol caches,
        providing 3-10x speedup for batch crash analysis.

        Returns:
            True if reset succeeded, False otherwise.
        """
        # SBAPI backend: direct kill
        if self._sbapi_backend:
            try:
                return self._sbapi_backend.kill()
            except Exception:
                return False

        # DAP backend: use MCP tools
        if not self._mcp_session:
            return False

        try:
            # Use lldb_kill to terminate debuggee but keep session alive
            if "lldb_kill" in self._tools:
                result = await self.call_tool("lldb_kill")
                return "error" not in result.lower()
            else:
                # Fallback: use raw LLDB command
                await self.call_tool("lldb_execute", {"command": "process kill"})
                return True
        except Exception:
            return False

    async def analyze_crash(
        self,
        crash_input: str,
        max_frames: int = 32,
        stack_bytes: int = 256,
    ) -> dict[str, Any]:
        """Analyze a single crash and return the context.

        This is optimized for batch processing - if keep_alive is True,
        it reuses the session between crashes.

        Args:
            crash_input: Path to the crash input file.
            max_frames: Maximum stack frames to capture.
            stack_bytes: Bytes of stack memory to read.

        Returns:
            Crash context dict with registers, backtrace, etc.
        """
        # Reset session if this isn't the first crash and keep_alive is enabled
        if self._crash_count > 0 and self.config.keep_alive:
            if not await self.reset_for_next_crash():
                # Reset failed, return error
                return {"error": "Failed to reset session for next crash"}

        self._crash_count += 1

        # Launch with the crash input
        launch_result = await self.launch(crash_input=crash_input)
        if launch_result.get("status") == "error":
            return {"error": launch_result.get("error", "Launch failed")}

        # Get crash context
        context = await self.get_crash_context(
            max_frames=max_frames,
            stack_bytes=stack_bytes,
        )

        return context

    @property
    def crash_count(self) -> int:
        """Number of crashes analyzed in this session."""
        return self._crash_count
