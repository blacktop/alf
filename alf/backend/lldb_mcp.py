"""
LLDB native MCP backend.

Implements the LLDBBackend interface using LLDB's native MCP protocol.
This connects directly to lldb's protocol-server MCP endpoint.

See: https://lldb.llvm.org/use/mcp.html

Unlike the DAP backend which provides structured responses, the native MCP
backend exposes a single `lldb_command` tool that executes LLDB commands
and returns their output. This requires parsing command output to extract
structured data.

Usage:
    # Start LLDB MCP server:
    # (lldb) protocol-server start MCP listen://localhost:59999

    backend = LLDBMCPBackend(host="127.0.0.1", port=59999)
    backend.connect()
    result = backend.launch("/path/to/binary")
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import time
from pathlib import Path
from typing import Any

from .base import (
    BreakpointResult,
    LaunchResult,
    LLDBBackend,
    StackFrame,
    StopEvent,
    ThreadInfo,
)

logger = logging.getLogger(__name__)


class MCPError(Exception):
    """Error from MCP communication."""

    pass


class LLDBMCPBackend(LLDBBackend):
    """LLDB backend using native MCP protocol.

    This backend connects directly to LLDB's MCP server (protocol-server)
    and uses the lldb_command tool to execute debugger commands.

    Features:
    - Hybrid JSON/text output: Uses Python-based JSON commands when available,
      falls back to text parsing for compatibility.
    - Automatic script loading: Loads helper script for structured output.

    Usage:
        # First start the MCP server in LLDB:
        # (lldb) protocol-server start MCP listen://localhost:59999

        backend = LLDBMCPBackend(host="127.0.0.1", port=59999)
        backend.connect()
        result = backend.launch("/path/to/binary", crash_input="/path/to/crash")
    """

    # LLDB initialization settings
    INIT_COMMANDS: list[str] = [
        "settings set use-color false",  # Disable ANSI colors for easier parsing
        "settings set symbols.load-on-demand true",  # 3.5x startup speedup
        "settings set symbols.enable-lldb-index-cache true",  # Cache symbols
        "settings set target.memory-module-load-level minimal",  # Minimal memory reads
    ]

    # Inline Python scripts for JSON output (executed via script command)
    # These scripts return structured JSON data for backtraces, registers, etc.
    # Must be single-line (semicolon-separated) for LLDB's script command.

    # Backtrace as JSON - {max_frames} is replaced at runtime
    SCRIPT_BACKTRACE_JSON: str = (
        'import json; t=lldb.debugger.GetSelectedTarget(); p=t.GetProcess() if t.IsValid() else None; '
        'th=p.GetSelectedThread() if p and p.IsValid() else None; '
        'frames=[{{"index":i,"pc":hex(th.GetFrameAtIndex(i).GetPC()),'
        '"function":th.GetFrameAtIndex(i).GetFunctionName() or "??",'
        '"module":th.GetFrameAtIndex(i).GetModule().GetFileSpec().GetFilename() if th.GetFrameAtIndex(i).GetModule() else None}} '
        'for i in range(min(th.GetNumFrames(),{max_frames}))] if th and th.IsValid() else []; '
        'print(json.dumps(frames) if frames else \'{{"error":"No thread"}}\')'
    )

    # Registers as JSON
    SCRIPT_REGISTERS_JSON: str = (
        'import json; t=lldb.debugger.GetSelectedTarget(); p=t.GetProcess() if t.IsValid() else None; '
        'th=p.GetSelectedThread() if p and p.IsValid() else None; f=th.GetSelectedFrame() if th else None; '
        'regs={{r.GetName():r.GetValue() for rg in f.GetRegisters() for r in rg if r.GetValue()}} if f and f.IsValid() else {{}}; '
        'print(json.dumps(regs) if regs else \'{{"error":"No frame"}}\')'
    )

    # Thread list as JSON
    SCRIPT_THREADS_JSON: str = (
        'import json; t=lldb.debugger.GetSelectedTarget(); p=t.GetProcess() if t.IsValid() else None; '
        'sel=p.GetSelectedThread().GetThreadID() if p and p.IsValid() else 0; '
        'threads=[{{"id":th.GetIndexID(),"tid":th.GetThreadID(),"name":th.GetName() or "Thread","stop_reason":th.GetStopReason()}} '
        'for th in p] if p and p.IsValid() else []; '
        'print(json.dumps(threads) if threads else \'{{"error":"No process"}}\')'
    )

    # Stop reason as JSON
    SCRIPT_STOP_JSON: str = (
        'import json; t=lldb.debugger.GetSelectedTarget(); p=t.GetProcess() if t.IsValid() else None; '
        'th=p.GetSelectedThread() if p and p.IsValid() else None; f=th.GetSelectedFrame() if th else None; '
        'sr=th.GetStopReason() if th else 0; '
        'rs={{0:"invalid",1:"none",2:"trace",3:"breakpoint",4:"watchpoint",5:"signal",6:"exception",7:"exec"}}.get(sr,"unknown"); '
        'info={{"reason":rs,"reason_id":sr,"thread_id":th.GetIndexID() if th else 0,'
        '"pc":hex(f.GetPC()) if f and f.IsValid() else None,"function":f.GetFunctionName() if f and f.IsValid() else None}} if th else {{}}; '
        'print(json.dumps(info) if info else \'{{"error":"No thread"}}\')'
    )

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 59999,
        timeout: float = 30.0,
        debugger_id: int = 1,
    ):
        """Initialize LLDB MCP backend.

        Args:
            host: MCP server host address.
            port: MCP server port (default: 59999).
            timeout: Default timeout for operations.
            debugger_id: LLDB debugger instance ID (default: 1).
        """
        super().__init__(timeout=timeout)
        self.host = host
        self.port = port
        self.debugger_id = debugger_id
        self._socket: socket.socket | None = None
        self._request_id = 0
        self._initialized = False
        self._json_commands_available = False  # Set True if JSON helper loaded

    @property
    def name(self) -> str:
        return "lldb_mcp"

    @property
    def connected(self) -> bool:
        """Check if connected to MCP server."""
        if self._socket is None:
            return False
        try:
            # Check socket is still alive with empty peek
            self._socket.setblocking(False)
            try:
                data = self._socket.recv(1, socket.MSG_PEEK)
                if not data:
                    self._socket = None
                    return False
            except BlockingIOError:
                pass  # No data available, still connected
            finally:
                self._socket.setblocking(True)
            return True
        except Exception:
            self._socket = None
            return False

    # =========================================================================
    # MCP Protocol
    # =========================================================================

    def _send_message(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message to the MCP server.

        LLDB MCP uses newline-delimited JSON (no Content-Length headers).
        """
        if not self._socket:
            raise MCPError("Not connected to MCP server")

        # LLDB MCP expects newline-delimited JSON, not Content-Length framed
        content = json.dumps(message).encode("utf-8") + b"\n"
        self._socket.sendall(content)

    def _recv_message(self) -> dict[str, Any]:
        """Receive a JSON-RPC message from the MCP server.

        LLDB MCP uses newline-delimited JSON (each message ends with \n).
        """
        if not self._socket:
            raise MCPError("Not connected to MCP server")

        # Read until newline (LLDB MCP uses newline-delimited JSON)
        data = b""
        while True:
            chunk = self._socket.recv(1)
            if not chunk:
                raise MCPError("Connection closed while reading message")
            if chunk == b'\n':
                break
            data += chunk

        if not data:
            raise MCPError("Empty message received")

        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise MCPError(f"Invalid JSON: {e} - data: {data[:100]}")

    def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Call an MCP tool and return the result.

        Args:
            tool_name: Name of the tool (typically "lldb_command").
            arguments: Tool arguments.

        Returns:
            Tool output as string.

        Raises:
            MCPError: If tool call fails.
        """
        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        self._send_message(request)

        # Wait for response
        response = self._recv_message()

        if "error" in response:
            raise MCPError(f"MCP error: {response['error']}")

        result = response.get("result", {})
        content = result.get("content", [])
        if content and isinstance(content, list):
            # MCP returns content as array of content blocks
            for block in content:
                if block.get("type") == "text":
                    return block.get("text", "")
        return str(result)

    def _lldb_command(self, command: str) -> str:
        """Execute an LLDB command via MCP.

        Args:
            command: LLDB command string.

        Returns:
            Command output.
        """
        logger.debug("LLDB command: %s", command)
        # LLDB MCP tool uses 'arguments' for the command and requires 'debugger_id'
        result = self._call_tool("lldb_command", {
            "debugger_id": self.debugger_id,
            "arguments": command,
        })
        logger.debug("LLDB result: %s", result[:200] if len(result) > 200 else result)
        return result

    def _load_json_helper(self) -> None:
        """Check if Python scripting is available for JSON output.

        NOTE: Currently disabled because inline Python scripts disrupt process state
        (executing script commands can resume the process). Text parsing is more reliable.
        """
        # Disable JSON scripts for now - they interfere with process state
        self._json_commands_available = False
        logger.debug("JSON scripting disabled (text parsing used instead)")

    def _run_json_script(self, script: str) -> str | None:
        """Run inline Python script and return output.

        Returns the script output or None if execution fails.
        NOTE: Currently not used - see _load_json_helper.
        """
        try:
            # Execute Python script inline
            output = self._lldb_command(f"script {script}")
            return output.strip() if output else None
        except MCPError as e:
            logger.debug("JSON script failed: %s", e)
            return None

    # =========================================================================
    # Connection Management
    # =========================================================================

    def connect(self) -> None:
        """Connect to LLDB MCP server."""
        if self._socket is not None:
            return

        logger.info("Connecting to LLDB MCP at %s:%s", self.host, self.port)

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Use a short timeout for connection, longer for operations
        self._socket.settimeout(5.0)

        try:
            self._socket.connect((self.host, self.port))
        except Exception as e:
            self._socket = None
            raise ConnectionError(
                f"Failed to connect to LLDB MCP at {self.host}:{self.port}: {e}"
            ) from e

        # Set longer timeout for operations
        self._socket.settimeout(self.timeout)

        # MCP initialization handshake
        try:
            self._request_id += 1
            init_request = {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "alf",
                        "version": "0.1.0",
                    },
                },
            }
            self._send_message(init_request)
            init_response = self._recv_message()

            if "error" in init_response:
                raise ConnectionError(f"MCP initialization failed: {init_response['error']}")

            # Send initialized notification
            self._send_message({"jsonrpc": "2.0", "method": "notifications/initialized"})

            self._initialized = True
            logger.info("MCP initialization complete")

        except TimeoutError:
            # LLDB MCP might not require strict initialization
            # Try to proceed without it
            logger.warning("MCP initialization timed out, trying without handshake")
            self._initialized = False

        # Apply initialization settings
        for cmd in self.INIT_COMMANDS:
            try:
                self._lldb_command(cmd)
            except (MCPError, TimeoutError):
                pass  # Ignore errors on settings

        # Load JSON helper script for structured output
        self._load_json_helper()

        logger.info("Connected to LLDB MCP server (JSON commands: %s)",
                    "enabled" if self._json_commands_available else "disabled")

    def disconnect(self) -> None:
        """Disconnect from LLDB MCP server.

        Note: This does NOT quit LLDB - it just closes the socket connection.
        The LLDB session remains available for reconnection or manual use.
        Launched processes are killed; attached / gdb-remote processes are
        detached so a remote inferior keeps running after teardown.
        """
        if self._socket:
            command = "process kill" if self.should_terminate_debuggee() else "process detach"
            try:
                self._lldb_command(command)
            except Exception:
                pass
            # Don't send quit - let the LLDB session stay running for reuse
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
            self._initialized = False

    # =========================================================================
    # Session Management
    # =========================================================================

    def launch(
        self,
        binary: str,
        args: list[str] | None = None,
        crash_input: str | None = None,
        stop_on_entry: bool = False,
        env: dict[str, str] | None = None,
    ) -> LaunchResult:
        """Launch a binary under the debugger."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        self.last_launch = {
            "binary": binary,
            "args": args,
            "crash_input": crash_input,
            "mode": self.SESSION_KIND_LAUNCH,
        }

        # Build target
        output = self._lldb_command(f'target create "{binary}"')
        if "error:" in output.lower():
            return LaunchResult(
                status="error",
                error=output,
                hint="Check binary path and permissions",
            )

        # Set environment
        if env:
            for key, value in env.items():
                self._lldb_command(f'settings set target.env-vars {key}="{value}"')

        # Build argument list
        all_args = []
        if args:
            all_args.extend(args)
        if crash_input:
            all_args.append(crash_input)

        # Set arguments if any
        if all_args:
            args_str = " ".join(f'"{a}"' for a in all_args)
            self._lldb_command(f"settings set target.run-args {args_str}")

        # Launch
        if stop_on_entry:
            output = self._lldb_command("process launch --stop-at-entry")
        else:
            output = self._lldb_command("run")

        result = self._parse_launch_output(output)

        # Wait for process to stop (crash, exit, or breakpoint)
        if result.status not in ("error", "exited"):
            result = self._wait_for_stop(timeout=5.0)

        return result

    def _wait_for_stop(self, timeout: float = 5.0) -> LaunchResult:
        """Wait for process to stop (crash, exit, or breakpoint).

        Polls process status until stopped or timeout.
        """
        import time

        start = time.time()
        poll_interval = 0.1

        while time.time() - start < timeout:
            status_output = self._lldb_command("process status")
            lower = status_output.lower()

            # Check for stopped state
            if "stopped" in lower:
                # Extract stop reason
                reason = "stopped"
                if "signal" in lower:
                    match = re.search(r"signal\s+(\w+)", lower)
                    if match:
                        reason = f"signal {match.group(1)}"
                elif "exception" in lower or "exc_" in lower:
                    reason = "exception"
                elif "breakpoint" in lower:
                    reason = "breakpoint"

                return LaunchResult(status="stopped", reason=reason)

            # Check for exited state
            if "exited" in lower:
                exit_match = re.search(r"exited with status = (\d+)", status_output)
                exit_code = int(exit_match.group(1)) if exit_match else None
                return LaunchResult(status="exited", exit_code=exit_code, reason="exited")

            # Check if no process
            if "no process" in lower or "invalid" in lower:
                return LaunchResult(status="exited", reason="process ended")

            time.sleep(poll_interval)

        # Timeout - process might still be running
        return LaunchResult(status="running", reason="timeout waiting for stop")

    def attach(
        self,
        pid: int,
        program: str | None = None,
        wait_for: bool = False,
    ) -> LaunchResult:
        """Attach to a running process."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        self.last_launch = {
            "pid": int(pid),
            "program": program,
            "mode": self.SESSION_KIND_ATTACH,
        }

        if program:
            self._lldb_command(f'target create "{program}"')

        if wait_for:
            output = self._lldb_command(f"process attach --waitfor --pid {pid}")
        else:
            output = self._lldb_command(f"process attach --pid {pid}")

        return self._parse_launch_output(output)

    def load_core(
        self,
        core_path: str,
        program: str | None = None,
    ) -> LaunchResult:
        """Load a core file for post-mortem analysis."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        self.last_launch = {
            "core_file": core_path,
            "program": program,
            "mode": self.SESSION_KIND_CORE,
        }

        if program:
            self._lldb_command(f'target create "{program}"')

        output = self._lldb_command(f'target create -c "{core_path}"')

        if "error:" in output.lower():
            return LaunchResult(status="error", error=output)

        return LaunchResult(status="stopped", reason="core file loaded")

    def _parse_launch_output(self, output: str) -> LaunchResult:
        """Parse LLDB launch/attach output to LaunchResult."""
        lower = output.lower()

        # Check for errors
        if "error:" in lower:
            return LaunchResult(status="error", error=output)

        # Check for exit
        exit_match = re.search(r"exited with status = (\d+)", output)
        if exit_match:
            return LaunchResult(
                status="exited",
                exit_code=int(exit_match.group(1)),
                reason="process exited",
            )

        # Check for signal/crash
        signal_match = re.search(r"signal (\w+)", lower)
        if signal_match:
            return LaunchResult(
                status="stopped",
                reason=f"signal {signal_match.group(1)}",
            )

        # Check for exception
        if "exception" in lower or "exc_" in lower:
            return LaunchResult(status="stopped", reason="exception")

        # Check for breakpoint
        if "breakpoint" in lower:
            return LaunchResult(status="stopped", reason="breakpoint")

        # Assume stopped if we got here
        return LaunchResult(status="stopped", reason="unknown")

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
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        if thread_id is not None:
            self._lldb_command(f"thread select {thread_id}")

        output = self._lldb_command("continue")
        return self._parse_stop_output(output)

    def step(
        self,
        kind: str = "over",
        count: int = 1,
        thread_id: int | None = None,
    ) -> StopEvent | None:
        """Step execution."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        if thread_id is not None:
            self._lldb_command(f"thread select {thread_id}")

        cmd_map = {
            "into": "step",
            "over": "next",
            "out": "finish",
            "instruction": "stepi",
        }
        cmd = cmd_map.get(kind, "next")

        for _ in range(count):
            output = self._lldb_command(cmd)

        return self._parse_stop_output(output)

    def set_breakpoint(
        self,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        condition: str | None = None,
    ) -> BreakpointResult:
        """Set a breakpoint."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        if function:
            output = self._lldb_command(f"breakpoint set --name {function}")
        elif address:
            output = self._lldb_command(f"breakpoint set --address {address}")
        elif file and line:
            output = self._lldb_command(f"breakpoint set --file {file} --line {line}")
        else:
            return BreakpointResult(verified=False, message="No breakpoint location specified")

        if condition:
            # Get breakpoint ID and add condition
            bp_match = re.search(r"Breakpoint (\d+):", output)
            if bp_match:
                bp_id = bp_match.group(1)
                self._lldb_command(f"breakpoint modify {bp_id} --condition '{condition}'")

        # Parse result
        bp_match = re.search(r"Breakpoint (\d+):", output)
        if bp_match:
            bp_id = int(bp_match.group(1))
            loc_match = re.search(r"(\d+) location", output)
            verified = loc_match is not None
            return BreakpointResult(id=bp_id, verified=verified, message=output)

        return BreakpointResult(verified=False, message=output)

    def _parse_stop_output(self, output: str) -> StopEvent | None:
        """Parse LLDB output to StopEvent."""
        lower = output.lower()

        reason = "unknown"
        description = None

        # Detect stop reason
        if "signal" in lower:
            signal_match = re.search(r"signal (\w+)", lower)
            if signal_match:
                reason = f"signal {signal_match.group(1)}"
        elif "breakpoint" in lower:
            reason = "breakpoint"
        elif "exception" in lower or "exc_" in lower:
            reason = "exception"
            # Extract exception details
            exc_match = re.search(r"EXC_\w+(?:\s*\([^)]+\))?", output, re.IGNORECASE)
            if exc_match:
                description = exc_match.group(0)
        elif "exited" in lower:
            reason = "exited"

        # Extract thread ID
        thread_match = re.search(r"thread #(\d+)", lower)
        thread_id = int(thread_match.group(1)) if thread_match else None

        event = StopEvent(
            reason=reason,
            thread_id=thread_id,
            description=description,
            raw={"output": output},
        )
        self.last_stop_event = event
        return event

    # =========================================================================
    # Inspection
    # =========================================================================

    def execute_command(self, command: str) -> str:
        """Execute a raw LLDB command."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")
        return self._lldb_command(command)

    def get_threads(self) -> list[ThreadInfo]:
        """Get list of threads in the target.

        Uses inline Python JSON script when available, falls back to text parsing.
        """
        if not self.connected:
            return []

        # Try inline JSON script first
        if self._json_commands_available:
            output = self._run_json_script(self.SCRIPT_THREADS_JSON)
            if output:
                try:
                    data = json.loads(output)
                    if isinstance(data, list):
                        return [
                            ThreadInfo(
                                id=t.get("id", i),
                                name=t.get("name", f"Thread {t.get('id', i)}"),
                                stopped=True,
                            )
                            for i, t in enumerate(data)
                        ]
                except json.JSONDecodeError as e:
                    logger.debug("JSON parse failed, falling back to text: %s", e)

        # Fallback to text parsing
        output = self._lldb_command("thread list")
        threads = []

        for line in output.splitlines():
            # Match: * thread #1: tid = 0x1234, 0x00... function...
            match = re.search(r"thread #(\d+)", line)
            if match:
                tid = int(match.group(1))
                is_current = line.strip().startswith("*")
                # Extract name if available
                name_match = re.search(r"name = '([^']+)'", line)
                name = name_match.group(1) if name_match else f"Thread {tid}"
                threads.append(ThreadInfo(id=tid, name=name, stopped=True))

        return threads

    def get_backtrace(
        self,
        thread_id: int | None = None,
        max_frames: int = 32,
    ) -> list[StackFrame]:
        """Get stack backtrace.

        Uses inline Python JSON script when available, falls back to text parsing.
        """
        if not self.connected:
            return []

        if thread_id is not None:
            self._lldb_command(f"thread select {thread_id}")

        # Try inline JSON script first
        if self._json_commands_available:
            script = self.SCRIPT_BACKTRACE_JSON.format(max_frames=max_frames)
            output = self._run_json_script(script)
            if output:
                try:
                    data = json.loads(output)
                    if isinstance(data, list):
                        return [
                            StackFrame(
                                id=f.get("index", i),
                                name=f.get("function", "??"),
                                line=f.get("line"),
                                source_path=f.get("file"),
                                instruction_pointer=f.get("pc"),
                                module_name=f.get("module"),
                            )
                            for i, f in enumerate(data)
                        ]
                except json.JSONDecodeError as e:
                    logger.debug("JSON parse failed, falling back to text: %s", e)

        # Fallback to text parsing
        output = self._lldb_command(f"bt {max_frames}")

        # Strip ANSI color codes from output
        output = re.sub(r'\x1b\[[0-9;]*m', '', output)

        frames = []

        for line in output.splitlines():
            # Match: frame #0: 0x00001234 module`function at file:line
            # Also handles: * frame #0: ... (current frame marker)
            match = re.match(
                r"\s*\*?\s*frame #(\d+):\s*(0x[0-9a-fA-F]+)\s+(\S+)`(\S*)\s*(?:at\s+(\S+):(\d+))?",
                line,
            )
            if match:
                frame_id = int(match.group(1))
                pc = match.group(2)
                module = match.group(3)
                name = match.group(4) or "??"
                source_file = match.group(5)
                line_num = int(match.group(6)) if match.group(6) else None

                frames.append(
                    StackFrame(
                        id=frame_id,
                        name=name,
                        line=line_num,
                        source_path=source_file,
                        instruction_pointer=pc,
                        module_name=module,
                    )
                )

        return frames

    def read_memory(
        self,
        address: int | str,
        size: int,
    ) -> bytes:
        """Read memory at address."""
        if not self.connected:
            raise MemoryError("Not connected to MCP server")

        if isinstance(address, str):
            addr_str = address
        else:
            addr_str = hex(address)

        output = self._lldb_command(f"memory read {addr_str} --size {size} --format x")

        # Parse hex bytes from output
        # Format: 0x0000: 0x12 0x34 0x56 ...
        data = bytearray()
        for line in output.splitlines():
            # Find hex values
            hex_values = re.findall(r"0x([0-9a-fA-F]{2})\b", line)
            for hv in hex_values:
                data.append(int(hv, 16))

        if len(data) < size:
            raise MemoryError(f"Could not read {size} bytes at {addr_str}")

        return bytes(data[:size])

    def read_register(self, register: str | None = None) -> dict[str, Any]:
        """Read register(s).

        Uses inline Python JSON script when available for all registers,
        falls back to text parsing.
        """
        if not self.connected:
            return {}

        # For all registers, try inline JSON script first
        if register is None and self._json_commands_available:
            output = self._run_json_script(self.SCRIPT_REGISTERS_JSON)
            if output:
                try:
                    data = json.loads(output)
                    if isinstance(data, dict) and "error" not in data:
                        return data
                except json.JSONDecodeError as e:
                    logger.debug("JSON parse failed, falling back to text: %s", e)

        # Fallback to text parsing
        if register:
            output = self._lldb_command(f"register read {register}")
        else:
            output = self._lldb_command("register read --all")

        regs: dict[str, Any] = {}

        for line in output.splitlines():
            # Match: x0 = 0x0000000000000001
            match = re.match(r"\s*(\w+)\s*=\s*(0x[0-9a-fA-F]+)", line)
            if match:
                reg_name = match.group(1).lower()
                reg_value = match.group(2)
                regs[reg_name] = reg_value

        return regs

    def write_register(self, register: str, value: str | int) -> bool:
        """Write to a register."""
        if not self.connected:
            return False

        if isinstance(value, int):
            value = hex(value)

        output = self._lldb_command(f"register write {register} {value}")
        return "error" not in output.lower()

    def evaluate(
        self,
        expression: str,
        frame_id: int | None = None,
    ) -> Any:
        """Evaluate an expression in the debugger."""
        if not self.connected:
            return None

        if frame_id is not None:
            self._lldb_command(f"frame select {frame_id}")

        output = self._lldb_command(f"expression {expression}")
        return output

    # =========================================================================
    # Crash Analysis
    # =========================================================================

    def collect_crash_context(self) -> dict[str, Any]:
        """Collect crash context for triage.

        Returns comprehensive crash data similar to DAP backend.
        Uses inline Python scripts for JSON output when available.
        """
        if not self.connected:
            return {}

        context: dict[str, Any] = {}

        # Get stop reason - use inline JSON script if available
        if self._json_commands_available:
            stop_output = self._run_json_script(self.SCRIPT_STOP_JSON)
            if stop_output:
                try:
                    stop_data = json.loads(stop_output)
                    if isinstance(stop_data, dict) and "error" not in stop_data:
                        context["stop"] = stop_data
                    else:
                        context["stop"] = {"raw": self._lldb_command("thread info")}
                except json.JSONDecodeError:
                    context["stop"] = {"raw": self._lldb_command("thread info")}
            else:
                context["stop"] = {"raw": self._lldb_command("thread info")}
        else:
            context["stop"] = {"raw": self._lldb_command("thread info")}

        # Get registers - use inline JSON script if available
        if self._json_commands_available:
            reg_output = self._run_json_script(self.SCRIPT_REGISTERS_JSON)
            if reg_output:
                try:
                    reg_data = json.loads(reg_output)
                    if isinstance(reg_data, dict) and "error" not in reg_data:
                        context["registers"] = reg_data
                    else:
                        context["registers"] = self._lldb_command("register read")
                except json.JSONDecodeError:
                    context["registers"] = self._lldb_command("register read")
            else:
                context["registers"] = self._lldb_command("register read")
        else:
            context["registers"] = self._lldb_command("register read")

        # Get backtrace - use inline JSON script if available
        frames = []
        pcs = []
        if self._json_commands_available:
            script = self.SCRIPT_BACKTRACE_JSON.format(max_frames=10)
            bt_output = self._run_json_script(script)
            if bt_output:
                try:
                    bt_data = json.loads(bt_output)
                    if isinstance(bt_data, list):
                        for f in bt_data:
                            pc = f.get("pc", "0x0")
                            name = f.get("function", "??")
                            frames.append({"pc": pc, "name": name})
                            pcs.append(pc)
                        context["backtrace"] = bt_data
                except json.JSONDecodeError:
                    pass

        # Fallback to text parsing if JSON didn't work
        if not frames:
            bt_output = self._lldb_command("bt 10")
            context["backtrace"] = bt_output

            # Strip ANSI color codes for parsing
            bt_clean = re.sub(r'\x1b\[[0-9;]*m', '', bt_output)

            for line in bt_clean.splitlines():
                match = re.match(
                    r"\s*\*?\s*frame #(\d+):\s*(0x[0-9a-fA-F]+)\s+(\S+)`(\S*)",
                    line,
                )
                if match:
                    pc = match.group(2)
                    name = match.group(4) or match.group(3)
                    frames.append({"pc": pc, "name": name})
                    pcs.append(pc)

        context["frames"] = frames
        context["pcs"] = pcs

        # Generate stack hash
        if pcs:
            hash_input = "|".join(pcs[:5])
            context["stack_hash"] = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        # Get disassembly around PC
        try:
            disasm = self._lldb_command("disassemble --pc --count 5")
            context["disassemble"] = disasm
        except MCPError:
            pass

        # Get stack bytes
        try:
            stack = self._lldb_command("memory read $sp --count 64 --format x")
            context["stack_bytes"] = stack
        except MCPError:
            pass

        return context

    def record_crash(self, crash_input: str | Path | None = None) -> dict[str, Any] | None:
        """Record a crash event if stopped due to crash.

        Returns crash entry dict if this is a new unique crash, None otherwise.
        """
        if not self.last_stop_event:
            return None

        if not self.is_crash_reason(self.last_stop_event.reason):
            return None

        context = self.collect_crash_context()
        stack_hash = context.get("stack_hash", "")

        if stack_hash in self.seen_crash_hashes:
            return None

        self.seen_crash_hashes.add(stack_hash)

        crash_entry = {
            "stack_hash": stack_hash,
            "reason": self.last_stop_event.reason,
            "crash_input": str(crash_input) if crash_input else None,
            "context": context,
            "timestamp": time.time(),
        }

        self.pending_crashes.append(crash_entry)
        return crash_entry
