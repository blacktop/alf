"""
SBAPI-based LLDB backend.

Implements the LLDBBackend interface using LLDB's Python Script Bridge API (SBAPI)
for maximum performance. This bypasses DAP entirely for in-process debugging.

Performance: ~10-100x faster than DAP for operations like stack hashing.

Requirements:
    - LLDB Python module from Homebrew LLVM or Xcode
    - Homebrew: brew install llvm (uses Python 3.14)
    - Xcode: comes with Xcode Command Line Tools (uses Python 3.9)

Usage:
    backend = SBAPIBackend()
    backend.connect()
    result = backend.launch("/path/to/binary", crash_input="/path/to/crash")
    frames = backend.get_backtrace(max_frames=5)
"""

from __future__ import annotations

import hashlib
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from alf.utils.address import strip_pac as _strip_pac

from .base import (
    BreakpointResult,
    LaunchResult,
    LLDBBackend,
    StackFrame,
    StopEvent,
    ThreadInfo,
)

if TYPE_CHECKING:
    import lldb as lldb_module

logger = logging.getLogger(__name__)

# Lazy import lldb to avoid import errors when not available
_lldb: lldb_module | None = None


def _get_lldb_paths() -> list[str]:
    """Get LLDB Python paths matching the current Python version."""
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    paths = []

    # Homebrew LLVM paths (version-specific)
    homebrew_base = Path("/opt/homebrew/opt/llvm")
    if homebrew_base.exists():
        # Try version-specific path first
        versioned = homebrew_base / "libexec" / f"python{py_ver}" / "site-packages"
        if versioned.exists():
            paths.append(str(versioned))
        paths.append(str(homebrew_base / "lib"))

    # Xcode paths (only for Python 3.9)
    if py_ver == "3.9":
        xcode_paths = [
            "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Resources/Python",
            "/Applications/Xcode-beta.app/Contents/SharedFrameworks/LLDB.framework/Resources/Python",
        ]
        for p in xcode_paths:
            if Path(p).exists():
                paths.append(p)

    return paths


def _setup_lldb_path() -> None:
    """Add LLDB Python paths to sys.path if needed."""
    # Check if lldb is already importable
    try:
        import lldb  # noqa: F401

        return
    except ImportError:
        pass

    # Try adding version-matched paths
    for path in _get_lldb_paths():
        if path not in sys.path:
            sys.path.insert(0, path)
            logger.debug(f"Added LLDB path: {path}")


def _get_lldb() -> lldb_module:
    """Lazy import of lldb module."""
    global _lldb
    if _lldb is None:
        _setup_lldb_path()
        try:
            import lldb

            _lldb = lldb
            logger.info(f"Loaded LLDB: {lldb.SBDebugger.GetVersionString()}")
        except ImportError as e:
            raise ImportError(
                "LLDB Python module not found. Install via:\n"
                "  - Homebrew: brew install llvm (recommended, Python 3.14)\n"
                "  - Xcode: xcode-select --install (Python 3.9)\n"
                "Then set PYTHONPATH or run with matching Python version."
            ) from e
    return _lldb


class SBAPIBackend(LLDBBackend):
    """LLDB backend using Python Script Bridge API (SBAPI).

    This backend directly uses LLDB's Python bindings for maximum performance.
    It's ideal for high-volume crash triage and automated analysis.

    Usage:
        backend = SBAPIBackend()
        backend.connect()
        result = backend.launch("/path/to/binary", crash_input="/path/to/crash")
        hash_val = backend.compute_stack_hash()
    """

    def __init__(self, timeout: float = 30.0):
        """Initialize SBAPI backend.

        Args:
            timeout: Default timeout for operations.
        """
        super().__init__(timeout=timeout)
        self._debugger: lldb_module.SBDebugger | None = None
        self._target: lldb_module.SBTarget | None = None
        self._process: lldb_module.SBProcess | None = None
        self._listener: lldb_module.SBListener | None = None

    @property
    def name(self) -> str:
        return "sbapi"

    @property
    def connected(self) -> bool:
        """Return True if debugger is initialized."""
        return self._debugger is not None and self._debugger.IsValid()

    # =========================================================================
    # Connection Management
    # =========================================================================

    def connect(self) -> None:
        """Initialize the LLDB debugger."""
        if self._debugger is not None:
            return

        lldb = _get_lldb()
        lldb.SBDebugger.Initialize()
        self._debugger = lldb.SBDebugger.Create()
        self._debugger.SetAsync(False)  # Synchronous mode for simplicity

        # Apply performance settings
        self._debugger.HandleCommand("settings set symbols.load-on-demand true")
        self._debugger.HandleCommand("settings set symbols.enable-lldb-index-cache true")
        self._debugger.HandleCommand("settings set target.memory-module-load-level minimal")

        logger.info("SBAPI backend initialized")

    def disconnect(self) -> None:
        """Terminate the debugger."""
        if self._process and self._process.IsValid():
            self._process.Kill()
            self._process = None

        if self._target and self._target.IsValid():
            self._debugger.DeleteTarget(self._target)
            self._target = None

        if self._debugger:
            lldb = _get_lldb()
            lldb.SBDebugger.Destroy(self._debugger)
            self._debugger = None

    def reset_target(self) -> bool:
        """Reset the current target without destroying the debugger.

        This preserves symbol caches for faster subsequent launches.

        Returns:
            True if reset succeeded.
        """
        if self._process and self._process.IsValid():
            self._process.Kill()
            self._process = None

        if self._target and self._target.IsValid():
            self._debugger.DeleteTarget(self._target)
            self._target = None

        # Reset internal state
        self.thread_id = None
        self.frame_id = None
        self.breakpoints = []
        self.last_launch = {}
        self.last_stop_event = None

        return True

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
        """Launch a binary under LLDB."""
        self.connect()
        lldb = _get_lldb()

        # Reset if we have an existing target
        if self._target and self._target.IsValid():
            self.reset_target()

        # Create target
        error = lldb.SBError()
        self._target = self._debugger.CreateTarget(binary, None, None, True, error)
        if not self._target or not self._target.IsValid():
            return LaunchResult(
                status="error",
                error=f"Failed to create target: {error.GetCString()}",
            )

        self.last_launch = {"binary": binary, "crash_input": crash_input}

        # Build launch arguments
        launch_args: list[str] = []
        if args:
            launch_args.extend(args)
        else:
            launch_args.append("-runs=1")
        if crash_input and crash_input not in launch_args:
            launch_args.append(crash_input)

        # Build environment
        env_list: list[str] | None = None
        if env:
            env_list = [f"{k}={v}" for k, v in env.items()]

        # Launch
        launch_info = lldb.SBLaunchInfo(launch_args)
        if env_list:
            launch_info.SetEnvironmentEntries(env_list, True)
        launch_info.SetLaunchFlags(lldb.eLaunchFlagStopAtEntry if stop_on_entry else lldb.eLaunchFlagNone)

        error = lldb.SBError()
        self._process = self._target.Launch(launch_info, error)

        if not self._process or not self._process.IsValid():
            return LaunchResult(
                status="error",
                error=f"Launch failed: {error.GetCString()}",
                hint="Ensure macOS Developer Mode is enabled: DevToolsSecurity -enable",
            )

        # Wait for stop or exit
        state = self._process.GetState()

        if state == lldb.eStateExited:
            return LaunchResult(
                status="exited",
                exit_code=self._process.GetExitStatus(),
            )

        if state == lldb.eStateStopped:
            thread = self._process.GetSelectedThread()
            if thread and thread.IsValid():
                self.thread_id = thread.GetThreadID()
                frame = thread.GetSelectedFrame()
                if frame and frame.IsValid():
                    self.frame_id = frame.GetFrameID()

                stop_reason = thread.GetStopReason()
                reason_str = self._stop_reason_to_string(stop_reason)

                return LaunchResult(
                    status="stopped",
                    thread_id=self.thread_id,
                    frame_id=self.frame_id,
                    reason=reason_str,
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
        lldb = _get_lldb()

        if self._target and self._target.IsValid():
            self.reset_target()

        # Create target from program if provided
        if program:
            error = lldb.SBError()
            self._target = self._debugger.CreateTarget(program, None, None, True, error)
        else:
            self._target = self._debugger.CreateTarget("")

        if not self._target or not self._target.IsValid():
            return LaunchResult(status="error", error="Failed to create target")

        self.last_launch = {"pid": pid, "program": program, "mode": "attach"}

        # Attach
        error = lldb.SBError()
        if wait_for:
            listener = self._debugger.GetListener()
            self._process = self._target.AttachToProcessWithName(listener, program or "", True, error)
        else:
            self._process = self._target.AttachToProcessWithID(self._debugger.GetListener(), pid, error)

        if not self._process or not self._process.IsValid():
            return LaunchResult(
                status="error",
                error=f"Attach failed: {error.GetCString()}",
            )

        state = self._process.GetState()
        if state == lldb.eStateStopped:
            thread = self._process.GetSelectedThread()
            if thread and thread.IsValid():
                self.thread_id = thread.GetThreadID()
                return LaunchResult(
                    status="stopped",
                    thread_id=self.thread_id,
                    reason=self._stop_reason_to_string(thread.GetStopReason()),
                )

        return LaunchResult(status="running")

    def load_core(
        self,
        core_path: str,
        program: str | None = None,
    ) -> LaunchResult:
        """Load a core file for post-mortem analysis."""
        self.connect()
        lldb = _get_lldb()

        if self._target and self._target.IsValid():
            self.reset_target()

        # Create target
        error = lldb.SBError()
        if program:
            self._target = self._debugger.CreateTarget(program, None, None, True, error)
        else:
            self._target = self._debugger.CreateTarget("")

        if not self._target or not self._target.IsValid():
            return LaunchResult(status="error", error="Failed to create target")

        self.last_launch = {"core_file": core_path, "program": program, "mode": "core"}

        # Load core
        self._process = self._target.LoadCore(core_path, error)

        if not self._process or not self._process.IsValid():
            return LaunchResult(
                status="error",
                error=f"Failed to load core: {error.GetCString()}",
            )

        thread = self._process.GetSelectedThread()
        if thread and thread.IsValid():
            self.thread_id = thread.GetThreadID()
            return LaunchResult(
                status="stopped",
                thread_id=self.thread_id,
                reason="core",
            )

        return LaunchResult(status="stopped")

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
        if not self._process or not self._process.IsValid():
            raise RuntimeError("No active process")

        lldb = _get_lldb()
        error = self._process.Continue()
        if error.Fail():
            raise RuntimeError(f"Continue failed: {error.GetCString()}")

        if not wait:
            return None

        # Wait for stop
        state = self._process.GetState()
        if state == lldb.eStateStopped:
            thread = self._process.GetSelectedThread()
            if thread and thread.IsValid():
                self.thread_id = thread.GetThreadID()
                reason = self._stop_reason_to_string(thread.GetStopReason())
                return StopEvent(
                    reason=reason,
                    thread_id=self.thread_id,
                )

        return None

    def step(
        self,
        kind: str = "over",
        count: int = 1,
        thread_id: int | None = None,
    ) -> StopEvent | None:
        """Step execution."""
        if not self._process or not self._process.IsValid():
            raise RuntimeError("No active process")

        thread = self._get_thread(thread_id)
        if not thread:
            raise RuntimeError("No valid thread")

        for _ in range(max(1, count)):
            if kind == "into":
                thread.StepInto()
            elif kind == "over":
                thread.StepOver()
            elif kind == "out":
                thread.StepOut()
            elif kind == "instruction":
                thread.StepInstruction(False)
            else:
                thread.StepOver()

        reason = self._stop_reason_to_string(thread.GetStopReason())
        self.thread_id = thread.GetThreadID()

        return StopEvent(
            reason=reason,
            thread_id=self.thread_id,
        )

    def set_breakpoint(
        self,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        condition: str | None = None,
    ) -> BreakpointResult:
        """Set a breakpoint."""
        if not self._target or not self._target.IsValid():
            return BreakpointResult(message="No active target")

        bp = None

        if function:
            bp = self._target.BreakpointCreateByName(function)
        elif address:
            addr_int = int(address, 16) if address.startswith("0x") else int(address)
            bp = self._target.BreakpointCreateByAddress(addr_int)
        elif file and line:
            bp = self._target.BreakpointCreateByLocation(file, line)

        if not bp or not bp.IsValid():
            return BreakpointResult(message="Failed to create breakpoint")

        if condition:
            bp.SetCondition(condition)

        bp_id = bp.GetID()
        self.breakpoints.append(f"bp_{bp_id}")

        return BreakpointResult(
            id=bp_id,
            verified=bp.GetNumLocations() > 0,
            message=f"Breakpoint {bp_id} set with {bp.GetNumLocations()} location(s)",
        )

    # =========================================================================
    # Inspection
    # =========================================================================

    def execute_command(self, command: str) -> str:
        """Execute a raw LLDB command."""
        if not self._debugger:
            return "Error: Debugger not initialized"

        lldb = _get_lldb()
        result = lldb.SBCommandReturnObject()
        self._debugger.GetCommandInterpreter().HandleCommand(command, result)

        output = result.GetOutput() or ""
        error = result.GetError() or ""

        return output + error if error else output

    def get_threads(self) -> list[ThreadInfo]:
        """Get list of threads."""
        if not self._process or not self._process.IsValid():
            return []

        threads = []

        for i in range(self._process.GetNumThreads()):
            thread = self._process.GetThreadAtIndex(i)
            if thread and thread.IsValid():
                threads.append(
                    ThreadInfo(
                        id=thread.GetThreadID(),
                        name=thread.GetName() or f"Thread {thread.GetIndexID()}",
                        stopped=thread.IsStopped(),
                    )
                )

        return threads

    def get_backtrace(
        self,
        thread_id: int | None = None,
        max_frames: int = 32,
    ) -> list[StackFrame]:
        """Get stack backtrace."""
        thread = self._get_thread(thread_id)
        if not thread:
            return []

        frames = []
        for i in range(min(thread.GetNumFrames(), max_frames)):
            frame = thread.GetFrameAtIndex(i)
            if not frame or not frame.IsValid():
                continue

            pc = frame.GetPC()
            func = frame.GetFunction()
            symbol = frame.GetSymbol()

            name = ""
            if func and func.IsValid():
                name = func.GetName() or ""
            elif symbol and symbol.IsValid():
                name = symbol.GetName() or ""

            line_entry = frame.GetLineEntry()
            source_path = None
            line_num = None
            column = None

            if line_entry and line_entry.IsValid():
                file_spec = line_entry.GetFileSpec()
                if file_spec and file_spec.IsValid():
                    source_path = str(file_spec)
                line_num = line_entry.GetLine()
                column = line_entry.GetColumn()

            module = frame.GetModule()
            module_name = None
            if module and module.IsValid():
                module_name = module.GetFileSpec().GetFilename()

            frames.append(
                StackFrame(
                    id=i,
                    name=name,
                    line=line_num,
                    column=column,
                    source_path=source_path,
                    instruction_pointer=f"0x{pc:x}",
                    module_name=module_name,
                )
            )

        return frames

    def read_memory(
        self,
        address: int | str,
        size: int,
    ) -> bytes:
        """Read memory at address."""
        if not self._process or not self._process.IsValid():
            raise MemoryError("No active process")

        lldb = _get_lldb()

        if isinstance(address, str):
            if address.startswith("0x"):
                addr_int = int(address, 16)
            else:
                addr_int = int(address)
        else:
            addr_int = address

        error = lldb.SBError()
        data = self._process.ReadMemory(addr_int, size, error)

        if error.Fail():
            raise MemoryError(f"Read failed: {error.GetCString()}")

        return bytes(data) if data else b""

    def read_register(self, register: str | None = None) -> dict[str, Any]:
        """Read register(s)."""
        thread = self._get_thread()
        if not thread:
            return {"error": "No valid thread"}

        frame = thread.GetSelectedFrame()
        if not frame or not frame.IsValid():
            return {"error": "No valid frame"}

        registers = frame.GetRegisters()
        result: dict[str, Any] = {}

        for reg_set in registers:
            for reg in reg_set:
                name = reg.GetName()
                if register and name != register:
                    continue
                value = reg.GetValue()
                result[name] = value

        return result

    def write_register(self, register: str, value: str | int) -> bool:
        """Write to a register."""
        # Use LLDB command for simplicity
        if isinstance(value, int):
            value = f"0x{value:x}"
        output = self.execute_command(f"register write {register} {value}")
        return "error" not in output.lower()

    def evaluate(
        self,
        expression: str,
        frame_id: int | None = None,
    ) -> Any:
        """Evaluate an expression."""
        thread = self._get_thread()
        if not thread:
            raise RuntimeError("No valid thread")

        frame = thread.GetSelectedFrame()
        if frame_id is not None:
            frame = thread.GetFrameAtIndex(frame_id)

        if not frame or not frame.IsValid():
            raise RuntimeError("No valid frame")

        result = frame.EvaluateExpression(expression)
        if result and result.IsValid():
            return result.GetValue()
        return None

    # =========================================================================
    # Fast Stack Hash (Performance-Critical)
    # =========================================================================

    def compute_stack_hash(self, max_frames: int = 5) -> tuple[str, list[str]]:
        """Compute a hash of the top stack frames for crash deduplication.

        This is the performance-critical method - SBAPI is ~100x faster than DAP here.

        Returns:
            Tuple of (hash_hex, list_of_pc_addresses)
        """
        thread = self._get_thread()
        if not thread:
            return "", []

        pcs: list[str] = []
        for i in range(min(thread.GetNumFrames(), max_frames)):
            frame = thread.GetFrameAtIndex(i)
            if frame and frame.IsValid():
                pc = _strip_pac(frame.GetPC())
                pcs.append(f"0x{pc:x}")

        if not pcs:
            return "", []

        h = hashlib.sha256("|".join(pcs).encode()).hexdigest()
        return h, pcs

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _get_thread(self, thread_id: int | None = None) -> lldb_module.SBThread | None:
        """Get a thread by ID or the selected thread."""
        if not self._process or not self._process.IsValid():
            return None

        if thread_id is not None:
            for i in range(self._process.GetNumThreads()):
                thread = self._process.GetThreadAtIndex(i)
                if thread and thread.GetThreadID() == thread_id:
                    return thread

        return self._process.GetSelectedThread()

    def _stop_reason_to_string(self, stop_reason: int) -> str:
        """Convert LLDB stop reason to string."""
        lldb = _get_lldb()

        reason_map = {
            lldb.eStopReasonInvalid: "invalid",
            lldb.eStopReasonNone: "none",
            lldb.eStopReasonTrace: "trace",
            lldb.eStopReasonBreakpoint: "breakpoint",
            lldb.eStopReasonWatchpoint: "watchpoint",
            lldb.eStopReasonSignal: "signal",
            lldb.eStopReasonException: "exception",
            lldb.eStopReasonExec: "exec",
            lldb.eStopReasonPlanComplete: "plan_complete",
            lldb.eStopReasonThreadExiting: "thread_exiting",
            lldb.eStopReasonInstrumentation: "instrumentation",
        }

        return reason_map.get(stop_reason, f"unknown_{stop_reason}")
