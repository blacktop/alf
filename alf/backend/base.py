"""
Abstract LLDB backend interface.

The backend abstraction allows different LLDB connection methods:
- DAP: Connect to lldb-dap via Debug Adapter Protocol (current implementation)
- Native MCP: Future native LLVM MCP support
- Remote: SSH/remote LLDB connections

All tool handlers operate on a backend instance, making them independent
of the underlying connection mechanism.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StopEvent:
    """Represents a debugger stop event."""

    reason: str
    thread_id: int | None = None
    frame_id: int | None = None
    description: str | None = None
    all_threads_stopped: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class LaunchResult:
    """Result of launching or attaching to a target."""

    status: str  # "stopped", "running", "exited", "terminated", "error"
    thread_id: int | None = None
    frame_id: int | None = None
    reason: str | None = None
    exit_code: int | None = None
    error: str | None = None
    hint: str | None = None


@dataclass
class StackFrame:
    """Represents a stack frame."""

    id: int
    name: str
    line: int | None = None
    column: int | None = None
    source_path: str | None = None
    instruction_pointer: str | None = None
    module_name: str | None = None


@dataclass
class ThreadInfo:
    """Represents a thread."""

    id: int
    name: str
    stopped: bool = False


@dataclass
class BreakpointResult:
    """Result of setting a breakpoint."""

    id: int | None = None
    verified: bool = False
    message: str | None = None
    locations: list[dict[str, Any]] = field(default_factory=list)


class BackendUnsupportedError(RuntimeError):
    """Raised when a backend does not implement an optional capability."""


class LLDBBackend(ABC):
    """Abstract base class for LLDB backends.

    All backends must implement these methods to provide debugger functionality.
    The interface is designed to be minimal yet complete for fuzzing and
    crash analysis use cases.
    """

    # Session-kind values recorded on last_launch["mode"] so teardown can
    # distinguish between launched (owned) and attached (remote) inferiors.
    SESSION_KIND_LAUNCH: str = "launch"
    SESSION_KIND_ATTACH: str = "attach"
    SESSION_KIND_CORE: str = "core"
    SESSION_KIND_GDB_REMOTE: str = "gdb_remote"

    def __init__(self, timeout: float = 30.0):
        """Initialize the backend.

        Args:
            timeout: Default timeout for operations in seconds.
        """
        self.timeout = timeout
        self._lock = threading.Lock()

        # Current state
        self.thread_id: int | None = None
        self.frame_id: int | None = None
        self.breakpoints: list[str] = []
        self.last_launch: dict[str, Any] = {}

        # Cached adapter capabilities from DAP `initialize` response (or
        # equivalent). Populated by backends that support capability probing.
        self.capabilities: dict[str, Any] = {}

        # Crash tracking
        self.seen_crash_hashes: set[str] = set()
        self.pending_crashes: list[dict[str, Any]] = []
        self.last_stop_event: StopEvent | None = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the backend name (e.g., 'dap', 'native_mcp')."""
        ...

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Return True if connected to the debugger."""
        ...

    # =========================================================================
    # Connection Management
    # =========================================================================

    @abstractmethod
    def connect(self) -> None:
        """Connect to the debugger backend.

        Raises:
            ConnectionError: If connection fails.
        """
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from the debugger backend."""
        ...

    # =========================================================================
    # Session Management
    # =========================================================================

    @abstractmethod
    def launch(
        self,
        binary: str,
        args: list[str] | None = None,
        crash_input: str | None = None,
        stop_on_entry: bool = False,
        env: dict[str, str] | None = None,
    ) -> LaunchResult:
        """Launch a binary under the debugger.

        Args:
            binary: Path to the executable.
            args: Command-line arguments.
            crash_input: Path to crash input file (added to args).
            stop_on_entry: Stop at entry point instead of running.
            env: Environment variables.

        Returns:
            LaunchResult with status and context.
        """
        ...

    @abstractmethod
    def attach(
        self,
        pid: int,
        program: str | None = None,
        wait_for: bool = False,
    ) -> LaunchResult:
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.
            program: Optional path to executable (for symbols).
            wait_for: Wait for process to start.

        Returns:
            LaunchResult with status and context.
        """
        ...

    @abstractmethod
    def load_core(
        self,
        core_path: str,
        program: str | None = None,
    ) -> LaunchResult:
        """Load a core file for post-mortem analysis.

        Args:
            core_path: Path to core dump file.
            program: Optional path to executable (for symbols).

        Returns:
            LaunchResult with status and context.
        """
        ...

    # =========================================================================
    # Execution Control
    # =========================================================================

    @abstractmethod
    def continue_execution(
        self,
        thread_id: int | None = None,
        wait: bool = True,
        timeout: float | None = None,
    ) -> StopEvent | None:
        """Continue execution.

        Args:
            thread_id: Specific thread to continue (None = all).
            wait: Wait for next stop event.
            timeout: Override default timeout.

        Returns:
            StopEvent if stopped, None if still running.
        """
        ...

    @abstractmethod
    def step(
        self,
        kind: str = "over",
        count: int = 1,
        thread_id: int | None = None,
    ) -> StopEvent | None:
        """Step execution.

        Args:
            kind: Step type ("into", "over", "out", "instruction").
            count: Number of steps.
            thread_id: Specific thread to step.

        Returns:
            StopEvent after stepping.
        """
        ...

    @abstractmethod
    def set_breakpoint(
        self,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        condition: str | None = None,
    ) -> BreakpointResult:
        """Set a breakpoint.

        Args:
            function: Function name to break on.
            address: Address to break at.
            file: Source file for file+line breakpoint.
            line: Line number for file+line breakpoint.
            condition: Optional breakpoint condition.

        Returns:
            BreakpointResult with breakpoint info.
        """
        ...

    # =========================================================================
    # Inspection
    # =========================================================================

    @abstractmethod
    def execute_command(self, command: str) -> str:
        """Execute a raw LLDB command.

        Args:
            command: LLDB command string.

        Returns:
            Command output as string.
        """
        ...

    @abstractmethod
    def get_threads(self) -> list[ThreadInfo]:
        """Get list of threads in the target.

        Returns:
            List of ThreadInfo objects.
        """
        ...

    @abstractmethod
    def get_backtrace(
        self,
        thread_id: int | None = None,
        max_frames: int = 32,
    ) -> list[StackFrame]:
        """Get stack backtrace.

        Args:
            thread_id: Thread to get backtrace for (None = current).
            max_frames: Maximum number of frames.

        Returns:
            List of StackFrame objects.
        """
        ...

    @abstractmethod
    def read_memory(
        self,
        address: int | str,
        size: int,
    ) -> bytes:
        """Read memory at address.

        Args:
            address: Memory address (int or hex string).
            size: Number of bytes to read.

        Returns:
            Raw bytes.

        Raises:
            MemoryError: If read fails.
        """
        ...

    @abstractmethod
    def read_register(self, register: str | None = None) -> dict[str, Any]:
        """Read register(s).

        Args:
            register: Specific register name (None = all).

        Returns:
            Dict mapping register names to values.
        """
        ...

    @abstractmethod
    def write_register(self, register: str, value: str | int) -> bool:
        """Write to a register.

        Args:
            register: Register name.
            value: Value to write.

        Returns:
            True if successful.
        """
        ...

    @abstractmethod
    def evaluate(
        self,
        expression: str,
        frame_id: int | None = None,
    ) -> Any:
        """Evaluate an expression in the debugger.

        Args:
            expression: Expression to evaluate.
            frame_id: Frame context for evaluation.

        Returns:
            Evaluation result.
        """
        ...

    # =========================================================================
    # Utility Methods (with default implementations)
    # =========================================================================

    def select_thread(self, thread_id: int) -> None:
        """Select a thread for subsequent operations."""
        self.thread_id = thread_id

    def select_frame(self, frame_id: int) -> None:
        """Select a frame for subsequent operations."""
        self.frame_id = frame_id

    def get_status(self) -> dict[str, Any]:
        """Get current debugger status."""
        return {
            "backend": self.name,
            "connected": self.connected,
            "binary": self.last_launch.get("binary"),
            "thread_id": self.thread_id,
            "frame_id": self.frame_id,
            "breakpoints": self.breakpoints,
            "mode": self.last_launch.get("mode"),
        }

    def should_terminate_debuggee(self) -> bool:
        """Return True when teardown should terminate the debuggee.

        Launched / core-loaded sessions own the inferior and should kill it;
        attach and gdb-remote sessions must detach so a remote inferior
        keeps running.
        """
        return self.last_launch.get("mode") not in (
            self.SESSION_KIND_ATTACH,
            self.SESSION_KIND_GDB_REMOTE,
        )

    # =========================================================================
    # Optional capability helpers (kernel / remote debugging)
    # =========================================================================
    #
    # These are intentionally non-abstract. Backends that cannot support the
    # operation raise BackendUnsupportedError with a clear message so callers
    # can surface an actionable error instead of silently degrading.

    def attach_gdb_remote(
        self,
        host: str,
        port: int,
        target: str | None = None,
        arch: str | None = None,
        plugin: str | None = None,
    ) -> LaunchResult:
        """Attach to a gdb-remote stub (e.g. VZ hypervisor, QEMU gdbstub).

        Args:
            host: gdb-remote host.
            port: gdb-remote port.
            target: Optional path to kernel/binary/dSYM for symbols.
            arch: Optional architecture override (e.g. "arm64e").
            plugin: Optional process plugin ("gdb-remote", "kdp-remote").

        Returns:
            LaunchResult after attach handshake.
        """
        raise BackendUnsupportedError(
            f"{self.name} backend does not implement attach_gdb_remote"
        )

    def add_module(
        self,
        path: str,
        dsym: str | None = None,
        slide: int | None = None,
        load_addr: int | None = None,
    ) -> dict[str, Any]:
        """Add a module and optional dSYM to the current target.

        Args:
            path: Path to the executable/kernel/kext.
            dsym: Optional path to a companion dSYM bundle.
            slide: Optional constant slide to apply when loading.
            load_addr: Optional explicit load address (alternative to slide).

        Returns:
            Dict with at least "module" and "loaded" keys.
        """
        raise BackendUnsupportedError(
            f"{self.name} backend does not implement add_module"
        )

    def get_module_slide(self, module: str | None = None) -> int | None:
        """Return the runtime slide (load_addr - link_addr) for a module.

        Args:
            module: Module basename or path. None uses the main executable.

        Returns:
            Slide as an integer, or None if it cannot be determined.
        """
        raise BackendUnsupportedError(
            f"{self.name} backend does not implement get_module_slide"
        )

    def write_memory(self, address: int | str, data: bytes) -> int:
        """Write bytes to target memory.

        Args:
            address: Destination address (int or hex/sym string).
            data: Raw bytes to write.

        Returns:
            Number of bytes written.
        """
        raise BackendUnsupportedError(
            f"{self.name} backend does not implement write_memory"
        )

    def interrupt(self, timeout: float | None = None) -> StopEvent | None:
        """Interrupt (pause) the running target.

        Used for kernel debugging flows that need to briefly halt the guest
        to read or write state and then resume. Backends that cannot halt
        a running target raise BackendUnsupportedError.

        Returns:
            StopEvent captured after the interrupt, or None on timeout.
        """
        raise BackendUnsupportedError(
            f"{self.name} backend does not implement interrupt"
        )

    def is_running(self) -> bool:
        """Return True when the target appears to be executing.

        Default uses last_stop_event as a hint; backends with explicit
        process state should override.
        """
        if not self.connected:
            return False
        return self.last_stop_event is None

    def is_crash_reason(self, reason: str) -> bool:
        """Check if a stop reason indicates a crash.

        Includes 'exited' for ASAN crashes that terminate before stopping.
        """
        r = (reason or "").lower()
        return any(key in r for key in ("exception", "signal", "crash", "fatal", "exited"))

    def pop_pending_crashes(self, limit: int = 5) -> list[dict[str, Any]]:
        """Pop pending crash events."""
        if limit <= 0:
            out = list(self.pending_crashes)
            self.pending_crashes.clear()
            return out
        out = self.pending_crashes[:limit]
        self.pending_crashes = self.pending_crashes[limit:]
        return out

    # =========================================================================
    # Common Crash Analysis (Default Implementations)
    # =========================================================================

    def compute_stack_hash(self, max_frames: int = 5) -> tuple[str, list[str]]:
        """Compute a hash of the top stack frames for crash deduplication.

        This default implementation uses get_backtrace() and the shared
        stack_hash utilities. Subclasses may override for better performance.

        Args:
            max_frames: Maximum number of frames to include in the hash.

        Returns:
            Tuple of (hash_hex, list_of_pc_addresses).
        """
        from ..utils.stack_hash import stack_hash_from_frames

        frames = self.get_backtrace(max_frames=max_frames)

        # Convert StackFrame objects to dicts for stack_hash_from_frames
        frame_dicts = [
            {"instruction_pointer": f.instruction_pointer}
            for f in frames
            if f.instruction_pointer
        ]

        return stack_hash_from_frames(frame_dicts, max_frames=max_frames)

    def collect_crash_context(self) -> dict[str, Any]:
        """Collect comprehensive crash context for triage and reporting.

        This default implementation uses the abstract methods to gather:
        - Stop reason
        - Registers
        - Backtrace with stack hash
        - Disassembly (if available)
        - Stack memory (if available)

        Subclasses may override for backend-specific optimizations.

        Returns:
            Dictionary with crash context data.
        """
        context: dict[str, Any] = {}

        # Stop reason from last_stop_event
        if self.last_stop_event:
            context["stop"] = {
                "reason": self.last_stop_event.reason,
                "description": self.last_stop_event.description,
                "thread_id": self.last_stop_event.thread_id,
            }

        # Registers
        try:
            context["registers"] = self.read_register()
        except Exception:
            context["registers"] = {}

        # Backtrace and frames
        try:
            frames = self.get_backtrace(max_frames=32)
            context["frames"] = [
                {
                    "pc": f.instruction_pointer,
                    "name": f.name,
                    "file": f.source_path,
                    "line": f.line,
                    "module": f.module_name,
                }
                for f in frames
            ]
            context["pcs"] = [f.instruction_pointer for f in frames if f.instruction_pointer]
        except Exception:
            context["frames"] = []
            context["pcs"] = []

        # Stack hash
        hash_val, pcs = self.compute_stack_hash(max_frames=5)
        context["stack_hash"] = hash_val
        if not context["pcs"]:
            context["pcs"] = pcs

        # Disassembly (best effort)
        try:
            context["disassemble"] = self.execute_command("disassemble --pc --count 10")
        except Exception:
            pass

        # Stack bytes (best effort)
        try:
            context["stack_bytes"] = self.execute_command("memory read $sp --count 64 --format x")
        except Exception:
            pass

        return context

    def record_crash(self, crash_input: str | None = None) -> dict[str, Any] | None:
        """Record a crash event if stopped due to crash.

        Checks if the current stop is a crash, collects context, and
        deduplicates based on stack hash.

        Args:
            crash_input: Optional path to the crash input file.

        Returns:
            Crash entry dict if this is a new unique crash, None otherwise.
        """
        import time

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
            "crash_input": crash_input,
            "context": context,
            "timestamp": time.time(),
        }

        self.pending_crashes.append(crash_entry)
        return crash_entry
