"""
Mock LLDB backend for testing and verification without native tools.
"""

from __future__ import annotations

import logging
import os
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


class MockBackend(LLDBBackend):
    """A mock backend that simulates an LLDB session.

    Useful for:
    - Verifying higher-level agent logic without binaries.
    - Testing crash reporting pipelines.
    - CI/CD where LLDB/macOS is unavailable.
    """

    def __init__(self, timeout: float = 30.0, **kwargs):
        super().__init__(timeout=timeout)
        self._connected = False
        self._mock_memory: dict[int, bytes] = {}
        self.scenario = kwargs.get("scenario", "default")
        
        # State
        self.thread_id = 1
        self.frame_id = 0

    @property
    def name(self) -> str:
        return "mock"

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        logger.info("MockBackend: Connected")
        self._connected = True

    def disconnect(self) -> None:
        logger.info("MockBackend: Disconnected")
        self._connected = False

    def launch(
        self,
        binary: str,
        args: list[str] | None = None,
        crash_input: str | None = None,
        stop_on_entry: bool = False,
        env: dict[str, str] | None = None,
    ) -> LaunchResult:
        self.connect()
        
        logger.info(f"MockBackend: Launching {binary} with input {crash_input}")
        self.last_launch = {"binary": binary, "crash_input": crash_input}
        
        # Simulate stopping at entry or crashing immediately depending on scenario
        if stop_on_entry:
            reason = "entry"
            self.last_stop_event = StopEvent(
                reason=reason,
                thread_id=1,
                frame_id=0,
                description="Stopped at entry",
                all_threads_stopped=True
            )
            return LaunchResult(
                status="stopped",
                thread_id=1,
                frame_id=0,
                reason=reason
            )
        else:
            # Simulate a crash run
            return self._simulate_crash()

    def attach(
        self,
        pid: int,
        program: str | None = None,
        wait_for: bool = False,
    ) -> LaunchResult:
        self.connect()
            
        logger.info(f"MockBackend: Attaching to {pid}")
        self.last_launch = {"pid": pid, "mode": "attach"}
        
        # Simulate stop on attach
        self.last_stop_event = StopEvent(
            reason="signal",
            thread_id=1,
            frame_id=0,
            description="Stopped (SIGSTOP)",
            all_threads_stopped=True
        )
        return LaunchResult(
            status="stopped",
            thread_id=1,
            frame_id=0,
            reason="signal"
        )

    def load_core(
        self,
        core_path: str,
        program: str | None = None,
    ) -> LaunchResult:
        if not self._connected:
            return LaunchResult(status="error", error="Not connected")
            
        logger.info(f"MockBackend: Loading core {core_path}")
        return self._simulate_crash()

    def _simulate_crash(self) -> LaunchResult:
        # Simulate a SEGFAULT at a specific address
        reason = "exception"
        self.last_stop_event = StopEvent(
            reason=reason,
            thread_id=1,
            frame_id=0,
            description="EXC_BAD_ACCESS (code=1, address=0xdeadbeef)",
            all_threads_stopped=True
        )
        # Also simulate "recording" the crash since base class logic usually does this
        # But base class record_crash is manually called by Director usually.
        return LaunchResult(
            status="stopped",
            thread_id=1,
            frame_id=0,
            reason=reason
        )

    def continue_execution(
        self,
        thread_id: int | None = None,
        wait: bool = True,
        timeout: float | None = None,
    ) -> StopEvent | None:
        if not self._connected:
            return None
        
        logger.info("MockBackend: Continuing...")
        # If we were at entry, now we crash
        if self.last_stop_event and self.last_stop_event.reason == "entry":
             self._simulate_crash()
             return self.last_stop_event
        
        # Already crashed? Stay crashed or exit
        if self.last_stop_event and self.is_crash_reason(self.last_stop_event.reason):
             # Maybe restart? Or just return same crash?
             # Real LLDB might let you continue after crash to see if it handles signal?
             return self.last_stop_event

        return self.last_stop_event

    def step(
        self,
        kind: str = "over",
        count: int = 1,
        thread_id: int | None = None,
    ) -> StopEvent | None:
        if not self._connected:
            return None
        logger.info(f"MockBackend: Stepping {kind} x{count}")
        return self.last_stop_event

    def set_breakpoint(
        self,
        function: str | None = None,
        address: str | None = None,
        file: str | None = None,
        line: int | None = None,
        condition: str | None = None,
    ) -> BreakpointResult:
        logger.info("MockBackend: Setting breakpoint")
        self.breakpoints.append(f"{function or address or file}")
        return BreakpointResult(id=1, verified=True, message="Mock BP Set")

    def execute_command(self, command: str) -> str:
        logger.info(f"MockBackend: Executing '{command}'")
        if "register read" in command:
            return "x0 = 0x0000000000000000\npc = 0x0000000100003f40"
        if "disassemble" in command:
            return "0x100003f40:  str    x0, [x1]  ; CRASH HERE"
        if "memory read" in command:
             return "00 00 00 00 00 00 00 00"
        return f"Mock output for: {command}"

    def get_threads(self) -> list[ThreadInfo]:
        return [ThreadInfo(id=1, name="Thread 1 (Mock)", stopped=True)]

    def get_backtrace(
        self,
        thread_id: int | None = None,
        max_frames: int = 32,
    ) -> list[StackFrame]:
        # Return a fake backtrace
        return [
            StackFrame(id=0, name="func_crash", instruction_pointer="0x100003f40", source_path="/tmp/test.c", line=10),
            StackFrame(id=1, name="main", instruction_pointer="0x100003f00", source_path="/tmp/test.c", line=20),
            StackFrame(id=2, name="start", instruction_pointer="0x100001000", source_path=None, line=None),
        ]

    def read_memory(
        self,
        address: int | str,
        size: int,
    ) -> bytes:
        return b"\x00" * size

    def read_register(self, register: str | None = None) -> dict[str, Any]:
        return {"x0": "0x0", "pc": "0x100003f40", "sp": "0x16fdff000"}

    def write_register(self, register: str, value: str | int) -> bool:
        return True

    def evaluate(
        self,
        expression: str,
        frame_id: int | None = None,
    ) -> Any:
        return f"MockEval({expression})"

    # =========================================================================
    # Kernel / remote helpers (deterministic stubs)
    # =========================================================================

    def attach_gdb_remote(
        self,
        host: str,
        port: int,
        target: str | None = None,
        arch: str | None = None,
        plugin: str | None = None,
    ) -> LaunchResult:
        self.connect()
        self.last_launch = {
            "host": host,
            "port": int(port),
            "program": target,
            "arch": arch,
            "plugin": plugin,
            "mode": self.SESSION_KIND_GDB_REMOTE,
        }
        self.last_stop_event = StopEvent(
            reason="signal",
            thread_id=1,
            frame_id=0,
            description=f"Mock gdb-remote attach to {host}:{port}",
            all_threads_stopped=True,
        )
        return LaunchResult(status="stopped", thread_id=1, frame_id=0, reason="signal")

    def add_module(
        self,
        path: str,
        dsym: str | None = None,
        slide: int | None = None,
        load_addr: int | None = None,
    ) -> dict[str, Any]:
        basename = os.path.basename(path)
        return {
            "module": basename,
            "path": path,
            "dsym": dsym,
            "loaded": True,
            "output": f"Mock add_module({path}, dsym={dsym}, slide={slide}, load_addr={load_addr})",
        }

    def get_module_slide(self, module: str | None = None) -> int | None:
        return 0x100000

    def write_memory(self, address: int | str, data: bytes) -> int:
        if isinstance(address, str):
            key = int(address, 16) if address.lower().startswith("0x") else 0
        else:
            key = int(address)
        self._mock_memory[key] = bytes(data)
        return len(data)

    def interrupt(self, timeout: float | None = None) -> StopEvent | None:
        self.last_stop_event = StopEvent(
            reason="signal",
            thread_id=1,
            frame_id=0,
            description="Mock interrupt",
            all_threads_stopped=True,
        )
        return self.last_stop_event

    def is_running(self) -> bool:
        return self.last_stop_event is None
