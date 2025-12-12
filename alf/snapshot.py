#!/usr/bin/env python3
"""
Process snapshotting for fast fuzzing iteration.

This module provides lightweight process snapshots using LLDB's SBAPI
to save and restore memory regions and register state. Unlike core files,
these snapshots can be restored to a live process for continued execution.

Usage:
    from alf.snapshot import ProcessSnapshot

    # Create snapshot at checkpoint
    snapshot = ProcessSnapshot.capture(process, frame)

    # For each iteration:
    snapshot.restore(process, frame)  # Reset state
    # ... mutate input ...
    process.Continue()  # Run iteration
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass  # lldb types are dynamic


@dataclass
class MemoryRegion:
    """A saved memory region."""

    address: int
    size: int
    data: bytes
    permissions: str  # e.g., "rwx", "r-x"


@dataclass
class RegisterState:
    """Saved register state."""

    values: dict[str, str]  # name -> hex string value


@dataclass
class ProcessSnapshot:
    """A restorable process snapshot.

    Captures:
    - All writable memory regions
    - All register values for the current thread

    Can be restored to reset process state between fuzzing iterations.
    """

    registers: RegisterState
    memory_regions: list[MemoryRegion]
    capture_time: float
    pc: int  # Program counter at capture
    function_name: str | None = None

    @classmethod
    def capture_minimal(
        cls,
        process: Any,  # lldb.SBProcess
        frame: Any,  # lldb.SBFrame
        input_address: int,
        input_size: int,
        stack_bytes: int = 4096,  # Capture stack around current SP
    ) -> ProcessSnapshot:
        """Capture a minimal snapshot (input buffer + stack + registers).

        Much faster than full capture, suitable for rapid fuzzing.

        Args:
            process: LLDB SBProcess instance.
            frame: LLDB SBFrame for register access.
            input_address: Address of input buffer.
            input_size: Size of input buffer.
            stack_bytes: Bytes of stack to capture around SP.

        Returns:
            Minimal ProcessSnapshot.
        """
        import lldb

        capture_start = time.time()

        # Capture registers
        reg_values: dict[str, str] = {}
        for reg_set in frame.GetRegisters():
            for reg in reg_set:
                if reg.IsValid() and reg.GetValue():
                    reg_values[reg.GetName()] = reg.GetValue()

        registers = RegisterState(values=reg_values)

        # Capture only essential memory regions
        memory_regions: list[MemoryRegion] = []
        err = lldb.SBError()

        # 1. Input buffer
        input_data = process.ReadMemory(input_address, input_size, err)
        if err.Success() and input_data:
            memory_regions.append(
                MemoryRegion(
                    address=input_address,
                    size=input_size,
                    data=input_data,
                    permissions="rw-",
                )
            )

        # 2. Stack around current SP
        sp = frame.FindRegister("sp").GetValueAsUnsigned()
        # Capture stack_bytes above SP (stack grows down on ARM64)
        stack_start = sp
        stack_data = process.ReadMemory(stack_start, stack_bytes, err)
        if err.Success() and stack_data:
            memory_regions.append(
                MemoryRegion(
                    address=stack_start,
                    size=stack_bytes,
                    data=stack_data,
                    permissions="rw-",
                )
            )

        pc = frame.GetPC()
        func_name = frame.GetFunctionName()

        return cls(
            registers=registers,
            memory_regions=memory_regions,
            capture_time=time.time() - capture_start,
            pc=pc,
            function_name=func_name,
        )

    @classmethod
    def capture(
        cls,
        process: Any,  # lldb.SBProcess
        frame: Any,  # lldb.SBFrame
        include_readonly: bool = False,
        max_region_size: int = 64 * 1024 * 1024,  # 64MB max per region
    ) -> ProcessSnapshot:
        """Capture a snapshot of the current process state.

        Args:
            process: LLDB SBProcess instance.
            frame: LLDB SBFrame for register access.
            include_readonly: Whether to save read-only regions.
            max_region_size: Skip regions larger than this.

        Returns:
            ProcessSnapshot that can be restored later.
        """
        import lldb

        capture_start = time.time()

        # Capture registers
        reg_values: dict[str, str] = {}
        for reg_set in frame.GetRegisters():
            for reg in reg_set:
                if reg.IsValid() and reg.GetValue():
                    reg_values[reg.GetName()] = reg.GetValue()

        registers = RegisterState(values=reg_values)

        # Capture writable memory regions
        memory_regions: list[MemoryRegion] = []
        region_list = process.GetMemoryRegions()
        err = lldb.SBError()

        for i in range(region_list.GetSize()):
            region = lldb.SBMemoryRegionInfo()
            region_list.GetMemoryRegionAtIndex(i, region)

            # Skip non-writable regions unless requested
            if not region.IsWritable() and not include_readonly:
                continue

            # Skip unmapped regions
            if not region.IsMapped():
                continue

            base = region.GetRegionBase()
            end = region.GetRegionEnd()
            size = end - base

            # Skip huge regions (shared libs, etc.)
            if size > max_region_size:
                continue

            # Skip kernel/system regions (high addresses)
            if base > 0x700000000000:
                continue

            # Read memory
            data = process.ReadMemory(base, size, err)
            if not err.Success() or not data:
                continue

            # Build permissions string
            perms = ""
            perms += "r" if region.IsReadable() else "-"
            perms += "w" if region.IsWritable() else "-"
            perms += "x" if region.IsExecutable() else "-"

            memory_regions.append(
                MemoryRegion(
                    address=base,
                    size=size,
                    data=data,
                    permissions=perms,
                )
            )

        pc = frame.GetPC()
        func_name = frame.GetFunctionName()

        return cls(
            registers=registers,
            memory_regions=memory_regions,
            capture_time=time.time() - capture_start,
            pc=pc,
            function_name=func_name,
        )

    def restore(
        self,
        process: Any,  # lldb.SBProcess
        frame: Any,  # lldb.SBFrame
        restore_pc: bool = True,
    ) -> tuple[int, int]:
        """Restore this snapshot to the process.

        Args:
            process: LLDB SBProcess instance.
            frame: LLDB SBFrame for register access.
            restore_pc: Whether to restore the program counter.

        Returns:
            Tuple of (regions_restored, registers_restored).
        """
        import lldb

        err = lldb.SBError()

        # Restore memory regions
        regions_restored = 0
        for region in self.memory_regions:
            bytes_written = process.WriteMemory(region.address, region.data, err)
            if err.Success() and bytes_written == region.size:
                regions_restored += 1

        # Restore registers
        registers_restored = 0
        for name, value in self.registers.values.items():
            # Skip pc if not requested (it's set implicitly by breakpoint)
            if not restore_pc and name == "pc":
                continue

            reg = frame.FindRegister(name)
            if reg and reg.IsValid():
                if reg.SetValueFromCString(value):
                    registers_restored += 1

        return regions_restored, registers_restored

    def memory_bytes(self) -> int:
        """Total bytes of saved memory."""
        return sum(r.size for r in self.memory_regions)

    def summary(self) -> str:
        """Human-readable summary."""
        return (
            f"Snapshot at {self.function_name or 'unknown'} (PC=0x{self.pc:x})\n"
            f"  Regions: {len(self.memory_regions)} ({self.memory_bytes() / 1024:.1f} KB)\n"
            f"  Registers: {len(self.registers.values)}\n"
            f"  Capture time: {self.capture_time * 1000:.1f} ms"
        )


class SnapshotFuzzer:
    """Fuzzer that uses snapshots for fast iteration.

    Instead of relaunching the process for each iteration, this fuzzer:
    1. Runs to a checkpoint (e.g., entry of parse function)
    2. Takes a snapshot
    3. For each iteration: restore snapshot, mutate input, continue
    """

    def __init__(
        self,
        process: Any,  # lldb.SBProcess
        target: Any,  # lldb.SBTarget
    ):
        self.process = process
        self.target = target
        self.snapshot: ProcessSnapshot | None = None
        self._iterations = 0
        self._restore_times: list[float] = []

    def checkpoint(self, frame: Any) -> ProcessSnapshot:
        """Create a checkpoint at the current state.

        Args:
            frame: SBFrame to capture.

        Returns:
            The captured snapshot.
        """
        self.snapshot = ProcessSnapshot.capture(self.process, frame)
        return self.snapshot

    def restore_and_mutate(
        self,
        frame: Any,
        input_address: int,
        mutated_data: bytes,
    ) -> bool:
        """Restore snapshot and inject mutated input.

        Args:
            frame: Current SBFrame.
            input_address: Address to write mutated data.
            mutated_data: The mutated input bytes.

        Returns:
            True if restore and mutation succeeded.
        """
        import lldb

        if not self.snapshot:
            raise RuntimeError("No snapshot to restore")

        restore_start = time.time()

        # Restore snapshot
        regions, regs = self.snapshot.restore(self.process, frame, restore_pc=False)

        # Inject mutated input
        err = lldb.SBError()
        written = self.process.WriteMemory(input_address, mutated_data, err)

        restore_time = time.time() - restore_start
        self._restore_times.append(restore_time)
        self._iterations += 1

        return err.Success() and written == len(mutated_data)

    def stats(self) -> dict[str, Any]:
        """Get performance statistics."""
        if not self._restore_times:
            return {"iterations": 0}

        avg_restore = sum(self._restore_times) / len(self._restore_times)
        return {
            "iterations": self._iterations,
            "avg_restore_ms": avg_restore * 1000,
            "min_restore_ms": min(self._restore_times) * 1000,
            "max_restore_ms": max(self._restore_times) * 1000,
            "snapshot_size_kb": self.snapshot.memory_bytes() / 1024 if self.snapshot else 0,
        }


def benchmark_snapshot(binary: str, iterations: int = 1000) -> dict[str, Any]:
    """Benchmark snapshot-based fuzzing.

    Args:
        binary: Path to target binary.
        iterations: Number of iterations to run.

    Returns:
        Performance statistics.
    """
    import tempfile
    from pathlib import Path

    import lldb

    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)

    target = debugger.CreateTarget(binary)
    if not target:
        return {"error": "Failed to create target"}

    # Set breakpoint
    bp = target.BreakpointCreateByName("parse_buggy")
    if bp.GetNumLocations() == 0:
        return {"error": "No breakpoint locations"}

    # Create safe seed
    seed_path = Path(tempfile.gettempdir()) / "snapshot_bench_seed"
    seed_path.write_bytes(b"BENCHMARK_SAFE_SEED_DATA")

    # Launch
    launch_info = lldb.SBLaunchInfo([str(seed_path)])
    error = lldb.SBError()
    process = target.Launch(launch_info, error)

    if not process or process.GetState() != lldb.eStateStopped:
        return {"error": f"Launch failed: {error}"}

    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # Create snapshot
    fuzzer = SnapshotFuzzer(process, target)
    snapshot = fuzzer.checkpoint(frame)
    print(snapshot.summary())

    # Get input buffer address
    x0 = frame.FindRegister("x0").GetValueAsUnsigned()
    x1 = frame.FindRegister("x1").GetValueAsUnsigned()

    # Benchmark restore loop
    start_time = time.time()
    crashes = 0

    for i in range(iterations):
        # Generate "mutation" (just varying data)
        mutated = f"SAFE_BENCH_{i:06d}".encode()[:x1]
        mutated = mutated.ljust(x1, b"\x00")

        # Restore and inject
        fuzzer.restore_and_mutate(frame, x0, mutated)

        # Continue execution
        process.Continue()

        # Check result
        state = process.GetState()
        if state == lldb.eStateStopped:
            stop_reason = thread.GetStopReason()
            if stop_reason == lldb.eStopReasonException:
                crashes += 1
            # Reset to breakpoint for next iteration
            # (We'd need to re-run to the breakpoint, which defeats the purpose)
            # For now, just count that we successfully restored

    elapsed = time.time() - start_time
    rate = iterations / elapsed if elapsed > 0 else 0

    process.Kill()
    lldb.SBDebugger.Destroy(debugger)

    stats = fuzzer.stats()
    stats.update(
        {
            "total_time": elapsed,
            "iterations": iterations,
            "exec_per_sec": rate,
            "crashes": crashes,
        }
    )

    return stats


if __name__ == "__main__":
    import sys

    binary = sys.argv[1] if len(sys.argv) > 1 else "examples/toy_bug/out/toy_bug_fuzz"
    iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 100

    print(f"[*] Benchmarking snapshot fuzzing: {binary}")
    print(f"[*] Iterations: {iterations}")

    results = benchmark_snapshot(binary, iterations)

    print("\n" + "=" * 50)
    print("SNAPSHOT BENCHMARK RESULTS")
    print("=" * 50)
    for key, value in results.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2f}")
        else:
            print(f"  {key}: {value}")
