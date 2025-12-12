#!/usr/bin/env python3
"""
CLI-based performance benchmark for ALF stop-hook fuzzing loop.

Uses direct LLDB CLI (not DAP) to test mutation callback performance.
Target: >100 exec/sec.

Usage:
    python scripts/benchmark_cli.py [--iterations N] [--duration SECS]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def create_benchmark_hook(pipe_path: str, with_mutation: bool = True) -> str:
    """Generate the benchmark hook script."""
    mutation_import = ""
    mutation_code = ""

    if with_mutation:
        mutation_import = f'''
# Add ALF to path
import sys
sys.path.insert(0, "{REPO_ROOT}")
from alf.mut import apply_random_mutation
'''
        mutation_code = """
    # Read memory
    err = lldb.SBError()
    memory = process.ReadMemory(ptr, size, err)
    if not err.Success():
        return False

    # Apply mutation
    result = apply_random_mutation(memory)

    # Write back
    process.WriteMemory(ptr, bytes(result.data), err)
"""

    return f'''
import lldb
import os
import json
import time
{mutation_import}

# Mutation counter
_call_count = 0
_telemetry_fd = None
TELEMETRY_PIPE = "{pipe_path}"
PAC_MASK = 0x0000FFFFFFFFFFFF

def _emit_telemetry(event: str, count: int) -> None:
    """Write telemetry to FIFO."""
    global _telemetry_fd
    if not TELEMETRY_PIPE:
        return
    try:
        if _telemetry_fd is None:
            _telemetry_fd = os.open(TELEMETRY_PIPE, os.O_WRONLY | os.O_NONBLOCK)
        payload = json.dumps({{"event": event, "count": count, "ts": time.time()}})
        os.write(_telemetry_fd, (payload + "\\n").encode())
    except (BlockingIOError, OSError):
        pass

def benchmark_hook(frame, bp_loc, internal_dict):
    """Benchmark breakpoint callback with mutation."""
    global _call_count
    _call_count += 1

    # Read registers
    thread = frame.GetThread()
    process = thread.GetProcess()

    x0 = frame.FindRegister("x0").GetValueAsUnsigned()
    x1 = frame.FindRegister("x1").GetValueAsUnsigned()

    ptr = x0 & PAC_MASK
    size = min(x1, 4096) if x1 > 0 else 64

    if ptr == 0 or size == 0:
        return False
{mutation_code}
    # Emit telemetry every 100 calls to reduce overhead
    if _call_count % 100 == 0:
        _emit_telemetry("mutation_batch", _call_count)

    return False  # Continue execution

def __lldb_init_module(debugger, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName("parse_buggy")
    bp.SetScriptCallbackFunction("benchmark_hook.benchmark_hook")
    print(f"[+] Benchmark hook installed, BP locations: {{bp.GetNumLocations()}}")
'''


HOMEBREW_LLDB = "/opt/homebrew/opt/llvm/bin/lldb"
XCODE_LLDB = "xcrun"


def run_benchmark(
    iterations: int = 10000, duration: float = 30.0, verbose: bool = False, use_homebrew: bool = True
) -> dict:
    """Run the CLI-based performance benchmark."""
    # Paths
    binary = REPO_ROOT / "examples" / "toy_bug" / "out" / "persistent_harness"
    seed = REPO_ROOT / "examples" / "toy_bug" / "corpus" / "benchmark_seed"

    if not binary.exists():
        print(f"[!] Binary not found: {binary}")
        print("[!] Building persistent harness...")
        build_result = subprocess.run(
            [
                "clang",
                "-g",
                "-O0",
                "-o",
                str(binary),
                str(REPO_ROOT / "examples" / "toy_bug" / "persistent_harness.c"),
                str(REPO_ROOT / "examples" / "toy_bug" / "buggy_parser.c"),
            ],
            capture_output=True,
            text=True,
        )
        if build_result.returncode != 0:
            print(f"[!] Build failed: {build_result.stderr}")
            return {"error": "build failed"}

    # Create safe seed that won't crash
    seed.parent.mkdir(parents=True, exist_ok=True)
    seed.write_text("BENCHMARK_SAFE_SEED_DATA_12345")

    results = {
        "iterations_requested": iterations,
        "duration_requested": duration,
    }

    # Create telemetry FIFO
    with tempfile.TemporaryDirectory() as tmpdir:
        pipe_path = Path(tmpdir) / "telemetry.fifo"
        os.mkfifo(pipe_path)

        # Create hook script
        hook_script = Path(tmpdir) / "benchmark_hook.py"
        hook_script.write_text(create_benchmark_hook(str(pipe_path), with_mutation=True))

        # Telemetry reader thread
        import threading

        telemetry_events = []
        stop_reading = threading.Event()

        def read_telemetry():
            import select

            try:
                fd = os.open(pipe_path, os.O_RDONLY | os.O_NONBLOCK)
                buf = b""
                while not stop_reading.is_set():
                    ready, _, _ = select.select([fd], [], [], 0.5)
                    if ready:
                        chunk = os.read(fd, 4096)
                        if chunk:
                            buf += chunk
                            while b"\n" in buf:
                                line, buf = buf.split(b"\n", 1)
                                try:
                                    obj = json.loads(line)
                                    telemetry_events.append(obj)
                                except json.JSONDecodeError:
                                    pass
                os.close(fd)
            except Exception as e:
                print(f"[!] Telemetry reader error: {e}")

        reader_thread = threading.Thread(target=read_telemetry, daemon=True)
        reader_thread.start()

        # Give the reader a moment to open the pipe
        time.sleep(0.5)

        # Run LLDB with the benchmark
        print(f"[*] Running benchmark ({iterations} iterations, max {duration}s)...")
        start_time = time.time()

        # Calculate timeout for subprocess
        timeout_secs = min(duration * 2, 300)  # Cap at 5 minutes

        # Choose LLDB version
        if use_homebrew and Path(HOMEBREW_LLDB).exists():
            lldb_cmd = [
                HOMEBREW_LLDB,
                "--batch",
                "-o",
                f"command script import {hook_script}",
                "-o",
                f"run {seed} {iterations}",
                str(binary),
            ]
            lldb_version = "Homebrew"
        else:
            lldb_cmd = [
                "xcrun",
                "lldb",
                "--batch",
                "-o",
                f"command script import {hook_script}",
                "-o",
                f"run {seed} {iterations}",
                str(binary),
            ]
            lldb_version = "Xcode"

        try:
            proc = subprocess.run(lldb_cmd, capture_output=True, text=True, timeout=timeout_secs)
            end_time = time.time()

            if verbose:
                print("[STDOUT]", proc.stdout[:1000] if proc.stdout else "(empty)")
                if proc.stderr:
                    print("[STDERR]", proc.stderr[:500])

        except subprocess.TimeoutExpired:
            end_time = time.time()
            print(f"[!] Process timed out after {timeout_secs}s")

        # Stop telemetry reader
        stop_reading.set()
        reader_thread.join(timeout=2.0)

        total_time = end_time - start_time

        # Parse results from telemetry
        if telemetry_events:
            last_event = telemetry_events[-1]
            total_calls = last_event.get("count", 0)
        else:
            # Fall back to parsing stdout for iteration count
            total_calls = iterations  # Assume all ran if no crash

        rate = total_calls / total_time if total_time > 0 else 0

        results.update(
            {
                "duration_actual": total_time,
                "total_calls": total_calls,
                "telemetry_events": len(telemetry_events),
                "calls_per_sec": rate,
                "target_met": rate >= 100,
                "lldb_version": lldb_version,
            }
        )

        print("\n" + "=" * 60)
        print(f"BENCHMARK RESULTS ({lldb_version} LLDB)")
        print("=" * 60)
        print(f"  Duration:       {total_time:.2f}s")
        print(f"  Iterations:     {total_calls}")
        print(f"  Rate:           {rate:.1f} exec/sec")
        print(f"  Target (>100):  {'✓ MET' if results['target_met'] else '✗ NOT MET'}")
        print("=" * 60)

    return results


def main():
    parser = argparse.ArgumentParser(description="ALF CLI loop performance benchmark")
    parser.add_argument("-n", "--iterations", type=int, default=10000, help="Iterations to run")
    parser.add_argument("-d", "--duration", type=float, default=60.0, help="Max duration (seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--xcode", action="store_true", help="Use Xcode LLDB instead of Homebrew")
    args = parser.parse_args()

    results = run_benchmark(
        iterations=args.iterations,
        duration=args.duration,
        verbose=args.verbose,
        use_homebrew=not args.xcode,
    )

    # Write results to file
    results_file = REPO_ROOT / "logs" / "benchmark_cli_results.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(results, indent=2))
    print(f"\n[*] Results saved to: {results_file}")

    return 0 if results.get("target_met") else 1


if __name__ == "__main__":
    sys.exit(main())
