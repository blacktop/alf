#!/usr/bin/env python3
"""
Performance benchmark for ALF stop-hook fuzzing loop.

Tests execution rate (mutations/sec) with the toy_bug example.
Target: >100 exec/sec (vs <1 via MCP tool calls).

Usage:
    python scripts/benchmark_loop.py [--iterations N] [--duration SECS]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def run_benchmark(iterations: int = 1000, duration: float = 10.0, verbose: bool = False) -> dict:
    """Run the performance benchmark.

    Args:
        iterations: Max iterations to run
        duration: Max duration in seconds
        verbose: Print detailed output

    Returns:
        Dict with benchmark results
    """
    from alf.server.lldb import LLDBDirector
    from alf.tools.definitions.instrumentation import _lldb_install_stop_hook_handler
    from alf.server.telemetry import TelemetrySession

    # Paths - use persistent harness for accurate benchmarking
    binary = REPO_ROOT / "examples" / "toy_bug" / "out" / "persistent_harness"
    seed = REPO_ROOT / "examples" / "toy_bug" / "corpus" / "marker_seed"

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

    if not seed.exists():
        # Create a test seed (avoid crash-triggering patterns)
        seed.parent.mkdir(parents=True, exist_ok=True)
        seed.write_text("BENCHMARK_MARKER_12345678")

    # Find available port and start lldb-dap
    import random

    port = 4730 + random.randint(0, 100)
    print(f"[*] Starting lldb-dap on port {port}...")
    dap_proc = subprocess.Popen(
        ["xcrun", "lldb-dap", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)  # Give more time to start

    results = {
        "iterations_requested": iterations,
        "duration_requested": duration,
    }

    try:
        # Connect to DAP
        print(f"[*] Connecting to lldb-dap on port {port}...")
        director = LLDBDirector(dap_host="127.0.0.1", dap_port=port, timeout=30.0)
        director.connect_dap()

        # Launch with stop_on_entry
        print(f"[*] Launching binary: {binary.name}")
        launch_result = director.initialize_session(
            binary=str(binary),
            crash_input=str(seed),
            stop_on_entry=True,
            extra_args=["-runs=0"],  # Don't exit after first run
        )
        print(f"[*] Launch result: {launch_result.get('status')}")

        # Install fork server at LLVMFuzzerTestOneInput for process reuse
        print("[*] Installing fork server at LLVMFuzzerTestOneInput...")
        from alf.tools.definitions.instrumentation import _lldb_install_fork_server_handler

        fork_result = _lldb_install_fork_server_handler(
            director,
            function="LLVMFuzzerTestOneInput",
            name="benchmark_fork",
            follow_mode="parent",
        )
        fork_data = json.loads(fork_result)
        if "error" in fork_data:
            print(f"[!] Failed to install fork server: {fork_data['error']}")
            # Continue without fork server
        else:
            print(f"[*] Fork server installed at breakpoint {fork_data.get('breakpoint_id')}")

        # Install stop hook on parse_buggy
        print("[*] Installing stop hook on parse_buggy...")
        hook_result = _lldb_install_stop_hook_handler(
            director,
            function="parse_buggy",
            ptr_reg="x0",
            len_reg="x1",
            max_size=4096,
            name="benchmark_hook",
        )
        hook_data = json.loads(hook_result)

        if "error" in hook_data:
            print(f"[!] Failed to install hook: {hook_data['error']}")
            return {"error": hook_data["error"]}

        telemetry_pipe = hook_data.get("telemetry_pipe")
        print(f"[*] Hook installed, telemetry: {telemetry_pipe}")

        # Get the telemetry sessions (fork server for iteration count, hook for mutations)
        fork_telem = director.telemetry_sessions.get("benchmark_fork")
        hook_telem = director.telemetry_sessions.get("benchmark_hook")

        # Use fork server telemetry as primary (child_exit events = iterations)
        telem_session = fork_telem if fork_telem else hook_telem

        # Continue execution and let it run (fork server will handle looping)
        print(f"[*] Starting execution (will run for {duration}s)...")
        start_time = time.time()

        # Continue without waiting - the fork server will loop
        director.continue_exec(wait=False)

        # Wait for the specified duration while collecting telemetry
        print("[*] Monitoring telemetry...")
        sample_interval = 2.0
        samples = []

        while time.time() - start_time < duration:
            time.sleep(sample_interval)
            elapsed = time.time() - start_time

            if telem_session:
                rate_stats = telem_session.rate(window_sec=sample_interval)
                current_rate = rate_stats.get("events_per_sec", 0)
                total = rate_stats.get("total_events", 0)
                samples.append({"time": elapsed, "rate": current_rate, "total": total})

                if verbose:
                    print(f"  [{elapsed:.1f}s] Rate: {current_rate:.1f}/sec, Total: {total}")

        end_time = time.time()
        total_time = end_time - start_time

        # Get final telemetry stats
        if telem_session:
            final_stats = telem_session.rate(window_sec=total_time)
            mutation_count = final_stats.get("total_events", 0)
            mutation_rate = mutation_count / total_time if total_time > 0 else 0
        else:
            mutation_count = 0
            mutation_rate = 0

        # Check for crashes
        crashes = len(director.pending_crashes)

        results.update(
            {
                "duration_actual": total_time,
                "crashes": crashes,
                "mutations_recorded": mutation_count,
                "mutations_per_sec": mutation_rate,
                "samples": samples,
                "target_met": mutation_rate >= 100,
            }
        )

        print("\n" + "=" * 60)
        print("BENCHMARK RESULTS")
        print("=" * 60)
        print(f"  Duration:       {total_time:.2f}s")
        print(f"  Crashes:        {crashes}")
        print(f"  Mutations:      {mutation_count}")
        print(f"  Mutation rate:  {mutation_rate:.1f} exec/sec")
        print(f"  Target (>100):  {'✓ MET' if results['target_met'] else '✗ NOT MET'}")
        print("=" * 60)

    except Exception as e:
        results["error"] = str(e)
        print(f"[!] Error: {e}")
        import traceback

        traceback.print_exc()
    finally:
        dap_proc.terminate()
        dap_proc.wait()

    return results


def main():
    parser = argparse.ArgumentParser(description="ALF loop performance benchmark")
    parser.add_argument("-n", "--iterations", type=int, default=500, help="Max iterations")
    parser.add_argument("-d", "--duration", type=float, default=30.0, help="Max duration (seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    results = run_benchmark(
        iterations=args.iterations,
        duration=args.duration,
        verbose=args.verbose,
    )

    # Write results to file
    results_file = REPO_ROOT / "logs" / "benchmark_results.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(results, indent=2))
    print(f"\n[*] Results saved to: {results_file}")

    return 0 if results.get("target_met") else 1


if __name__ == "__main__":
    sys.exit(main())
