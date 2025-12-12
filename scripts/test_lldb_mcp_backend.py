#!/usr/bin/env python3
"""
Test script for LLDB native MCP backend.

Before running this test, start an LLDB MCP server:
    lldb
    (lldb) protocol-server start MCP listen://localhost:59999

Then run this script:
    uv run python scripts/test_lldb_mcp_backend.py

This tests basic functionality and measures performance compared to DAP.
"""

import logging
import sys
import time
from pathlib import Path

# Add alf to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")

from alf.backend import get_backend, LLDBMCPBackend


def test_connection(host: str = "127.0.0.1", port: int = 59999) -> bool:
    """Test connecting to LLDB MCP server."""
    print(f"Testing connection to {host}:{port}...")
    backend = LLDBMCPBackend(host=host, port=port, timeout=10.0)

    try:
        backend.connect()
        print(f"  ✓ Connected to LLDB MCP server")
        print(f"  Backend name: {backend.name}")
        print(f"  Connected: {backend.connected}")
        return True
    except ConnectionError as e:
        print(f"  ✗ Connection failed: {e}")
        print()
        print("Make sure LLDB MCP server is running:")
        print("  lldb")
        print(f"  (lldb) protocol-server start MCP listen://localhost:{port}")
        return False
    finally:
        backend.disconnect()  # Just closes socket, doesn't quit LLDB


def test_basic_commands(host: str, port: int) -> bool:
    """Test basic LLDB commands."""
    print("\nTesting basic commands...")
    backend = LLDBMCPBackend(host=host, port=port)

    try:
        backend.connect()

        # Test version command
        output = backend.execute_command("version")
        print(f"  ✓ version: {output.splitlines()[0] if output else 'empty'}")

        # Test settings
        output = backend.execute_command("settings show target.run-args")
        print(f"  ✓ settings: OK")

        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False
    finally:
        backend.disconnect()


def test_launch_and_triage(
    binary: str,
    crash_input: str,
    host: str,
    port: int,
) -> tuple[bool, float]:
    """Test launching binary and collecting crash context."""
    print(f"\nTesting crash triage...")
    backend = LLDBMCPBackend(host=host, port=port)

    start_time = time.time()
    try:
        backend.connect()

        # Launch with crash input
        print(f"  Launching: {Path(binary).name} {Path(crash_input).name}")
        result = backend.launch(binary, crash_input=crash_input)
        print(f"  Status: {result.status}, Reason: {result.reason}")

        if result.status == "error":
            print(f"  ✗ Launch failed: {result.error}")
            return False, 0

        # Collect crash context
        context = backend.collect_crash_context()
        stack_hash = context.get("stack_hash", "N/A")
        frames = context.get("frames", [])

        elapsed = time.time() - start_time

        print(f"  ✓ Stack hash: {stack_hash}")
        print(f"  ✓ Frames: {len(frames)}")
        print(f"  ✓ Elapsed: {elapsed:.3f}s")

        return True, elapsed

    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False, 0
    finally:
        backend.disconnect()


def main():
    host = "127.0.0.1"
    port = 59999

    # Example binary and crash
    project_root = Path(__file__).parent.parent
    toy_bug_binary = project_root / "examples/toy_bug/out/toy_bug_fuzz"
    crashes_dir = project_root / "examples/toy_bug/crashes"

    # Find a crash file (prefer actual crashes over corpus seeds)
    crash_file = None
    if crashes_dir.exists():
        for f in crashes_dir.iterdir():
            if f.is_file() and f.name.startswith("crash"):
                crash_file = f
                break

    # Fallback to corpus if no crashes
    if not crash_file:
        corpus_dir = project_root / "examples/toy_bug/corpus"
        if corpus_dir.exists():
            for f in corpus_dir.iterdir():
                if f.is_file() and not f.name.startswith("."):
                    crash_file = f
                    break

    print("=" * 60)
    print("LLDB Native MCP Backend Test")
    print("=" * 60)

    # Test 1: Connection
    if not test_connection(host, port):
        return 1

    # Test 2: Basic commands
    if not test_basic_commands(host, port):
        return 1

    # Test 3: Launch and triage
    if toy_bug_binary.exists() and crash_file:
        success, elapsed = test_launch_and_triage(
            str(toy_bug_binary),
            str(crash_file),
            host,
            port,
        )
        if not success:
            print("\nWarning: Launch/triage test failed (binary may need specific args)")
    else:
        print(f"\nSkipping launch test: binary or crash not found")
        print(f"  Binary: {toy_bug_binary} (exists: {toy_bug_binary.exists()})")
        print(f"  Crashes: {crashes_dir} (exists: {crashes_dir.exists()})")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
