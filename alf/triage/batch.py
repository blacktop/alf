#!/usr/bin/env python3
"""
Run a one-shot LLDB batch triage (no DAP, no MCP).
Batch triage mode: runs LLDB directly without DAP or MCP.
"""

from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    # alf/triage/batch.py -> alf/ -> repo root
    return Path(__file__).resolve().parents[2]


def find_llvm_prefix() -> str | None:
    if os.environ.get("LLVM_PREFIX"):
        return os.environ["LLVM_PREFIX"]

    candidates = [
        "/opt/homebrew/opt/llvm",
        "/usr/local/opt/llvm",
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c

    # Try to find via clang
    clang = shutil.which("clang")
    if clang:
        # /usr/bin/clang -> /usr
        # /opt/homebrew/opt/llvm/bin/clang -> /opt/homebrew/opt/llvm
        clang_path = Path(clang).resolve()
        # check if sibling has llvm-symbolizer
        if (clang_path.parent / "llvm-symbolizer").exists():
            return str(clang_path.parent.parent)
        return str(clang_path.parent.parent)
    return None


def run_batch_triage(binary: str, crash: str, tag: str, extra_cmds: list[str]) -> int:
    bin_path = Path(binary).resolve()
    crash_path = Path(crash).resolve()
    root = repo_root()
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    if not bin_path.exists() or not os.access(bin_path, os.X_OK):
        print(f"[-] binary not executable: {bin_path}", file=sys.stderr)
        return 1
    if not crash_path.exists():
        print(f"[-] crash input missing: {crash_path}", file=sys.stderr)
        return 1

    # First, reproduce with libFuzzer to see sanitizers on stderr (optional but good)
    print("[*] Reproducing crash with libFuzzer runner")

    llvm_prefix = find_llvm_prefix()
    env = os.environ.copy()

    # Set up sanitizer options matching the shell script
    asan_symbolizer = "llvm-symbolizer"
    if llvm_prefix:
        possible_sym = Path(llvm_prefix) / "bin" / "llvm-symbolizer"
        if possible_sym.exists():
            asan_symbolizer = str(possible_sym)

    env.setdefault("ASAN_SYMBOLIZER_PATH", asan_symbolizer)

    default_asan = f"abort_on_error=1:symbolize=1:external_symbolizer_path={asan_symbolizer}"
    default_ubsan = "print_stacktrace=1:halt_on_error=1"

    env.setdefault("ASAN_OPTIONS", default_asan)
    env.setdefault("UBSAN_OPTIONS", default_ubsan)

    # Run reproduction (ignore failure)
    subprocess.run([str(bin_path), "-runs=1", str(crash_path)], env=env, check=False)

    # Now LLDB batch mode
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"{tag}_triage_{ts}.log"

    print(f"[*] Capturing LLDB triage to {log_path}")

    # Prepare LLDB commands
    commands = [
        f"settings set target.env-vars ASAN_OPTIONS={env['ASAN_OPTIONS']} UBSAN_OPTIONS={env['UBSAN_OPTIONS']}",
        f"target create {bin_path}",
        f"settings set target.run-args -- -runs=1 {crash_path}",
        "run",
        "bt all",
        "register read",
        "disassemble -p -c 32",
        "memory read -fx -s1 $sp 256",
    ]
    commands.extend(extra_cmds)
    commands.append("quit")

    lldb_args = []
    for cmd in commands:
        lldb_args.extend(["-o", cmd])

    # Run LLDB
    with open(log_path, "w") as f:
        # We also want to tee to stdout. subprocess.Popen can pipe.
        # But simpler to just run and capture, then print or just let LLDB write to stdout and we tee?
        # The script does `lldb ... | tee log`.
        # We'll use subprocess to write to file and assume user sees it if they tail it,
        # or we can read it back. Let's just pipe to file for now to be safe with large output.
        # Actually, let's replicate `tee` behavior manually.

        proc = subprocess.Popen(
            ["lldb", "--batch"] + lldb_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr
            text=True,
        )

        if proc.stdout:
            for line in proc.stdout:
                print(line, end="")
                f.write(line)

        proc.wait()

    # Check for the macOS -1 status error
    with open(log_path) as f:
        content = f.read()
        if "process exited with status -1 (no such process)" in content:
            print("[-] LLDB could not launch the debuggee (status -1).", file=sys.stderr)
            print("    This is usually a macOS Developer Mode / DevToolsSecurity issue.", file=sys.stderr)
            print("    Run: uv run alf doctor", file=sys.stderr)

    print(f"[+] LLDB triage saved to {log_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run LLDB batch triage.")
    parser.add_argument("binary", help="Path to fuzz binary")
    parser.add_argument("crash", help="Path to crash input")
    parser.add_argument("tag", help="Tag for logs")
    parser.add_argument("extra_cmds", nargs="*", help="Extra LLDB commands")

    args = parser.parse_args(argv)

    return run_batch_triage(args.binary, args.crash, args.tag, args.extra_cmds)


if __name__ == "__main__":
    raise SystemExit(main())
