#!/usr/bin/env python3
"""
Minimize a crashing input using the target binary's internal minimizer (libFuzzer-compatible).

Replaces bin/minimize.sh.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def minimize(binary: str, crash: str, timeout: int, output: str | None = None) -> int:
    bin_path = Path(binary).resolve()
    crash_path = Path(crash).resolve()

    if not bin_path.exists() or not os.access(bin_path, os.X_OK):
        print(f"[-] binary not executable: {bin_path}", file=sys.stderr)
        return 1
    if not crash_path.exists():
        print(f"[-] crash input missing: {crash_path}", file=sys.stderr)
        return 1

    # Determine output path: explicit > env var > default
    if output:
        out_path = Path(output).resolve()
    elif os.environ.get("ALF_MINIMIZE_OUTPUT"):
        out_path = Path(os.environ["ALF_MINIMIZE_OUTPUT"]).resolve()
    else:
        out_path = crash_path.with_suffix(crash_path.suffix + ".min" if crash_path.suffix else ".min")
        if out_path == crash_path:
            out_path = crash_path.with_name(crash_path.name + ".min")

    print(f"[*] Minimizing {crash_path} -> {out_path}")

    # Run the binary with minimization flags
    cmd = [
        str(bin_path),
        "-minimize_crash=1",
        "-runs=1000000",
        f"-timeout={timeout}",
        f"-exact_artifact_path={out_path}",
        str(crash_path),
    ]

    try:
        # We don't check return code strictly because minimizers often exit with non-zero
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("\n[!] Minimization interrupted")
        return 130

    if out_path.exists():
        print(f"[+] minimized -> {out_path}")
        return 0
    else:
        print(f"[!] minimization did not produce {out_path} (check output)", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimize a crash input.")
    parser.add_argument("binary", help="Path to fuzz binary")
    parser.add_argument("crash", help="Path to crash input")
    parser.add_argument("timeout", nargs="?", type=int, default=5, help="Timeout in seconds (default: 5)")
    args = parser.parse_args(argv)

    return minimize(args.binary, args.crash, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
