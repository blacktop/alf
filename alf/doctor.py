#!/usr/bin/env python3
"""
Environment preflight checks for ALF on macOS.

This is intentionally pragmatic: it detects the most common configuration issues
that prevent LLDB/lldb-dap from launching targets (e.g. Developer Mode / debug
privileges), and prints actionable fixes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class CheckResult:
    name: str
    ok: bool
    details: str
    hint: str | None = None


def run_cmd(cmd: list[str], timeout: float = 10.0) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return int(p.returncode), p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def check_lldb_exists() -> CheckResult:
    path = shutil.which("lldb")
    if not path:
        return CheckResult(
            name="lldb",
            ok=False,
            details="lldb not found in PATH",
            hint="Install Xcode Command Line Tools or Xcode.",
        )
    code, out, err = run_cmd([path, "--version"], timeout=5.0)
    ver = out.splitlines()[0] if out else (err.splitlines()[0] if err else "")
    return CheckResult(name="lldb", ok=code == 0, details=f"{path} ({ver})" if ver else path)


def check_lldb_can_launch() -> CheckResult:
    """
    Launch a harmless system binary under LLDB.

    If this fails with:
      "process exited with status -1 (no such process)"
    it's almost always a system debugging entitlement / Developer Mode issue.
    """
    path = shutil.which("lldb")
    if not path:
        return CheckResult(name="lldb_launch", ok=False, details="lldb not found", hint="Install lldb.")

    cmds = [
        path,
        "--batch",
        "-o",
        "target create /bin/echo",
        "-o",
        "settings set target.run-args hello",
        "-o",
        "run",
    ]
    code, out, err = run_cmd(cmds, timeout=10.0)
    text = "\n".join([out, err]).strip()
    if "process exited with status -1" in text:
        return CheckResult(
            name="lldb_launch",
            ok=False,
            details="LLDB cannot launch debuggee (process exited with status -1).",
            hint=(
                "Enable macOS Developer Mode and debug privileges:\n"
                "  1) System Settings → Privacy & Security → Developer Mode → On (reboot)\n"
                "  2) sudo /usr/sbin/DevToolsSecurity --enable\n"
                '  3) sudo dseditgroup -o edit -a "$USER" -t user _developer\n'
                "If debugging only fails for a specific target, try:\n"
                "  codesign --force --sign - /path/to/your/bin"
            ),
        )
    if code != 0:
        return CheckResult(
            name="lldb_launch",
            ok=False,
            details=(text.splitlines()[-1] if text else f"lldb returned {code}"),
            hint="Run `lldb --batch -o 'target create /bin/echo' -o 'run'` to see the exact failure.",
        )
    return CheckResult(name="lldb_launch", ok=True, details="OK")


def find_lldb_dap() -> str | None:
    env_bin = os.environ.get("LLDB_DAP_BIN")
    if env_bin:
        return env_bin
    if shutil.which("xcrun"):
        code, out, _ = run_cmd(["xcrun", "--find", "lldb-dap"], timeout=5.0)
        if code == 0 and out:
            return out
    return shutil.which("lldb-dap")


def check_lldb_dap_exists() -> CheckResult:
    path = find_lldb_dap()
    if not path:
        return CheckResult(
            name="lldb_dap",
            ok=False,
            details="lldb-dap not found",
            hint="Install Xcode 16+ or LLVM (brew) and set LLDB_DAP_BIN if needed.",
        )
    code, out, err = run_cmd([path, "--help"], timeout=5.0)
    ok = code == 0
    details = path
    if not ok:
        details = f"{path} (failed to run: {err or out})"
    return CheckResult(name="lldb_dap", ok=ok, details=details)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ALF environment preflight checks.")
    p.add_argument("--json", action="store_true", help="Output machine-readable JSON.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    checks = [
        check_lldb_exists(),
        check_lldb_can_launch(),
        check_lldb_dap_exists(),
    ]

    ok = all(c.ok for c in checks)
    if args.json:
        payload: dict[str, Any] = {
            "ok": ok,
            "checks": [asdict(c) for c in checks],
        }
        print(json.dumps(payload, indent=2))
        return 0 if ok else 1

    print("ALF doctor\n-----------")
    for c in checks:
        status = "OK" if c.ok else "FAIL"
        print(f"- {c.name}: {status} — {c.details}")
        if c.hint and not c.ok:
            print(c.hint)
            print("")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
