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
    # Advisory checks surface hints but do not fail the overall run.
    advisory: bool = False


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
    from .utils.lldb_dap import find_lldb_dap as _find

    resolved = _find()
    return resolved if resolved and resolved != "lldb-dap" else shutil.which("lldb-dap")


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


def check_lldb_dap_gdb_remote() -> CheckResult:
    """Best-effort: confirm lldb-dap supports gdb-remote attach.

    Probes the adapter binary's strings for the DAP schema keys
    `gdb-remote-hostname` / `gdb-remote-port`. CLI `--help` doesn't
    document attach-time JSON keys, so string inspection is the cheapest
    check that works on both Xcode and LLVM-shipped builds.
    """
    path = find_lldb_dap()
    if not path:
        return CheckResult(
            name="lldb_dap_gdb_remote",
            ok=False,
            details="lldb-dap not found",
            hint="Install a recent Xcode or LLVM that ships lldb-dap.",
            advisory=True,
        )
    try:
        with open(path, "rb") as fp:
            blob = fp.read()
    except OSError as e:
        return CheckResult(
            name="lldb_dap_gdb_remote",
            ok=False,
            details=f"cannot read {path}: {e}",
            advisory=True,
        )
    has_hostname = b"gdb-remote-hostname" in blob
    has_port = b"gdb-remote-port" in blob
    if has_hostname and has_port:
        return CheckResult(
            name="lldb_dap_gdb_remote",
            ok=True,
            details="adapter binary exposes gdb-remote-hostname / gdb-remote-port",
            advisory=True,
        )
    return CheckResult(
        name="lldb_dap_gdb_remote",
        ok=False,
        details=(
            "lldb-dap binary does not reference gdb-remote-hostname/"
            "gdb-remote-port (heuristic; may still work at runtime)"
        ),
        hint=(
            "Upgrade to a recent Xcode command-line tools or LLVM. The VZ "
            "hypervisor/QEMU gdbstub attach path requires these config keys."
        ),
        advisory=True,
    )


def check_xnu_lldbmacros() -> CheckResult:
    """Check whether xnu lldbmacros is discoverable on disk."""
    from .utils.xnu import find_lldbmacros

    found = find_lldbmacros()
    if found is not None:
        return CheckResult(
            name="xnu_lldbmacros",
            ok=True,
            details=str(found),
            advisory=True,
        )
    return CheckResult(
        name="xnu_lldbmacros",
        ok=False,
        details="xnu lldbmacros not found in common locations",
        hint=(
            "Optional for userspace debugging. For kernel work, install a "
            "KDK or clone apple-oss-distributions/xnu and set "
            "ALF_XNU_LLDBMACROS to tools/lldbmacros."
        ),
        advisory=True,
    )


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
        check_lldb_dap_gdb_remote(),
        check_xnu_lldbmacros(),
    ]

    ok = all(c.ok for c in checks if not c.advisory)
    if args.json:
        payload: dict[str, Any] = {
            "ok": ok,
            "checks": [asdict(c) for c in checks],
        }
        print(json.dumps(payload, indent=2))
        return 0 if ok else 1

    print("ALF doctor\n-----------")
    for c in checks:
        if c.ok:
            status = "OK"
        elif c.advisory:
            status = "WARN"
        else:
            status = "FAIL"
        print(f"- {c.name}: {status} — {c.details}")
        if c.hint and not c.ok:
            print(c.hint)
            print("")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
