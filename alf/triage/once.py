#!/usr/bin/env python3
"""
Collect crash triage data by driving LLDB through the local LLDB‑MCP server.

This is a thin, reproducible client intended for demos:
1) spin up lldb-dap on an ephemeral port
2) wrap it with `python -m alf.server`
3) run a small, opinionated triage playbook via MCP tools
4) write JSON + a short Markdown report under logs/

Example:
  uv run alf analyze triage \
    --binary harnesses/toy_bug/out/toy_bug_fuzz \
    --crash crashes/toy_bug/crash-abc123 \
    --tag demo
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .config import TriageConfig, TriageResult


def repo_root() -> Path:
    # alf/triage/once.py -> alf/ -> repo root
    return Path(__file__).resolve().parents[2]


def infer_target(binary_path: Path) -> str:
    parts = binary_path.parts
    if "harnesses" in parts:
        idx = parts.index("harnesses")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return binary_path.stem


def find_lldb_dap(explicit: str | None) -> str:
    if explicit:
        return explicit
    env_bin = os.environ.get("LLDB_DAP_BIN")
    if env_bin:
        return env_bin
    if shutil_which("xcrun"):
        try:
            out = subprocess.check_output(["xcrun", "--find", "lldb-dap"], text=True).strip()
            if out:
                return out
        except Exception:
            pass
    # Fallback: hope it's on PATH
    return "lldb-dap"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return int(port)


def shutil_which(cmd: str) -> str | None:
    try:
        import shutil

        return shutil.which(cmd)
    except Exception:
        return None


class MCPClient:
    """Simple synchronous MCP client for triage playbooks."""

    # MCP protocol version (must match server expectations)
    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, proc: subprocess.Popen[str]):
        self.proc = proc
        self.req_id = 1
        self.transcript: list[dict[str, Any]] = []

    def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and wait for response."""
        req: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "id": self.req_id}
        if params is not None:
            req["params"] = params
        self.req_id += 1
        self.transcript.append({"direction": "out", "payload": req})
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()

        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("ALF MCP server closed stdout unexpectedly")
        resp = json.loads(line)
        self.transcript.append({"direction": "in", "payload": resp})
        return resp

    def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        notif: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            notif["params"] = params
        self.transcript.append({"direction": "out", "payload": notif})
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(notif) + "\n")
        self.proc.stdin.flush()

    def initialize(self) -> dict[str, Any]:
        """Perform MCP initialization handshake."""
        # Send initialize request with required fields
        init_params = {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {},  # Empty capabilities for simple client
            "clientInfo": {
                "name": "alf-triage",
                "version": "0.1.0",
            },
        }
        resp = self.send_request("initialize", init_params)

        # Send initialized notification (required by MCP protocol)
        self.send_notification("notifications/initialized")

        return resp

    # Legacy alias for backward compatibility
    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.send_request(method, params)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        resp = self.send("tools/call", {"name": name, "arguments": arguments})
        result = resp.get("result")
        if not isinstance(result, dict):
            return json.dumps(resp, indent=2)

        is_error = bool(result.get("isError", False))

        # Collect all text/content parts, but fall back to structuredContent or
        # full JSON when the server returns non-text blocks.
        parts: list[str] = []
        content = result.get("content")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text" and isinstance(block.get("text"), str):
                    parts.append(block["text"])
                elif btype == "image":
                    parts.append(f"[Image: {block.get('mimeType')}]")
                elif btype == "resource":
                    uri = block.get("resource", {}).get("uri") if isinstance(block.get("resource"), dict) else None
                    parts.append(f"[Resource: {uri}]")

        text = "\n".join(parts).strip()
        if not text and result.get("structuredContent") is not None:
            try:
                text = json.dumps(result["structuredContent"], indent=2)
            except Exception:
                text = str(result["structuredContent"])

        if is_error:
            msg = text if text else "Unknown tool error"
            return json.dumps({"tool": name, "error": msg}, indent=2)

        return text if text else json.dumps(result, indent=2)


def start_dap(dap_bin: str, port: int, env: dict[str, str]) -> subprocess.Popen[str]:
    cmd = [dap_bin, "--port", str(port)]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=env)


def start_mcp_server(port: int, env: dict[str, str], timeout: float, log_level: str) -> subprocess.Popen[str]:
    cmd = [
        sys.executable,
        "-m",
        "alf.server",
        "--dap-host",
        "127.0.0.1",
        "--dap-port",
        str(port),
        "--timeout",
        str(timeout),
        "--log-level",
        log_level,
    ]
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, text=True, env=env)


def default_playbook(client: MCPClient, binary: str, crash: str) -> dict[str, str]:
    results: dict[str, str] = {}
    results["launch"] = client.call_tool("lldb_launch", {"binary": binary, "crash_input": crash})
    results["crash_context"] = client.call_tool("lldb_crash_context", {"max_frames": 32, "stack_bytes": 256})
    results["backtrace"] = client.call_tool("lldb_backtrace", {"count": 32})
    results["registers"] = client.call_tool("lldb_execute", {"command": "register read"})
    results["disassemble"] = client.call_tool("lldb_disassemble", {"address": "--pc", "count": 24})
    results["stack_bytes"] = client.call_tool("lldb_execute", {"command": "memory read -fx -s1 $sp 256"})
    return results


def write_json(logs_dir: Path, stamp: str, target: str, tag: str, payload: dict[str, Any]) -> Path:
    logs_dir.mkdir(parents=True, exist_ok=True)
    path = logs_dir / f"{stamp}_{target}_mcp_triage_{tag}.json"
    with path.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)
        fp.write("\n")
    return path


def write_markdown(logs_dir: Path, stamp: str, target: str, tag: str, playbook: dict[str, str]) -> Path:
    logs_dir.mkdir(parents=True, exist_ok=True)
    path = logs_dir / f"{stamp}_{target}_mcp_triage_{tag}.md"
    lines = [
        f"# MCP Triage Report — {target}",
        "",
        f"- Tag: `{tag}`",
        f"- Timestamp: `{stamp}`",
        "",
        "## Launch",
        "```json",
        playbook.get("launch", "").strip(),
        "```",
        "",
        "## Backtrace",
        "```",
        playbook.get("backtrace", "").strip(),
        "```",
        "",
        "## Crash Context",
        "```json",
        playbook.get("crash_context", "").strip(),
        "```",
        "",
        "## Registers",
        "```",
        playbook.get("registers", "").strip(),
        "```",
        "",
        "## Disassembly",
        "```",
        playbook.get("disassemble", "").strip(),
        "```",
        "",
        "## Stack Bytes",
        "```",
        playbook.get("stack_bytes", "").strip(),
        "```",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def run_triage(config: TriageConfig) -> TriageResult:
    """Run triage from a TriageConfig object.

    Args:
        config: Triage configuration with paths and options.

    Returns:
        TriageResult with success status, output paths, and metadata.
    """
    from .config import TriageResult

    binary = config.binary
    crash = config.crash

    if not binary.exists():
        return TriageResult(success=False, error=f"binary not found: {binary}")
    if not crash.exists():
        return TriageResult(success=False, error=f"crash input not found: {crash}")

    root = repo_root()
    target = infer_target(binary)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    logs_dir = root / "logs"

    dap_bin = find_lldb_dap(config.dap_path)
    port = config.dap_port or free_port()

    env = os.environ.copy()
    env["PYTHONPATH"] = str(root)

    dap_proc: subprocess.Popen[str] | None = None
    mcp_proc: subprocess.Popen[str] | None = None

    try:
        dap_proc = start_dap(dap_bin, port, env)
        mcp_proc = start_mcp_server(port, env, config.timeout, config.log_level)
        client = MCPClient(mcp_proc)

        # MCP handshake
        client.initialize()
        client.send_request("tools/list")

        playbook = default_playbook(client, str(binary), str(crash))

        payload: dict[str, Any] = {
            "metadata": {
                "timestamp": stamp,
                "target": target,
                "tag": config.tag,
                "binary": str(binary),
                "crash": str(crash),
                "dap_port": port,
                "host": f"{os.uname().sysname} {os.uname().release}",
            },
            "playbook": playbook,
            "transcript": client.transcript,
        }

        # Extract stack hash from crash context if available
        stack_hash: str | None = None
        try:
            crash_ctx = json.loads(playbook.get("crash_context", "{}"))
            stack_hash = crash_ctx.get("stack_hash")
        except Exception:
            pass

        if config.output:
            out_path = config.output
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            json_path = out_path
        else:
            json_path = write_json(logs_dir, stamp, target, config.tag, payload)

        md_path = None
        if not config.no_markdown and not config.output:
            md_path = write_markdown(logs_dir, stamp, target, config.tag, playbook)

        return TriageResult(
            success=True,
            json_path=json_path,
            markdown_path=md_path,
            stack_hash=stack_hash,
            metadata=payload.get("metadata"),
        )
    except Exception as e:
        return TriageResult(success=False, error=str(e))
    finally:
        if mcp_proc and mcp_proc.poll() is None:
            mcp_proc.terminate()
        if dap_proc and dap_proc.poll() is None:
            dap_proc.terminate()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect crash triage via LLDB-MCP server.")
    p.add_argument("--binary", required=True, help="Path to fuzz binary.")
    p.add_argument("--crash", required=True, help="Path to crash input.")
    p.add_argument("--tag", default="triage", help="Short tag for artifact names.")
    p.add_argument("--dap-path", default=None, help="Explicit lldb-dap path (else xcrun/PATH).")
    p.add_argument("--dap-port", type=int, default=0, help="DAP port (0 = auto).")
    p.add_argument("--timeout", type=float, default=30.0, help="DAP/MCP timeout in seconds.")
    p.add_argument("--log-level", default="ERROR", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--output", default=None, help="Write JSON to this path instead of logs/.")
    p.add_argument("--no-markdown", action="store_true", help="Skip Markdown report.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point - parses args and delegates to run_triage."""
    from .config import TriageConfig

    args = parse_args(argv)

    config = TriageConfig(
        binary=Path(args.binary),
        crash=Path(args.crash),
        tag=args.tag,
        dap_path=args.dap_path,
        dap_port=args.dap_port,
        timeout=args.timeout,
        log_level=args.log_level,
        output=Path(args.output) if args.output else None,
        no_markdown=args.no_markdown,
    )

    result = run_triage(config)

    if not result.success:
        print(f"[-] {result.error}", file=sys.stderr)
        return 1

    print(f"[+] MCP triage JSON: {result.json_path}")
    if result.markdown_path:
        print(f"[+] MCP triage report: {result.markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
