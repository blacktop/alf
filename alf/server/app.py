"""
FastMCP entrypoint wiring together LLDB control tools and Apple analysis tools.

This module registers canonical tools from alf.tools.definitions with FastMCP.
Tools are defined once in alf/tools/definitions/ and can be exported to both
MCP and provider APIs (Anthropic, OpenAI, Gemini).

Special cases kept inline:
- lldb_continue: Has MCP-specific crash notifications via SSE
- MCP resources: Use inline tool functions for resource callbacks
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import platform
import socket
import subprocess
import weakref
from typing import Annotated, Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession
from pydantic import Field

from ..backend.factory import get_backend
from ..tools.definitions import (
    CAPABILITY_TOOLS,
    INSTRUMENTATION_TOOLS,
    LLDB_TOOLS,
    META_TOOLS,
    RUNTIME_TOOLS,
    STATIC_TOOLS,
)
from ..tools.mcp import register_tools
from .lldb import LLDBDirector

logger = logging.getLogger(__name__)


class SessionRegistry:
    """Registry of active MCP sessions for broadcasting notifications."""

    def __init__(self):
        self._sessions: weakref.WeakSet[ServerSession] = weakref.WeakSet()
        self._lock = asyncio.Lock()

    async def register(self, session: ServerSession) -> None:
        """Register a session for notifications."""
        async with self._lock:
            self._sessions.add(session)

    async def broadcast(self, method: str, params: dict[str, Any], logger_name: str = "alf") -> None:
        """Broadcast a notification to all registered sessions."""
        # Note: FastMCP sessions handle send_log_message or send_notification
        # We'll use send_log_message for standard logs/events for now to be safe
        # as it maps cleanly to MCP 'notifications/message'

        # Snapshot sessions
        sessions = list(self._sessions)
        if not sessions:
            return

        level = params.get("level", "info")
        data = params.get("data", {})

        for session in sessions:
            try:
                await session.send_log_message(level=level, data=data, logger=logger_name)
            except Exception:
                pass


async def _notification_loop(director: LLDBDirector, registry: SessionRegistry) -> None:
    """Background task to push events to clients."""
    while True:
        try:
            # 1. Pop pending crashes from Director
            with director._lock:
                crashes = director.pop_pending_crashes(limit=5)

            if crashes:
                for crash in crashes:
                    await registry.broadcast(
                        method="notifications/message",
                        params={"level": "error", "data": {"event": "crash", "crash": crash}},
                    )

            # 2. Check telemetry pipes (simple aggregation)
            # This is a bit more complex as we need to poll active telemetry sessions
            # For Phase 1, we just do crash notifs.

            await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Notification loop error: %s", e)
            await asyncio.sleep(5.0)


def _free_port(host: str = "127.0.0.1") -> int:
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return int(port)


def _find_lldb_dap(explicit: str | None) -> str:
    from ..utils.lldb_dap import find_lldb_dap

    return find_lldb_dap(explicit)


def _wait_for_port(
    host: str,
    port: int,
    proc: subprocess.Popen[str] | None = None,
    budget_seconds: float = 5.0,
    interval_seconds: float = 0.1,
) -> tuple[bool, str]:
    """Poll until `host:port` accepts TCP connections or the budget expires.

    If the child process exits during the wait, stop early and return the
    captured stderr. Returns (ready, detail).
    """
    import time

    attempts = max(1, int(budget_seconds / max(interval_seconds, 0.01)))
    last_err: str = ""
    for _ in range(attempts):
        if proc is not None and proc.poll() is not None:
            err = ""
            if proc.stderr is not None:
                try:
                    err = proc.stderr.read() or ""
                except Exception:  # noqa: BLE001
                    err = ""
            return False, (
                f"lldb-dap exited with code {proc.returncode} before binding "
                f"{host}:{port}. stderr: {err.strip() or '<empty>'}"
            )
        try:
            with socket.create_connection((host, port), timeout=interval_seconds):
                return True, f"listening on {host}:{port}"
        except OSError as err:
            last_err = str(err)
            time.sleep(interval_seconds)
    return False, (
        f"timed out after {budget_seconds:.1f}s waiting for lldb-dap at "
        f"{host}:{port} (last error: {last_err or 'unknown'})"
    )


def build_mcp(director: LLDBDirector, host: str = "127.0.0.1", port: int = 8000) -> FastMCP:
    mcp = FastMCP("alf", json_response=True, host=host, port=port)
    registry = SessionRegistry()

    # Start notification loop on startup
    # FastMCP doesn't have a clean 'on_startup' hook exposed in the decorator style easily usually
    # but we can rely on lldb_launch or subscribe to kick things off, OR we can monkeypatch/wrapper run.
    # Actually, let's start it in a tool call for now to be safe, or just spawn it if we can.
    # We'll spawn it lazily in 'server_subscribe'.

    _loop_task: asyncio.Task | None = None

    def _ensure_loop():
        nonlocal _loop_task
        if _loop_task is None or _loop_task.done():
            _loop_task = asyncio.create_task(_notification_loop(director, registry))

    # Register all canonical tool definitions from alf.tools.definitions
    # These tools are defined once and can be exported to both MCP and provider APIs
    meta_registered = register_tools(mcp, None, META_TOOLS)
    lldb_registered = register_tools(mcp, director, LLDB_TOOLS)
    static_registered = register_tools(mcp, None, STATIC_TOOLS)
    runtime_registered = register_tools(mcp, director, RUNTIME_TOOLS)
    instr_registered = register_tools(mcp, director, INSTRUMENTATION_TOOLS)
    cap_registered = register_tools(mcp, director, CAPABILITY_TOOLS)


    total = (
        len(meta_registered)
        + len(lldb_registered)
        + len(static_registered)
        + len(runtime_registered)
        + len(runtime_registered)
        + len(instr_registered)
        + len(cap_registered)
    )
    logger.debug(
        "Registered %d canonical tools: %d meta, %d lldb, %d static, %d runtime, %d instrumentation, %d capability",
        total,
        len(meta_registered),
        len(lldb_registered),
        len(static_registered),
        len(runtime_registered),
        len(instr_registered),
        len(cap_registered),
    )


    # =========================================================================
    # Inline tools - kept for MCP-specific features
    # =========================================================================

    @mcp.tool()
    async def lldb_continue(
        thread_id: Annotated[int | None, Field(description="Thread to continue (all threads if omitted)")] = None,
        wait: Annotated[bool, Field(description="Wait for process to stop before returning")] = True,
        timeout: Annotated[float | None, Field(description="Timeout in seconds (None = use default)")] = None,
        ctx: Context | None = None,
    ) -> str:
        """Continue process execution after a stop.

        Resumes the debugged process. If wait=True, blocks until the process
        stops again (breakpoint, crash, or exit). Crash notifications are
        emitted over SSE when available.
        """
        new_crashes: list[dict[str, Any]] = []
        with director._lock:
            pre_len = len(director.pending_crashes)
            out = director.continue_exec(thread_id=thread_id, wait=wait, timeout=timeout)
            post_len = len(director.pending_crashes)
            if post_len > pre_len:
                new_crashes = director.pending_crashes[pre_len:post_len]

        # MCP-specific: Send crash notifications via SSE
        if ctx and new_crashes:
            for crash in new_crashes:
                try:
                    await ctx.session.send_log_message(
                        level="error",
                        data={"message": "New crash stop detected", "crash": crash},
                        logger="alf",
                        related_request_id=ctx.request_context.request_id,
                    )
                except Exception:
                    pass

        return out

        return out

    @mcp.tool()
    async def server_subscribe(ctx: Context) -> str:
        """Subscribe to asynchronous server events (crashes, status).

        Call this once at the start of a session to enable push notifications.
        """
        if ctx and ctx.session:
            await registry.register(ctx.session)
            _ensure_loop()
            return "Subscribed to ALF events"
        return "No session context available"

    # =========================================================================
    # MCP Resources - need inline functions for callbacks
    # =========================================================================

    @mcp.resource("crash://current/context")
    def crash_current_context() -> str:
        """Get current crash context with backtrace, registers, and disassembly."""
        from ..tools.definitions.lldb.inspection import (
            _lldb_backtrace_handler,
            _lldb_disassemble_handler,
        )

        with director._lock:
            if not director.connected:
                return "No active session."
            bt = _lldb_backtrace_handler(director, count=24)
            regs = director.execute_lldb_command("register read")
            dis = _lldb_disassemble_handler(director, address="--pc", count=24)
            return json.dumps({"backtrace": bt, "registers": regs, "disassemble": dis}, indent=2)

    @mcp.resource("crash://current/source")
    def crash_current_source() -> str:
        """Get source code window around current crash location."""
        with director._lock:
            return director.source_window()

    return mcp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ALF LLDB‑MCP server (Apple arm64e).")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"])
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=7777)
    parser.add_argument(
        "--backend",
        default="dap",
        choices=["dap", "sbapi", "lldb_mcp", "mock"],
        help="LLDB backend type (default: dap). Future: native_mcp, remote.",
    )
    parser.add_argument(
        "--spawn-dap",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Spawn and manage lldb-dap automatically (default: true).",
    )
    parser.add_argument("--dap-path", default=None, help="Explicit lldb-dap path (else LLDB_DAP_BIN/xcrun/PATH).")
    parser.add_argument("--dap-host", default="127.0.0.1", help="lldb-dap host (when --no-spawn-dap).")
    parser.add_argument(
        "--dap-port",
        type=int,
        default=0,
        help="lldb-dap port (0 = auto when spawning; required when --no-spawn-dap).",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level))

    if platform.machine() not in ("arm64", "arm64e") and args.backend != "mock":
        logger.warning("ALF targets Apple arm64(e); running on %s", platform.machine())

    dap_proc: subprocess.Popen[str] | None = None
    
    try:
        backend = None
        dap_host = str(args.dap_host)
        dap_port = int(args.dap_port)

        if args.backend == "dap":
            if args.spawn_dap:
                dap_bin = _find_lldb_dap(args.dap_path)
                dap_host = "127.0.0.1"
                if dap_port <= 0:
                    dap_port = _free_port(dap_host)
                logger.info("Starting lldb-dap (%s) on %s:%s", dap_bin, dap_host, dap_port)
                # Current lldb-dap (Xcode 16+, LLVM 20+) uses `--connection
                # listen://host:port`. `--port` silently exits on these builds,
                # which used to hide itself behind a failed TCP connect later.
                dap_proc = subprocess.Popen(
                    [
                        dap_bin,
                        "--connection",
                        f"listen://{dap_host}:{dap_port}",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                ready, detail = _wait_for_port(dap_host, dap_port, proc=dap_proc)
                if not ready:
                    raise SystemExit(
                        f"lldb-dap readiness check failed: {detail}. "
                        f"Check that '{dap_bin}' is signed and executable, that "
                        f"port {dap_port} is free, and run `uv run alf doctor`."
                    )
                logger.debug("lldb-dap readiness OK: %s", detail)
            else:
                if dap_port <= 0:
                    raise SystemExit("--dap-port is required when --no-spawn-dap is set")
                ready, detail = _wait_for_port(dap_host, dap_port, budget_seconds=2.0)
                if not ready:
                    raise SystemExit(
                        f"lldb-dap not reachable at {dap_host}:{dap_port}: {detail}. "
                        f"Start it with: xcrun lldb-dap --port {dap_port}"
                    )

            backend = get_backend("dap", host=dap_host, port=dap_port, timeout=args.timeout)

        elif args.backend == "mock":
            logger.warning("Initializing Mock Backend")
            backend = get_backend("mock", timeout=args.timeout)
            dap_host = "mock"
            dap_port = 0

        elif args.backend == "lldb_mcp":
            backend_kwargs: dict[str, Any] = {"timeout": args.timeout, "host": dap_host}
            if dap_port > 0:
                backend_kwargs["port"] = dap_port

            backend = get_backend("lldb_mcp", **backend_kwargs)
            dap_host = str(getattr(backend, "host", dap_host))
            dap_port = int(getattr(backend, "port", 59999))

        else:
            backend = get_backend(args.backend, timeout=args.timeout)
            dap_host = "other"
            dap_port = 0

        director = LLDBDirector(dap_host=dap_host, dap_port=dap_port, timeout=args.timeout, backend=backend)
        mcp = build_mcp(director, host=args.listen_host, port=args.listen_port)
        mcp.run(transport=args.transport)
    finally:
        if dap_proc and dap_proc.poll() is None:
            dap_proc.terminate()
