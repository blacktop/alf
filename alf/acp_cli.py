"""ACP bridge commands.

ACP (Agent Client Protocol) lets ALF drive *agent CLIs* (Codex, Claude Code, Gemini CLI)
that are authenticated via a user's subscription account instead of an API key.

These commands are intentionally separate from the main LLM provider system.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import click

from .acp_events import normalize_update, parse_event


def _repo_root() -> Path:
    # alf/acp_cli.py -> alf/ -> repo root
    return Path(__file__).resolve().parents[1]


def _default_agent(agent: str) -> tuple[str, list[str]]:
    agent = (agent or "").strip().lower()
    if agent == "gemini":
        return (os.environ.get("ACP_GEMINI_BIN", "gemini"), ["--experimental-acp"])
    if agent == "claude":
        return (os.environ.get("ACP_CLAUDE_BIN", "claude-code-acp"), [])
    if agent == "codex":
        return (os.environ.get("ACP_CODEX_BIN", "codex-acp"), [])
    raise click.BadParameter(f"unknown agent '{agent}' (expected: gemini, claude, codex)")


def _mcp_server_alf_stdio(*, name: str) -> dict[str, Any]:
    """Return an ACP McpServer config for spawning ALF as an stdio MCP server."""
    repo = _repo_root()
    existing_pp = os.environ.get("PYTHONPATH", "")
    pp = f"{repo}{os.pathsep}{existing_pp}" if existing_pp else str(repo)

    # ACP schema: env is a list of {name,value} objects.
    env: list[dict[str, str]] = [{"name": "PYTHONPATH", "value": pp}]

    return {
        "name": name,
        "command": sys.executable,
        "args": ["-m", "alf.server", "--transport", "stdio"],
        "env": env,
    }


def _truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… (truncated; re-run with --raw-updates for full payload)"


def _find_zed_external_agent(executable: str) -> str | None:
    """Best-effort discovery for Zed-installed external agents.

    Zed can install ACP agents under:
      ~/Library/Application Support/Zed/external_agents/
    """
    base = Path.home() / "Library" / "Application Support" / "Zed" / "external_agents"
    if not base.exists():
        return None

    # Zed's claude-code-acp is a Node script: .../claude-code-acp/<ver>/node_modules/.../dist/index.js
    if executable == "claude-code-acp":
        candidates = sorted(base.glob("claude-code-acp/*/node_modules/@zed-industries/claude-code-acp/dist/index.js"))
        if candidates:
            return str(candidates[-1])
        return None

    # Zed's codex agent is a native executable: .../codex/v*/codex-acp
    if executable == "codex-acp":
        candidates = sorted(base.glob("codex/*/codex-acp"))
        if candidates:
            return str(candidates[-1])
        return None

    return None


async def _run_acp_session(
    *,
    agent_bin: str,
    agent_args: list[str],
    cwd: Path,
    prompt: str,
    mcp_server_name: str,
    client: Any,
) -> str:
    try:
        from acp import PROTOCOL_VERSION, RequestError, spawn_agent_process, text_block
    except ImportError as e:  # noqa: PERF203
        raise click.ClickException(
            "ACP SDK not installed. Install with: uv sync --extra acp (or pip install agent-client-protocol)"
        ) from e

    mcp_servers = [_mcp_server_alf_stdio(name=mcp_server_name)]

    resolved_bin = None
    if agent_bin and (os.sep in agent_bin or (os.altsep and os.altsep in agent_bin)):
        p = Path(agent_bin).expanduser()
        if p.exists():
            resolved_bin = str(p)
    else:
        resolved_bin = shutil.which(agent_bin)

    if not resolved_bin:
        resolved_bin = _find_zed_external_agent(agent_bin)

    if not resolved_bin:
        cmd = " ".join([agent_bin, *agent_args]) if agent_args else agent_bin
        raise click.ClickException(
            f"ACP agent executable not found: {agent_bin!r}\n"
            f"Tried to run: {cmd}\n\n"
            "Fix:\n"
            "- Pass `--agent-bin /path/to/agent` (and `--agent-arg ...` if needed), or\n"
            "- Set `ACP_GEMINI_BIN` / `ACP_CLAUDE_BIN` / `ACP_CODEX_BIN`.\n"
            "- If you installed the agent via Zed, ensure it exists under "
            "`~/Library/Application Support/Zed/external_agents/`.\n"
        )

    async with spawn_agent_process(client, resolved_bin, *agent_args) as (conn, _proc):
        try:
            try:
                await conn.initialize(
                    protocol_version=PROTOCOL_VERSION,
                    client_info={"name": "alf", "version": "0.1.0"},
                )
            except RequestError as err:
                # Gemini CLI (and other experimental agents) may lag the stable ACP
                # schema. If the agent rejects the minimal InitializeRequest, retry
                # with a more explicit payload via the raw JSON-RPC connection.
                if getattr(err, "code", None) != -32602:
                    raise

                raw_conn = getattr(conn, "_conn", None)
                if raw_conn is None:
                    raise

                init_variants: list[dict[str, Any] | None] = [
                    # Explicit (v1-ish) payload
                    {
                        "protocolVersion": int(PROTOCOL_VERSION),
                        "clientInfo": {"name": "alf", "version": "0.1.0"},
                        "clientCapabilities": {
                            "terminal": False,
                            "fs": {"readTextFile": False, "writeTextFile": False},
                        },
                    },
                    # Some agents still report protocolVersion=0.
                    {
                        "protocolVersion": 0,
                        "clientInfo": {"name": "alf", "version": "0.1.0"},
                        "clientCapabilities": {
                            "terminal": False,
                            "fs": {"readTextFile": False, "writeTextFile": False},
                        },
                    },
                    # Legacy snake_case.
                    {"protocol_version": int(PROTOCOL_VERSION), "client_info": {"name": "alf", "version": "0.1.0"}},
                    {"protocol_version": 0, "client_info": {"name": "alf", "version": "0.1.0"}},
                    # No params (very old draft).
                    None,
                ]

                last_err: RequestError | None = None
                for params in init_variants:
                    try:
                        await raw_conn.send_request("initialize", params)
                        last_err = None
                        break
                    except RequestError as e:
                        last_err = e
                if last_err is not None:
                    raise click.ClickException(f"ACP initialize failed: {last_err}") from err

            session = await conn.new_session(
                cwd=str(cwd.resolve()),
                mcp_servers=mcp_servers,
            )
            resp = await conn.prompt(
                session_id=session.session_id,
                prompt=[text_block(prompt)],
            )
            stop_reason = getattr(resp, "stop_reason", None) or getattr(resp, "stopReason", None) or str(resp)
            return str(stop_reason)
        finally:
            # Ensure the child process is reaped before asyncio.run() closes the loop,
            # otherwise Python can emit "Event loop is closed" warnings from transport
            # finalizers.
            with contextlib.suppress(Exception):
                await conn.close()
            if _proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    _proc.terminate()
                try:
                    await asyncio.wait_for(_proc.wait(), timeout=5.0)
                except TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        _proc.kill()
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(_proc.wait(), timeout=5.0)
            else:
                with contextlib.suppress(Exception):
                    await _proc.wait()

            transport = getattr(_proc, "_transport", None)
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()

            # Let pending transport callbacks run before asyncio.run() closes the loop.
            with contextlib.suppress(Exception):
                await asyncio.sleep(0)


async def _run_acp_prompt_plain(
    *,
    agent_bin: str,
    agent_args: list[str],
    cwd: Path,
    prompt: str,
    mcp_server_name: str,
    yolo: bool,
    raw_updates: bool,
) -> int:
    try:
        from acp.interfaces import Client
    except ImportError as e:  # noqa: PERF203
        raise click.ClickException(
            "ACP SDK not installed. Install with: uv sync --extra acp (or pip install agent-client-protocol)"
        ) from e

    class ALFACPClient(Client):
        def __init__(self, *, yolo: bool, raw_updates: bool):
            self._yolo = bool(yolo)
            self._raw_updates = bool(raw_updates)

        async def request_permission(self, options: Any, session_id: str, tool_call: Any, **kwargs: Any) -> Any:
            # options: list[PermissionOption]
            opts = options or []

            def _as_dict(o: Any) -> dict[str, Any]:
                if isinstance(o, dict):
                    return o
                if hasattr(o, "model_dump"):
                    return o.model_dump()
                if hasattr(o, "dict"):
                    return o.dict()
                return {"value": str(o)}

            def _pick_option_id(kinds: tuple[str, ...]) -> str | None:
                for opt in opts:
                    od = _as_dict(opt)
                    if str(od.get("kind", "")).lower() in kinds:
                        oid = od.get("optionId") or od.get("option_id")
                        if isinstance(oid, str) and oid:
                            return oid
                return None

            allow_id = _pick_option_id(("allow_once", "allow_always"))
            reject_id = _pick_option_id(("reject_once", "reject_always"))

            if self._yolo and allow_id:
                return {"outcome": {"outcome": "selected", "optionId": allow_id}}

            tool = _as_dict(tool_call)
            click.echo("\n[acp] Permission requested:", err=True)
            click.echo(click.style(str(tool.get("title") or tool.get("name") or "tool_call"), bold=True), err=True)

            if isinstance(tool.get("kind"), str):
                click.echo(f"[acp] kind: {tool['kind']}", err=True)

            if click.confirm("[acp] Allow this operation?", default=False):
                if allow_id:
                    return {"outcome": {"outcome": "selected", "optionId": allow_id}}
            if reject_id:
                return {"outcome": {"outcome": "selected", "optionId": reject_id}}
            return {"outcome": {"outcome": "cancelled"}}

        async def session_update(self, session_id: str, update: Any, **kwargs: Any) -> None:
            event = parse_event(update)
            if self._raw_updates:
                click.echo(f"\n[acp] update: {normalize_update(update)}", err=True)
                return

            if event.kind == "thought" and event.text:
                click.echo(click.style(f"\n[thought]\n{event.text.strip()}\n", fg="bright_black"), err=True)
                return

            if event.kind == "message" and event.text:
                click.echo(event.text, nl=False)
                return

            if event.kind == "tool_call":
                tool = event.tool or "tool_call"
                title = (event.title or "").strip()
                line = f"[tool] {tool} {title}".rstrip()
                click.echo(f"\n{click.style(line, fg='cyan')}", err=True)
                return

            if event.kind == "tool_call_update":
                tool = event.tool or "tool_call"
                status = event.status or "update"
                click.echo(f"\n{click.style(f'[tool] {tool} -> {status}', fg='cyan')}", err=True)
                if event.text:
                    click.echo(_truncate(event.text.strip()), err=True)
                return

            if event.kind == "raw":
                click.echo(f"\n[acp] update: {event.payload}", err=True)

    client = ALFACPClient(yolo=yolo, raw_updates=raw_updates)
    stop_reason = await _run_acp_session(
        agent_bin=agent_bin,
        agent_args=agent_args,
        cwd=cwd,
        prompt=prompt,
        mcp_server_name=mcp_server_name,
        client=client,
    )
    click.echo(f"\n[acp] stop_reason: {stop_reason}", err=True)
    return 0


async def _run_acp_prompt_tui(
    *,
    agent_bin: str,
    agent_args: list[str],
    cwd: Path,
    prompt: str,
    mcp_server_name: str,
    yolo: bool,
) -> int:
    try:
        from acp.interfaces import Client
    except ImportError as e:  # noqa: PERF203
        raise click.ClickException(
            "ACP SDK not installed. Install with: uv sync --extra acp (or pip install agent-client-protocol)"
        ) from e

    try:
        from .ui.acp_tui import ACPUI, PermissionRequest
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e

    try:
        ui = ACPUI()
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e

    class ALFACPClient(Client):
        def __init__(self, *, yolo: bool):
            self._yolo = bool(yolo)

        async def request_permission(self, options: Any, session_id: str, tool_call: Any, **kwargs: Any) -> Any:
            opts = options or []

            def _as_dict(o: Any) -> dict[str, Any]:
                if isinstance(o, dict):
                    return o
                if hasattr(o, "model_dump"):
                    return o.model_dump()
                if hasattr(o, "dict"):
                    return o.dict()
                return {"value": str(o)}

            def _pick_option_id(kinds: tuple[str, ...]) -> str | None:
                for opt in opts:
                    od = _as_dict(opt)
                    if str(od.get("kind", "")).lower() in kinds:
                        oid = od.get("optionId") or od.get("option_id")
                        if isinstance(oid, str) and oid:
                            return oid
                return None

            allow_id = _pick_option_id(("allow_once", "allow_always"))
            reject_id = _pick_option_id(("reject_once", "reject_always"))

            if self._yolo and allow_id:
                return {"outcome": {"outcome": "selected", "optionId": allow_id}}

            tool = _as_dict(tool_call)
            title = str(tool.get("title") or tool.get("name") or "tool_call")
            kind = tool.get("kind") if isinstance(tool.get("kind"), str) else None
            detail = None
            if isinstance(tool.get("raw_input"), str):
                detail = tool["raw_input"]
            elif isinstance(tool.get("title"), str) and tool["title"].strip().startswith("{"):
                detail = tool["title"]

            allow = await ui.request_permission(PermissionRequest(title=title, kind=kind, detail=detail))
            if allow and allow_id:
                return {"outcome": {"outcome": "selected", "optionId": allow_id}}
            if reject_id:
                return {"outcome": {"outcome": "selected", "optionId": reject_id}}
            return {"outcome": {"outcome": "cancelled"}}

        async def session_update(self, session_id: str, update: Any, **kwargs: Any) -> None:
            ui.post_event(parse_event(update))

    client = ALFACPClient(yolo=yolo)

    ui_task = asyncio.create_task(ui.run())
    session_task = asyncio.create_task(
        _run_acp_session(
            agent_bin=agent_bin,
            agent_args=agent_args,
            cwd=cwd,
            prompt=prompt,
            mcp_server_name=mcp_server_name,
            client=client,
        )
    )

    done, _pending = await asyncio.wait({ui_task, session_task}, return_when=asyncio.FIRST_COMPLETED)
    if ui_task in done and session_task not in done:
        session_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await session_task
        return 1

    stop_reason = ""
    with contextlib.suppress(Exception):
        stop_reason = str(await session_task)
    ui.post_status(f"stop_reason: {stop_reason}")
    ui.exit()
    with contextlib.suppress(Exception):
        await ui_task
    return 0


async def _run_acp_prompt(
    *,
    agent_bin: str,
    agent_args: list[str],
    cwd: Path,
    prompt: str,
    mcp_server_name: str,
    yolo: bool,
    ui: str,
    raw_updates: bool,
) -> int:
    ui_norm = (ui or "").strip().lower()
    if ui_norm == "tui":
        if raw_updates:
            raise click.ClickException("--raw-updates is not supported with --ui tui")
        return await _run_acp_prompt_tui(
            agent_bin=agent_bin,
            agent_args=agent_args,
            cwd=cwd,
            prompt=prompt,
            mcp_server_name=mcp_server_name,
            yolo=yolo,
        )

    return await _run_acp_prompt_plain(
        agent_bin=agent_bin,
        agent_args=agent_args,
        cwd=cwd,
        prompt=prompt,
        mcp_server_name=mcp_server_name,
        yolo=yolo,
        raw_updates=raw_updates,
    )


@click.group()
def acp() -> None:
    """Use subscription-auth’d agent CLIs (ACP) to drive ALF’s MCP tools."""


@acp.command("chat")
@click.option("--agent", type=click.Choice(["gemini", "claude", "codex"]), default="gemini", show_default=True)
@click.option("--agent-bin", default=None, help="Override agent executable (else uses a preset).")
@click.option("--agent-arg", "agent_args", multiple=True, help="Extra args for the agent process (repeatable).")
@click.option("--cwd", "cwd_str", default=".", show_default=True, help="Agent working directory.")
@click.option("--mcp-name", default="alf", show_default=True, help="Name used for the ALF MCP server.")
@click.option("--yolo", is_flag=True, help="Auto-approve permission requests.")
@click.option("--ui", type=click.Choice(["plain", "tui"]), default="plain", show_default=True, help="Output UI.")
@click.option("--raw-updates", is_flag=True, help="Print raw ACP update payloads (debug).")
@click.argument("prompt", nargs=-1, required=True)
def acp_chat(
    agent: str,
    agent_bin: str | None,
    agent_args: tuple[str, ...],
    cwd_str: str,
    mcp_name: str,
    yolo: bool,
    ui: str,
    raw_updates: bool,
    prompt: tuple[str, ...],
) -> None:
    """Send a single prompt to an ACP agent with ALF configured as an MCP server."""
    default_bin, default_args = _default_agent(agent)
    bin_path = agent_bin or default_bin
    args = list(default_args) + list(agent_args)
    cwd = Path(cwd_str).expanduser().resolve()
    prompt_text = " ".join(prompt).strip()
    if not prompt_text:
        raise click.ClickException("prompt is empty")

    asyncio.run(
        _run_acp_prompt(
            agent_bin=bin_path,
            agent_args=args,
            cwd=cwd,
            prompt=prompt_text,
            mcp_server_name=mcp_name,
            yolo=yolo,
            ui=ui,
            raw_updates=raw_updates,
        )
    )


@acp.command("triage")
@click.option("--agent", type=click.Choice(["gemini", "claude", "codex"]), default="gemini", show_default=True)
@click.option("--agent-bin", default=None, help="Override agent executable (else uses a preset).")
@click.option("--agent-arg", "agent_args", multiple=True, help="Extra args for the agent process (repeatable).")
@click.option("--cwd", "cwd_str", default=".", show_default=True, help="Agent working directory.")
@click.option("--mcp-name", default="alf", show_default=True, help="Name used for the ALF MCP server.")
@click.option("--yolo", is_flag=True, help="Auto-approve permission requests.")
@click.option("--ui", type=click.Choice(["plain", "tui"]), default="plain", show_default=True, help="Output UI.")
@click.option("--raw-updates", is_flag=True, help="Print raw ACP update payloads (debug).")
@click.option("--binary", required=True, help="Path to target binary.")
@click.option("--crash", required=True, help="Path to crashing input.")
def acp_triage(
    agent: str,
    agent_bin: str | None,
    agent_args: tuple[str, ...],
    cwd_str: str,
    mcp_name: str,
    yolo: bool,
    ui: str,
    raw_updates: bool,
    binary: str,
    crash: str,
) -> None:
    """Ask an ACP agent to triage a crash using ALF’s MCP tools."""
    default_bin, default_args = _default_agent(agent)
    bin_path = agent_bin or default_bin
    args = list(default_args) + list(agent_args)
    cwd = Path(cwd_str).expanduser().resolve()

    prompt_text = f"""You are driving LLDB via ALF MCP tools.

CRITICAL RULES:
- Do not guess crash details. Use tools and base conclusions on tool output.
- After launching, always call lldb_crash_context to collect real data.

Task:
1) Call lldb_launch with:
   - binary: {Path(binary).expanduser().resolve()}
   - crash_input: {Path(crash).expanduser().resolve()}
2) Call lldb_crash_context (max_frames=32, stack_bytes=256)
3) Summarize root cause and propose:
   - corpus seeds to go deeper
   - dictionary tokens (if applicable)
"""

    asyncio.run(
        _run_acp_prompt(
            agent_bin=bin_path,
            agent_args=args,
            cwd=cwd,
            prompt=prompt_text,
            mcp_server_name=mcp_name,
            yolo=yolo,
            ui=ui,
            raw_updates=raw_updates,
        )
    )
