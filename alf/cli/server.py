"""Server command for MCP server."""

from __future__ import annotations

import click

from .. import server as server_mod


@click.command()
@click.option(
    "--transport",
    default="stdio",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    help="MCP transport.",
)
@click.option(
    "--listen-host",
    default="127.0.0.1",
    help="Host for sse/streamable-http transports.",
)
@click.option(
    "--listen-port",
    default=7777,
    help="Port for sse/streamable-http transports.",
)
@click.option(
    "--spawn-dap/--no-spawn-dap",
    default=True,
    help="Spawn and manage lldb-dap automatically (default: true).",
)
@click.option("--dap-path", default=None, help="Explicit lldb-dap path (else LLDB_DAP_BIN/xcrun/PATH).")
@click.option("--dap-host", default="127.0.0.1", help="Debugger backend host (when --no-spawn-dap).")
@click.option("--dap-port", default=0, type=int, help="Debugger backend port (0 = auto when spawning).")
@click.option("--timeout", default=30.0, help="DAP timeout (seconds).")
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level.",
)
@click.option(
    "--backend",
    default="dap",
    type=click.Choice(["dap", "sbapi", "lldb_mcp", "mock"]),
    help="LLDB backend type (default: dap).",
)
def server(
    transport: str,
    listen_host: str,
    listen_port: int,
    spawn_dap: bool,
    dap_path: str | None,
    dap_host: str,
    dap_port: int,
    timeout: float,
    log_level: str,
    backend: str,
) -> None:
    """Start the ALF LLDB-MCP server."""
    argv = [
        "--transport",
        transport,
        "--listen-host",
        listen_host,
        "--listen-port",
        str(listen_port),
        "--timeout",
        str(timeout),
        "--log-level",
        log_level,
        "--backend",
        backend,
    ]
    if not spawn_dap:
        argv.append("--no-spawn-dap")
    if dap_path:
        argv.extend(["--dap-path", dap_path])
    argv.extend(["--dap-host", dap_host, "--dap-port", str(dap_port)])
    server_mod.main(argv)
