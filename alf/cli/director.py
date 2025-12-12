"""Director command for AI-driven crash analysis."""

from __future__ import annotations

import click

from .. import config as alf_config
from .. import director as director_mod


@click.command()
@click.option("--binary", required=True, help="Path to fuzz binary.")
@click.option("--crash", required=True, help="Path to crash input.")
@click.option("--tag", default="director", help="Short tag for artifact names.")
@click.option(
    "--mode",
    default=None,
    type=click.Choice(["auto", "researcher"]),
    help="Operation mode (default: from config or 'auto').",
)
@click.option("--model", default=None, help="LLM model (default: from config).")
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["anthropic", "openai", "google", "ollama", "lmstudio", "vllm", "localai"]),
    help="LLM provider (auto-detected from config if not set).",
)
@click.option("--timeout", default=None, type=int, help="Adapter timeout seconds (default: from config or 180).")
@click.option("--max-turns", default=None, type=int, help="Max LLM/MCP turns (default: from config or 10).")
@click.option("--minimal-tools", is_flag=True, default=None, help="Use minimal tools (4 + search) for small context.")
@click.option("--dap-path", default=None, help="Explicit lldb-dap path.")
@click.option("--dap-port", default=0, help="DAP port (0 = auto).")
@click.option(
    "--log-level",
    default="ERROR",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level.",
)
@click.option("--write-corpus/--no-write-corpus", default=None, help="Write corpus seeds (default: from config).")
@click.option("--write-dict/--no-write-dict", default=None, help="Write dictionary (default: from config).")
@click.option("--dict-out", default=None, help="Dictionary output path.")
@click.option(
    "--trace-output",
    default=None,
    help="Optional JSONL trace output path for tool-call episodes (experimental).",
)
def director(
    binary: str,
    crash: str,
    tag: str,
    mode: str | None,
    model: str | None,
    provider: str | None,
    timeout: int | None,
    max_turns: int | None,
    minimal_tools: bool | None,
    dap_path: str | None,
    dap_port: int,
    log_level: str,
    write_corpus: bool | None,
    write_dict: bool | None,
    dict_out: str | None,
    trace_output: str | None,
) -> None:
    """Run the AI Director Loop."""
    # Load config defaults
    director_cfg = alf_config.get_director_config()
    provider_cfg = alf_config.get_provider_config()

    # Apply config defaults where CLI didn't override
    if mode is None:
        mode = director_cfg.get("mode", "auto")
    if timeout is None:
        timeout = int(provider_cfg.get("timeout") or 180)
    if max_turns is None:
        max_turns = director_cfg.get("max_turns", 10)
    if minimal_tools is None:
        minimal_tools = director_cfg.get("minimal_tools", False)
    if write_corpus is None:
        write_corpus = director_cfg.get("write_corpus", True)
    if write_dict is None:
        write_dict = director_cfg.get("write_dict", True)

    argv = [
        "--binary",
        binary,
        "--crash",
        crash,
        "--tag",
        tag,
        "--mode",
        mode,
        "--timeout",
        str(timeout),
        "--max-turns",
        str(max_turns),
        "--dap-port",
        str(dap_port),
        "--log-level",
        log_level,
    ]
    if model:
        argv.extend(["--model", model])
    if provider:
        argv.extend(["--provider", provider])
    if minimal_tools:
        argv.append("--minimal-tools")
    if dap_path:
        argv.extend(["--dap-path", dap_path])
    if not write_corpus:
        argv.append("--no-write-corpus")
    if not write_dict:
        argv.append("--no-write-dict")
    if dict_out:
        argv.extend(["--dict-out", dict_out])
    if trace_output:
        argv.extend(["--trace-output", trace_output])

    director_mod.main(argv)
