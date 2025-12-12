"""Analyze commands for crash triage, classification, and reporting."""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import click

from .. import corpus as corpus_mod
from .. import minimize as minimize_mod
from .. import triage as triage_mod
from ._helpers import infer_target, repo_root, safe_slug


def _run_lldb_mcp_triage(
    binary: str,
    crash_path: Path,
    tag: str,
    output: str | None,
    no_markdown: bool,
    batch: bool,
    mcp_host: str,
    mcp_port: int,
    timeout: float,
) -> None:
    """Run triage using LLDB native MCP backend."""
    import datetime as dt
    import json

    from ..backend.lldb_mcp import LLDBMCPBackend

    binary_path = Path(binary).expanduser().resolve()
    if not binary_path.exists():
        click.echo(f"[!] Binary not found: {binary_path}", err=True)
        raise SystemExit(1)

    # Get list of crash files
    if batch or crash_path.is_dir():
        if not crash_path.is_dir():
            click.echo(f"[!] --batch requires a directory, got: {crash_path}", err=True)
            raise SystemExit(1)
        crash_files = sorted(
            [
                f
                for f in crash_path.iterdir()
                if f.is_file() and (f.name.startswith("crash-") or f.name.startswith("timeout-"))
            ]
        )
        if not crash_files:
            click.echo(f"[!] No crash files found in {crash_path}", err=True)
            raise SystemExit(1)
        click.echo(f"[+] LLDB MCP batch mode: {len(crash_files)} crashes")
        output_dir = Path(output) if output else crash_path / "triage"
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        if not crash_path.exists():
            click.echo(f"[!] Crash input not found: {crash_path}", err=True)
            raise SystemExit(1)
        crash_files = [crash_path]
        output_dir = None

    # Create backend
    backend = LLDBMCPBackend(host=mcp_host, port=mcp_port, timeout=timeout)
    try:
        backend.connect()
    except Exception as e:
        click.echo(f"[!] Failed to connect to LLDB MCP at {mcp_host}:{mcp_port}: {e}", err=True)
        click.echo("[!] Make sure LLDB MCP server is running:", err=True)
        click.echo(f"    (lldb) protocol-server start MCP listen://localhost:{mcp_port}", err=True)
        raise SystemExit(1) from e

    success_count = 0
    start_time = dt.datetime.now()

    for i, crash_file in enumerate(crash_files, 1):
        if len(crash_files) > 1:
            click.echo(f"[{i}/{len(crash_files)}] {crash_file.name}")

        try:
            # Launch with crash input
            launch_result = backend.launch(str(binary_path), crash_input=str(crash_file))
            if launch_result.status == "error":
                click.echo(f"  [!] Launch failed: {launch_result.error}", err=True)
                continue

            # Collect crash context
            context = backend.collect_crash_context()
            context["binary"] = str(binary_path)
            context["crash_input"] = str(crash_file)
            context["tag"] = tag
            context["backend"] = "lldb_mcp"
            context["timestamp"] = dt.datetime.now().isoformat()

            # Add launch result info
            context["stop"] = {
                "reason": launch_result.reason,
                "status": launch_result.status,
            }

            # Write output
            if output_dir:
                out_path = output_dir / f"{crash_file.stem}.json"
            elif output:
                out_path = Path(output)
            else:
                out_path = crash_file.with_suffix(".triage.json")

            out_path.write_text(json.dumps(context, indent=2))
            success_count += 1

            if len(crash_files) == 1:
                stack_hash = context.get("stack_hash", "")
                click.echo(f"[+] Stack hash: {stack_hash[:16]}...")
                click.echo(f"[+] Output: {out_path}")

        except Exception as e:
            click.echo(f"  [!] Error: {e}", err=True)
            continue

    elapsed = (dt.datetime.now() - start_time).total_seconds()

    if len(crash_files) > 1:
        click.echo(f"[+] LLDB MCP batch complete: {success_count}/{len(crash_files)} in {elapsed:.1f}s")
        if output_dir:
            click.echo(f"[+] Results in: {output_dir}")

    backend.disconnect()

    if success_count == 0:
        raise SystemExit(1)


def _run_sbapi_triage(
    binary: str,
    crash_path: Path,
    tag: str,
    output: str | None,
    no_markdown: bool,
    batch: bool,
) -> None:
    """Run triage using SBAPI backend (10-100x faster than DAP)."""
    import datetime as dt
    import json

    try:
        from ..backend.sbapi import SBAPIBackend
    except ImportError as e:
        click.echo(f"[!] SBAPI backend requires LLDB Python bindings: {e}", err=True)
        click.echo("[!] Make sure lldb Python module is in your PYTHONPATH", err=True)
        raise SystemExit(1) from e

    binary_path = Path(binary).expanduser().resolve()
    if not binary_path.exists():
        click.echo(f"[!] Binary not found: {binary_path}", err=True)
        raise SystemExit(1)

    # Get list of crash files
    if batch or crash_path.is_dir():
        if not crash_path.is_dir():
            click.echo(f"[!] --batch requires a directory, got: {crash_path}", err=True)
            raise SystemExit(1)
        crash_files = sorted(
            [
                f
                for f in crash_path.iterdir()
                if f.is_file() and (f.name.startswith("crash-") or f.name.startswith("timeout-"))
            ]
        )
        if not crash_files:
            click.echo(f"[!] No crash files found in {crash_path}", err=True)
            raise SystemExit(1)
        click.echo(f"[+] SBAPI batch mode: {len(crash_files)} crashes")
        output_dir = Path(output) if output else crash_path / "triage"
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        if not crash_path.exists():
            click.echo(f"[!] Crash input not found: {crash_path}", err=True)
            raise SystemExit(1)
        crash_files = [crash_path]
        output_dir = None

    # Create backend once, reuse for all crashes (major performance win)
    backend = SBAPIBackend(str(binary_path))
    success_count = 0
    start_time = dt.datetime.now()

    for i, crash_file in enumerate(crash_files, 1):
        if len(crash_files) > 1:
            click.echo(f"[{i}/{len(crash_files)}] {crash_file.name}")

        try:
            # Launch with crash input
            launch_result = backend.launch(crash_input=str(crash_file))
            if launch_result.status != "stopped":
                click.echo(f"  [!] Launch failed: {launch_result.error}", err=True)
                continue

            # Get crash context
            context = {
                "binary": str(binary_path),
                "crash_input": str(crash_file),
                "tag": tag,
                "backend": "sbapi",
                "timestamp": dt.datetime.now().isoformat(),
            }

            # Get backtrace
            backtrace = backend.get_backtrace()
            context["backtrace"] = [
                {"frame": f.index, "pc": f.pc, "symbol": f.symbol or "", "module": f.module or ""} for f in backtrace
            ]

            # Get stack hash
            stack_hash, pcs = backend.compute_stack_hash(max_frames=5)
            context["stack_hash"] = stack_hash
            context["stack_pcs"] = pcs

            # Get registers
            regs = backend.read_registers()
            context["registers"] = regs

            # Get stop reason
            stop = backend.get_stop_reason()
            if stop:
                context["stop_reason"] = {
                    "type": stop.reason,
                    "description": stop.description or "",
                    "signal": stop.signal,
                }

            # Kill process for next iteration
            backend.kill()

            # Write output
            if output_dir:
                out_path = output_dir / f"{crash_file.stem}.json"
            elif output:
                out_path = Path(output)
            else:
                out_path = crash_file.with_suffix(".triage.json")

            out_path.write_text(json.dumps(context, indent=2))
            success_count += 1

            if len(crash_files) == 1:
                click.echo(f"[+] Stack hash: {stack_hash[:16]}...")
                click.echo(f"[+] Output: {out_path}")

        except Exception as e:
            click.echo(f"  [!] Error: {e}", err=True)
            continue

    elapsed = (dt.datetime.now() - start_time).total_seconds()

    if len(crash_files) > 1:
        click.echo(f"[+] SBAPI batch complete: {success_count}/{len(crash_files)} in {elapsed:.1f}s")
        if output_dir:
            click.echo(f"[+] Results in: {output_dir}")

    backend.terminate()

    if success_count == 0:
        raise SystemExit(1)


@click.group(name="analyze", invoke_without_command=True)
@click.option("--pipeline/--no-pipeline", default=False, help="Run triage -> classify -> report.")
@click.option("--binary", default=None, help="Path to fuzz binary (required for --pipeline).")
@click.option("--crash", default=None, help="Path to crash input (required for --pipeline).")
@click.option("--tag", default="analysis", help="Tag/identifier.")
@click.option("--model", default=None, help="LLM model (default: from config).")
@click.option("--adapter", default="alf-llm", help="LLM adapter binary.")
@click.option("--timeout", default=180, help="LLM adapter timeout seconds (classify step).")
@click.option("--dry-run", is_flag=True, help="Skip LLM; use heuristics (classify step).")
@click.option("--dap-path", default=None, help="Explicit lldb-dap path (triage step).")
@click.option("--dap-port", default=0, help="DAP port (0 = auto) (triage step).")
@click.option("--triage-timeout", default=30.0, help="DAP/MCP timeout seconds (triage step).")
@click.option(
    "--log-level",
    default="ERROR",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level (triage step).",
)
@click.pass_context
def analyze(
    ctx: click.Context,
    pipeline: bool,
    binary: str | None,
    crash: str | None,
    tag: str,
    model: str,
    adapter: str,
    timeout: int,
    dry_run: bool,
    dap_path: str | None,
    dap_port: int,
    triage_timeout: float,
    log_level: str,
) -> None:
    """Post-mortem crash analysis workflows (triage/classify/report)."""
    if ctx.invoked_subcommand is not None:
        return
    if not pipeline:
        raise click.UsageError("Missing subcommand. Use `alf analyze triage|classify|report` or pass `--pipeline`.")
    if not binary or not crash:
        raise click.UsageError("`--binary` and `--crash` are required in `--pipeline` mode.")

    root = repo_root()
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    binary_path = Path(binary).expanduser().resolve()
    crash_path = Path(crash).expanduser().resolve()
    if not binary_path.exists():
        raise click.ClickException(f"binary not found: {binary_path}")
    if not crash_path.exists():
        raise click.ClickException(f"crash input not found: {crash_path}")

    from ..triage import (
        ClassifyConfig,
        ReportConfig,
        TriageConfig,
        run_classify,
        run_report,
        run_triage,
    )

    target = infer_target(binary_path)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    model_slug = safe_slug(model)

    triage_json = logs_dir / f"{stamp}_{target}_mcp_triage_{tag}.json"
    classify_json = logs_dir / f"{stamp}_{target}_classify_{model_slug}.json"
    rca_md = logs_dir / f"{stamp}_{target}_rca_{tag}.md"

    # Step 1: Triage
    triage_config = TriageConfig(
        binary=binary_path,
        crash=crash_path,
        tag=tag,
        dap_path=dap_path,
        dap_port=dap_port,
        timeout=triage_timeout,
        log_level=log_level,
        output=triage_json,
        no_markdown=True,
    )
    triage_result = run_triage(triage_config)
    if not triage_result.success:
        click.echo(f"[-] triage failed: {triage_result.error}", err=True)
        raise SystemExit(1)

    # Step 2: Classify
    classify_ok = True
    classify_config = ClassifyConfig(
        binary=binary_path,
        crash=crash_path,
        dap_logs=[triage_json],
        tag=tag,
        model=model if model else None,
        adapter=adapter,
        timeout=timeout,
        dry_run=dry_run,
        output=classify_json,
    )
    classify_result = run_classify(classify_config)
    if not classify_result.success:
        classify_ok = False
        click.echo("[!] classify step failed; generating report without classification", err=True)

    # Step 3: Report
    report_config = ReportConfig(
        context_json=triage_json,
        classification_json=classify_json if classify_ok else None,
        output=rca_md,
        tag=tag,
    )
    report_result = run_report(report_config)
    if not report_result.success:
        click.echo(f"[-] report failed: {report_result.error}", err=True)
        raise SystemExit(1)

    click.echo(f"[+] analyze pipeline triage: {triage_result.json_path}")
    if classify_ok:
        click.echo(f"[+] analyze pipeline classify: {classify_result.json_path}")
    click.echo(f"[+] analyze pipeline report: {report_result.output_path}")


@analyze.command(name="triage")
@click.option("--binary", required=True, help="Path to fuzz binary.")
@click.option("--crash", required=True, help="Path to crash input or directory of crashes.")
@click.option("--tag", default="triage", help="Short tag.")
@click.option("--dap-path", default=None, help="Explicit lldb-dap path.")
@click.option("--dap-port", default=0, help="DAP port (0 = auto).")
@click.option("--timeout", default=30.0, help="Timeout seconds.")
@click.option(
    "--log-level",
    default="ERROR",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level.",
)
@click.option("--output", default=None, help="Write JSON to this path (or directory for batch).")
@click.option("--no-markdown", is_flag=True, help="Skip Markdown report.")
@click.option(
    "--batch",
    is_flag=True,
    help="Batch mode: process all crash files in the directory. Reuses session for 3-10x speedup.",
)
@click.option(
    "--backend",
    default="dap",
    type=click.Choice(["dap", "sbapi", "lldb_mcp"]),
    help="Backend: dap (default), sbapi (direct LLDB Python API), or lldb_mcp (native LLDB MCP).",
)
@click.option(
    "--mcp-host",
    default="127.0.0.1",
    help="LLDB MCP server host (for lldb_mcp backend).",
)
@click.option(
    "--mcp-port",
    default=59999,
    type=int,
    help="LLDB MCP server port (for lldb_mcp backend).",
)
def analyze_triage(
    binary: str,
    crash: str,
    tag: str,
    dap_path: str | None,
    dap_port: int,
    timeout: float,
    log_level: str,
    output: str | None,
    no_markdown: bool,
    batch: bool,
    backend: str,
    mcp_host: str,
    mcp_port: int,
) -> None:
    """Collect crash triage via the ALF MCP server or SBAPI backend."""
    from ..utils.crash_files import CRASH_PREFIXES, EXCLUDE_EXTENSIONS

    crash_path = Path(crash).expanduser().resolve()

    # SBAPI backend: direct LLDB Python API for maximum performance
    if backend == "sbapi":
        _run_sbapi_triage(binary, crash_path, tag, output, no_markdown, batch)
        return

    # LLDB native MCP backend: direct connection to LLDB protocol-server
    if backend == "lldb_mcp":
        _run_lldb_mcp_triage(binary, crash_path, tag, output, no_markdown, batch, mcp_host, mcp_port, timeout)
        return

    # DAP backend: use MCP server (original behavior)
    # Detect batch mode: explicit flag or crash is a directory
    if batch or crash_path.is_dir():
        if not crash_path.is_dir():
            click.echo(f"[!] --batch requires a directory, got: {crash_path}", err=True)
            raise SystemExit(1)

        # Find all crash files using centralized utils
        crash_files = sorted(
            [
                f
                for f in crash_path.iterdir()
                if f.is_file()
                and not f.name.startswith(".")
                and f.suffix.lower() not in EXCLUDE_EXTENSIONS
                and (
                    any(f.name.startswith(prefix) for prefix in CRASH_PREFIXES)
                    or f.suffix == ""  # Files without extension are likely crash inputs
                )
            ]
        )
        if not crash_files:
            click.echo(f"[!] No crash files found in {crash_path}", err=True)
            raise SystemExit(1)

        click.echo(f"[+] Batch mode: {len(crash_files)} crashes in {crash_path}")

        # Create output directory if needed
        output_dir = Path(output) if output else crash_path / "triage"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Process each crash (session reuse happens inside triage_mod)
        success_count = 0
        for i, crash_file in enumerate(crash_files, 1):
            click.echo(f"[{i}/{len(crash_files)}] {crash_file.name}")
            crash_output = output_dir / f"{crash_file.stem}.json"

            argv = [
                "--binary",
                binary,
                "--crash",
                str(crash_file),
                "--tag",
                tag,
                "--dap-port",
                str(dap_port),
                "--timeout",
                str(timeout),
                "--log-level",
                log_level,
                "--output",
                str(crash_output),
            ]
            if dap_path:
                argv.extend(["--dap-path", dap_path])
            if no_markdown:
                argv.append("--no-markdown")

            code = triage_mod.main(argv)
            if code == 0:
                success_count += 1

        click.echo(f"[+] Batch complete: {success_count}/{len(crash_files)} succeeded")
        click.echo(f"[+] Results in: {output_dir}")
        return

    # Single crash mode
    from ..triage import TriageConfig, run_triage

    config = TriageConfig(
        binary=Path(binary),
        crash=crash_path,
        tag=tag,
        dap_path=dap_path,
        dap_port=dap_port,
        timeout=timeout,
        log_level=log_level,
        output=Path(output) if output else None,
        no_markdown=no_markdown,
    )

    result = run_triage(config)

    if not result.success:
        click.echo(f"[-] {result.error}", err=True)
        raise SystemExit(1)

    click.echo(f"[+] MCP triage JSON: {result.json_path}")
    if result.markdown_path:
        click.echo(f"[+] MCP triage report: {result.markdown_path}")


@analyze.command(name="classify")
@click.option("--binary", required=True, help="Path to fuzz binary.")
@click.option("--crash", required=True, help="Path to crash input.")
@click.option("--triage-log", multiple=True, help="Path to sanitizer/LLDB triage logs.")
@click.option("--dap-log", multiple=True, help="Path to DAP JSON logs.")
@click.option("--tag", default="triage", help="Tag/identifier.")
@click.option("--model", default=None, help="LLM model (default: from config).")
@click.option("--adapter", default="alf-llm", help="LLM adapter binary.")
@click.option("--timeout", default=180, help="Timeout seconds.")
@click.option("--dry-run", is_flag=True, help="Skip LLM call.")
@click.option("--output", default=None, help="Write classification JSON to this path.")
@click.option("--max-log-lines", default=200, help="Max lines per log snippet.")
@click.option("--extra-note", multiple=True, help="Additional context strings.")
@click.option("--exploitability/--no-exploitability", default=True, help="Include exploitability analysis.")
@click.option("--crash-context", default=None, help="Path to crash context JSON for exploitability.")
def analyze_classify(
    binary: str,
    crash: str,
    triage_log: tuple[str, ...],
    dap_log: tuple[str, ...],
    tag: str,
    model: str,
    adapter: str,
    timeout: int,
    dry_run: bool,
    output: str | None,
    max_log_lines: int,
    extra_note: tuple[str, ...],
    exploitability: bool,
    crash_context: str | None,
) -> None:
    """Classify crash artifacts (optional LLM adapter)."""
    from ..triage import ClassifyConfig, run_classify

    config = ClassifyConfig(
        binary=Path(binary),
        crash=Path(crash),
        triage_logs=[Path(log) for log in triage_log],
        dap_logs=[Path(log) for log in dap_log],
        tag=tag,
        model=model if model else None,
        adapter=adapter,
        timeout=timeout,
        dry_run=dry_run,
        output=Path(output) if output else None,
        max_log_lines=max_log_lines,
        extra_notes=list(extra_note),
        exploitability=exploitability,
        crash_context=Path(crash_context) if crash_context else None,
    )

    result = run_classify(config)

    if not result.success:
        click.echo(f"[-] {result.error}", err=True)
        raise SystemExit(1)

    click.echo(f"[+] Classification: {result.classification} (confidence: {result.confidence:.2f})")
    click.echo(f"[+] Source: {result.source}")
    if result.json_path:
        click.echo(f"[+] Output: {result.json_path}")


@analyze.command(name="report")
@click.option(
    "--context-json",
    required=True,
    help="Path to lldb_crash_context JSON (or triage JSON embedding it).",
)
@click.option(
    "--classification-json",
    default=None,
    help="Optional classification JSON from `alf analyze classify`.",
)
@click.option("--output", default=None, help="Write Markdown to this path (default logs/).")
@click.option("--tag", default="rca", help="Tag for output filename.")
@click.option("--exploitability/--no-exploitability", default=True, help="Include exploitability analysis.")
def analyze_report(
    context_json: str,
    classification_json: str | None,
    output: str | None,
    tag: str,
    exploitability: bool,
) -> None:
    """Generate a Markdown RCA report from crash artifacts."""
    from ..triage import ReportConfig, run_report

    config = ReportConfig(
        context_json=Path(context_json),
        classification_json=Path(classification_json) if classification_json else None,
        output=Path(output) if output else None,
        tag=tag,
        exploitability=exploitability,
    )

    result = run_report(config)

    if not result.success:
        click.echo(f"[-] {result.error}", err=True)
        raise SystemExit(1)

    click.echo(f"[+] Wrote RCA report: {result.output_path}")


@analyze.command(name="minimize")
@click.argument("binary")
@click.argument("crash")
@click.option("--timeout", type=int, default=5, help="Timeout per run in seconds.")
@click.option("--output", default=None, help="Output path for minimized crash (default: <crash>.min).")
def analyze_minimize(binary: str, crash: str, timeout: int, output: str | None) -> None:
    """Minimize a crashing input using libFuzzer's -minimize_crash=1."""
    code = minimize_mod.minimize(binary, crash, timeout, output)
    if code:
        raise SystemExit(code)


@analyze.command(name="corpus")
@click.argument("binary")
@click.argument("crash")
@click.option("--output-dir", default=None, help="Output directory for seeds.")
@click.option("--dict", "dict_path", default=None, help="Path for dictionary file.")
@click.option("--llm", is_flag=True, help="Use LLM to suggest additional mutations.")
@click.option(
    "--model",
    default=None,
    help="LLM model name (defaults from ALF_LLM_MODEL/LLDB_MCP_MODEL or provider defaults).",
)
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["anthropic", "openai", "google", "ollama", "lmstudio"]),
    help="LLM provider (auto-detected if not specified).",
)
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON.")
def analyze_corpus(
    binary: str,
    crash: str,
    output_dir: str | None,
    dict_path: str | None,
    llm: bool,
    model: str,
    provider: str | None,
    json_out: bool,
) -> None:
    """Generate corpus seeds and dictionary tokens from a crash input."""
    argv = [binary, crash]
    if output_dir:
        argv.extend(["--output-dir", output_dir])
    if dict_path:
        argv.extend(["--dict", dict_path])
    if llm:
        argv.append("--llm")
    if model:
        argv.extend(["--model", model])
    if provider:
        argv.extend(["--provider", provider])
    if json_out:
        argv.append("--json")

    code = corpus_mod.main(argv)
    if code:
        raise SystemExit(code)
