"""Fuzzing commands: alf fuzz auto|hybrid|jackalope."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path

import click


def _run_async(coro: Coroutine[None, None, int]) -> None:
    """Run an async command, handle KeyboardInterrupt, and exit on failure."""
    try:
        code = asyncio.run(coro)
    except KeyboardInterrupt:
        click.echo("\n[*] Fuzzing interrupted by user", err=True)
        code = 130
    if code:
        raise SystemExit(code)


class _DefaultSubcommandGroup(click.Group):
    """Click group that treats unknown first arg as a default subcommand."""

    default_subcommand = "auto"

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and args[0] not in self.commands and args[0] not in ("-h", "--help"):
            args.insert(0, self.default_subcommand)
        return super().parse_args(ctx, args)


@click.group(cls=_DefaultSubcommandGroup, invoke_without_command=True)
@click.pass_context
def fuzz(ctx: click.Context) -> None:
    """Autonomous AI-driven fuzzing.

    Subcommands:
      auto       LLM-driven fuzzing with mutation hooks (default)
      hybrid     LLM cold-start + native libFuzzer + LLM triage
      jackalope  LLM cold-start + Jackalope/TinyInst + LLM triage

    When called with arguments and no subcommand, delegates to `alf fuzz auto`.

    Examples:
        alf fuzz auto /path/to/binary --mode auto
        alf fuzz /path/to/binary --corpus /path/to/seeds
        alf fuzz hybrid ./fuzz_target --corpus ./seeds
        alf fuzz jackalope ./target --fuzzer /path/to/fuzzer --corpus ./seeds
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@fuzz.command(name="auto")
@click.argument("binary")
@click.option("--corpus", default=None, help="Directory containing initial corpus seeds.")
@click.option(
    "--mode",
    default="auto",
    type=click.Choice(["auto", "researcher"]),
    help="Fuzzing mode: auto (fully autonomous) or researcher (human-in-the-loop).",
)
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["anthropic", "openai", "google", "ollama", "lmstudio"]),
    help="LLM provider (auto-detected if not specified).",
)
@click.option("--model", default=None, help="LLM model name (default: from config/provider).")
@click.option("--max-turns", default=12, type=int, help="Max LLM/MCP turns during setup/crash analysis.")
@click.option("--max-iterations", default=100, help="Maximum fuzzing iterations.")
@click.option("--timeout", default=180, help="LLM request timeout (seconds).")
@click.option("--dap-path", default=None, help="Explicit lldb-dap path.")
@click.option("--dap-port", default=0, help="DAP port (0 = auto).")
@click.option(
    "--log-level",
    default="ERROR",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level.",
)
@click.option("--write-corpus/--no-write-corpus", default=True, help="Write corpus seeds to disk.")
@click.option("--write-crashes/--no-write-crashes", default=True, help="Write crashes to disk.")
@click.option("--corpus-dir", default=None, help="Output directory for corpus seeds.")
@click.option("--crashes-dir", default=None, help="Output directory for crashes.")
@click.option(
    "--trace-output",
    default=None,
    help="Optional JSONL trace output path for tool-call episodes (experimental).",
)
def auto(
    binary: str,
    corpus: str | None,
    mode: str,
    provider: str | None,
    model: str | None,
    max_turns: int,
    max_iterations: int,
    timeout: int,
    dap_path: str | None,
    dap_port: int,
    log_level: str,
    write_corpus: bool,
    write_crashes: bool,
    corpus_dir: str | None,
    crashes_dir: str | None,
    trace_output: str | None,
) -> None:
    """Run autonomous AI-driven fuzzing on a binary.

    BINARY: Path to the target binary to fuzz.

    The agent uses an LLM to:
    - Analyze the target and identify interesting functions
    - Install mutation hooks at strategic breakpoints
    - Run the target with various inputs
    - Collect and deduplicate crashes
    - Generate new corpus seeds based on coverage/crashes

    Examples:
        alf fuzz auto /path/to/binary --mode auto
        alf fuzz auto /path/to/binary --corpus /path/to/seeds --provider anthropic
    """
    import sys

    from ..fuzz import FuzzAgent, FuzzSession
    from ..fuzz.agent import AgentConfig
    from ..log import configure_logging_from_level

    binary_path = Path(binary).expanduser().resolve()
    if not binary_path.exists():
        click.echo(f"[!] Binary not found: {binary_path}", err=True)
        raise SystemExit(1)

    configure_logging_from_level(log_level)

    # Collect initial inputs from corpus directory
    initial_inputs: list[Path] = []
    if corpus:
        corpus_path = Path(corpus).expanduser().resolve()
        if corpus_path.is_dir():
            initial_inputs = list(corpus_path.iterdir())
            click.echo(f"[+] Loaded {len(initial_inputs)} corpus seeds from {corpus_path}", err=True)
        elif corpus_path.is_file():
            initial_inputs = [corpus_path]
            click.echo(f"[+] Using single seed: {corpus_path}", err=True)
        else:
            click.echo(f"[!] Corpus path not found: {corpus_path}", err=True)

    config = AgentConfig(
        mode=mode,
        provider=provider,
        model=model,
        max_iterations=max_iterations,
        max_turns=max_turns,
        timeout=float(timeout),
        write_corpus=write_corpus,
        write_crashes=write_crashes,
        corpus_dir=corpus_dir,
        crashes_dir=crashes_dir,
        trace_output=trace_output,
    )

    async def run_fuzzing() -> int:
        try:
            async with FuzzSession(
                binary=str(binary_path),
                corpus_dir=corpus_dir,
                dap_path=dap_path,
                dap_port=dap_port,
                timeout=30.0,
                log_level=log_level,
            ) as session:
                click.echo(f"[+] Session started, available tools: {len(session.tools)}", err=True)

                agent = FuzzAgent(session, config=config)
                stats = await agent.run(
                    initial_inputs=initial_inputs,
                    max_iterations=max_iterations,
                )

                # Print summary
                click.echo("\n" + "=" * 50, err=True)
                click.echo("Fuzzing Campaign Summary", err=True)
                click.echo("=" * 50, err=True)
                click.echo(f"  Iterations:     {stats.iterations}", err=True)
                click.echo(f"  Total crashes:  {stats.crashes}", err=True)
                click.echo(f"  Unique crashes: {stats.unique_crashes}", err=True)
                click.echo(f"  Corpus size:    {stats.corpus_size}", err=True)
                click.echo(f"  Elapsed:        {stats.elapsed_seconds:.1f}s", err=True)
                click.echo("=" * 50, err=True)

                # Print crash hashes if any
                if agent.crashes:
                    click.echo("\nCrashes found:", err=True)
                    for crash in agent.crashes:
                        click.echo(f"  - {crash.get('hash', 'unknown')}: {crash.get('type', 'unknown')}", err=True)

                return 0
        except Exception as e:
            # Check for ModelNotFoundError to provide helpful output
            from ..providers import ModelNotFoundError

            if isinstance(e, ModelNotFoundError):
                click.echo(f"[!] Model not found: {e.model}", err=True)
                if e.available:
                    click.echo("[+] Available models:", err=True)
                    for m in e.available:
                        click.echo(f"    - {m}", err=True)
                return 1

            click.echo(f"[!] Fuzzing failed: {e}", err=True)
            import traceback

            traceback.print_exc(file=sys.stderr)
            return 1

    _run_async(run_fuzzing())


@fuzz.command(name="jackalope")
@click.argument("target")
@click.option("--fuzzer", required=True, help="Path to Jackalope fuzzer binary.")
@click.option("--corpus", "-i", required=True, help="Input corpus directory.")
@click.option("--output", "-o", default=None, help="Output directory (default: corpus/../out).")
@click.option("--instrument-module", default=None, help="Module to instrument for coverage (TinyInst).")
@click.option("--target-module", default=None, help="Module containing target function.")
@click.option("--target-method", default=None, help="Target function name (e.g., _fuzz).")
@click.option("--nargs", default=None, type=int, help="Number of arguments to target method.")
@click.option("--timeout", "-t", default=1000, type=int, help="Sample timeout in milliseconds.")
@click.option("--init-timeout", default=5000, type=int, help="Initialization timeout in milliseconds.")
@click.option("--iterations", default=5000, type=int, help="Iterations before process restart.")
@click.option("--threads", "-j", default=1, type=int, help="Parallel fuzzing threads.")
@click.option("--max-time", default=3600, type=int, help="Max fuzzing time in seconds (0=unlimited).")
@click.option("--triage-interval", default=60, type=int, help="Seconds between crash triage cycles.")
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["anthropic", "openai", "google", "ollama", "lmstudio"]),
    help="LLM provider for analysis.",
)
@click.option("--model", default=None, help="LLM model for analysis.")
@click.option("--cold-start/--no-cold-start", default=True, help="Run LLM seed synthesis at start.")
@click.option("--persist/--no-persist", default=True, help="Persistent mode (reuse process).")
@click.option("--delivery", type=click.Choice(["file", "shmem"]), default="file", help="Sample delivery method.")
@click.option("--delivery-dir", default=None, help="Delivery directory (e.g., /Volumes/RAMDisk).")
@click.option("--file-extension", default=None, help="File extension for samples (e.g., png, mov).")
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level.",
)
def jackalope(
    target: str,
    fuzzer: str,
    corpus: str,
    output: str | None,
    instrument_module: str | None,
    target_module: str | None,
    target_method: str | None,
    nargs: int | None,
    timeout: int,
    init_timeout: int,
    iterations: int,
    threads: int,
    max_time: int,
    triage_interval: int,
    provider: str | None,
    model: str | None,
    cold_start: bool,
    persist: bool,
    delivery: str,
    delivery_dir: str | None,
    file_extension: str | None,
    log_level: str,
) -> None:
    """Hybrid fuzzing with Jackalope + LLM triage.

    TARGET: Path to the target binary/harness to fuzz.

    This command runs hybrid fuzzing using Google Project Zero's Jackalope
    fuzzer with TinyInst binary instrumentation. The LLM handles:
    - Cold start: Generates initial seeds from binary analysis
    - Grind: Jackalope runs at native speed with coverage feedback
    - Triage: Analyzes crashes via LLDB and generates refined seeds

    Examples:
        # Basic usage
        alf fuzz jackalope ./target --fuzzer /path/to/fuzzer --corpus ./seeds

        # macOS framework fuzzing (ImageIO)
        alf fuzz jackalope ./harness \\
            --fuzzer /path/to/fuzzer \\
            --corpus ./in \\
            --output ./out \\
            --instrument-module ImageIO \\
            --target-module harness \\
            --target-method _fuzz \\
            --persist \\
            --delivery shmem \\
            --threads 4

        # Without cold start (skip LLM seed generation)
        alf fuzz jackalope ./target --fuzzer ./fuzzer --corpus ./seeds --no-cold-start
    """
    import sys

    from ..fuzz.jackalope import JackalopeHybridFuzzer
    from ..log import configure_logging_from_level

    target_path = Path(target).expanduser().resolve()
    if not target_path.exists():
        click.echo(f"[!] Target binary not found: {target_path}", err=True)
        raise SystemExit(1)

    fuzzer_path = Path(fuzzer).expanduser().resolve()
    if not fuzzer_path.exists():
        click.echo(f"[!] Jackalope fuzzer not found: {fuzzer_path}", err=True)
        raise SystemExit(1)

    configure_logging_from_level(log_level)

    corpus_dir = Path(corpus).expanduser().resolve()
    corpus_dir.mkdir(parents=True, exist_ok=True)

    output_dir = Path(output).expanduser().resolve() if output else None
    delivery_dir_path = Path(delivery_dir).expanduser().resolve() if delivery_dir else None

    async def run_jackalope() -> int:
        try:
            fuzzer_instance = JackalopeHybridFuzzer(
                fuzzer_path=fuzzer_path,
                target_binary=target_path,
                corpus_dir=corpus_dir,
                output_dir=output_dir,
                instrument_module=instrument_module,
                target_module=target_module,
                target_method=target_method,
                nargs=nargs,
                timeout_ms=timeout,
                init_timeout_ms=init_timeout,
                iterations=iterations,
                nthreads=threads,
                persist=persist,
                delivery=delivery,
                delivery_dir=delivery_dir_path,
                file_extension=file_extension,
                provider=provider,
                model=model,
                triage_interval=float(triage_interval),
                cold_start=cold_start,
            )

            stats = await fuzzer_instance.run(max_time=max_time)

            # Print summary
            click.echo("\n" + "=" * 50, err=True)
            click.echo("Jackalope Hybrid Fuzzing Summary", err=True)
            click.echo("=" * 50, err=True)
            click.echo(f"  Elapsed:        {stats.elapsed_seconds:.1f}s", err=True)
            click.echo(
                f"  Cold start:     {stats.cold_start_seeds} seeds in {stats.cold_start_time:.1f}s",
                err=True,
            )
            click.echo(f"  Fuzzer execs:   {stats.fuzzer_execs:,}", err=True)
            click.echo(f"  Coverage:       {stats.fuzzer_coverage}", err=True)
            click.echo(f"  Crashes found:  {stats.crashes_found}", err=True)
            click.echo(f"  Hangs found:    {stats.hangs_found}", err=True)
            click.echo(f"  Unique crashes: {stats.unique_crashes}", err=True)
            click.echo(f"  Seeds injected: {stats.seeds_injected}", err=True)
            click.echo("=" * 50, err=True)

            return 0 if stats.unique_crashes == 0 else 1

        except Exception as e:
            click.echo(f"[!] Jackalope fuzzing failed: {e}", err=True)
            import traceback

            traceback.print_exc(file=sys.stderr)
            return 1

    _run_async(run_jackalope())


@fuzz.command(name="hybrid")
@click.argument("binary")
@click.option("--corpus", default=None, help="Initial corpus directory.")
@click.option("--artifacts", default=None, help="Crash artifacts directory.")
@click.option("--dict", "dict_path", default=None, help="Fuzzer dictionary file.")
@click.option("--max-time", default=3600, type=int, help="Max fuzzing time in seconds (0=unlimited).")
@click.option("--triage-interval", default=60, type=int, help="Seconds between triage cycles.")
@click.option("-j", "--jobs", default=1, type=int, help="Parallel fuzzer jobs.")
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["anthropic", "openai", "google", "ollama", "lmstudio"]),
    help="LLM provider for analysis.",
)
@click.option("--model", default=None, help="LLM model for analysis.")
@click.option("--cold-start/--no-cold-start", default=True, help="Run LLM seed synthesis at start.")
@click.option("--tui", is_flag=True, help="Run with split-view TUI dashboard.")
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level.",
)
def hybrid(
    binary: str,
    corpus: str | None,
    artifacts: str | None,
    dict_path: str | None,
    max_time: int,
    triage_interval: int,
    jobs: int,
    provider: str | None,
    model: str | None,
    cold_start: bool,
    tui: bool,
    log_level: str,
) -> None:
    """Hybrid fuzzing: LLM cold-start + native fuzzer + LLM triage loop.

    BINARY: Path to a libFuzzer-instrumented binary.

    This command runs hybrid fuzzing where the LLM:
    - Cold start: Generates initial seeds from binary analysis
    - Grind: Launches native libFuzzer for high-throughput fuzzing
    - Triage: Analyzes crashes and generates refined seeds

    Examples:
        alf fuzz hybrid ./fuzz_target --corpus ./seeds --max-time 3600
        alf fuzz hybrid ./fuzz_target --no-cold-start --jobs 4
    """
    import sys

    from ..fuzz.orchestrator import HybridFuzzer
    from ..log import configure_logging_from_level

    binary_path = Path(binary).expanduser().resolve()
    if not binary_path.exists():
        click.echo(f"[!] Binary not found: {binary_path}", err=True)
        raise SystemExit(1)

    configure_logging_from_level(log_level)

    # Default corpus directory
    if corpus:
        corpus_dir = Path(corpus).expanduser().resolve()
    else:
        corpus_dir = binary_path.parent / "corpus"

    corpus_dir.mkdir(parents=True, exist_ok=True)

    # Artifacts directory
    artifacts_dir = Path(artifacts).expanduser().resolve() if artifacts else None
    dict_file = Path(dict_path).expanduser().resolve() if dict_path else None

    async def run_hybrid() -> int:
        try:
            fuzzer = HybridFuzzer(
                binary=binary_path,
                corpus_dir=corpus_dir,
                artifacts_dir=artifacts_dir,
                dict_path=dict_file,
                provider=provider,
                model=model,
                triage_interval=float(triage_interval),
                cold_start=cold_start,
                max_jobs=jobs,
            )

            if tui:
                # Run with TUI dashboard
                from ..ui.hybrid_tui import HybridFuzzerWithTUI, HybridTUI

                tui_app = HybridTUI()
                wrapper = HybridFuzzerWithTUI(fuzzer, tui_app)
                stats = await wrapper.run(max_time=max_time)
            else:
                # Run without TUI
                stats = await fuzzer.run(max_time=max_time)

                # Print summary
                click.echo("\n" + "=" * 50, err=True)
                click.echo("Hybrid Fuzzing Summary", err=True)
                click.echo("=" * 50, err=True)
                click.echo(f"  Elapsed:        {stats.elapsed_seconds:.1f}s", err=True)
                click.echo(
                    f"  Cold start:     {stats.cold_start_seeds} seeds in {stats.cold_start_time:.1f}s", err=True
                )
                click.echo(f"  Fuzzer execs:   {stats.fuzzer_execs:,}", err=True)
                click.echo(f"  Coverage:       {stats.fuzzer_coverage}", err=True)
                click.echo(f"  Crashes found:  {stats.crashes_found}", err=True)
                click.echo(f"  Unique crashes: {stats.unique_crashes}", err=True)
                click.echo(f"  Seeds injected: {stats.seeds_injected}", err=True)
                click.echo("=" * 50, err=True)

            return 0 if stats.unique_crashes == 0 else 1

        except Exception as e:
            click.echo(f"[!] Hybrid fuzzing failed: {e}", err=True)
            import traceback

            traceback.print_exc(file=sys.stderr)
            return 1

    _run_async(run_hybrid())
