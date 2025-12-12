"""Textual-based TUI for hybrid fuzzing sessions.

Split-view dashboard showing:
- Left: Agent messages (LLM chat, triage results)
- Right: Fuzzer stream (libFuzzer output, crashes)
- Bottom: Stats bar (execs/s, coverage, crashes)

Usage:
    alf fuzz hybrid ./target --tui
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from ..fuzz.orchestrator import HybridStats

if TYPE_CHECKING:
    from ..fuzz.orchestrator import HybridFuzzer


@dataclass
class FuzzerStatsUpdate:
    """Real-time fuzzer statistics for display."""

    execs: int = 0
    execs_per_sec: int = 0
    coverage: int = 0
    corpus_size: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    elapsed_seconds: float = 0.0


@dataclass
class AgentMessage:
    """Message from the LLM agent."""

    text: str
    kind: str = "info"  # info, triage, seed, error
    timestamp: datetime | None = None


@dataclass
class FuzzerOutput:
    """Line of output from the fuzzer."""

    text: str
    is_crash: bool = False
    is_new_coverage: bool = False


def _format_number(n: int) -> str:
    """Format large numbers with K/M suffixes."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _format_elapsed(seconds: float) -> str:
    """Format elapsed time as HH:MM:SS."""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    if hours > 0:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


class HybridTUI:
    """Split-view TUI for hybrid fuzzing with agent chat and fuzzer stream."""

    def __init__(self) -> None:
        try:
            from textual.app import App, ComposeResult
            from textual.containers import Horizontal, Vertical
            from textual.widgets import Footer, Header, RichLog, Static
        except ImportError as e:
            raise RuntimeError("Textual not installed. Install with: uv sync --extra tui") from e

        import queue

        # Use thread-safe queue instead of asyncio.Queue
        self._queue: queue.Queue[AgentMessage | FuzzerOutput | FuzzerStatsUpdate | str] = queue.Queue()
        self._stats = FuzzerStatsUpdate()
        self._running = False

        outer_self = self

        class _HybridApp(App[None]):
            CSS = """
            #main { height: 1fr; }
            #agent-panel {
                width: 1fr;
                border: solid $primary;
                border-title-color: $primary;
            }
            #fuzzer-panel {
                width: 1fr;
                border: solid $secondary;
                border-title-color: $secondary;
            }
            #agent-log, #fuzzer-log {
                height: 1fr;
            }
            #stats-bar {
                height: 3;
                padding: 0 1;
                background: $surface;
                border-top: solid $panel;
            }
            .stat-item {
                width: auto;
                padding: 0 2;
            }
            .stat-label {
                color: $text-muted;
            }
            .stat-value {
                color: $text;
            }
            .crash-line {
                color: $error;
            }
            .new-cov-line {
                color: $success;
            }
            """

            BINDINGS = [
                ("q", "quit", "Quit"),
                ("c", "clear_logs", "Clear"),
            ]

            def __init__(self, ui_queue: asyncio.Queue) -> None:
                super().__init__()
                self._ui_queue = ui_queue

            def compose(self) -> ComposeResult:
                yield Header(show_clock=True)
                with Horizontal(id="main"):
                    with Vertical(id="agent-panel"):
                        yield Static("Agent", classes="panel-title")
                        yield RichLog(id="agent-log", highlight=True, markup=True)
                    with Vertical(id="fuzzer-panel"):
                        yield Static("Fuzzer", classes="panel-title")
                        yield RichLog(id="fuzzer-log", highlight=True, markup=False)
                yield Static(self._format_stats_bar(), id="stats-bar")
                yield Footer()

            def _format_stats_bar(self) -> str:
                s = outer_self._stats
                return (
                    f"[bold]Execs:[/] {_format_number(s.execs)} "
                    f"│ [bold]Speed:[/] {_format_number(s.execs_per_sec)}/s "
                    f"│ [bold]Cov:[/] {s.coverage} "
                    f"│ [bold]Corpus:[/] {s.corpus_size} "
                    f"│ [bold]Crashes:[/] {s.crashes_found} ({s.unique_crashes} unique) "
                    f"│ [bold]Time:[/] {_format_elapsed(s.elapsed_seconds)}"
                )

            def _agent_log(self) -> RichLog:
                return self.query_one("#agent-log", RichLog)

            def _fuzzer_log(self) -> RichLog:
                return self.query_one("#fuzzer-log", RichLog)

            def _stats_bar(self) -> Static:
                return self.query_one("#stats-bar", Static)

            async def on_mount(self) -> None:
                self.title = "ALF Hybrid Fuzzer"
                self.sub_title = "LLM + libFuzzer"
                self.run_worker(self._event_worker(), exclusive=True, group="events")
                self.set_interval(0.5, self._update_stats_bar)

            def _update_stats_bar(self) -> None:
                self._stats_bar().update(self._format_stats_bar())

            async def _event_worker(self) -> None:
                import queue as queue_module

                while True:
                    # Poll thread-safe queue (non-blocking)
                    try:
                        item = self._ui_queue.get_nowait()
                    except queue_module.Empty:
                        await asyncio.sleep(0.05)  # Yield to event loop
                        continue

                    if isinstance(item, AgentMessage):
                        prefix = ""
                        if item.kind == "triage":
                            prefix = "[bold red]🔍 Triage:[/] "
                        elif item.kind == "seed":
                            prefix = "[bold green]🌱 Seed:[/] "
                        elif item.kind == "error":
                            prefix = "[bold red]❌ Error:[/] "
                        else:
                            prefix = "[bold blue]💬[/] "
                        self._agent_log().write(f"{prefix}{item.text}")

                    elif isinstance(item, FuzzerOutput):
                        if item.is_crash:
                            self._fuzzer_log().write(f"[bold red]{item.text}[/]")
                        elif item.is_new_coverage:
                            self._fuzzer_log().write(f"[green]{item.text}[/]")
                        else:
                            self._fuzzer_log().write(item.text)

                    elif isinstance(item, FuzzerStatsUpdate):
                        outer_self._stats = item

                    elif isinstance(item, str):
                        # Simple string goes to agent log
                        self._agent_log().write(item)

            def action_clear_logs(self) -> None:
                self._agent_log().clear()
                self._fuzzer_log().clear()

        self._app = _HybridApp(self._queue)

    def post_agent_message(self, text: str, kind: str = "info") -> None:
        """Post a message to the agent panel."""
        self._queue.put_nowait(AgentMessage(text=text, kind=kind, timestamp=datetime.now()))

    def post_fuzzer_output(self, text: str, is_crash: bool = False, is_new_coverage: bool = False) -> None:
        """Post a line of fuzzer output."""
        self._queue.put_nowait(FuzzerOutput(text=text, is_crash=is_crash, is_new_coverage=is_new_coverage))

    def update_stats(self, stats: FuzzerStatsUpdate) -> None:
        """Update the stats bar."""
        self._queue.put_nowait(stats)

    async def run(self) -> None:
        """Run the TUI application."""
        self._running = True
        await self._app.run_async()

    def exit(self) -> None:
        """Exit the TUI."""
        self._running = False
        self._app.exit()

    @property
    def is_running(self) -> bool:
        return self._running


class HybridFuzzerWithTUI:
    """Wrapper that runs HybridFuzzer with TUI output."""

    def __init__(
        self,
        fuzzer: HybridFuzzer,
        tui: HybridTUI,
    ):
        self.fuzzer = fuzzer
        self.tui = tui
        self._output_task: asyncio.Task | None = None
        self._stats_task: asyncio.Task | None = None

        # Hook into fuzzer status callback
        self.fuzzer._status_callback = self._on_status

    def _on_status(self, message: str, kind: str) -> None:
        """Handle status messages from fuzzer."""
        self.tui.post_agent_message(message, kind=kind)

    def _run_fuzzer_sync(self, max_time: int) -> HybridStats:
        """Run fuzzer in separate event loop (for thread)."""
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.fuzzer.run(max_time=max_time))
        finally:
            loop.close()

    async def run(self, max_time: int = 3600) -> HybridStats:
        """Run the fuzzer with TUI output."""
        import concurrent.futures

        # Post initial message
        self.tui.post_agent_message("Starting hybrid fuzzing...", kind="info")

        # Start streaming tasks
        self._start_output_streaming()
        self._start_stats_streaming()

        # Store stats for retrieval
        self._final_stats: HybridStats | None = None
        self._fuzzer_error: Exception | None = None

        # Run fuzzer in a separate thread with its own event loop
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

        async def run_fuzzer_in_thread() -> HybridStats:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(executor, self._run_fuzzer_sync, max_time)

        # Create task for fuzzer
        fuzzer_task = asyncio.create_task(run_fuzzer_in_thread())

        # Run TUI - this blocks until TUI exits
        try:
            await self.tui.run()
        except Exception:
            pass

        # Cancel fuzzer if TUI exited early
        if not fuzzer_task.done():
            fuzzer_task.cancel()
            self.fuzzer._running = False
            try:
                await fuzzer_task
            except asyncio.CancelledError:
                pass

        # Get results
        if fuzzer_task.done() and not fuzzer_task.cancelled():
            try:
                self._final_stats = fuzzer_task.result()
            except Exception as e:
                self._fuzzer_error = e

        # Stop streaming tasks
        if self._output_task:
            self._output_task.cancel()
        if self._stats_task:
            self._stats_task.cancel()

        executor.shutdown(wait=False)

        if self._fuzzer_error:
            raise self._fuzzer_error

        return self._final_stats or HybridStats()

    def _start_output_streaming(self) -> None:
        """Start streaming fuzzer output to TUI."""

        async def stream_output() -> None:
            # Wait for orchestrator to be created
            while self.tui.is_running and not self.fuzzer._orchestrator:
                await asyncio.sleep(0.2)

            if not self.tui.is_running:
                return

            last_line_count = 0
            while self.tui.is_running:
                if self.fuzzer._orchestrator:
                    output = self.fuzzer._orchestrator.output
                    new_lines = output[last_line_count:]
                    last_line_count = len(output)

                    for line in new_lines:
                        is_crash = "SUMMARY" in line and "ERROR" in line
                        is_new_cov = "NEW" in line or "REDUCE" in line
                        self.tui.post_fuzzer_output(line, is_crash=is_crash, is_new_coverage=is_new_cov)

                await asyncio.sleep(0.1)

        self._output_task = asyncio.create_task(stream_output())

    def _start_stats_streaming(self) -> None:
        """Start streaming fuzzer stats to TUI."""

        async def stream_stats() -> None:
            start_time = datetime.now()
            # Wait for orchestrator to be created
            while self.tui.is_running and not self.fuzzer._orchestrator:
                await asyncio.sleep(0.2)

            while self.tui.is_running:
                if self.fuzzer._orchestrator:
                    orch_stats = self.fuzzer._orchestrator.stats
                    elapsed = (datetime.now() - start_time).total_seconds()

                    self.tui.update_stats(
                        FuzzerStatsUpdate(
                            execs=orch_stats.execs,
                            execs_per_sec=orch_stats.execs_per_sec,
                            coverage=orch_stats.coverage,
                            corpus_size=orch_stats.corpus_size,
                            crashes_found=self.fuzzer._stats.crashes_found,
                            unique_crashes=self.fuzzer._stats.unique_crashes,
                            elapsed_seconds=elapsed,
                        )
                    )

                await asyncio.sleep(0.5)

        self._stats_task = asyncio.create_task(stream_stats())
