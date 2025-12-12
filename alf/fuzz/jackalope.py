"""
Jackalope fuzzer orchestration for "Sandwich" fuzzing.

This module provides classes to launch and control Jackalope fuzzer
while the LLM handles seed generation and crash triage.

Architecture:
    JackalopeHybridFuzzer orchestrates the hybrid workflow:
    1. Cold Start: LLM generates initial seeds
    2. Grind: Jackalope runs at native speed with TinyInst coverage
    3. Triage: LLM analyzes crashes and generates refined seeds

Usage:
    fuzzer = JackalopeHybridFuzzer(
        fuzzer_path="/path/to/jackalope/fuzzer",
        target_binary="./harness",
        corpus_dir="./corpus",
        instrument_module="ImageIO",
    )
    stats = await fuzzer.run(max_time=3600)
"""

from __future__ import annotations

import asyncio
import atexit
import os
import re
import signal
import subprocess
import sys
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

# Track active fuzzer processes for cleanup
_active_jackalope_procs: weakref.WeakSet[subprocess.Popen] = weakref.WeakSet()


def _cleanup_jackalope_procs() -> None:
    """Terminate any remaining Jackalope processes on exit."""
    for proc in list(_active_jackalope_procs):
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


atexit.register(_cleanup_jackalope_procs)


@dataclass
class JackalopeConfig:
    """Configuration for Jackalope fuzzer."""

    fuzzer_path: Path  # Path to Jackalope fuzzer binary
    target_binary: Path  # Target to fuzz
    corpus_dir: Path  # Input corpus (-in)
    output_dir: Path | None = None  # Output directory (-out), default: corpus/../out
    target_args: list[str] = field(default_factory=list)  # Args after -- (use @@ for input)

    # TinyInst instrumentation options
    instrument_module: str | None = None  # -instrument_module (e.g., ImageIO)
    target_module: str | None = None  # -target_module (module with target func)
    target_method: str | None = None  # -target_method (e.g., _fuzz)
    nargs: int | None = None  # -nargs (number of args to target method)

    # Execution options
    timeout_ms: int = 1000  # -t (sample timeout in ms)
    init_timeout_ms: int = 5000  # -t1 (init timeout before target method)
    iterations: int = 5000  # -iterations (before process restart)
    nthreads: int = 1  # -nthreads
    persist: bool = True  # -persist (reuse process across iterations)
    loop: bool = True  # -loop (keep fuzzing loop alive)

    # Delivery options
    delivery: str = "file"  # file or shmem
    delivery_dir: Path | None = None  # -delivery_dir (e.g., /Volumes/RAMDisk)
    file_extension: str | None = None  # -file_extension (e.g., png, mov)

    # Coverage options
    cmp_coverage: bool = True  # -cmp_coverage (comparison coverage)
    dump_coverage: bool = False  # -dump_coverage (export coverage.txt)
    generate_unwind: bool = False  # -generate_unwind (C++ exception handling)

    # Other options
    mute_child: bool = True  # -mute_child (suppress target output)
    max_sample_size: int = 1000000  # -max_sample_size
    deterministic_mutations: bool = False  # -deterministic_mutations
    extra_args: list[str] = field(default_factory=list)  # Additional flags

    def __post_init__(self) -> None:
        self.fuzzer_path = Path(self.fuzzer_path).expanduser().resolve()
        self.target_binary = Path(self.target_binary).expanduser().resolve()
        self.corpus_dir = Path(self.corpus_dir).expanduser().resolve()

        if self.output_dir:
            self.output_dir = Path(self.output_dir).expanduser().resolve()
        else:
            self.output_dir = self.corpus_dir.parent / "out"

        if self.delivery_dir:
            self.delivery_dir = Path(self.delivery_dir).expanduser().resolve()

    def build_command(self) -> list[str]:
        """Build Jackalope command line arguments."""
        cmd = [str(self.fuzzer_path)]

        # Input/output directories
        cmd.extend(["-in", str(self.corpus_dir)])
        cmd.extend(["-out", str(self.output_dir)])

        # Timeouts
        cmd.extend(["-t", str(self.timeout_ms)])
        cmd.extend(["-t1", str(self.init_timeout_ms)])

        # Execution
        cmd.extend(["-nthreads", str(self.nthreads)])
        cmd.extend(["-iterations", str(self.iterations)])

        if self.persist:
            cmd.append("-persist")
        if self.loop:
            cmd.append("-loop")

        # TinyInst options
        if self.instrument_module:
            cmd.extend(["-instrument_module", self.instrument_module])
        if self.target_module:
            cmd.extend(["-target_module", self.target_module])
        if self.target_method:
            cmd.extend(["-target_method", self.target_method])
        if self.nargs is not None:
            cmd.extend(["-nargs", str(self.nargs)])

        # Delivery
        cmd.extend(["-delivery", self.delivery])
        if self.delivery_dir:
            cmd.extend(["-delivery_dir", str(self.delivery_dir)])
        if self.file_extension:
            cmd.extend(["-file_extension", self.file_extension])

        # Coverage
        if self.cmp_coverage:
            cmd.append("-cmp_coverage")
        if self.dump_coverage:
            cmd.append("-dump_coverage")
        if self.generate_unwind:
            cmd.append("-generate_unwind")

        # Other
        if self.mute_child:
            cmd.append("-mute_child")
        cmd.extend(["-max_sample_size", str(self.max_sample_size)])
        if self.deterministic_mutations:
            cmd.append("-deterministic_mutations")

        # Extra args
        cmd.extend(self.extra_args)

        # Target binary and args (after --)
        cmd.append("--")
        cmd.append(str(self.target_binary))
        if self.target_args:
            cmd.extend(self.target_args)
        else:
            # Default: pass input file via @@
            cmd.append("@@")

        return cmd


@dataclass
class JackalopeStats:
    """Statistics from Jackalope output."""

    execs: int = 0
    execs_per_sec: int = 0
    coverage: int = 0
    corpus_size: int = 0
    crashes: int = 0
    hangs: int = 0
    new_samples: int = 0
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execs": self.execs,
            "execs_per_sec": self.execs_per_sec,
            "coverage": self.coverage,
            "corpus_size": self.corpus_size,
            "crashes": self.crashes,
            "hangs": self.hangs,
            "new_samples": self.new_samples,
        }


@dataclass
class JackalopeCrashArtifact:
    """Represents a crash artifact from Jackalope."""

    path: Path
    crash_type: str  # crash, hang, unique
    discovered_at: datetime
    input_bytes: bytes | None = None
    stack_hash: str | None = None
    triaged: bool = False

    def load_input(self) -> bytes:
        """Load crash input bytes."""
        if self.input_bytes is None:
            self.input_bytes = self.path.read_bytes()
        return self.input_bytes


class JackalopeOrchestrator:
    """Launch and control Jackalope fuzzer subprocess."""

    # Regex patterns for parsing Jackalope output
    # Example: #12345 NEW cov: 1234 corp: 567 exec/s: 890
    STATS_PATTERN = re.compile(
        r"#(\d+)\s+"  # iteration count
        r"(?:NEW|RELOAD|cov|corp)?\s*"  # optional status
        r"(?:cov:\s*(\d+))?\s*"  # coverage
        r"(?:corp:\s*(\d+))?\s*"  # corpus size
        r"(?:exec/s:\s*(\d+))?",  # execs per second
        re.IGNORECASE,
    )

    # Crash patterns in Jackalope output
    CRASH_LOG_PATTERN = re.compile(r"(crash|hang|exception|signal)", re.IGNORECASE)

    def __init__(self, config: JackalopeConfig):
        self.config = config
        self._proc: subprocess.Popen | None = None
        self._stats = JackalopeStats()
        self._output_lines: list[str] = []
        self._reader_task: asyncio.Task | None = None

    @property
    def stats(self) -> JackalopeStats:
        """Current fuzzer statistics."""
        return self._stats

    @property
    def output(self) -> list[str]:
        """Raw output lines from fuzzer."""
        return self._output_lines.copy()

    def is_alive(self) -> bool:
        """Check if fuzzer process is running."""
        return self._proc is not None and self._proc.poll() is None

    async def launch(self) -> dict[str, Any]:
        """Spawn Jackalope fuzzer subprocess."""
        if self.is_alive():
            return {"error": "Fuzzer already running", "pid": self._proc.pid}

        # Ensure directories exist
        self.config.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        if self.config.delivery_dir:
            self.config.delivery_dir.mkdir(parents=True, exist_ok=True)

        # Build command
        cmd = self.config.build_command()

        # Spawn process
        env = os.environ.copy()

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            text=True,
            bufsize=1,  # Line buffered
            env=env,
        )
        _active_jackalope_procs.add(self._proc)

        # Start async output reader
        self._reader_task = asyncio.create_task(self._read_output())

        return {
            "pid": self._proc.pid,
            "status": "running",
            "command": " ".join(cmd),
            "corpus_dir": str(self.config.corpus_dir),
            "output_dir": str(self.config.output_dir),
        }

    async def _read_output(self) -> None:
        """Background task to read and parse fuzzer output."""
        if not self._proc or not self._proc.stdout:
            return

        try:
            while self.is_alive():
                line = self._proc.stdout.readline()
                if not line:
                    await asyncio.sleep(0.01)
                    continue

                line = line.rstrip()
                self._output_lines.append(line)

                # Keep output buffer bounded
                if len(self._output_lines) > 10000:
                    self._output_lines = self._output_lines[-5000:]

                # Parse stats
                self._parse_stats_line(line)

        except Exception:
            pass  # Process ended or other error

    def _parse_stats_line(self, line: str) -> None:
        """Parse a line of Jackalope output for statistics."""
        match = self.STATS_PATTERN.search(line)
        if match:
            if match.group(1):
                self._stats.execs = int(match.group(1))
            if match.group(2):
                self._stats.coverage = int(match.group(2))
            if match.group(3):
                self._stats.corpus_size = int(match.group(3))
            if match.group(4):
                self._stats.execs_per_sec = int(match.group(4))
            self._stats.updated_at = datetime.now()

        # Check for NEW samples
        if "NEW" in line.upper():
            self._stats.new_samples += 1

        # Check for crashes/hangs in log
        if self.CRASH_LOG_PATTERN.search(line):
            if "hang" in line.lower():
                self._stats.hangs += 1
            else:
                self._stats.crashes += 1

    async def stop(self, timeout: float = 5.0) -> None:
        """Gracefully stop the fuzzer."""
        if not self._proc:
            return

        # Cancel reader task
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        # Stop process
        if self._proc.poll() is None:
            # Send SIGINT for graceful shutdown
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.kill()

        self._proc = None

    async def inject_seed(self, seed_bytes: bytes, name: str | None = None) -> Path:
        """Write a new seed to the corpus directory.

        Jackalope will pick it up on the next iteration.
        """
        import hashlib

        if name is None:
            # Generate name from content hash
            h = hashlib.sha256(seed_bytes).hexdigest()[:16]
            name = f"seed_{h}"

        seed_path = self.config.corpus_dir / name
        seed_path.write_bytes(seed_bytes)
        return seed_path

    def get_new_crashes(self) -> list[JackalopeCrashArtifact]:
        """Find crash artifacts in the output directory."""
        crashes = []
        if not self.config.output_dir or not self.config.output_dir.exists():
            return crashes

        for path in self.config.output_dir.iterdir():
            if not path.is_file():
                continue

            # Match Jackalope crash patterns
            name = path.name.lower()
            crash_type = None

            if name.startswith("crash"):
                crash_type = "crash"
            elif name.startswith("hang"):
                crash_type = "hang"
            elif name.startswith("unique"):
                crash_type = "unique"

            if crash_type:
                stat = path.stat()
                crashes.append(
                    JackalopeCrashArtifact(
                        path=path,
                        crash_type=crash_type,
                        discovered_at=datetime.fromtimestamp(stat.st_mtime),
                    )
                )

        return sorted(crashes, key=lambda c: c.discovered_at)


class JackalopeCrashMonitor:
    """Monitor Jackalope output directory for new crash artifacts."""

    def __init__(self, output_dir: Path, poll_interval: float = 1.0):
        self.output_dir = Path(output_dir)
        self.poll_interval = poll_interval
        self._known_crashes: dict[Path, JackalopeCrashArtifact] = {}
        self._pending_crashes: list[JackalopeCrashArtifact] = []
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start background monitoring task."""
        if self._running:
            return

        self._running = True
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                self._scan_for_crashes()
            except Exception as e:
                print(f"[JackalopeCrashMonitor] Error scanning: {e}", file=sys.stderr)

            await asyncio.sleep(self.poll_interval)

    def _scan_for_crashes(self) -> None:
        """Scan output directory for new crashes."""
        if not self.output_dir.exists():
            return

        for path in self.output_dir.iterdir():
            if not path.is_file() or path in self._known_crashes:
                continue

            name = path.name.lower()
            crash_type = None

            if name.startswith("crash"):
                crash_type = "crash"
            elif name.startswith("hang"):
                crash_type = "hang"
            elif name.startswith("unique"):
                crash_type = "unique"

            if crash_type:
                stat = path.stat()
                crash = JackalopeCrashArtifact(
                    path=path,
                    crash_type=crash_type,
                    discovered_at=datetime.fromtimestamp(stat.st_mtime),
                )
                self._known_crashes[path] = crash
                self._pending_crashes.append(crash)

    def get_new_crashes(self) -> list[JackalopeCrashArtifact]:
        """Return unprocessed crashes since last call."""
        crashes = self._pending_crashes
        self._pending_crashes = []
        return crashes

    def mark_triaged(self, crash: JackalopeCrashArtifact, stack_hash: str) -> None:
        """Mark crash as triaged with its stack hash."""
        crash.stack_hash = stack_hash
        crash.triaged = True

    @property
    def total_crashes(self) -> int:
        """Total crashes discovered."""
        return len(self._known_crashes)

    @property
    def triaged_crashes(self) -> int:
        """Number of triaged crashes."""
        return sum(1 for c in self._known_crashes.values() if c.triaged)


@dataclass
class JackalopeHybridStats:
    """Statistics for a Jackalope hybrid fuzzing session."""

    # Overall
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    elapsed_seconds: float = 0.0

    # Cold start
    cold_start_seeds: int = 0
    cold_start_time: float = 0.0

    # Fuzzer stats
    fuzzer_execs: int = 0
    fuzzer_coverage: int = 0
    fuzzer_execs_per_sec: int = 0

    # Crash stats
    crashes_found: int = 0
    crashes_triaged: int = 0
    unique_crashes: int = 0
    hangs_found: int = 0

    # Seed injection
    seeds_injected: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "elapsed_seconds": self.elapsed_seconds,
            "cold_start": {
                "seeds": self.cold_start_seeds,
                "time_seconds": self.cold_start_time,
            },
            "fuzzer": {
                "execs": self.fuzzer_execs,
                "coverage": self.fuzzer_coverage,
                "execs_per_sec": self.fuzzer_execs_per_sec,
            },
            "crashes": {
                "found": self.crashes_found,
                "triaged": self.crashes_triaged,
                "unique": self.unique_crashes,
                "hangs": self.hangs_found,
            },
            "seeds_injected": self.seeds_injected,
        }


class JackalopeHybridFuzzer:
    """Coordinate LLM cold-start + Jackalope fuzzing + LLM triage."""

    def __init__(
        self,
        fuzzer_path: Path,
        target_binary: Path,
        corpus_dir: Path,
        output_dir: Path | None = None,
        target_args: list[str] | None = None,
        # TinyInst options
        instrument_module: str | None = None,
        target_module: str | None = None,
        target_method: str | None = None,
        nargs: int | None = None,
        # Execution options
        timeout_ms: int = 1000,
        init_timeout_ms: int = 5000,
        iterations: int = 5000,
        nthreads: int = 1,
        persist: bool = True,
        # Delivery options
        delivery: str = "file",
        delivery_dir: Path | None = None,
        file_extension: str | None = None,
        # LLM options
        provider: str | None = None,
        model: str | None = None,
        # Timing
        triage_interval: float = 60.0,
        cold_start: bool = True,
        # UI
        status_callback: Callable[[str, str], None] | None = None,
    ):
        self.fuzzer_path = Path(fuzzer_path).resolve()
        self.target_binary = Path(target_binary).resolve()
        self.corpus_dir = Path(corpus_dir).resolve()
        self.output_dir = Path(output_dir).resolve() if output_dir else self.corpus_dir.parent / "out"
        self.target_args = target_args or []

        # TinyInst options
        self.instrument_module = instrument_module
        self.target_module = target_module
        self.target_method = target_method
        self.nargs = nargs

        # Execution options
        self.timeout_ms = timeout_ms
        self.init_timeout_ms = init_timeout_ms
        self.iterations = iterations
        self.nthreads = nthreads
        self.persist = persist

        # Delivery options
        self.delivery = delivery
        self.delivery_dir = Path(delivery_dir) if delivery_dir else None
        self.file_extension = file_extension

        # LLM options
        self.provider_name = provider
        self.model = model

        # Timing
        self.triage_interval = triage_interval
        self.cold_start_enabled = cold_start

        # UI
        self._status_callback = status_callback

        # State
        self._orchestrator: JackalopeOrchestrator | None = None
        self._monitor: JackalopeCrashMonitor | None = None
        self._stats = JackalopeHybridStats()
        self._seen_hashes: set[str] = set()
        self._running = False

    def _emit_status(self, message: str, kind: str = "info") -> None:
        """Emit a status message to callback and stderr."""
        print(f"[Jackalope] {message}", file=sys.stderr)
        if self._status_callback:
            self._status_callback(message, kind)

    @property
    def stats(self) -> JackalopeHybridStats:
        return self._stats

    async def run(self, max_time: int = 3600) -> JackalopeHybridStats:
        """Run the hybrid fuzzing loop.

        Args:
            max_time: Maximum fuzzing time in seconds (0 = unlimited).

        Returns:
            JackalopeHybridStats with session results.
        """
        self._stats = JackalopeHybridStats()
        self._running = True

        try:
            # Phase 1: Cold start (LLM-driven seed synthesis)
            if self.cold_start_enabled:
                self._emit_status("Phase 1: Cold start - generating seeds with LLM...", "info")
                cold_start_begin = datetime.now()
                seed_count = await self._cold_start()
                self._stats.cold_start_seeds = seed_count
                self._stats.cold_start_time = (datetime.now() - cold_start_begin).total_seconds()
                self._emit_status(f"Generated {seed_count} seeds in {self._stats.cold_start_time:.1f}s", "seed")

            # Phase 2: Launch Jackalope
            self._emit_status("Phase 2: Launching Jackalope fuzzer...", "info")
            config = JackalopeConfig(
                fuzzer_path=self.fuzzer_path,
                target_binary=self.target_binary,
                corpus_dir=self.corpus_dir,
                output_dir=self.output_dir,
                target_args=self.target_args,
                instrument_module=self.instrument_module,
                target_module=self.target_module,
                target_method=self.target_method,
                nargs=self.nargs,
                timeout_ms=self.timeout_ms,
                init_timeout_ms=self.init_timeout_ms,
                iterations=self.iterations,
                nthreads=self.nthreads,
                persist=self.persist,
                delivery=self.delivery,
                delivery_dir=self.delivery_dir,
                file_extension=self.file_extension,
            )
            self._orchestrator = JackalopeOrchestrator(config)
            launch_result = await self._orchestrator.launch()
            self._emit_status(f"Fuzzer running (PID {launch_result.get('pid')})", "info")

            # Start crash monitor
            self._monitor = JackalopeCrashMonitor(self.output_dir)
            await self._monitor.start()

            # Phase 3: Triage loop
            self._emit_status(f"Phase 3: Monitoring (triage interval={self.triage_interval}s)...", "info")
            await self._triage_loop(max_time)

        except KeyboardInterrupt:
            self._emit_status("Interrupted, shutting down...", "info")
        finally:
            self._running = False
            await self._shutdown()

        # Final stats
        self._stats.end_time = datetime.now()
        self._stats.elapsed_seconds = (self._stats.end_time - self._stats.start_time).total_seconds()

        if self._orchestrator:
            self._stats.fuzzer_execs = self._orchestrator.stats.execs
            self._stats.fuzzer_coverage = self._orchestrator.stats.coverage
            self._stats.fuzzer_execs_per_sec = self._orchestrator.stats.execs_per_sec

        return self._stats

    async def _cold_start(self) -> int:
        """LLM-driven seed synthesis."""
        try:
            from ..generate import InputGenerator, write_seeds
        except ImportError:
            self._emit_status("InputGenerator not available, skipping cold start", "warning")
            return 0

        generator = InputGenerator(provider=self.provider_name, model=self.model)

        # Generate seeds from binary analysis with timeout
        self._emit_status("Analyzing binary and generating seeds...", "info")
        try:
            seeds = await asyncio.wait_for(
                generator.synthesize_from_binary(self.target_binary, count=10),
                timeout=120.0,  # 2 minute timeout
            )
        except asyncio.TimeoutError:
            self._emit_status("LLM call timed out after 120s", "error")
            seeds = []
        except Exception as e:
            err_str = str(e)
            self._emit_status(f"LLM error: {err_str[:100]}", "error")
            seeds = []

        if not seeds:
            self._emit_status("No seeds generated, using heuristic fallback", "info")
            # Generate basic seeds as fallback
            try:
                from ..corpus import heuristic_mutations
                from ..generate import GeneratedSeed
            except ImportError:
                return 0

            # Read any existing corpus file for mutation base
            existing = list(self.corpus_dir.glob("*"))
            if existing:
                base_data = existing[0].read_bytes()
                mutations = heuristic_mutations(base_data)
                seeds = [
                    GeneratedSeed(
                        name=f"heuristic_{i}",
                        data=data,
                        rationale="Heuristic mutation fallback",
                    )
                    for i, (_, data) in enumerate(mutations[:10])
                ]

        if seeds:
            written = write_seeds(self.corpus_dir, seeds)
            return len(written)

        return 0

    async def _triage_loop(self, max_time: int) -> None:
        """Monitor loop: triage crashes, inject seeds."""
        start = datetime.now()
        last_stats_print = start

        while self._running:
            # Check if fuzzer is still alive
            if self._orchestrator and not self._orchestrator.is_alive():
                self._emit_status("Fuzzer exited", "info")
                break

            # Check time limit
            elapsed = (datetime.now() - start).total_seconds()
            if max_time > 0 and elapsed >= max_time:
                self._emit_status(f"Time limit reached ({max_time}s)", "info")
                break

            # Print stats periodically
            if (datetime.now() - last_stats_print).total_seconds() >= 10:
                self._print_stats()
                last_stats_print = datetime.now()

            # Get new crashes
            if self._monitor:
                new_crashes = self._monitor.get_new_crashes()
                for crash in new_crashes:
                    if crash.crash_type == "hang":
                        self._stats.hangs_found += 1
                    else:
                        self._stats.crashes_found += 1

                    self._emit_status(f"New {crash.crash_type}: {crash.path.name}", "triage")

                    # Triage the crash
                    try:
                        triage_result = await self._triage_crash(crash)
                        if triage_result:
                            self._stats.crashes_triaged += 1

                            # Check for uniqueness
                            if crash.stack_hash and crash.stack_hash not in self._seen_hashes:
                                self._seen_hashes.add(crash.stack_hash)
                                self._stats.unique_crashes += 1
                                self._emit_status(f"Unique crash: {crash.stack_hash[:16]}", "triage")

                                # Generate refined seeds
                                refined = await self._generate_refined_seeds(crash, triage_result)
                                if refined and self._orchestrator:
                                    for seed_bytes in refined:
                                        await self._orchestrator.inject_seed(seed_bytes)
                                        self._stats.seeds_injected += 1
                                    self._emit_status(f"Injected {len(refined)} refined seeds", "seed")

                    except Exception as e:
                        self._emit_status(f"Triage failed: {e}", "error")

            await asyncio.sleep(self.triage_interval)

    async def _triage_crash(self, crash: JackalopeCrashArtifact) -> dict[str, Any] | None:
        """Triage a crash using LLDB."""
        try:
            from .session import FuzzSession
        except ImportError:
            self._emit_status("FuzzSession not available, skipping LLDB triage", "warning")
            return None

        try:
            async with FuzzSession(binary=str(self.target_binary)) as session:
                # Launch with crash input
                result = await session.launch(crash_input=str(crash.path))

                if result.get("status") == "error":
                    return None

                # Get stack hash
                hash_result = await session.get_stack_hash()
                try:
                    import json

                    hash_obj = json.loads(hash_result)
                    crash.stack_hash = hash_obj.get("stack_hash") or hash_obj.get("hash")
                except Exception:
                    crash.stack_hash = hash_result[:16] if hash_result else None

                # Get crash context
                ctx = await session.get_crash_context()
                crash.triaged = True

                if self._monitor:
                    self._monitor.mark_triaged(crash, crash.stack_hash or "unknown")

                return ctx

        except Exception as e:
            self._emit_status(f"LLDB triage error: {e}", "error")
            return None

    async def _generate_refined_seeds(
        self,
        crash: JackalopeCrashArtifact,
        triage_ctx: dict[str, Any],
    ) -> list[bytes]:
        """Generate refined seeds based on crash analysis."""
        try:
            from ..corpus import heuristic_mutations
        except ImportError:
            return []

        crash_data = crash.load_input()

        # Use heuristic mutations (fast, no LLM)
        mutations = heuristic_mutations(crash_data)

        # Return just the bytes
        return [data for _, data in mutations[:5]]

    def _print_stats(self) -> None:
        """Print current stats."""
        if not self._orchestrator:
            return

        # Skip periodic stats in TUI mode (callback handles it)
        if self._status_callback:
            return

        stats = self._orchestrator.stats
        print(
            f"[Jackalope] {stats.execs:,} execs | "
            f"{stats.execs_per_sec:,} exec/s | "
            f"cov: {stats.coverage} | "
            f"crashes: {self._stats.crashes_found} ({self._stats.unique_crashes} unique)",
            file=sys.stderr,
        )

    async def _shutdown(self) -> None:
        """Shutdown fuzzer and monitor."""
        if self._monitor:
            await self._monitor.stop()

        if self._orchestrator:
            await self._orchestrator.stop()
            # Print final output (non-TUI only)
            if not self._status_callback:
                final_lines = self._orchestrator.output[-20:]
                if final_lines:
                    print("[Jackalope] Final fuzzer output:", file=sys.stderr)
                    for line in final_lines:
                        print(f"  {line}", file=sys.stderr)
