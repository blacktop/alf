"""
Native fuzzer orchestration for "Sandwich" fuzzing.

This module provides classes to launch and control native fuzzers (libFuzzer)
while the LLM handles seed generation and crash triage.

Architecture:
    SandwichFuzzer orchestrates the hybrid workflow:
    1. Cold Start: LLM generates initial seeds
    2. Grind: libFuzzer runs at native speed
    3. Triage: LLM analyzes crashes and generates refined seeds

Usage:
    fuzzer = SandwichFuzzer(binary, corpus_dir)
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
_active_fuzzer_procs: weakref.WeakSet[subprocess.Popen] = weakref.WeakSet()


def _get_coverage_manager() -> Any:
    """Lazy import to avoid circular deps."""
    from ..coverage import CoverageManager

    return CoverageManager(check_tools=False)


def _cleanup_fuzzer_procs() -> None:
    """Terminate any remaining fuzzer processes on exit."""
    for proc in list(_active_fuzzer_procs):
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


atexit.register(_cleanup_fuzzer_procs)


@dataclass
class FuzzerConfig:
    """Configuration for native fuzzer."""

    binary: Path
    corpus_dir: Path
    artifacts_dir: Path | None = None  # Default: corpus_dir/../artifacts
    dict_path: Path | None = None
    max_total_time: int = 0  # 0 = unlimited
    max_len: int = 0  # 0 = auto
    jobs: int = 1
    print_final_stats: bool = True
    extra_args: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.binary = Path(self.binary).expanduser().resolve()
        self.corpus_dir = Path(self.corpus_dir).expanduser().resolve()
        if self.artifacts_dir:
            self.artifacts_dir = Path(self.artifacts_dir).expanduser().resolve()
        else:
            self.artifacts_dir = self.corpus_dir.parent / "artifacts"
        if self.dict_path:
            self.dict_path = Path(self.dict_path).expanduser().resolve()


@dataclass
class FuzzerStats:
    """Statistics from libFuzzer output."""

    execs: int = 0
    execs_per_sec: int = 0
    coverage: int = 0  # cov: N
    features: int = 0  # ft: N
    corpus_size: int = 0  # corp: N
    corpus_bytes: int = 0  # corp: N/Mb
    rss_mb: int = 0
    crashes: int = 0
    timeouts: int = 0
    ooms: int = 0
    new_units: int = 0
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execs": self.execs,
            "execs_per_sec": self.execs_per_sec,
            "coverage": self.coverage,
            "features": self.features,
            "corpus_size": self.corpus_size,
            "corpus_bytes": self.corpus_bytes,
            "rss_mb": self.rss_mb,
            "crashes": self.crashes,
            "timeouts": self.timeouts,
            "ooms": self.ooms,
            "new_units": self.new_units,
        }


@dataclass
class CrashArtifact:
    """Represents a crash artifact from the fuzzer."""

    path: Path
    crash_type: str  # crash, timeout, oom, slow-unit
    discovered_at: datetime
    input_bytes: bytes | None = None
    stack_hash: str | None = None
    triaged: bool = False

    def load_input(self) -> bytes:
        """Load crash input bytes."""
        if self.input_bytes is None:
            self.input_bytes = self.path.read_bytes()
        return self.input_bytes


class NativeFuzzerOrchestrator:
    """Launch and control native libFuzzer subprocess."""

    # Regex patterns for parsing libFuzzer output
    STATS_PATTERN = re.compile(
        r"#(\d+)\s+"
        r"(?:NEW|INITED|REDUCE|pulse|DONE|RELOAD)?\s*"
        r"(?:cov:\s*(\d+))?\s*"
        r"(?:ft:\s*(\d+))?\s*"
        r"(?:corp:\s*(\d+)/(\d+)([KMb]))?\s*"
        r"(?:lim:\s*\d+)?\s*"
        r"(?:exec/s:\s*(\d+))?\s*"
        r"(?:rss:\s*(\d+)Mb)?",
        re.IGNORECASE,
    )
    CRASH_PATTERN = re.compile(r"(crash|timeout|oom|slow-unit)-[a-f0-9]+", re.IGNORECASE)

    def __init__(self, config: FuzzerConfig):
        self.config = config
        self._proc: subprocess.Popen | None = None
        self._stats = FuzzerStats()
        self._output_lines: list[str] = []
        self._reader_task: asyncio.Task | None = None

    @property
    def stats(self) -> FuzzerStats:
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
        """Spawn fuzzer subprocess."""
        if self.is_alive():
            return {"error": "Fuzzer already running", "pid": self._proc.pid}

        # Ensure directories exist
        self.config.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.config.artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Build command
        cmd = [str(self.config.binary)]

        # Add libFuzzer flags
        cmd.append(f"-artifact_prefix={self.config.artifacts_dir}/")

        if self.config.max_total_time > 0:
            cmd.append(f"-max_total_time={self.config.max_total_time}")

        if self.config.max_len > 0:
            cmd.append(f"-max_len={self.config.max_len}")

        if self.config.jobs > 1:
            cmd.append(f"-jobs={self.config.jobs}")
            cmd.append(f"-workers={self.config.jobs}")

        if self.config.print_final_stats:
            cmd.append("-print_final_stats=1")

        if self.config.dict_path and self.config.dict_path.exists():
            cmd.append(f"-dict={self.config.dict_path}")

        # Add extra args
        cmd.extend(self.config.extra_args)

        # Add corpus directory
        cmd.append(str(self.config.corpus_dir))

        # Spawn process
        env = os.environ.copy()
        # Ensure sanitizer output goes to stderr
        env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") + ":abort_on_error=1"

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            text=True,
            bufsize=1,  # Line buffered
            env=env,
        )
        _active_fuzzer_procs.add(self._proc)

        # Start async output reader
        self._reader_task = asyncio.create_task(self._read_output())

        return {
            "pid": self._proc.pid,
            "status": "running",
            "command": " ".join(cmd),
            "corpus_dir": str(self.config.corpus_dir),
            "artifacts_dir": str(self.config.artifacts_dir),
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
        """Parse a line of libFuzzer output for statistics."""
        match = self.STATS_PATTERN.search(line)
        if match:
            self._stats.execs = int(match.group(1)) if match.group(1) else self._stats.execs
            self._stats.coverage = int(match.group(2)) if match.group(2) else self._stats.coverage
            self._stats.features = int(match.group(3)) if match.group(3) else self._stats.features
            if match.group(4) and match.group(5):
                self._stats.corpus_size = int(match.group(4))
                size_val = int(match.group(5))
                size_unit = match.group(6) or "b"
                if size_unit.lower() == "k":
                    self._stats.corpus_bytes = size_val * 1024
                elif size_unit.lower() == "m":
                    self._stats.corpus_bytes = size_val * 1024 * 1024
                else:
                    self._stats.corpus_bytes = size_val
            self._stats.execs_per_sec = int(match.group(7)) if match.group(7) else self._stats.execs_per_sec
            self._stats.rss_mb = int(match.group(8)) if match.group(8) else self._stats.rss_mb
            self._stats.updated_at = datetime.now()

        # Check for NEW units
        if "NEW" in line:
            self._stats.new_units += 1

        # Check for crashes
        if "SUMMARY" in line.upper() and "ERROR" in line.upper():
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
            # Send SIGINT for graceful shutdown (libFuzzer prints final stats)
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

        libFuzzer will pick it up on the next iteration.
        """
        import hashlib

        if name is None:
            # Generate name from content hash
            h = hashlib.sha256(seed_bytes).hexdigest()[:16]
            name = f"seed-{h}"

        seed_path = self.config.corpus_dir / name
        seed_path.write_bytes(seed_bytes)
        return seed_path

    async def inject_dict_entry(self, token: str) -> None:
        """Append a token to the dictionary file."""
        if not self.config.dict_path:
            self.config.dict_path = self.config.corpus_dir.parent / "fuzz.dict"

        # Escape the token for libFuzzer dict format
        escaped = token.encode("unicode_escape").decode("ascii")
        entry = f'"{escaped}"\n'

        with open(self.config.dict_path, "a") as f:
            f.write(entry)

    def get_new_crashes(self) -> list[CrashArtifact]:
        """Find new crash artifacts in the artifacts directory."""
        crashes = []
        if not self.config.artifacts_dir or not self.config.artifacts_dir.exists():
            return crashes

        for path in self.config.artifacts_dir.iterdir():
            if not path.is_file():
                continue

            # Match libFuzzer artifact patterns
            name = path.name.lower()
            crash_type = None
            if name.startswith("crash-"):
                crash_type = "crash"
            elif name.startswith("timeout-"):
                crash_type = "timeout"
            elif name.startswith("oom-"):
                crash_type = "oom"
            elif name.startswith("slow-unit-"):
                crash_type = "slow-unit"

            if crash_type:
                stat = path.stat()
                crashes.append(
                    CrashArtifact(
                        path=path,
                        crash_type=crash_type,
                        discovered_at=datetime.fromtimestamp(stat.st_mtime),
                    )
                )

        return sorted(crashes, key=lambda c: c.discovered_at)


class CrashMonitor:
    """Monitor for new crash artifacts with deduplication."""

    def __init__(self, artifacts_dir: Path, poll_interval: float = 1.0):
        self.artifacts_dir = Path(artifacts_dir)
        self.poll_interval = poll_interval
        self._known_crashes: dict[Path, CrashArtifact] = {}
        self._pending_crashes: list[CrashArtifact] = []
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start background monitoring task."""
        if self._running:
            return

        self._running = True
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
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
                print(f"[CrashMonitor] Error scanning: {e}", file=sys.stderr)

            await asyncio.sleep(self.poll_interval)

    def _scan_for_crashes(self) -> None:
        """Scan artifacts directory for new crashes."""
        if not self.artifacts_dir.exists():
            return

        for path in self.artifacts_dir.iterdir():
            if not path.is_file() or path in self._known_crashes:
                continue

            name = path.name.lower()
            crash_type = None
            if name.startswith("crash-"):
                crash_type = "crash"
            elif name.startswith("timeout-"):
                crash_type = "timeout"
            elif name.startswith("oom-"):
                crash_type = "oom"
            elif name.startswith("slow-unit-"):
                crash_type = "slow-unit"

            if crash_type:
                stat = path.stat()
                crash = CrashArtifact(
                    path=path,
                    crash_type=crash_type,
                    discovered_at=datetime.fromtimestamp(stat.st_mtime),
                )
                self._known_crashes[path] = crash
                self._pending_crashes.append(crash)

    def get_new_crashes(self) -> list[CrashArtifact]:
        """Return unprocessed crashes since last call."""
        crashes = self._pending_crashes
        self._pending_crashes = []
        return crashes

    def mark_triaged(self, crash: CrashArtifact, stack_hash: str) -> None:
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
class HybridStats:
    """Statistics for a hybrid fuzzing session."""

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
            },
            "seeds_injected": self.seeds_injected,
        }


class HybridFuzzer:
    """Coordinate LLM cold-start + native fuzzing + LLM triage."""

    def __init__(
        self,
        binary: Path,
        corpus_dir: Path,
        artifacts_dir: Path | None = None,
        dict_path: Path | None = None,
        provider: str | None = None,
        model: str | None = None,
        triage_interval: float = 60.0,
        coverage_interval: float = 300.0,
        cold_start: bool = True,
        max_jobs: int = 1,
        status_callback: Callable[[str, str], None] | None = None,
    ):
        self.binary = Path(binary).resolve()
        self.corpus_dir = Path(corpus_dir).resolve()
        self.artifacts_dir = Path(artifacts_dir).resolve() if artifacts_dir else self.corpus_dir.parent / "artifacts"
        self.dict_path = Path(dict_path).resolve() if dict_path else None

        self.provider_name = provider
        self.model = model
        self.triage_interval = triage_interval
        self.coverage_interval = coverage_interval
        self.cold_start_enabled = cold_start
        self.max_jobs = max_jobs
        self._status_callback = status_callback

        self._orchestrator: NativeFuzzerOrchestrator | None = None
        self._monitor: CrashMonitor | None = None
        self._coverage: Any | None = None
        self._stats = HybridStats()
        self._seen_hashes: set[str] = set()
        self._running = False

    def _emit_status(self, message: str, kind: str = "info") -> None:
        """Emit a status message to callback and stderr."""
        print(f"[Hybrid] {message}", file=sys.stderr)
        if self._status_callback:
            self._status_callback(message, kind)

    @property
    def stats(self) -> HybridStats:
        return self._stats

    async def run(self, max_time: int = 3600) -> HybridStats:
        """Run the hybrid fuzzing loop.

        Args:
            max_time: Maximum fuzzing time in seconds (0 = unlimited).

        Returns:
            HybridStats with session results.
        """
        self._stats = HybridStats()
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

            # Phase 2: Launch native fuzzer
            self._emit_status("Phase 2: Launching native fuzzer...", "info")
            config = FuzzerConfig(
                binary=self.binary,
                corpus_dir=self.corpus_dir,
                artifacts_dir=self.artifacts_dir,
                dict_path=self.dict_path,
                max_total_time=max_time,
                jobs=self.max_jobs,
            )
            self._orchestrator = NativeFuzzerOrchestrator(config)
            launch_result = await self._orchestrator.launch()
            self._emit_status(f"Fuzzer running (PID {launch_result.get('pid')})", "info")

            # Start crash monitor
            self._monitor = CrashMonitor(self.artifacts_dir)
            await self._monitor.start()

            # Initialize coverage manager
            try:
                self._coverage = _get_coverage_manager()
            except ImportError:
                self._emit_status("Coverage module not found, skipping coverage feedback", "warning")

            # Phase 3: Triage loop
            self._emit_status(
                f"Phase 3: Monitoring (triage={self.triage_interval}s, cov={self.coverage_interval}s)...",
                "info",
            )
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
        from ..generate import InputGenerator, write_seeds

        generator = InputGenerator(provider=self.provider_name, model=self.model)

        # Generate seeds from binary analysis with timeout
        self._emit_status("Analyzing binary and generating seeds...", "info")
        try:
            seeds = await asyncio.wait_for(
                generator.synthesize_from_binary(self.binary, count=10),
                timeout=120.0,  # 2 minute timeout
            )
        except asyncio.TimeoutError:
            self._emit_status("LLM call timed out after 120s", "error")
            seeds = []
        except Exception as e:
            err_str = str(e)
            self._emit_status(f"LLM error: {err_str[:100]}", "error")
            if "Connection refused" in err_str or "urlopen error" in err_str:
                self._emit_status("Hint: Use --provider anthropic/openai/google or --no-cold-start", "error")
            seeds = []  # Fall through to heuristic fallback

        if not seeds:
            self._emit_status("No seeds generated, using heuristic fallback", "info")
            # Generate basic seeds as fallback
            from ..corpus import heuristic_mutations
            from ..generate import GeneratedSeed

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
        last_coverage_run = start

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

            # Run coverage analysis
            if self._coverage and (datetime.now() - last_coverage_run).total_seconds() >= self.coverage_interval:
                await self._run_coverage_feedback()
                last_coverage_run = datetime.now()

    async def _run_coverage_feedback(self) -> None:
        """Run coverage analysis and generate seeds for uncovered paths."""
        if not self._orchestrator:
            return

        self._emit_status("Running coverage analysis...", "info")
        try:
            # 1. Merge profiles
            # Note: libFuzzer writes default.profraw by default if configured
            profraw = Path("default.profraw")  # Default libFuzzer output
            if not profraw.exists():
                # Try to find one in CWD
                candidates = list(Path.cwd().glob("*.profraw"))
                if candidates:
                    profraw = candidates[0]

            if not profraw.exists():
                self._emit_status("No profile data found (run with -fprofile-instr-generate)", "warning")
                return

            profdata = self.corpus_dir.parent / "fuzz.profdata"

            # For accurate coverage, we should ideally re-run the corpus against the binary
            # with -runs=0 to generate a specialized profile, rather than relying on the live one
            # which might be partial. But for now, let's use what we have to be non-intrusive.

            merged = await self._coverage.merge_profiles([profraw], profdata)
            if not merged:
                return

            # 2. Get uncovered functions
            uncovered = await self._coverage.get_uncovered_functions(self.binary, profdata)
            if not uncovered:
                self._emit_status("Coverage analysis: all functions have some coverage", "info")
                return

            self._emit_status(f"Found {len(uncovered)} uncovered functions", "cov")

            # 3. Generate seeds for top 5 uncovered
            # Filter out boring ones (underscore prefixed, or standard lib)
            targets = [f.name for f in uncovered if not f.name.startswith("_") and "std::" not in f.name][:5]

            if not targets:
                return

            self._emit_status(f"Synthesizing seeds for: {', '.join(targets)}", "seed")

            # Using the generator to synthesize inputs
            from ..generate import InputGenerator

            # We need to read some existing seeds for context
            existing_seeds = []
            for f in list(self.corpus_dir.glob("*"))[:5]:
                if f.is_file():
                    existing_seeds.append(f.read_bytes())

            generator = InputGenerator(provider=self.provider_name, model=self.model)
            # We might need to analyze binary again to get format spec if not cached
            try:
                format_spec = await generator.analyze_binary(self.binary)
            except Exception:
                format_spec = None

            seeds = await generator.synthesize_for_coverage(
                uncovered_functions=targets, existing_seeds=existing_seeds, format_spec=format_spec, count=5
            )

            if seeds:
                injected = 0
                for seed in seeds:
                    await self._orchestrator.inject_seed(seed.data, name=f"cov_{seed.name}")
                    injected += 1
                self._emit_status(f"Injected {injected} coverage-guided seeds", "seed")
                self._stats.seeds_injected += injected

        except Exception as e:
            self._emit_status(f"Coverage feedback failed: {e}", "error")

    async def _triage_crash(self, crash: CrashArtifact) -> dict[str, Any] | None:
        """Triage a crash using LLDB."""
        from .session import FuzzSession

        try:
            async with FuzzSession(binary=str(self.binary)) as session:
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
        crash: CrashArtifact,
        triage_ctx: dict[str, Any],
    ) -> list[bytes]:
        """Generate refined seeds based on crash analysis."""
        from ..corpus import heuristic_mutations

        crash_data = crash.load_input()

        # Use heuristic mutations (fast, no LLM)
        mutations = heuristic_mutations(crash_data)

        # Return just the bytes
        return [data for _, data in mutations[:5]]

    def _print_stats(self) -> None:
        """Print current stats (non-TUI mode only)."""
        if not self._orchestrator:
            return

        # Skip periodic stats in TUI mode (callback handles it)
        if self._status_callback:
            return

        stats = self._orchestrator.stats
        print(
            f"[Hybrid] {stats.execs:,} execs | "
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
                    print("[Hybrid] Final fuzzer output:", file=sys.stderr)
                    for line in final_lines:
                        print(f"  {line}", file=sys.stderr)
