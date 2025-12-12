"""
Autonomous fuzzing agent driven by LLM.

The agent uses an LLM to:
1. Analyze the target binary and identify interesting functions
2. Install mutation hooks at strategic breakpoints
3. Run the target with various inputs
4. Collect and deduplicate crashes
5. Generate new corpus seeds based on coverage/crashes

Architecture:
    - FuzzSession: Manages LLDB/DAP connection and MCP tool execution
    - FuzzAgent: LLM-driven agent that uses the session for tool execution
    - AgenticLoop: Provider-agnostic tool loop (LLM calls tools directly)
    - ToolExecutor: Executes tools via MCP session
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..providers.base import LLMProvider, RateLimitError
    from ..tools.loop import AgenticLoop
    from .session import FuzzSession

from ..providers.base import RateLimitError
from .hooks import HookManager


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@dataclass
class FuzzResult:
    """Result of a fuzzing iteration."""

    iteration: int
    input_path: str
    crashed: bool
    stack_hash: str | None = None
    crash_type: str | None = None
    is_new_crash: bool = False
    mutation_applied: str | None = None


@dataclass
class FuzzStats:
    """Statistics for a fuzzing campaign."""

    iterations: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    corpus_size: int = 0
    start_time: str = ""
    elapsed_seconds: float = 0.0


@dataclass
class AgentConfig:
    """Configuration for the fuzzing agent."""

    mode: str = "auto"  # "auto" or "researcher"
    provider: str | None = None
    model: str | None = None
    max_iterations: int = 100
    max_turns: int = 12
    timeout: float = 180.0
    write_corpus: bool = True
    write_crashes: bool = True
    corpus_dir: str | None = None
    crashes_dir: str | None = None
    # Corpus generation settings
    generate_corpus: bool = True  # Generate new seeds from crashes
    use_llm_corpus: bool = False  # Use LLM for corpus generation (slower but smarter)
    max_corpus_size: int = 1000  # Limit corpus growth
    # Initial seed synthesis
    synthesize_initial_seeds: bool = False  # Generate seeds from binary analysis at startup
    initial_seed_count: int = 10  # Number of initial seeds to generate
    trace_output: str | None = None  # Optional JSONL trace output path (experimental)


class FuzzAgent:
    """LLM-driven autonomous fuzzing agent.

    The agent operates in two modes:
    - auto: Fully autonomous, makes all decisions
    - researcher: Human-in-the-loop, asks for approval

    Usage:
        async with FuzzSession(binary="/path/to/bin") as session:
            agent = FuzzAgent(session, provider="anthropic")
            stats = await agent.run(max_iterations=100)
    """

    def __init__(
        self,
        session: FuzzSession,
        config: AgentConfig | None = None,
        provider: str | None = None,
        model: str | None = None,
    ):
        self.session = session
        self.config = config or AgentConfig()
        if provider:
            self.config.provider = provider
        if model:
            self.config.model = model

        self.hooks = HookManager(session)
        self.stats = FuzzStats()
        self._seen_hashes: set[str] = set()
        self._corpus: list[Path] = []
        self._crashes: list[dict[str, Any]] = []

        # Tool-calling support (LLM drives MCP tools via AgenticLoop)
        self._provider: LLMProvider | None = None
        self._agentic_loop: AgenticLoop | None = None

        # Session recovery state
        self._session_healthy: bool = True
        self._consecutive_failures: int = 0
        self._max_consecutive_failures: int = 3

    @property
    def crashes(self) -> list[dict[str, Any]]:
        """List of collected crashes."""
        return self._crashes.copy()

    @property
    def corpus(self) -> list[Path]:
        """List of corpus files."""
        return self._corpus.copy()

    def _get_provider(self) -> LLMProvider:
        """Get or create the LLM provider."""
        if self._provider is None:
            from ..providers import get_provider

            self._provider = get_provider(self.config.provider)
        return self._provider

    def _get_agentic_loop(self) -> AgenticLoop:
        """Get or create the agentic loop for tool calling.

        The agentic loop handles the tool use pattern:
        1. Send request with tools to LLM
        2. If LLM wants to use tools, execute them via MCP session
        3. Send results back, repeat until done

        Returns:
            Configured AgenticLoop instance.
        """
        if self._agentic_loop is None:
            from ..tools.executor import ToolExecutor
            from ..tools.loop import AgenticLoop
            from ..tools.registry import ToolRegistry

            # Initialize registry with canonical tools
            if ToolRegistry.count() == 0:
                ToolRegistry.initialize_canonical_tools()

            # Create executor that uses the MCP session
            executor = ToolExecutor(session=self.session, prefer_mcp=True)

            self._agentic_loop = AgenticLoop(
                provider=self._get_provider(),
                executor=executor,
                max_turns=self.config.max_turns,
                verbose=True,
                trace_output=self.config.trace_output,
            )
        return self._agentic_loop

    async def _setup_with_tools(self) -> None:
        """Phase 1: analyze target and install hooks via tool calling.

        The LLM drives LLDB by calling tools directly (launch, symtab lookup,
        stop-hook installation, fork server installation).

        Handles session failures by restarting and retrying.
        """
        max_setup_retries = 2
        last_error = None

        for attempt in range(max_setup_retries + 1):
            try:
                await self._setup_with_tools_inner()
                return  # Success
            except Exception as e:
                last_error = e
                error_str = str(e)

                # Check if this is a recoverable session error
                if "DAP socket closed" in error_str or "Tool loop exceeded" in error_str:
                    if attempt < max_setup_retries:
                        print(f"[!] Setup failed (attempt {attempt + 1}), restarting session...", file=sys.stderr)
                        if await self._restart_session():
                            continue  # Retry setup
                        else:
                            break  # Restart failed, give up
                else:
                    # Non-recoverable error
                    raise

        # All retries exhausted
        raise last_error or RuntimeError("Setup failed after retries")

    async def _setup_with_tools_inner(self) -> None:
        """Inner setup logic - separated to allow retry on failure."""
        loop = self._get_agentic_loop()

        system_prompt = self._build_system_prompt()

        # Determine marker from corpus if available
        marker = "FUZZ_MARKER"
        seed_file = None
        if self._corpus:
            seed_file = str(self._corpus[0])
            # Try to read first few bytes as potential marker
            try:
                content = self._corpus[0].read_bytes()[:32]
                if content and len(content) >= 4:
                    marker = content.decode("utf-8", errors="ignore").split()[0][:16] or marker
            except Exception:
                pass

        user_prompt = (
            f"Analyze and set up fuzzing for target: {self.session.binary}\n\n"
            f"Seed file: {seed_file or 'none (will create marker seed)'}\n"
            f"Marker to search for: '{marker}'\n\n"
            "IMPORTANT: If you encounter errors like 'DAP socket closed', STOP immediately and report what you learned.\n"
            "Do NOT retry failed operations - just summarize your findings so far.\n\n"
            "Steps:\n"
            "1. Launch the binary with stop_on_entry=true and the seed file\n"
            "2. Use lldb_dump_symtab to find candidate functions (filter by 'parse|decode|read|handle')\n"
            "3. For EACH promising candidate, validate with lldb_validate_input_control:\n"
            f"   - Call: lldb_validate_input_control(function='<name>', marker='{marker}')\n"
            "   - Check 'validated' field - if true, note which register controls input\n"
            "   - Extract ptr_reg and len_reg from the result's interpretation\n"
            "4. Install hooks ONLY on validated functions using the discovered registers:\n"
            "   - lldb_install_stop_hook(function='<name>', ptr_reg='x0', len_reg='x1')\n"
            "5. Optionally install a fork server at main using lldb_install_fork_server\n"
            "6. Report: which functions you validated, which passed, what hooks you installed\n"
            "\nIf the binary crashes during analysis, that's useful information - report what you found.\n"
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        response = await loop.run(
            messages=messages,
            model=self.config.model or "",
        )

        if response.content:
            print(f"[+] Setup complete: {response.content[:200]}...", file=sys.stderr)

    async def analyze_crash(self, crash_context: dict[str, Any]) -> dict[str, Any]:
        """Analyze a crash using tool calling.

        This method uses AgenticLoop to let the LLM explore the crash
        interactively using LLDB tools.

        Args:
            crash_context: Initial crash context from lldb_crash_context.

        Returns:
            Analysis result with classification, root cause, and recommendations.
        """
        loop = self._get_agentic_loop()

        prompt = (
            "Analyze this crash and determine the root cause.\n\n"
            f"Crash context:\n{json.dumps(crash_context, indent=2)}\n\n"
            "Use LLDB tools to:\n"
            "1. Examine the backtrace and identify the crash site\n"
            "2. Read memory and registers around the crash\n"
            "3. Disassemble the crashing instruction\n"
            "4. Classify the vulnerability type\n"
            "5. Provide a root cause analysis\n\n"
            "When done, summarize your findings.\n"
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": prompt},
        ]

        try:
            response = await loop.run(messages=messages, model=self.config.model or "")
            return {
                "analysis": response.content,
                "tool_calls_used": len(response.tool_calls or []),
                "success": True,
            }
        except RateLimitError as e:
            return {"error": f"Rate limit exceeded: {e}", "success": False, "rate_limited": True}
        except Exception as e:
            return {"error": str(e), "success": False}

    async def run(
        self,
        initial_inputs: Sequence[str | Path] | None = None,
        max_iterations: int | None = None,
    ) -> FuzzStats:
        """Run the fuzzing campaign.

        Args:
            initial_inputs: Initial corpus files to start with.
            max_iterations: Override max iterations from config.

        Returns:
            FuzzStats with campaign results.
        """
        max_iter = max_iterations or self.config.max_iterations
        self.stats = FuzzStats(start_time=_dt.datetime.now().isoformat())

        # Load initial corpus
        if initial_inputs:
            for inp in initial_inputs:
                path = Path(inp)
                if path.exists():
                    self._corpus.append(path)
            self.stats.corpus_size = len(self._corpus)

        # Optionally synthesize initial seeds from binary analysis
        if self.config.synthesize_initial_seeds and not self._corpus:
            print("[*] Synthesizing initial seeds from binary analysis...", file=sys.stderr)
            try:
                synth_count = await self._synthesize_initial_seeds()
                print(f"[+] Synthesized {synth_count} initial seeds", file=sys.stderr)
            except Exception as e:
                print(f"[!] Seed synthesis failed: {e}", file=sys.stderr)

        # Phase 1: Analyze target and set up hooks
        print(f"[+] Analyzing target: {self.session.binary}", file=sys.stderr)
        try:
            await self._setup_with_tools()
        except RateLimitError as e:
            print(f"\n[!] Rate limit exceeded: {e}", file=sys.stderr)
            print("[!] Ending session and saving results...", file=sys.stderr)
            return self.stats
        except Exception as e:
            raise RuntimeError(f"setup failed: {e}") from e

        # Phase 2: Fuzzing loop
        print(f"[+] Starting fuzzing loop (max {max_iter} iterations)", file=sys.stderr)
        for i in range(max_iter):
            self.stats.iterations = i + 1

            try:
                result = await self._fuzz_iteration(i)
                if result.crashed:
                    self.stats.crashes += 1
                    if result.is_new_crash:
                        self.stats.unique_crashes += 1
                        print(f"[!] New crash found: {result.stack_hash}", file=sys.stderr)
            except KeyboardInterrupt:
                print("\n[*] Fuzzing interrupted", file=sys.stderr)
                break
            except Exception as e:
                print(f"[!] Iteration {i} failed: {e}", file=sys.stderr)
                continue

        # Calculate elapsed time
        start = _dt.datetime.fromisoformat(self.stats.start_time)
        self.stats.elapsed_seconds = (_dt.datetime.now() - start).total_seconds()

        return self.stats

    def _build_system_prompt(self) -> str:
        """Build the system prompt for the fuzzing agent."""
        return (
            "You are an autonomous fuzzing agent. You drive LLDB through MCP tools "
            "to fuzz a target binary and discover crashes.\n\n"
            "CRITICAL RULES:\n"
            "1. NEVER fabricate, guess, or make up binary/crash details. If you need data, call tools.\n"
            "2. Tool names must match exactly. If unsure, call tool_search.\n"
            "3. Prefer high-level tools (lldb_crash_context, lldb_read_memory, lldb_disassemble) over raw commands.\n"
            "4. ALWAYS validate targets before installing hooks - only install hooks where you control input.\n\n"
            "Scope: Apple Mach-O on arm64(e). Key ARM64 registers:\n"
            "- x0-x7: function arguments (x0 often points to input buffer)\n"
            "- x1: often length (if present)\n"
            "- sp/lr/pc: stack pointer / return address / program counter\n\n"
            "Setup workflow:\n"
            "1. Call lldb_launch(stop_on_entry=true) with a seed file containing a marker (e.g., 'FUZZ_MARKER')\n"
            "2. Use lldb_dump_symtab to find candidate functions (parsers, handlers, decoders)\n"
            "3. For each candidate, call lldb_validate_input_control(function=..., marker='...') to verify:\n"
            "   - The marker is found in memory at the function entry\n"
            "   - Which register (x0, x1, etc.) points to the buffer\n"
            "   - What the size parameter is (if any)\n"
            "4. For validated targets, choose installation method:\n"
            "   - SIMPLE: lldb_install_stop_hook for basic buffer mutation\n"
            "   - CUSTOM: lldb_generate_fuzz_script for complex targets with:\n"
            "     * Multiple registers to inspect\n"
            "     * Skip conditions (e.g., skip certain selectors)\n"
            "     * Custom ABI awareness\n"
            "5. Optionally install a fork server with lldb_install_fork_server for one-shot binaries\n"
            "6. Explain what you validated and installed.\n\n"
            "Crash workflow:\n"
            "1. Call lldb_crash_context to capture the real crash state\n"
            "2. Use lldb_stack_hash to dedupe\n"
            "3. Use memory/register/disassembly tools to confirm the root cause\n"
            "4. Summarize findings and suggest next hooks/seeds.\n"
        )

    async def _check_session_health(self) -> bool:
        """Check if the session is healthy and can accept commands.

        Returns:
            True if session is healthy, False otherwise.
        """
        try:
            # Try a simple status check
            result = await self.session.call_tool("lldb_status", {})
            # If we get a response without error, session is healthy
            return "error" not in result.lower() or "DAP socket closed" not in result
        except Exception:
            return False

    async def _restart_session(self) -> bool:
        """Restart the LLDB/DAP session after a failure.

        Returns:
            True if restart succeeded, False otherwise.
        """
        print("[*] Restarting LLDB session...", file=sys.stderr)
        try:
            # Stop the old session
            await self.session._stop()

            # Start a new session
            await self.session._start()

            # Reset the agentic loop to use the new session
            self._agentic_loop = None

            self._session_healthy = True
            self._consecutive_failures = 0
            print("[+] Session restarted successfully", file=sys.stderr)
            return True
        except Exception as e:
            print(f"[!] Failed to restart session: {e}", file=sys.stderr)
            return False

    async def _ensure_session_ready(self) -> bool:
        """Ensure the session is ready for the next iteration.

        Handles session reset after crashes and restart after failures.

        Returns:
            True if session is ready, False if unrecoverable.
        """
        # First, try to reset the session for the next crash
        try:
            reset_ok = await self.session.reset_for_next_crash()
            if reset_ok:
                self._consecutive_failures = 0
                return True
        except Exception:
            pass

        # Reset failed, check if session is still healthy
        if not await self._check_session_health():
            self._session_healthy = False
            self._consecutive_failures += 1

            if self._consecutive_failures >= self._max_consecutive_failures:
                print(f"[!] Too many consecutive failures ({self._consecutive_failures}), giving up", file=sys.stderr)
                return False

            # Try to restart the session
            if not await self._restart_session():
                return False

        return True

    async def _fuzz_iteration(self, iteration: int) -> FuzzResult:
        """Run a single fuzzing iteration."""
        # Ensure session is ready (handles reset/restart)
        if iteration > 0:  # Skip for first iteration
            if not await self._ensure_session_ready():
                raise RuntimeError("Session unrecoverable after multiple restart attempts")

        # Pick an input from corpus (or generate one)
        if self._corpus:
            import random

            input_path = random.choice(self._corpus)
        else:
            # No corpus - let the target run without input
            input_path = Path("/dev/null")

        # Launch target
        try:
            launch_result = await self.session.launch(
                crash_input=str(input_path) if input_path.exists() else None,
                stop_on_entry=False,
            )
        except Exception as e:
            # Session might have died, mark for recovery
            self._session_healthy = False
            raise RuntimeError(f"Launch failed: {e}") from e

        # Check for session errors in launch result
        if launch_result.get("error") and "DAP socket closed" in str(launch_result.get("error", "")):
            self._session_healthy = False
            raise RuntimeError("Session died during launch")

        crashed = launch_result.get("status") == "stopped"
        stack_hash = None
        crash_type = None
        is_new = False

        if crashed:
            # Get stack hash for deduplication
            try:
                hash_result = await self.session.get_stack_hash()
                try:
                    hash_obj = json.loads(hash_result)
                    stack_hash = hash_obj.get("stack_hash") or hash_obj.get("hash")
                except json.JSONDecodeError:
                    stack_hash = hash_result[:16] if hash_result else None
            except Exception:
                # Session might have died after crash
                stack_hash = None

            if stack_hash and stack_hash not in self._seen_hashes:
                is_new = True
                self._seen_hashes.add(stack_hash)

                # Get crash details (may fail if session died)
                try:
                    ctx = await self.session.get_crash_context()
                    crash_type = ctx.get("reason") or (ctx.get("stop", {}) or {}).get("reason") or "unknown"
                except Exception:
                    ctx = {"error": "Session died before context could be captured"}
                    crash_type = "unknown"

                # Save crash
                self._crashes.append(
                    {
                        "iteration": iteration,
                        "hash": stack_hash,
                        "type": crash_type,
                        "input": str(input_path),
                        "context": ctx,
                    }
                )

                if self.config.write_crashes:
                    await self._save_crash(iteration, stack_hash, input_path)

                # Generate new corpus seeds from this crash
                if self.config.generate_corpus:
                    try:
                        await self._generate_corpus_from_crash(input_path, stack_hash, ctx)
                    except Exception as e:
                        print(f"[!] Corpus generation failed: {e}", file=sys.stderr)

        return FuzzResult(
            iteration=iteration,
            input_path=str(input_path),
            crashed=crashed,
            stack_hash=stack_hash,
            crash_type=crash_type,
            is_new_crash=is_new,
        )

    async def _save_crash(self, iteration: int, stack_hash: str, input_path: Path) -> None:
        """Save a crash to disk."""
        root = _repo_root()
        target = Path(self.session.binary).stem

        if self.config.crashes_dir:
            crashes_dir = Path(self.config.crashes_dir)
        else:
            crashes_dir = root / "crashes" / target

        crashes_dir.mkdir(parents=True, exist_ok=True)

        # Copy input file
        crash_file = crashes_dir / f"crash-{iteration:04d}-{stack_hash[:8]}"
        if input_path.exists():
            crash_file.write_bytes(input_path.read_bytes())

        # Save crash context
        if self._crashes:
            ctx_file = crashes_dir / f"crash-{iteration:04d}-{stack_hash[:8]}.json"
            ctx_file.write_text(json.dumps(self._crashes[-1], indent=2))

    async def _generate_corpus_from_crash(
        self,
        input_path: Path,
        stack_hash: str,
        crash_context: dict[str, Any],
    ) -> int:
        """Generate new corpus seeds from a crash.

        Uses heuristic mutations and optionally LLM-guided suggestions
        to create new seeds that might trigger similar or related crashes.

        Args:
            input_path: Path to the crash input file.
            stack_hash: Hash of the crash for naming.
            crash_context: Crash context dict with backtrace, registers, etc.

        Returns:
            Number of new seeds added to corpus.
        """
        if not input_path.exists():
            return 0

        # Check corpus size limit
        if len(self._corpus) >= self.config.max_corpus_size:
            print(f"[*] Corpus at max size ({self.config.max_corpus_size}), skipping generation", file=sys.stderr)
            return 0

        from ..corpus import extract_dict_tokens, heuristic_mutations, write_corpus, write_dict

        crash_data = input_path.read_bytes()

        # Generate heuristic mutations
        seeds = heuristic_mutations(crash_data)

        # Optionally use LLM for smarter mutations
        if self.config.use_llm_corpus:
            try:
                llm_seeds = await self._llm_generate_seeds(crash_data, crash_context)
                seeds.extend(llm_seeds)
            except Exception as e:
                print(f"[!] LLM corpus generation failed: {e}", file=sys.stderr)

        if not seeds:
            return 0

        # Determine output directory
        root = _repo_root()
        target = Path(self.session.binary).stem

        if self.config.corpus_dir:
            corpus_dir = Path(self.config.corpus_dir) / "generated" / stack_hash[:8]
        else:
            corpus_dir = root / "corpora" / target / "generated" / stack_hash[:8]

        # Write seeds to disk
        written = write_corpus(corpus_dir, seeds)

        # Add to live corpus
        for seed_path in written:
            if seed_path not in self._corpus:
                self._corpus.append(seed_path)

        # Extract and save dictionary tokens
        tokens = extract_dict_tokens(crash_data)
        if tokens:
            dict_path = corpus_dir.parent.parent / "crash.dict"
            write_dict(dict_path, tokens)

        self.stats.corpus_size = len(self._corpus)
        print(f"[+] Generated {len(written)} seeds from crash {stack_hash[:8]}", file=sys.stderr)

        return len(written)

    async def _llm_generate_seeds(
        self,
        crash_data: bytes,
        crash_context: dict[str, Any],
    ) -> list[tuple[str, bytes]]:
        """Use LLM to generate targeted seeds based on crash analysis.

        Args:
            crash_data: Raw bytes of crash input.
            crash_context: Crash context with backtrace, registers, etc.

        Returns:
            List of (name, bytes) tuples for new seeds.
        """
        provider = self._get_provider()

        # Build crash summary for LLM
        crash_hex = crash_data[:256].hex()
        ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in crash_data[:128])

        # Extract key info from context
        backtrace = crash_context.get("backtrace", [])[:5]
        crash_reason = crash_context.get("stop_reason", {}).get("description", "unknown")
        registers = crash_context.get("registers", {})

        # Get key registers
        key_regs = {k: v for k, v in registers.items() if k in ("x0", "x1", "x2", "pc", "lr", "sp")}

        prompt = f"""Analyze this crash and suggest targeted mutations for fuzzing.

## Crash Input
- Size: {len(crash_data)} bytes
- Hex (first 256 bytes): {crash_hex}
- ASCII preview: {ascii_preview}

## Crash Context
- Reason: {crash_reason}
- Key registers: {json.dumps(key_regs, indent=2)}
- Backtrace (top 5):
{json.dumps(backtrace, indent=2)}

## Task
Generate mutations that might trigger similar crashes or explore nearby code paths.

Respond with JSON:
{{
  "analysis": "Brief analysis of why this crashed",
  "mutations": [
    {{"name": "descriptive_name", "hex": "hexbytes", "rationale": "why this might work"}}
  ]
}}

Focus on:
- Values that might trigger the same vulnerability
- Boundary conditions around the crash point
- Format-specific mutations if you detect a known format
"""

        from ..providers import ChatMessage, ChatRequest

        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system",
                    content="You are a fuzzing expert. Generate targeted mutations based on crash analysis.",
                ),
                ChatMessage(role="user", content=prompt),
            ],
            model=self.config.model or "",
            json_output=True,
            temperature=0.3,
        )

        response = await provider.chat_async(request)

        seeds: list[tuple[str, bytes]] = []
        try:
            result = json.loads(response.content)
            for item in result.get("mutations", []):
                if isinstance(item, dict):
                    name = str(item.get("name", f"llm_{len(seeds)}"))
                    hex_str = str(item.get("hex", "")).replace(" ", "")
                    try:
                        seeds.append((f"llm_{name}", bytes.fromhex(hex_str)))
                    except ValueError:
                        continue
        except json.JSONDecodeError:
            pass

        return seeds[:8]  # Limit LLM seeds

    async def _synthesize_initial_seeds(self) -> int:
        """Synthesize initial seeds by analyzing the target binary.

        Uses the InputGenerator to analyze symbols/strings and generate
        format-aware seeds when no initial corpus is provided.

        Returns:
            Number of seeds synthesized.
        """
        from ..generate import InputGenerator, write_seeds

        generator = InputGenerator(
            provider=self.config.provider,
            model=self.config.model,
        )

        # Analyze binary and generate seeds
        binary = Path(self.session.binary)
        seeds = await generator.synthesize_from_binary(
            binary,
            count=self.config.initial_seed_count,
        )

        if not seeds:
            return 0

        # Determine output directory
        root = _repo_root()
        target = binary.stem

        if self.config.corpus_dir:
            corpus_dir = Path(self.config.corpus_dir) / "synthesized"
        else:
            corpus_dir = root / "corpora" / target / "synthesized"

        # Write seeds to disk
        written = write_seeds(corpus_dir, seeds)

        # Add to live corpus
        for seed_path in written:
            self._corpus.append(seed_path)

        self.stats.corpus_size = len(self._corpus)
        return len(written)
