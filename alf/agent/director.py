#!/usr/bin/env python3
"""
AI Director Loop (MCP Python SDK)
--------------------------------

End-to-end demo loop where an LLM drives LLDB through the local ALF LLDB‑MCP
server to explore crashes, try breakpoint/continue strategies, and emit
corpus/dict suggestions for deeper fuzzing.

This implementation uses the official MCP Python SDK for robust stdio
transport and log/notification handling.

Example:
  uv run alf director \
    --binary /path/to/fuzz_bin \
    --crash /path/to/crash_input \
    --tag demo \
    --mode auto
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path
from typing import Any

import anyio

from ..log import logger


def _get_default_model(provider_name: str | None = None) -> str | None:
    """Resolve the default model for a provider.

    Resolution order (highest to lowest):
    - CLI `--model`
    - `.alf.toml` / `~/.config/alf/config.toml`
    - Environment (`ALF_LLM_MODEL`, etc.)
    - Provider defaults (e.g., gpt-4o-mini / gemini-2.5-flash / llama3.1…)
    """
    from ..providers import get_config

    return get_config(provider_name).model


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def infer_target(binary_path: Path) -> str:
    parts = binary_path.parts
    if "harnesses" in parts:
        idx = parts.index("harnesses")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return binary_path.stem


def crash_hash(crash_path: Path) -> str:
    name = crash_path.name
    name = name.replace("crash-", "").replace("timeout-", "")
    return name[:12] if name else "unknown"


def read_crash_bytes(crash: Path, limit: int = 4096) -> bytes:
    data = crash.read_bytes()
    return data[:limit]


def hexdump(data: bytes, limit: int = 256) -> str:
    return data[:limit].hex()


def write_director_logs(root: Path, stamp: str, target: str, tag: str, payload: dict[str, Any]) -> Path:
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    path = logs_dir / f"{stamp}_{target}_director_{tag}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def build_system_prompt(mode: str = "auto") -> str:
    """Build system prompt for the director tool loop.

    The model must base all conclusions on tool output and avoid guessing.
    """
    base = (
        "You are an autonomous crash analysis agent. You drive LLDB through tools "
        "to analyze crashes and understand their root cause.\n\n"
        "CRITICAL RULES:\n"
        "1. NEVER fabricate, guess, or make up crash details. All information MUST come "
        "from tool results.\n"
        "2. ALWAYS call lldb_crash_context after launching to get real crash data.\n"
        "3. Your analysis MUST be based on actual tool output, not assumptions from "
        "filenames or guesses.\n"
        "4. If you don't have data from a tool, call the tool first.\n"
        "5. Call lldb_launch ONLY ONCE. If you get 'DAP socket closed', 'Broken pipe', "
        "or similar errors, the debug session has ended - DO NOT retry lldb_launch. "
        "Instead, analyze the crash data you already collected.\n"
        "6. Avoid calling 'continue' or lldb_continue unless you specifically need to "
        "hit another breakpoint. The process may exit, ending your session.\n\n"
        "REQUIRED WORKFLOW:\n"
        "1. Call lldb_launch ONCE to start debugging the binary with the crash input\n"
        "2. Call lldb_crash_context to get the REAL crash state (registers, backtrace, "
        "disassembly)\n"
        "3. Examine the tool results to understand what happened\n"
        "4. Use additional tools (lldb_read_memory, lldb_disassemble) if needed\n"
        "5. Provide your analysis based on the ACTUAL data collected\n"
        "6. If the session dies, use the data you already have - do NOT retry launch\n\n"
        "All targets are Apple Mach-O on arm64(e). Key arm64 registers:\n"
        "- x0-x7: Function arguments (x0=return value)\n"
        "- sp: Stack pointer\n"
        "- lr/x30: Link register (return address)\n"
        "- pc: Program counter (crash location)\n"
        "- x29/fp: Frame pointer\n\n"
        "Vulnerability classifications (choose based on ACTUAL evidence):\n"
        "- Stack Buffer Overflow: sp corruption, stack canary failure\n"
        "- Heap Buffer Overflow: heap metadata corruption\n"
        "- Use-After-Free: accessing freed memory\n"
        "- NULL Pointer Dereference: dereferencing 0x0 or near-null address\n"
        "- Division by Zero: SIGFPE with division instruction\n"
        "- Assertion Failure: explicit abort/assert\n"
        "- Unknown: if evidence is insufficient\n"
    )
    if mode == "researcher":
        base += (
            "\nYou are working with a human researcher. Ask clarifying questions "
            "if needed and explain your reasoning.\n"
        )
    return base


async def run_director(args: argparse.Namespace) -> int:
    """Run crash triage by letting the LLM call tools via AgenticLoop."""
    from ..fuzz import FuzzSession
    from ..log import configure_logging
    from ..providers import get_provider
    from ..tools.executor import ToolExecutor
    from ..tools.loop import AgenticLoop
    from ..tools.registry import ToolRegistry

    # Configure logging - always show info for director, debug for verbose
    configure_logging(verbose=True, debug=(args.log_level == "DEBUG"))

    binary = Path(args.binary).expanduser().resolve()
    crash = Path(args.crash).expanduser().resolve()

    if not binary.exists():
        logger.error(f"binary not found: {binary}")
        return 1
    if not crash.exists():
        logger.error(f"crash input not found: {crash}")
        return 1

    root = repo_root()
    target = infer_target(binary)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    hsh = crash_hash(crash)
    crash_hex = hexdump(read_crash_bytes(crash))

    # Initialize registry with canonical tools
    if ToolRegistry.count() == 0:
        ToolRegistry.initialize_canonical_tools()

    # Resolve model from config if not specified
    model = args.model or _get_default_model(args.provider)
    if not model:
        logger.error("No model specified. Use --model, set ALF_LLM_MODEL, or configure provider.model in .alf.toml.")
        return 1

    logger.info("Using tool-calling director loop")
    logger.info(f"Provider: {args.provider or 'auto-detect'}")
    logger.info(f"Model: {model}")

    async with FuzzSession(
        binary=str(binary),
        dap_path=args.dap_path,
        dap_port=args.dap_port,
        timeout=args.timeout,
        log_level=args.log_level,
    ) as session:
        # Create provider and agentic loop
        provider = get_provider(args.provider)
        executor = ToolExecutor(session=session, prefer_mcp=True)
        loop = AgenticLoop(
            provider=provider,
            executor=executor,
            max_turns=args.max_turns,
            verbose=True,
            trace_output=args.trace_output,
        )

        # Get tools based on context size preference
        if args.minimal_tools:
            from ..tools.definitions import get_minimal_tools

            selected_tools = get_minimal_tools()
            logger.info(f"Using {len(selected_tools)} minimal tools (with tool_search)")
        else:
            from ..tools.definitions import get_essential_tools

            selected_tools = get_essential_tools()
            logger.info(f"Using {len(selected_tools)} essential tools")

        # Convert tools to the provider's schema.
        from ..tools.converters.anthropic import to_anthropic_schema
        from ..tools.converters.gemini import to_gemini_schema
        from ..tools.converters.openai import to_openai_schema

        provider_name = (args.provider or provider.name).lower()
        if provider_name == "anthropic":
            converter = to_anthropic_schema
        elif provider_name in ("google", "gemini"):
            converter = to_gemini_schema
        else:
            converter = to_openai_schema

        tools = [converter(t) for t in selected_tools]

        system_prompt = build_system_prompt(args.mode)
        user_prompt = (
            f"Analyze this crash:\n\n"
            f"Binary: {binary}\n"
            f"Crash input: {crash}\n"
            f"Crash input (first 256 bytes, hex): {crash_hex}\n\n"
            "IMPORTANT: You MUST use the tools to get real data. Do NOT guess or "
            "fabricate any crash details based on filenames or assumptions.\n\n"
            "Required steps:\n"
            "1. Call lldb_launch with the binary and crash_input paths\n"
            "2. Call lldb_crash_context to get the ACTUAL crash state\n"
            "3. Analyze the REAL data from the tool results\n"
            "4. Provide your analysis citing specific addresses, registers, and "
            "frames from the tool output\n"
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response = await loop.run(
                messages=messages,
                model=model,
                tools=tools,  # Use essential tools for smaller context
            )

            print("\n" + "=" * 60)
            print("ANALYSIS COMPLETE")
            print("=" * 60)
            if response.content:
                print(response.content)
            print("=" * 60)

            corpus_dir: Path | None = None
            dict_path: Path | None = None
            dict_tokens_added: int | None = None

            if args.write_corpus or args.write_dict:
                from ..corpus import extract_dict_tokens, heuristic_mutations, write_corpus, write_dict

                crash_data = crash.read_bytes()
                if len(crash_data) > 1024 * 1024:
                    crash_data = crash_data[: 1024 * 1024]

                if args.write_corpus:
                    corpus_dir = root / "corpora" / target / "llm_generated" / f"{stamp}_{hsh}"
                    write_corpus(corpus_dir, heuristic_mutations(crash_data))

                if args.write_dict:
                    dict_path = (
                        Path(args.dict_out).expanduser().resolve()
                        if args.dict_out
                        else root / "corpora" / target / "llm.dict"
                    )
                    dict_tokens_added = write_dict(dict_path, extract_dict_tokens(crash_data))

            # Write log
            payload = {
                "metadata": {
                    "timestamp": stamp,
                    "target": target,
                    "tag": args.tag,
                    "binary": str(binary),
                    "crash": str(crash),
                    "provider": args.provider or provider.name,
                    "model": model,
                    "autonomy": args.mode,
                    "loop": "tool_calling",
                },
                "analysis": response.content,
                "artifacts": {
                    "corpus_dir": str(corpus_dir) if corpus_dir else None,
                    "dict_path": str(dict_path) if dict_path else None,
                    "dict_tokens_added": dict_tokens_added,
                },
            }
            log_path = write_director_logs(root, stamp, target, args.tag, payload)
            logger.success(f"Director log: {log_path}")
            if corpus_dir:
                logger.success(f"Wrote corpus seeds to {corpus_dir}")
            if dict_path:
                logger.success(f"Updated dict {dict_path}")

            return 0
        except Exception as e:
            logger.warning(f"Director loop failed: {e}")
            return 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    # Load config defaults
    from .. import config as alf_config

    director_cfg = alf_config.get_director_config()
    provider_cfg = alf_config.get_provider_config()
    lldb_cfg = alf_config.get_lldb_config()

    p = argparse.ArgumentParser(description="LLM director loop using LLDB-MCP tools.")
    p.add_argument("--binary", required=True, help="Path to fuzz binary.")
    p.add_argument("--crash", required=True, help="Path to crash input.")
    p.add_argument("--tag", default="director", help="Short tag for artifact names.")
    p.add_argument(
        "--mode",
        default=director_cfg.get("mode", "auto"),
        choices=["auto", "researcher"],
        help="Operation mode: auto (full autonomous) or researcher (human-in-the-loop).",
    )
    p.add_argument("--model", default=None, help="LLM model (default from .alf.toml).")
    p.add_argument(
        "--provider",
        default=provider_cfg.get("name"),
        choices=["anthropic", "openai", "google", "ollama", "lmstudio", "vllm", "localai"],
        help="LLM provider (auto-detected from .alf.toml or API keys if not set).",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=int(provider_cfg.get("timeout") or 180),
        help="Adapter timeout seconds.",
    )
    p.add_argument(
        "--max-turns",
        type=int,
        default=director_cfg.get("max_turns", 10),
        help="Max LLM/MCP turns.",
    )
    p.add_argument(
        "--minimal-tools",
        action="store_true",
        default=director_cfg.get("minimal_tools", False),
        help="Use minimal tool set (4 tools + search) for small context windows (4K-8K).",
    )
    p.add_argument(
        "--dap-path",
        default=lldb_cfg.get("dap_path"),
        help="Explicit lldb-dap path.",
    )
    p.add_argument(
        "--dap-port",
        type=int,
        default=lldb_cfg.get("dap_port", 0),
        help="DAP port (0 = auto).",
    )
    p.add_argument("--log-level", default="ERROR", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument(
        "--write-corpus",
        action=argparse.BooleanOptionalAction,
        default=director_cfg.get("write_corpus", True),
    )
    p.add_argument(
        "--write-dict",
        action=argparse.BooleanOptionalAction,
        default=director_cfg.get("write_dict", True),
    )
    p.add_argument("--dict-out", default=None, help="Dictionary output path (default corpora/<target>/llm.dict).")
    p.add_argument(
        "--trace-output",
        default=None,
        help="Optional JSONL trace output path for tool-call episodes (experimental).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return anyio.run(lambda: run_director(args))
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130  # Standard exit code for SIGINT


if __name__ == "__main__":
    raise SystemExit(main())
