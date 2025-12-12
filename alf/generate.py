#!/usr/bin/env python3
"""
LLM-guided input generation for fuzzing.

This module provides intelligent seed synthesis based on:
1. Binary analysis (symbols, strings, format detection)
2. Crash context (what triggered the crash)
3. Coverage feedback (which paths need more exploration)

Usage:
    from alf.generate import InputGenerator

    generator = InputGenerator(provider="anthropic")
    seeds = await generator.synthesize_from_binary("/path/to/binary")
    seeds = await generator.synthesize_from_crash(crash_data, crash_context)
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .providers.base import LLMProvider


@dataclass
class FormatSpec:
    """Inferred input format specification."""

    name: str
    magic: bytes | None = None
    description: str = ""
    fields: list[dict[str, Any]] = field(default_factory=list)
    examples: list[bytes] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)

    def to_prompt(self) -> str:
        """Convert to prompt-friendly description."""
        lines = [f"Format: {self.name}"]
        if self.magic:
            lines.append(f"Magic bytes: {self.magic.hex()} ({self.magic!r})")
        if self.description:
            lines.append(f"Description: {self.description}")
        if self.fields:
            lines.append("Fields:")
            for f in self.fields:
                lines.append(f"  - {f.get('name', '?')}: {f.get('type', '?')} @ offset {f.get('offset', '?')}")
        if self.constraints:
            lines.append("Constraints:")
            for c in self.constraints:
                lines.append(f"  - {c}")
        return "\n".join(lines)


@dataclass
class GeneratedSeed:
    """A generated seed with metadata."""

    name: str
    data: bytes
    rationale: str
    format_spec: str | None = None
    coverage_target: str | None = None


class InputGenerator:
    """LLM-guided input generator for fuzzing.

    Analyzes targets and generates intelligent seed inputs using:
    - Symbol analysis to detect expected formats
    - String extraction for magic bytes and keywords
    - Crash analysis for targeted mutations
    - Coverage feedback for path exploration
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
    ):
        self._provider_name = provider
        self._model = model
        self._provider: LLMProvider | None = None
        self._format_cache: dict[str, FormatSpec] = {}

    def _get_provider(self) -> LLMProvider:
        """Get or create the LLM provider."""
        if self._provider is None:
            from .providers import get_provider

            self._provider = get_provider(self._provider_name)
        return self._provider

    async def analyze_binary(self, binary: str | Path) -> FormatSpec:
        """Analyze a binary to infer its expected input format.

        Uses symbol names, strings, and heuristics to detect:
        - File format parsers (plist, JSON, XML, protobuf)
        - Network protocols (HTTP, TLS, custom)
        - Custom formats with magic bytes

        Args:
            binary: Path to the target binary.

        Returns:
            FormatSpec with inferred format details.
        """
        binary = Path(binary).resolve()
        cache_key = str(binary)

        if cache_key in self._format_cache:
            return self._format_cache[cache_key]

        # Extract symbols and strings
        symbols = self._extract_symbols(binary)
        strings = self._extract_strings(binary)

        # Use LLM to infer format
        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        prompt = f"""Analyze this binary and infer its expected input format.

## Symbols (sample)
{chr(10).join(symbols[:100])}

## Strings (sample)
{chr(10).join(s for s in strings[:100] if len(s) >= 4)}

## Task
Based on the symbols and strings, infer:
1. What format does this binary parse? (e.g., plist, JSON, custom protocol)
2. What magic bytes or headers does it expect?
3. What fields/structure does the input have?
4. What constraints exist (size limits, checksums, etc.)?

Respond with JSON:
{{
  "name": "format name",
  "magic": "hex bytes or null",
  "description": "brief description",
  "fields": [
    {{"name": "field_name", "type": "type", "offset": 0, "size": 4}}
  ],
  "constraints": ["constraint1", "constraint2"]
}}
"""

        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system",
                    content="You are a binary analysis expert. Infer input formats from symbols and strings.",
                ),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            json_output=True,
            temperature=0.2,
        )

        # Run blocking LLM call in thread pool to avoid blocking event loop
        response = await asyncio.to_thread(provider.chat, request)

        try:
            result = json.loads(response.content)
            spec = FormatSpec(
                name=result.get("name", "unknown"),
                magic=bytes.fromhex(result["magic"]) if result.get("magic") else None,
                description=result.get("description", ""),
                fields=result.get("fields", []),
                constraints=result.get("constraints", []),
            )
        except (json.JSONDecodeError, ValueError):
            # Fallback to heuristic detection
            spec = self._heuristic_format_detection(symbols, strings)

        self._format_cache[cache_key] = spec
        return spec

    def _extract_symbols(self, binary: Path) -> list[str]:
        """Extract symbol names from binary."""
        try:
            result = subprocess.run(
                ["nm", "-j", str(binary)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return [s.strip() for s in result.stdout.splitlines() if s.strip()]
        except Exception:
            pass
        return []

    def _extract_strings(self, binary: Path) -> list[str]:
        """Extract printable strings from binary."""
        try:
            result = subprocess.run(
                ["strings", "-n", "4", str(binary)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.splitlines()[:500]
        except Exception:
            pass
        return []

    def _heuristic_format_detection(self, symbols: list[str], strings: list[str]) -> FormatSpec:
        """Detect format using heuristics when LLM fails."""
        symbol_text = " ".join(symbols).lower()
        string_text = " ".join(strings).lower()

        # Check for known format indicators
        if "plist" in symbol_text or "bplist" in string_text:
            return FormatSpec(
                name="plist",
                magic=b"bplist",
                description="Apple Property List format",
                fields=[
                    {"name": "magic", "type": "bytes", "offset": 0, "size": 6},
                    {"name": "version", "type": "bytes", "offset": 6, "size": 2},
                ],
            )

        if "json" in symbol_text or "parse_json" in symbol_text:
            return FormatSpec(
                name="json",
                magic=b"{",
                description="JSON format",
                fields=[],
                constraints=["Must be valid JSON"],
            )

        if "xml" in symbol_text or "<?xml" in string_text:
            return FormatSpec(
                name="xml",
                magic=b"<?xml",
                description="XML format",
                fields=[],
            )

        if "protobuf" in symbol_text or "proto" in symbol_text:
            return FormatSpec(
                name="protobuf",
                description="Protocol Buffers format",
                fields=[],
            )

        # Generic binary format
        return FormatSpec(
            name="binary",
            description="Unknown binary format",
            fields=[],
        )

    async def synthesize_from_format(
        self,
        format_spec: FormatSpec,
        count: int = 10,
        variations: list[str] | None = None,
    ) -> list[GeneratedSeed]:
        """Generate seeds based on a format specification.

        Args:
            format_spec: The format specification to generate for.
            count: Number of seeds to generate.
            variations: Specific variations to target (e.g., ["boundary", "malformed"]).

        Returns:
            List of generated seeds.
        """
        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        variations_text = ""
        if variations:
            variations_text = f"\nFocus on these variations: {', '.join(variations)}"

        prompt = f"""Generate {count} test inputs for fuzzing based on this format:

{format_spec.to_prompt()}
{variations_text}

Generate diverse inputs that might trigger bugs:
- Valid inputs that exercise edge cases
- Slightly malformed inputs (off-by-one, truncated)
- Boundary values (0, 1, max, overflow)
- Deeply nested or recursive structures
- Empty/null fields

Respond with JSON:
{{
  "seeds": [
    {{
      "name": "descriptive_name",
      "hex": "hexadecimal bytes",
      "rationale": "why this might find bugs"
    }}
  ]
}}
"""

        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system",
                    content="You are a fuzzing expert. Generate test inputs that might trigger vulnerabilities.",
                ),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            json_output=True,
            temperature=0.7,  # Higher temp for diversity
        )

        # Run blocking LLM call in thread pool to avoid blocking event loop
        response = await asyncio.to_thread(provider.chat, request)

        seeds: list[GeneratedSeed] = []
        try:
            result = json.loads(response.content)
            for item in result.get("seeds", []):
                if isinstance(item, dict):
                    name = str(item.get("name", f"gen_{len(seeds)}"))
                    hex_str = str(item.get("hex", "")).replace(" ", "")
                    rationale = str(item.get("rationale", ""))
                    try:
                        data = bytes.fromhex(hex_str)
                        seeds.append(
                            GeneratedSeed(
                                name=name,
                                data=data,
                                rationale=rationale,
                                format_spec=format_spec.name,
                            )
                        )
                    except ValueError:
                        continue
        except json.JSONDecodeError:
            pass

        return seeds[:count]

    async def synthesize_from_binary(
        self,
        binary: str | Path,
        count: int = 10,
    ) -> list[GeneratedSeed]:
        """Analyze binary and generate seeds.

        Convenience method that combines analyze_binary + synthesize_from_format.

        Args:
            binary: Path to target binary.
            count: Number of seeds to generate.

        Returns:
            List of generated seeds.
        """
        format_spec = await self.analyze_binary(binary)
        return await self.synthesize_from_format(format_spec, count=count)

    async def synthesize_from_crash(
        self,
        crash_data: bytes,
        crash_context: dict[str, Any],
        count: int = 5,
    ) -> list[GeneratedSeed]:
        """Generate targeted seeds based on crash analysis.

        Args:
            crash_data: Raw bytes of the crash input.
            crash_context: Crash context (backtrace, registers, etc.).
            count: Number of seeds to generate.

        Returns:
            List of targeted seeds.
        """
        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        # Build crash summary
        crash_hex = crash_data[:256].hex()
        ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in crash_data[:128])

        # Extract key info
        backtrace = crash_context.get("backtrace", [])[:5]
        crash_reason = crash_context.get("stop_reason", {}).get("description", "unknown")
        registers = crash_context.get("registers", {})
        key_regs = {k: v for k, v in registers.items() if k in ("x0", "x1", "x2", "pc", "lr")}

        prompt = f"""Analyze this crash and generate {count} targeted mutations.

## Crash Input
- Size: {len(crash_data)} bytes
- Hex (first 256): {crash_hex}
- ASCII: {ascii_preview}

## Crash Context
- Reason: {crash_reason}
- Registers: {json.dumps(key_regs, indent=2)}
- Backtrace (top 5): {json.dumps(backtrace, indent=2)}

## Task
Generate mutations that:
1. Might trigger the same crash more reliably
2. Might trigger similar crashes in nearby code
3. Explore boundary conditions around the crash point

Respond with JSON:
{{
  "analysis": "Brief analysis of the crash",
  "seeds": [
    {{
      "name": "descriptive_name",
      "hex": "hexadecimal bytes",
      "rationale": "why this targets the crash"
    }}
  ]
}}
"""

        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system", content="You are a crash analysis expert. Generate targeted fuzzing inputs."
                ),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            json_output=True,
            temperature=0.3,
        )

        # Run blocking LLM call in thread pool to avoid blocking event loop
        response = await asyncio.to_thread(provider.chat, request)

        seeds: list[GeneratedSeed] = []
        try:
            result = json.loads(response.content)
            for item in result.get("seeds", []):
                if isinstance(item, dict):
                    name = str(item.get("name", f"crash_{len(seeds)}"))
                    hex_str = str(item.get("hex", "")).replace(" ", "")
                    rationale = str(item.get("rationale", ""))
                    try:
                        data = bytes.fromhex(hex_str)
                        seeds.append(
                            GeneratedSeed(
                                name=name,
                                data=data,
                                rationale=rationale,
                                coverage_target="crash_vicinity",
                            )
                        )
                    except ValueError:
                        continue
        except json.JSONDecodeError:
            pass

        return seeds[:count]

    async def synthesize_for_coverage(
        self,
        uncovered_functions: list[str],
        existing_seeds: list[bytes],
        format_spec: FormatSpec | None = None,
        count: int = 5,
    ) -> list[GeneratedSeed]:
        """Generate seeds targeting uncovered code paths.

        Args:
            uncovered_functions: List of function names not yet covered.
            existing_seeds: Existing corpus seeds for reference.
            format_spec: Optional format specification.
            count: Number of seeds to generate.

        Returns:
            List of coverage-targeting seeds.
        """
        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        # Summarize existing seeds
        seed_summary = []
        for i, seed in enumerate(existing_seeds[:10]):
            hex_preview = seed[:32].hex()
            seed_summary.append(f"  seed_{i}: {hex_preview}... ({len(seed)} bytes)")

        format_text = format_spec.to_prompt() if format_spec else "Unknown format"

        prompt = f"""Generate {count} inputs to cover these uncovered functions:

## Uncovered Functions
{chr(10).join(f"- {fn}" for fn in uncovered_functions[:20])}

## Format
{format_text}

## Existing Seeds (for reference)
{chr(10).join(seed_summary)}

## Task
Generate inputs that might reach the uncovered functions.
Look at function names for hints:
- "parse_X" suggests X-type data
- "handle_error" suggests invalid inputs
- "validate_Y" suggests boundary testing for Y

Respond with JSON:
{{
  "seeds": [
    {{
      "name": "descriptive_name",
      "hex": "hexadecimal bytes",
      "rationale": "which function this targets and why",
      "target_function": "function_name"
    }}
  ]
}}
"""

        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system", content="You are a code coverage expert. Generate inputs to reach uncovered code."
                ),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            json_output=True,
            temperature=0.5,
        )

        # Run blocking LLM call in thread pool to avoid blocking event loop
        response = await asyncio.to_thread(provider.chat, request)

        seeds: list[GeneratedSeed] = []
        try:
            result = json.loads(response.content)
            for item in result.get("seeds", []):
                if isinstance(item, dict):
                    name = str(item.get("name", f"cov_{len(seeds)}"))
                    hex_str = str(item.get("hex", "")).replace(" ", "")
                    rationale = str(item.get("rationale", ""))
                    target = str(item.get("target_function", ""))
                    try:
                        data = bytes.fromhex(hex_str)
                        seeds.append(
                            GeneratedSeed(
                                name=name,
                                data=data,
                                rationale=rationale,
                                coverage_target=target,
                            )
                        )
                    except ValueError:
                        continue
        except json.JSONDecodeError:
            pass

        return seeds[:count]


def write_seeds(output_dir: Path, seeds: list[GeneratedSeed]) -> list[Path]:
    """Write generated seeds to disk.

    Args:
        output_dir: Directory to write seeds to.
        seeds: List of generated seeds.

    Returns:
        List of written file paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for i, seed in enumerate(seeds):
        path = output_dir / f"seed-{i:03d}_{seed.name}"
        path.write_bytes(seed.data)

        # Write metadata
        meta_path = output_dir / f"seed-{i:03d}_{seed.name}.meta"
        meta = {
            "name": seed.name,
            "rationale": seed.rationale,
            "format": seed.format_spec,
            "coverage_target": seed.coverage_target,
            "size": len(seed.data),
        }
        meta_path.write_text(json.dumps(meta, indent=2))

        written.append(path)

    return written


async def main(argv: list[str] | None = None) -> int:
    """CLI for LLM-guided input generation."""
    import argparse

    parser = argparse.ArgumentParser(description="LLM-guided input generation for fuzzing")
    parser.add_argument("binary", help="Path to target binary")
    parser.add_argument("-o", "--output", default=None, help="Output directory for seeds")
    parser.add_argument("-n", "--count", type=int, default=10, help="Number of seeds to generate")
    parser.add_argument("--provider", default=None, help="LLM provider")
    parser.add_argument("--model", default=None, help="LLM model")
    parser.add_argument("--crash", default=None, help="Crash input file for targeted generation")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.exists():
        print(f"[-] Binary not found: {binary}", file=sys.stderr)
        return 1

    generator = InputGenerator(provider=args.provider, model=args.model)

    # Analyze and generate
    print(f"[*] Analyzing {binary.name}...", file=sys.stderr)
    format_spec = await generator.analyze_binary(binary)
    print(f"[+] Detected format: {format_spec.name}", file=sys.stderr)

    if args.crash:
        crash_path = Path(args.crash)
        crash_data = crash_path.read_bytes()
        print(f"[*] Generating seeds from crash: {crash_path.name}...", file=sys.stderr)
        seeds = await generator.synthesize_from_crash(crash_data, {}, count=args.count)
    else:
        print(f"[*] Generating {args.count} seeds...", file=sys.stderr)
        seeds = await generator.synthesize_from_format(format_spec, count=args.count)

    if not seeds:
        print("[-] No seeds generated", file=sys.stderr)
        return 1

    # Output
    if args.output:
        output_dir = Path(args.output)
        written = write_seeds(output_dir, seeds)
        print(f"[+] Wrote {len(written)} seeds to {output_dir}", file=sys.stderr)
        for path in written:
            print(f"    {path.name}", file=sys.stderr)
    elif args.json:
        output = {
            "format": {
                "name": format_spec.name,
                "description": format_spec.description,
            },
            "seeds": [
                {
                    "name": s.name,
                    "hex": s.data.hex(),
                    "rationale": s.rationale,
                    "size": len(s.data),
                }
                for s in seeds
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n[+] Generated {len(seeds)} seeds:")
        for seed in seeds:
            print(f"  {seed.name}: {seed.data[:32].hex()}... ({len(seed.data)} bytes)")
            print(f"    Rationale: {seed.rationale}")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
