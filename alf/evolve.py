#!/usr/bin/env python3
"""
Harness evolution and self-healing for fuzzing.

This module provides LLM-driven capabilities for:
1. Harness Evolution: Analyze and improve fuzzing harnesses
2. Self-Healing: Generate patches for discovered vulnerabilities

Usage:
    from alf.evolve import HarnessEvolver, VulnerabilityHealer

    # Evolve a harness
    evolver = HarnessEvolver(provider="anthropic")
    suggestions = await evolver.analyze_harness("harness.c", "target.h")
    new_harness = await evolver.evolve_harness("harness.c", suggestions)

    # Generate a patch for a vulnerability
    healer = VulnerabilityHealer(provider="anthropic")
    patch = await healer.generate_patch(crash_context, source_file)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .providers.base import LLMProvider


@dataclass
class HarnessSuggestion:
    """A suggestion for improving a harness."""

    category: str  # "missing_api", "error_handling", "coverage", "safety"
    description: str
    code_snippet: str | None = None
    priority: str = "medium"  # "high", "medium", "low"
    api_function: str | None = None


@dataclass
class HarnessAnalysis:
    """Analysis result for a fuzzing harness."""

    harness_path: str
    target_apis: list[str]  # APIs being called
    missing_apis: list[str]  # APIs not yet covered
    suggestions: list[HarnessSuggestion]
    coverage_score: float  # 0.0 - 1.0 estimated coverage
    issues: list[str]  # Potential issues found


@dataclass
class PatchSuggestion:
    """A suggested patch for a vulnerability."""

    vulnerability_type: str  # "buffer_overflow", "use_after_free", etc.
    file_path: str
    line_number: int | None
    original_code: str
    patched_code: str
    explanation: str
    confidence: float  # 0.0 - 1.0


class HarnessEvolver:
    """LLM-driven harness evolution.

    Analyzes fuzzing harnesses and suggests improvements:
    - Missing API coverage
    - Error handling gaps
    - Safety issues (memory leaks, uninitialized vars)
    - Code path coverage improvements
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
    ):
        self._provider_name = provider
        self._model = model
        self._provider: LLMProvider | None = None

    def _get_provider(self) -> LLMProvider:
        """Get or create the LLM provider."""
        if self._provider is None:
            from .providers import get_provider

            self._provider = get_provider(self._provider_name)
        return self._provider

    def extract_apis_from_header(self, header_path: str | Path) -> list[str]:
        """Extract function declarations from a header file."""
        header = Path(header_path)
        if not header.exists():
            return []

        content = header.read_text()

        # Match function declarations (simplified regex)
        # Handles: return_type function_name(args);
        pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*;"
        matches = re.findall(pattern, content)

        # Filter out common non-function patterns
        exclude = {"if", "while", "for", "switch", "sizeof", "typeof"}
        apis = [m for m in matches if m not in exclude]

        return list(set(apis))

    def extract_apis_from_binary(self, binary_path: str | Path) -> list[str]:
        """Extract exported function symbols from a binary/library."""
        binary = Path(binary_path)
        if not binary.exists():
            return []

        try:
            result = subprocess.run(
                ["nm", "-gU", str(binary)],  # -g: external only, -U: defined only
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return []

            apis = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T", "t"):  # Text section
                    symbol = parts[2]
                    # Remove leading underscore (common on macOS)
                    if symbol.startswith("_"):
                        symbol = symbol[1:]
                    apis.append(symbol)

            return apis
        except Exception:
            return []

    def extract_called_apis(self, harness_path: str | Path) -> list[str]:
        """Extract function calls from harness source."""
        harness = Path(harness_path)
        if not harness.exists():
            return []

        content = harness.read_text()

        # Match function calls (identifier followed by parenthesis)
        pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\("
        matches = re.findall(pattern, content)

        # Filter out control flow keywords
        exclude = {"if", "while", "for", "switch", "sizeof", "typeof", "return"}
        calls = [m for m in matches if m not in exclude]

        return list(set(calls))

    async def analyze_harness(
        self,
        harness_path: str | Path,
        target_header: str | Path | None = None,
        target_binary: str | Path | None = None,
    ) -> HarnessAnalysis:
        """Analyze a harness and identify improvement opportunities.

        Args:
            harness_path: Path to the harness source file.
            target_header: Optional header file for API discovery.
            target_binary: Optional binary/library for symbol extraction.

        Returns:
            HarnessAnalysis with suggestions.
        """
        harness = Path(harness_path)
        if not harness.exists():
            return HarnessAnalysis(
                harness_path=str(harness),
                target_apis=[],
                missing_apis=[],
                suggestions=[],
                coverage_score=0.0,
                issues=["Harness file not found"],
            )

        harness_content = harness.read_text()
        called_apis = self.extract_called_apis(harness)

        # Discover target APIs
        target_apis: list[str] = []
        if target_header:
            target_apis.extend(self.extract_apis_from_header(target_header))
        if target_binary:
            target_apis.extend(self.extract_apis_from_binary(target_binary))
        target_apis = list(set(target_apis))

        # Find missing APIs
        missing_apis = [api for api in target_apis if api not in called_apis]

        # Use LLM for deeper analysis
        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        prompt = f"""Analyze this fuzzing harness and suggest improvements.

## Harness Code
```c
{harness_content}
```

## Target APIs Available
{json.dumps(target_apis[:50], indent=2) if target_apis else "Not provided"}

## APIs Currently Called
{json.dumps(called_apis, indent=2)}

## APIs Not Yet Covered
{json.dumps(missing_apis[:20], indent=2) if missing_apis else "All discovered APIs covered"}

## Task
Analyze the harness and provide:
1. Missing API coverage suggestions (which uncovered APIs should be added?)
2. Error handling improvements (are return values checked?)
3. Safety issues (memory leaks, uninitialized variables, null checks)
4. Coverage improvements (additional code paths to exercise)

Respond with JSON:
{{
  "suggestions": [
    {{
      "category": "missing_api|error_handling|coverage|safety",
      "description": "What to improve",
      "code_snippet": "Example code or null",
      "priority": "high|medium|low",
      "api_function": "function name if applicable"
    }}
  ],
  "coverage_score": 0.0-1.0,
  "issues": ["list of issues found"]
}}
"""

        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system", content="You are a fuzzing expert. Analyze harnesses and suggest improvements."
                ),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            json_output=True,
            temperature=0.2,
        )

        response = provider.chat(request)

        suggestions: list[HarnessSuggestion] = []
        coverage_score = 0.5
        issues: list[str] = []

        try:
            result = json.loads(response.content)
            for item in result.get("suggestions", []):
                if isinstance(item, dict):
                    suggestions.append(
                        HarnessSuggestion(
                            category=item.get("category", "coverage"),
                            description=item.get("description", ""),
                            code_snippet=item.get("code_snippet"),
                            priority=item.get("priority", "medium"),
                            api_function=item.get("api_function"),
                        )
                    )
            coverage_score = float(result.get("coverage_score", 0.5))
            issues = result.get("issues", [])
        except (json.JSONDecodeError, ValueError):
            pass

        return HarnessAnalysis(
            harness_path=str(harness),
            target_apis=target_apis,
            missing_apis=missing_apis,
            suggestions=suggestions,
            coverage_score=coverage_score,
            issues=issues,
        )

    async def evolve_harness(
        self,
        harness_path: str | Path,
        analysis: HarnessAnalysis | None = None,
        focus: list[str] | None = None,  # Categories to focus on
    ) -> str:
        """Generate an evolved harness based on analysis.

        Args:
            harness_path: Path to the original harness.
            analysis: Previous analysis result (or will analyze first).
            focus: Categories to focus on ("missing_api", "error_handling", etc.)

        Returns:
            Evolved harness source code.
        """
        harness = Path(harness_path)
        if not harness.exists():
            raise FileNotFoundError(f"Harness not found: {harness}")

        harness_content = harness.read_text()

        if analysis is None:
            analysis = await self.analyze_harness(harness_path)

        # Filter suggestions by focus
        suggestions = analysis.suggestions
        if focus:
            suggestions = [s for s in suggestions if s.category in focus]

        if not suggestions:
            return harness_content  # No changes needed

        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        suggestions_text = "\n".join(
            f"- [{s.priority}] {s.category}: {s.description}"
            + (f"\n  Code: {s.code_snippet}" if s.code_snippet else "")
            for s in suggestions
        )

        prompt = f"""Evolve this fuzzing harness based on the suggestions.

## Original Harness
```c
{harness_content}
```

## Improvement Suggestions
{suggestions_text}

## Task
Generate an improved harness that incorporates the suggestions.
Maintain the same structure and LLVMFuzzerTestOneInput signature.
Add appropriate error handling and cleanup.
Include comments explaining the changes.

Respond with ONLY the complete C code, no markdown fences or explanations.
"""

        request = ChatRequest(
            messages=[
                ChatMessage(role="system", content="You are a C programmer expert in fuzzing harness development."),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            temperature=0.3,
        )

        response = provider.chat(request)

        # Clean up response (remove markdown if present)
        code = response.content.strip()
        if code.startswith("```"):
            lines = code.split("\n")
            code = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

        return code

    def verify_harness(
        self,
        harness_code: str,
        output_path: str | Path,
        compile_command: list[str] | None = None,
    ) -> tuple[bool, str]:
        """Verify that a harness compiles successfully.

        Args:
            harness_code: The harness source code.
            output_path: Where to write the harness file.
            compile_command: Custom compile command (default: clang).

        Returns:
            Tuple of (success, error_message).
        """
        output = Path(output_path)
        output.write_text(harness_code)

        if compile_command is None:
            compile_command = ["clang", "-fsyntax-only", "-Wall", "-Wextra", str(output)]

        try:
            result = subprocess.run(
                compile_command,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return True, ""
            return False, result.stderr
        except Exception as e:
            return False, str(e)


class VulnerabilityHealer:
    """LLM-driven vulnerability patching.

    Analyzes crash context and generates source patches to fix vulnerabilities.
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
    ):
        self._provider_name = provider
        self._model = model
        self._provider: LLMProvider | None = None

    def _get_provider(self) -> LLMProvider:
        """Get or create the LLM provider."""
        if self._provider is None:
            from .providers import get_provider

            self._provider = get_provider(self._provider_name)
        return self._provider

    async def analyze_vulnerability(
        self,
        crash_context: dict[str, Any],
        source_file: str | Path | None = None,
    ) -> dict[str, Any]:
        """Analyze a crash to understand the vulnerability.

        Args:
            crash_context: Crash context from lldb_crash_context.
            source_file: Optional source file for context.

        Returns:
            Analysis with vulnerability type, cause, and location.
        """
        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        source_content = ""
        if source_file:
            source = Path(source_file)
            if source.exists():
                source_content = f"\n## Source Code\n```c\n{source.read_text()}\n```"

        # Extract key info from crash context
        backtrace = crash_context.get("backtrace", [])[:10]
        registers = crash_context.get("registers", {})
        stop_reason = crash_context.get("stop_reason", {})
        disassembly = crash_context.get("disassembly", "")

        prompt = f"""Analyze this crash and identify the vulnerability type and root cause.

## Crash Information
- Stop Reason: {stop_reason}
- Backtrace:
{json.dumps(backtrace, indent=2)}

## Key Registers
{json.dumps({k: v for k, v in registers.items() if k in ("x0", "x1", "x2", "pc", "lr", "sp")}, indent=2)}

## Disassembly at Crash
{disassembly[:500] if disassembly else "Not available"}
{source_content}

## Task
Analyze the crash and identify:
1. Vulnerability type (buffer_overflow, use_after_free, null_deref, integer_overflow, format_string, etc.)
2. Root cause (what triggered the crash)
3. Affected code location (function, approximate line)
4. Exploitation potential (low, medium, high)

Respond with JSON:
{{
  "vulnerability_type": "type",
  "root_cause": "description",
  "location": {{"function": "name", "line": null or number}},
  "exploitation_potential": "low|medium|high",
  "details": "detailed explanation"
}}
"""

        request = ChatRequest(
            messages=[
                ChatMessage(role="system", content="You are a security researcher expert in vulnerability analysis."),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            json_output=True,
            temperature=0.2,
        )

        response = provider.chat(request)

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            return {
                "vulnerability_type": "unknown",
                "root_cause": "Analysis failed",
                "location": {},
                "exploitation_potential": "unknown",
                "details": response.content,
            }

    async def generate_patch(
        self,
        crash_context: dict[str, Any],
        source_file: str | Path,
        vuln_analysis: dict[str, Any] | None = None,
    ) -> PatchSuggestion | None:
        """Generate a patch suggestion for a vulnerability.

        Args:
            crash_context: Crash context from lldb_crash_context.
            source_file: Path to the vulnerable source file.
            vuln_analysis: Previous vulnerability analysis (or will analyze first).

        Returns:
            PatchSuggestion or None if patch cannot be generated.
        """
        source = Path(source_file)
        if not source.exists():
            return None

        source_content = source.read_text()

        if vuln_analysis is None:
            vuln_analysis = await self.analyze_vulnerability(crash_context, source_file)

        provider = self._get_provider()
        from .providers import ChatMessage, ChatRequest

        prompt = f"""Generate a patch to fix this vulnerability.

## Vulnerability Analysis
{json.dumps(vuln_analysis, indent=2)}

## Source Code
```c
{source_content}
```

## Task
Generate a minimal patch that fixes the vulnerability without breaking functionality.
The patch should:
1. Address the root cause, not just the symptom
2. Be as minimal as possible
3. Include appropriate bounds checking, null checks, or other safety measures
4. Maintain the original code's intent

Respond with JSON:
{{
  "original_code": "the vulnerable code section",
  "patched_code": "the fixed code section",
  "line_number": approximate line number or null,
  "explanation": "why this fix works",
  "confidence": 0.0-1.0
}}
"""

        request = ChatRequest(
            messages=[
                ChatMessage(
                    role="system", content="You are a security engineer expert in writing secure code patches."
                ),
                ChatMessage(role="user", content=prompt),
            ],
            model=self._model or "",
            json_output=True,
            temperature=0.2,
        )

        response = provider.chat(request)

        try:
            result = json.loads(response.content)
            return PatchSuggestion(
                vulnerability_type=vuln_analysis.get("vulnerability_type", "unknown"),
                file_path=str(source),
                line_number=result.get("line_number"),
                original_code=result.get("original_code", ""),
                patched_code=result.get("patched_code", ""),
                explanation=result.get("explanation", ""),
                confidence=float(result.get("confidence", 0.5)),
            )
        except (json.JSONDecodeError, ValueError):
            return None

    def apply_patch(
        self,
        patch: PatchSuggestion,
        output_path: str | Path | None = None,
    ) -> tuple[bool, str]:
        """Apply a patch to the source file.

        Args:
            patch: The patch to apply.
            output_path: Where to write patched file (default: overwrite original).

        Returns:
            Tuple of (success, patched_content or error_message).
        """
        source = Path(patch.file_path)
        if not source.exists():
            return False, f"Source file not found: {source}"

        content = source.read_text()

        if patch.original_code not in content:
            return False, "Original code not found in source file"

        patched = content.replace(patch.original_code, patch.patched_code, 1)

        output = Path(output_path) if output_path else source
        output.write_text(patched)

        return True, patched

    def generate_diff(self, patch: PatchSuggestion) -> str:
        """Generate a unified diff for the patch."""
        lines = []
        lines.append(f"--- a/{Path(patch.file_path).name}")
        lines.append(f"+++ b/{Path(patch.file_path).name}")

        if patch.line_number:
            lines.append(f"@@ -{patch.line_number},1 +{patch.line_number},1 @@")

        for line in patch.original_code.splitlines():
            lines.append(f"-{line}")
        for line in patch.patched_code.splitlines():
            lines.append(f"+{line}")

        return "\n".join(lines)


async def main(argv: list[str] | None = None) -> int:
    """CLI for harness evolution and self-healing."""
    import argparse

    parser = argparse.ArgumentParser(description="Harness evolution and vulnerability healing")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a harness")
    analyze_parser.add_argument("harness", help="Path to harness source file")
    analyze_parser.add_argument("--header", help="Target header file")
    analyze_parser.add_argument("--binary", help="Target binary/library")
    analyze_parser.add_argument("--provider", help="LLM provider")
    analyze_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # evolve command
    evolve_parser = subparsers.add_parser("evolve", help="Evolve a harness")
    evolve_parser.add_argument("harness", help="Path to harness source file")
    evolve_parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    evolve_parser.add_argument("--header", help="Target header file")
    evolve_parser.add_argument("--focus", nargs="+", help="Categories to focus on")
    evolve_parser.add_argument("--provider", help="LLM provider")
    evolve_parser.add_argument("--verify", action="store_true", help="Verify compilation")

    # heal command
    heal_parser = subparsers.add_parser("heal", help="Generate patch for vulnerability")
    heal_parser.add_argument("source", help="Vulnerable source file")
    heal_parser.add_argument("--crash", help="Crash context JSON file")
    heal_parser.add_argument("-o", "--output", help="Output patched file")
    heal_parser.add_argument("--provider", help="LLM provider")
    heal_parser.add_argument("--diff", action="store_true", help="Show diff only")

    args = parser.parse_args(argv)

    if args.command == "analyze":
        evolver = HarnessEvolver(provider=args.provider)
        analysis = await evolver.analyze_harness(
            args.harness,
            target_header=args.header,
            target_binary=args.binary,
        )

        if args.json:
            print(
                json.dumps(
                    {
                        "harness_path": analysis.harness_path,
                        "target_apis": analysis.target_apis[:20],
                        "missing_apis": analysis.missing_apis[:20],
                        "suggestions": [
                            {
                                "category": s.category,
                                "description": s.description,
                                "priority": s.priority,
                            }
                            for s in analysis.suggestions
                        ],
                        "coverage_score": analysis.coverage_score,
                        "issues": analysis.issues,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Harness: {analysis.harness_path}")
            print(f"Coverage Score: {analysis.coverage_score:.0%}")
            print(
                f"\nAPIs Called: {len(analysis.target_apis) - len(analysis.missing_apis)}/{len(analysis.target_apis)}"
            )
            if analysis.missing_apis:
                print(f"Missing APIs: {', '.join(analysis.missing_apis[:10])}")
            print(f"\nSuggestions ({len(analysis.suggestions)}):")
            for s in analysis.suggestions:
                print(f"  [{s.priority}] {s.category}: {s.description}")
            if analysis.issues:
                print(f"\nIssues: {', '.join(analysis.issues)}")

    elif args.command == "evolve":
        evolver = HarnessEvolver(provider=args.provider)

        print(f"[*] Analyzing {args.harness}...", file=sys.stderr)
        analysis = await evolver.analyze_harness(args.harness, target_header=args.header)

        print("[*] Evolving harness...", file=sys.stderr)
        evolved = await evolver.evolve_harness(args.harness, analysis, focus=args.focus)

        if args.verify:
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
                success, error = evolver.verify_harness(evolved, f.name)
                if success:
                    print("[+] Harness compiles successfully", file=sys.stderr)
                else:
                    print(f"[-] Compilation failed: {error}", file=sys.stderr)
                    return 1

        if args.output:
            Path(args.output).write_text(evolved)
            print(f"[+] Written to {args.output}", file=sys.stderr)
        else:
            print(evolved)

    elif args.command == "heal":
        healer = VulnerabilityHealer(provider=args.provider)

        crash_context = {}
        if args.crash:
            crash_context = json.loads(Path(args.crash).read_text())

        print("[*] Analyzing vulnerability...", file=sys.stderr)
        analysis = await healer.analyze_vulnerability(crash_context, args.source)
        print(f"[+] Type: {analysis.get('vulnerability_type', 'unknown')}", file=sys.stderr)

        print("[*] Generating patch...", file=sys.stderr)
        patch = await healer.generate_patch(crash_context, args.source, analysis)

        if not patch:
            print("[-] Could not generate patch", file=sys.stderr)
            return 1

        print(f"[+] Confidence: {patch.confidence:.0%}", file=sys.stderr)

        if args.diff:
            print(healer.generate_diff(patch))
        elif args.output:
            success, result = healer.apply_patch(patch, args.output)
            if success:
                print(f"[+] Patched file written to {args.output}", file=sys.stderr)
            else:
                print(f"[-] Failed to apply patch: {result}", file=sys.stderr)
                return 1
        else:
            print("\n## Patch Suggestion")
            print(f"Vulnerability: {patch.vulnerability_type}")
            print(f"Confidence: {patch.confidence:.0%}")
            print("\n### Original Code:")
            print(patch.original_code)
            print("\n### Patched Code:")
            print(patch.patched_code)
            print("\n### Explanation:")
            print(patch.explanation)

    return 0


if __name__ == "__main__":
    import asyncio

    raise SystemExit(asyncio.run(main()))
