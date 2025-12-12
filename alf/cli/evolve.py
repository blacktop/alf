"""Evolve commands for harness evolution and vulnerability healing."""

from __future__ import annotations

from pathlib import Path

import click

from .. import evolve as evolve_mod


@click.group()
def evolve() -> None:
    """Harness evolution and vulnerability healing commands."""


@evolve.command(name="analyze")
@click.argument("harness")
@click.option("--header", help="Target header file for API discovery")
@click.option("--binary", help="Target binary/library for symbol extraction")
@click.option("--provider", help="LLM provider")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def evolve_analyze(
    harness: str,
    header: str | None,
    binary: str | None,
    provider: str | None,
    json_output: bool,
) -> None:
    """Analyze a harness for improvement opportunities."""
    import asyncio
    import json

    async def run_analyze() -> int:
        evolver = evolve_mod.HarnessEvolver(provider=provider)
        analysis = await evolver.analyze_harness(harness, target_header=header, target_binary=binary)

        if json_output:
            click.echo(
                json.dumps(
                    {
                        "harness_path": analysis.harness_path,
                        "target_apis": analysis.target_apis[:20],
                        "missing_apis": analysis.missing_apis[:20],
                        "suggestions": [
                            {"category": s.category, "description": s.description, "priority": s.priority}
                            for s in analysis.suggestions
                        ],
                        "coverage_score": analysis.coverage_score,
                        "issues": analysis.issues,
                    },
                    indent=2,
                )
            )
        else:
            click.echo(f"Harness: {analysis.harness_path}")
            click.echo(f"Coverage Score: {analysis.coverage_score:.0%}")
            click.echo(
                f"\nAPIs Called: {len(analysis.target_apis) - len(analysis.missing_apis)}/{len(analysis.target_apis)}"
            )
            if analysis.missing_apis:
                click.echo(f"Missing APIs: {', '.join(analysis.missing_apis[:10])}")
            click.echo(f"\nSuggestions ({len(analysis.suggestions)}):")
            for s in analysis.suggestions:
                click.echo(f"  [{s.priority}] {s.category}: {s.description}")
            if analysis.issues:
                click.echo(f"\nIssues: {', '.join(analysis.issues)}")

        return 0

    code = asyncio.run(run_analyze())
    if code:
        raise SystemExit(code)


@evolve.command(name="improve")
@click.argument("harness")
@click.option("--output", "-o", help="Output file (default: stdout)")
@click.option("--header", help="Target header file")
@click.option("--focus", multiple=True, help="Categories to focus on (missing_api, error_handling, coverage, safety)")
@click.option("--provider", help="LLM provider")
@click.option("--verify", is_flag=True, help="Verify compilation")
def evolve_improve(
    harness: str,
    output: str | None,
    header: str | None,
    focus: tuple[str, ...],
    provider: str | None,
    verify: bool,
) -> None:
    """Generate an improved harness based on analysis."""
    import asyncio
    import tempfile

    async def run_evolve() -> int:
        evolver = evolve_mod.HarnessEvolver(provider=provider)

        click.echo(f"[*] Analyzing {harness}...", err=True)
        analysis = await evolver.analyze_harness(harness, target_header=header)

        click.echo("[*] Evolving harness...", err=True)
        evolved = await evolver.evolve_harness(harness, analysis, focus=list(focus) if focus else None)

        if verify:
            with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
                success, error = evolver.verify_harness(evolved, f.name)
                if success:
                    click.echo("[+] Harness compiles successfully", err=True)
                else:
                    click.echo(f"[-] Compilation failed: {error}", err=True)
                    return 1

        if output:
            Path(output).write_text(evolved)
            click.echo(f"[+] Written to {output}", err=True)
        else:
            click.echo(evolved)

        return 0

    code = asyncio.run(run_evolve())
    if code:
        raise SystemExit(code)


@evolve.command(name="heal")
@click.argument("source")
@click.option("--crash", help="Crash context JSON file")
@click.option("--output", "-o", help="Output patched file")
@click.option("--provider", help="LLM provider")
@click.option("--diff", "show_diff", is_flag=True, help="Show diff only")
def evolve_heal(
    source: str,
    crash: str | None,
    output: str | None,
    provider: str | None,
    show_diff: bool,
) -> None:
    """Generate a patch for a vulnerability."""
    import asyncio
    import json

    async def run_heal() -> int:
        healer = evolve_mod.VulnerabilityHealer(provider=provider)

        crash_context = {}
        if crash:
            crash_context = json.loads(Path(crash).read_text())

        click.echo("[*] Analyzing vulnerability...", err=True)
        analysis = await healer.analyze_vulnerability(crash_context, source)
        click.echo(f"[+] Type: {analysis.get('vulnerability_type', 'unknown')}", err=True)

        click.echo("[*] Generating patch...", err=True)
        patch = await healer.generate_patch(crash_context, source, analysis)

        if not patch:
            click.echo("[-] Could not generate patch", err=True)
            return 1

        click.echo(f"[+] Confidence: {patch.confidence:.0%}", err=True)

        if show_diff:
            click.echo(healer.generate_diff(patch))
        elif output:
            success, result = healer.apply_patch(patch, output)
            if success:
                click.echo(f"[+] Patched file written to {output}", err=True)
            else:
                click.echo(f"[-] Failed to apply patch: {result}", err=True)
                return 1
        else:
            click.echo("\n## Patch Suggestion")
            click.echo(f"Vulnerability: {patch.vulnerability_type}")
            click.echo(f"Confidence: {patch.confidence:.0%}")
            click.echo("\n### Original Code:")
            click.echo(patch.original_code)
            click.echo("\n### Patched Code:")
            click.echo(patch.patched_code)
            click.echo("\n### Explanation:")
            click.echo(patch.explanation)

        return 0

    code = asyncio.run(run_heal())
    if code:
        raise SystemExit(code)
