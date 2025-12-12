"""Input generation command."""

from __future__ import annotations

from pathlib import Path

import click

from .. import generate as generate_mod


@click.command()
@click.argument("binary")
@click.option("--output", "-o", help="Output directory for seeds")
@click.option("--count", "-n", type=int, default=10, help="Number of seeds to generate")
@click.option("--crash", help="Crash input file for targeted generation")
@click.option("--provider", help="LLM provider")
@click.option("--model", help="LLM model")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def generate(
    binary: str,
    output: str | None,
    count: int,
    crash: str | None,
    provider: str | None,
    model: str | None,
    json_output: bool,
) -> None:
    """Generate fuzzing seeds using LLM-guided analysis."""
    import asyncio
    import json

    async def run_generate() -> int:
        binary_path = Path(binary).resolve()
        if not binary_path.exists():
            click.echo(f"[-] Binary not found: {binary_path}", err=True)
            return 1

        generator = generate_mod.InputGenerator(provider=provider, model=model)

        click.echo(f"[*] Analyzing {binary_path.name}...", err=True)
        format_spec = await generator.analyze_binary(binary_path)
        click.echo(f"[+] Detected format: {format_spec.name}", err=True)

        if crash:
            crash_path = Path(crash)
            crash_data = crash_path.read_bytes()
            click.echo(f"[*] Generating seeds from crash: {crash_path.name}...", err=True)
            seeds = await generator.synthesize_from_crash(crash_data, {}, count=count)
        else:
            click.echo(f"[*] Generating {count} seeds...", err=True)
            seeds = await generator.synthesize_from_format(format_spec, count=count)

        if not seeds:
            click.echo("[-] No seeds generated", err=True)
            return 1

        if output:
            output_dir = Path(output)
            written = generate_mod.write_seeds(output_dir, seeds)
            click.echo(f"[+] Wrote {len(written)} seeds to {output_dir}", err=True)
            for path in written:
                click.echo(f"    {path.name}", err=True)
        elif json_output:
            result = {
                "format": {"name": format_spec.name, "description": format_spec.description},
                "seeds": [
                    {"name": s.name, "hex": s.data.hex(), "rationale": s.rationale, "size": len(s.data)} for s in seeds
                ],
            }
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo(f"\n[+] Generated {len(seeds)} seeds:")
            for seed in seeds:
                click.echo(f"  {seed.name}: {seed.data[:32].hex()}... ({len(seed.data)} bytes)")
                click.echo(f"    Rationale: {seed.rationale}")

        return 0

    try:
        code = asyncio.run(run_generate())
    except KeyboardInterrupt:
        click.echo("\n[*] Generation interrupted", err=True)
        code = 130
    if code:
        raise SystemExit(code)
