"""Corpus generation command."""

from __future__ import annotations

import click

from .. import corpus as corpus_mod


@click.command()
@click.argument("binary")
@click.argument("crash")
@click.option("--output-dir", "-o", help="Output directory for seeds")
@click.option("--dict", "dict_path", help="Path for dictionary file")
@click.option("--llm", is_flag=True, help="Use LLM to suggest additional mutations")
@click.option("--model", default="gpt-4o-mini", help="LLM model name")
@click.option("--provider", help="LLM provider")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def corpus(
    binary: str,
    crash: str,
    output_dir: str | None,
    dict_path: str | None,
    llm: bool,
    model: str,
    provider: str | None,
    json_output: bool,
) -> None:
    """Generate corpus seeds and dictionary from a crash input."""
    import json

    result = corpus_mod.generate_corpus(
        binary=binary,
        crash=crash,
        output_dir=output_dir,
        dict_path=dict_path,
        use_llm=llm,
        model=model,
        provider=provider,
    )

    if "error" in result:
        click.echo(f"[-] {result['error']}", err=True)
        raise SystemExit(1)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"[+] Target: {result['target']}")
        click.echo(f"[+] Crash: {result['crash']} ({result['crash_hash']})")
        click.echo(f"[+] Corpus: {result['corpus_dir']} ({result['seeds_written']} seeds)")
        for name in result["seed_names"]:
            click.echo(f"    - {name}")
        click.echo(f"[+] Dictionary: {result['dict_path']} (+{result['dict_tokens_added']} tokens)")
