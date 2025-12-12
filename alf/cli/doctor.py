"""Doctor command for environment checks."""

from __future__ import annotations

import click

from .. import doctor as doctor_mod


@click.command()
@click.option("--json", "json_out", is_flag=True, help="Output machine-readable JSON.")
def doctor(json_out: bool) -> None:
    """Run environment preflight checks (macOS debugging prerequisites)."""
    argv: list[str] = []
    if json_out:
        argv.append("--json")
    code = doctor_mod.main(argv)
    if code:
        raise SystemExit(code)
