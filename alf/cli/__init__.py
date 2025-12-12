"""ALF Click CLI entry point."""

from __future__ import annotations

import click

from ..acp_cli import acp as acp_cmd
from .analyze import analyze
from .corpus import corpus
from .director import director
from .doctor import doctor
from .evolve import evolve
from .fuzz import fuzz
from .generate import generate
from .server import server


@click.group()
def cli() -> None:
    """ALF: Agentic LLDB Fuzzer."""


cli.add_command(acp_cmd)
cli.add_command(server)
cli.add_command(director)
cli.add_command(analyze)
cli.add_command(fuzz)
cli.add_command(generate)
cli.add_command(corpus)
cli.add_command(evolve)
cli.add_command(doctor)


def main() -> None:
    cli(prog_name="alf")


if __name__ == "__main__":
    main()
