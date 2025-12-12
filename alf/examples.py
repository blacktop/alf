"""
Helper module for locating example files.

Examples are stored at the repository root in the `examples/` directory.
They are NOT included in wheel distributions - only available when
installing from source (git clone).

Usage:
    from alf.examples import get_examples_dir, get_example_binary

    # Get paths to example files
    examples_dir = get_examples_dir()
    binary = get_example_binary("toy_bug")
    crash = get_example_crash("toy_bug", "crash_div0")
"""

from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    """Get the repository root directory."""
    # alf/examples.py -> alf/ -> repo root
    return Path(__file__).resolve().parents[1]


def get_examples_dir() -> Path:
    """Get the path to the examples directory.

    Returns:
        Path to the examples/ directory.

    Raises:
        RuntimeError: If examples directory is not found (e.g., installed from wheel).
    """
    examples = _repo_root() / "examples"

    if not examples.exists():
        raise RuntimeError(
            f"Examples directory not found at {examples}. "
            "Examples are only available when installing from source. "
            "Run: git clone https://github.com/blacktop/alf"
        )

    return examples


def get_example_binary(name: str) -> Path:
    """Get the path to a pre-built example binary.

    Args:
        name: Example name (e.g., "toy_bug", "libplist").

    Returns:
        Path to the compiled binary in examples/<name>/out/.

    Raises:
        RuntimeError: If examples directory is not found.
        FileNotFoundError: If the example or binary doesn't exist.
    """
    examples_dir = get_examples_dir()
    example_dir = examples_dir / name

    if not example_dir.exists():
        available = [d.name for d in examples_dir.iterdir() if d.is_dir()]
        raise FileNotFoundError(f"Example '{name}' not found. Available examples: {available}")

    # Look for binary in out/ directory
    out_dir = example_dir / "out"
    if not out_dir.exists():
        raise FileNotFoundError(f"No out/ directory found in {example_dir}")

    # Find the main binary (exclude .o files and .dSYM directories)
    binaries = [f for f in out_dir.iterdir() if f.is_file() and f.suffix not in (".o", ".dSYM")]

    if not binaries:
        raise FileNotFoundError(f"No binary found in {out_dir}")

    # Return the first (usually only) binary
    return binaries[0]


def get_example_crash(name: str, crash_name: str) -> Path:
    """Get the path to a crash input file.

    Args:
        name: Example name (e.g., "toy_bug").
        crash_name: Crash file name (e.g., "crash_div0").

    Returns:
        Path to the crash file.

    Raises:
        RuntimeError: If examples directory is not found.
        FileNotFoundError: If the crash file doesn't exist.
    """
    examples_dir = get_examples_dir()
    crash_file = examples_dir / name / "crashes" / crash_name

    if not crash_file.exists():
        crashes_dir = examples_dir / name / "crashes"
        if crashes_dir.exists():
            available = [f.name for f in crashes_dir.iterdir() if f.is_file()]
            raise FileNotFoundError(f"Crash '{crash_name}' not found in {name}. Available: {available}")
        raise FileNotFoundError(f"No crashes directory found for {name}")

    return crash_file


def get_example_corpus(name: str) -> Path:
    """Get the path to an example's corpus directory.

    Args:
        name: Example name (e.g., "toy_bug").

    Returns:
        Path to the corpus directory.

    Raises:
        RuntimeError: If examples directory is not found.
        FileNotFoundError: If the corpus directory doesn't exist.
    """
    examples_dir = get_examples_dir()
    corpus_dir = examples_dir / name / "corpus"

    if not corpus_dir.exists():
        raise FileNotFoundError(f"No corpus directory found for {name}")

    return corpus_dir


def list_examples() -> list[str]:
    """List available examples.

    Returns:
        List of example names.

    Raises:
        RuntimeError: If examples directory is not found.
    """
    examples_dir = get_examples_dir()
    return sorted([d.name for d in examples_dir.iterdir() if d.is_dir() and not d.name.startswith(".")])


def list_crashes(name: str) -> list[str]:
    """List available crash files for an example.

    Args:
        name: Example name.

    Returns:
        List of crash file names.
    """
    examples_dir = get_examples_dir()
    crashes_dir = examples_dir / name / "crashes"

    if not crashes_dir.exists():
        return []

    return sorted([f.name for f in crashes_dir.iterdir() if f.is_file()])
