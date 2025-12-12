"""
Crash file detection and matching utilities.

Consolidates crash file handling patterns from:
- alf/cli.py
- alf/fuzz/orchestrator.py
- alf/triage/dedupe.py

Supports common fuzzer output naming conventions:
- libFuzzer: crash-<hash>, timeout-<hash>, oom-<hash>, slow-unit-<hash>
- AFL: crashes/id:000000,*
"""

from __future__ import annotations

from pathlib import Path

# Common prefixes for fuzzer-generated crash files
CRASH_PREFIXES = (
    "crash-",
    "crash_",
    "timeout-",
    "timeout_",
    "oom-",
    "oom_",
    "slow-",
    "slow_",
)

# Extensions to exclude (metadata files, not crash inputs)
EXCLUDE_EXTENSIONS = (
    ".json",
    ".md",
    ".txt",
    ".log",
    ".dict",
    ".yaml",
    ".toml",
    ".dSYM",
)


def is_crash_file(path: Path) -> bool:
    """
    Check if a path looks like a crash file.

    Identifies files with fuzzer output naming patterns and excludes
    metadata files and hidden files.

    Args:
        path: Path to check.

    Returns:
        True if the path appears to be a crash input file.

    Examples:
        >>> is_crash_file(Path("crash-abc123"))
        True
        >>> is_crash_file(Path("crash-abc123.json"))
        False
        >>> is_crash_file(Path(".hidden"))
        False
    """
    if not path.is_file():
        return False

    name = path.name

    # Skip hidden files
    if name.startswith("."):
        return False

    # Skip metadata files
    if any(name.endswith(ext) for ext in EXCLUDE_EXTENSIONS):
        return False

    # Check for fuzzer prefixes
    return any(name.startswith(prefix) for prefix in CRASH_PREFIXES)


def find_crash_files(
    directory: Path,
    *,
    recursive: bool = False,
    include_all: bool = False,
) -> list[Path]:
    """
    Find crash files in a directory.

    Args:
        directory: Directory to search.
        recursive: If True, search subdirectories.
        include_all: If True, include all non-hidden files (not just crash-prefixed).

    Returns:
        Sorted list of crash file paths.

    Examples:
        >>> find_crash_files(Path("crashes/"))
        [PosixPath('crashes/crash-abc'), PosixPath('crashes/timeout-xyz')]
    """
    if not directory.is_dir():
        return []

    if recursive:
        files = directory.rglob("*")
    else:
        files = directory.iterdir()

    result: list[Path] = []
    for f in files:
        if not f.is_file():
            continue

        name = f.name

        # Skip hidden files
        if name.startswith("."):
            continue

        # Skip metadata files
        if any(name.endswith(ext) for ext in EXCLUDE_EXTENSIONS):
            continue

        if include_all or any(name.startswith(prefix) for prefix in CRASH_PREFIXES):
            result.append(f)

    return sorted(result)


def infer_crash_type(filename: str) -> str:
    """
    Infer crash type from filename prefix.

    Args:
        filename: Crash file name.

    Returns:
        One of: "crash", "timeout", "oom", "slow", or "unknown".

    Examples:
        >>> infer_crash_type("crash-abc123")
        'crash'
        >>> infer_crash_type("timeout-xyz")
        'timeout'
    """
    lower = filename.lower()
    if lower.startswith(("crash-", "crash_")):
        return "crash"
    elif lower.startswith(("timeout-", "timeout_")):
        return "timeout"
    elif lower.startswith(("oom-", "oom_")):
        return "oom"
    elif lower.startswith(("slow-", "slow_")):
        return "slow"
    return "unknown"


def strip_crash_prefix(filename: str) -> str:
    """
    Remove crash type prefix from filename.

    Useful for extracting hash/identifier from crash filenames.

    Args:
        filename: Crash file name.

    Returns:
        Filename with prefix removed.

    Examples:
        >>> strip_crash_prefix("crash-abc123")
        'abc123'
        >>> strip_crash_prefix("timeout-xyz")
        'xyz'
    """
    for prefix in CRASH_PREFIXES:
        if filename.startswith(prefix):
            return filename[len(prefix) :]
    return filename
