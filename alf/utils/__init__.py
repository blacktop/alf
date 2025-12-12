"""
ALF shared utilities.

Common functionality extracted from various modules:
- address: PAC stripping, address parsing
- stack_hash: Stack hash computation
- crash_files: Crash file detection and matching
"""

from __future__ import annotations

from .address import parse_address, parse_hex, strip_pac
from .crash_files import (
    CRASH_PREFIXES,
    EXCLUDE_EXTENSIONS,
    find_crash_files,
    is_crash_file,
)
from .stack_hash import compute_fuzzy_hash, compute_stack_hash

__all__ = [
    # address
    "parse_hex",
    "parse_address",
    "strip_pac",
    # crash_files
    "CRASH_PREFIXES",
    "EXCLUDE_EXTENSIONS",
    "is_crash_file",
    "find_crash_files",
    # stack_hash
    "compute_stack_hash",
    "compute_fuzzy_hash",
]
