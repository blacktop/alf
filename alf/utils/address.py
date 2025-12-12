"""
Address parsing and PAC stripping utilities for ARM64(e).

Consolidates address handling from:
- alf/server/runtime/memory.py
- alf/triage/exploitability.py
- alf/backend/dap.py
- alf/backend/sbapi.py
"""

from __future__ import annotations

import os
import re

# PAC mask - configurable via environment for kernel/user space differences
# Default: 48-bit user-space mask (upper 16 bits stripped)
PAC_STRIP_MASK = int(os.environ.get("ALF_PAC_MASK", "0x0000ffffffffffff"), 16)


def strip_pac(address: int) -> int:
    """
    Strip PAC (Pointer Authentication Code) bits from an ARM64e address.

    On Apple Silicon, pointers can be signed with PAC bits in the upper bytes.
    This function removes those bits to get the canonical address.

    Args:
        address: An ARM64e pointer value, potentially PAC-signed.

    Returns:
        The canonical address with PAC bits stripped.

    Example:
        >>> strip_pac(0x8000000100001234)
        0x100001234
    """
    return address & PAC_STRIP_MASK


def parse_hex(value: str | int | None) -> int | None:
    """
    Parse a hex string or integer to int.

    Handles common hex formats and ignores invalid input.

    Args:
        value: A hex string (e.g., "0x1234"), integer, or None.

    Returns:
        The integer value, or None if parsing fails.

    Examples:
        >>> parse_hex("0x1234")
        4660
        >>> parse_hex(0x1234)
        4660
        >>> parse_hex("invalid")
        None
    """
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip().lower()
        if value.startswith("0x"):
            try:
                return int(value, 16)
            except ValueError:
                return None
    return None


def parse_address(text: str) -> int | None:
    """
    Extract and parse the first hex address from text.

    Searches for 0x-prefixed hex numbers in the input string.
    Useful for parsing LLDB output that embeds addresses in descriptive text.

    Args:
        text: Text that may contain a hex address.

    Returns:
        The first hex address found, or None if no valid address is found.

    Examples:
        >>> parse_address("pointer at 0x100001234")
        0x100001234
        >>> parse_address("no address here")
        None
    """
    if not text:
        return None
    m = re.search(r"0x[0-9a-fA-F]+", text)
    if not m:
        return None
    try:
        return int(m.group(0), 16)
    except ValueError:
        return None


# Alias for backwards compatibility
try_parse_address = parse_address

# Export the mask for modules that need it
__all__ = [
    "PAC_STRIP_MASK",
    "strip_pac",
    "parse_hex",
    "parse_address",
    "try_parse_address",
]
