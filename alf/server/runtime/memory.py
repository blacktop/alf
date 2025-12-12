"""
Runtime memory helpers for arm64(e) processes, including PAC stripping.

This module re-exports from alf.utils.address for backwards compatibility.
New code should import directly from alf.utils.
"""

from __future__ import annotations

# Re-export from centralized utils for backwards compatibility
from alf.utils.address import (
    PAC_STRIP_MASK,
    strip_pac,
)
from alf.utils.address import (
    parse_address as try_parse_address,
)

__all__ = ["strip_pac", "try_parse_address", "PAC_STRIP_MASK"]
