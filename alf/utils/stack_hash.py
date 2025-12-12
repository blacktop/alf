"""
Stack hash computation for crash deduplication.

Provides deterministic hashing of program counter (PC) addresses
for identifying unique crashes and grouping similar ones.

Based on techniques from:
- CASR (Crash Analysis and Severity Rating)
- libFuzzer's stack trace hashing
"""

from __future__ import annotations

import hashlib

from .address import parse_hex, strip_pac


def compute_stack_hash(pcs: list[str], max_frames: int = 5) -> str:
    """
    Compute a stable hash from program counter addresses.

    Strips PAC bits for consistent hashing across runs and normalizes
    addresses to produce deterministic results.

    Args:
        pcs: List of PC addresses as hex strings (e.g., ["0x100001000", "0x100002000"]).
        max_frames: Maximum number of frames to include in the hash.

    Returns:
        A 64-character SHA256 hex digest, or empty string if no valid PCs.

    Example:
        >>> compute_stack_hash(["0x100001000", "0x100002000"])
        'a1b2c3d4...'  # 64 char hex
    """
    normalized: list[str] = []
    for pc in pcs[:max_frames]:
        addr = parse_hex(pc)
        if addr is not None:
            normalized.append(f"0x{strip_pac(addr):x}")

    if not normalized:
        return ""

    return hashlib.sha256("|".join(normalized).encode()).hexdigest()


def compute_fuzzy_hash(pcs: list[str], max_frames: int = 5, bucket_bits: int = 20) -> str:
    """
    Compute a fuzzy hash that groups nearby crashes.

    Buckets addresses by zeroing low bits to reduce sensitivity to:
    - ASLR variations between runs
    - Minor differences in crash location

    Args:
        pcs: List of PC addresses as hex strings.
        max_frames: Maximum number of frames to include.
        bucket_bits: Number of low bits to zero out (higher = coarser grouping).

    Returns:
        A 32-character MD5 hex digest, or empty string if no valid PCs.

    Example:
        >>> compute_fuzzy_hash(["0x100001234", "0x100002567"])
        'abcd1234...'  # 32 char hex
    """
    bucket_mask = ~((1 << bucket_bits) - 1)  # Zero out low bits

    bucketed: list[str] = []
    for pc in pcs[:max_frames]:
        addr = parse_hex(pc)
        if addr is not None:
            stripped = strip_pac(addr)
            bucketed.append(f"0x{stripped & bucket_mask:x}")

    if not bucketed:
        return ""

    return hashlib.md5("|".join(bucketed).encode()).hexdigest()


def stack_hash_from_frames(
    frames: list[dict[str, str | int | None]],
    max_frames: int = 5,
    pc_key: str = "instruction_pointer",
) -> tuple[str, list[str]]:
    """
    Compute stack hash from frame dictionaries.

    Convenience function for backends that return structured frame data.

    Args:
        frames: List of frame dicts with PC addresses.
        max_frames: Maximum frames to hash.
        pc_key: Dictionary key for the PC address.

    Returns:
        Tuple of (hash, normalized_pcs).

    Example:
        >>> frames = [{"instruction_pointer": "0x100001000"}, {"instruction_pointer": "0x100002000"}]
        >>> hash_val, pcs = stack_hash_from_frames(frames)
    """
    pcs: list[str] = []
    for frame in frames[:max_frames]:
        pc = frame.get(pc_key)
        if pc is not None:
            addr = parse_hex(str(pc))
            if addr is not None:
                pcs.append(f"0x{strip_pac(addr):x}")

    hash_val = compute_stack_hash(pcs, max_frames=max_frames) if pcs else ""
    return hash_val, pcs
