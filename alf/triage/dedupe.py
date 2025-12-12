#!/usr/bin/env python3
"""
Crash deduplication and clustering for triage.

Enhances basic stack-hash deduplication with:
- CWE-aware clustering (heap-UAF vs stack-overflow)
- Memory region grouping
- Fuzzy hash comparison for similar crashes

Inspired by CASR's clustering approach but implemented natively
for ALF's DAP-based workflow.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from alf.utils.address import parse_hex
from alf.utils.address import strip_pac as strip_pac_bits

from .exploitability import analyze_crash_reason


@dataclass
class CrashEntry:
    """Represents a single crash for deduplication."""

    crash_path: Path | str
    stack_hash: str
    pcs: list[str] = field(default_factory=list)
    reason: str = ""
    crash_type: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    timestamp: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def cluster_key(self) -> str:
        """
        Generate a cluster key that groups similar crashes.

        Combines crash type + memory region + top 3 PCs for grouping.
        """
        # Use crash type as primary grouping
        type_part = self.crash_type or "unknown"

        # Compute memory region from first PC
        region = "unknown"
        if self.pcs:
            first_pc = parse_hex(self.pcs[0])
            if first_pc is not None:
                stripped = strip_pac_bits(first_pc)
                # Bucket into coarse regions
                if stripped < 0x10000:
                    region = "null"
                elif 0x100000000 <= stripped < 0x200000000:
                    region = "heap"
                elif 0x16F000000000 <= stripped <= 0x170000000000:
                    region = "stack"
                else:
                    # Use high bits as region identifier
                    region = f"0x{(stripped >> 32):08x}"

        # Use top 3 PCs for finer grouping
        pc_part = "|".join(self.pcs[:3]) if self.pcs else ""
        pc_hash = hashlib.md5(pc_part.encode()).hexdigest()[:8]

        return f"{type_part}:{region}:{pc_hash}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "crash_path": str(self.crash_path),
            "stack_hash": self.stack_hash,
            "pcs": self.pcs,
            "reason": self.reason,
            "crash_type": self.crash_type,
            "cwe_ids": self.cwe_ids,
            "timestamp": self.timestamp,
            "cluster_key": self.cluster_key,
            **self.metadata,
        }


@dataclass
class CrashCluster:
    """A group of similar crashes."""

    cluster_id: str
    crash_type: str
    cwe_ids: list[str]
    entries: list[CrashEntry] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def representative(self) -> CrashEntry | None:
        """Return the first (or most interesting) crash in the cluster."""
        return self.entries[0] if self.entries else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "crash_type": self.crash_type,
            "cwe_ids": self.cwe_ids,
            "count": self.count,
            "entries": [e.to_dict() for e in self.entries],
        }


class CrashDeduplicator:
    """
    Manages crash deduplication and clustering.

    Supports two levels of deduplication:
    1. Exact: Same stack_hash -> identical crash
    2. Cluster: Same cluster_key -> similar crash
    """

    def __init__(self):
        self._seen_hashes: set[str] = set()
        self._clusters: dict[str, CrashCluster] = {}
        self._entries: list[CrashEntry] = []

    def add_crash(
        self,
        crash_path: Path | str,
        stack_hash: str,
        pcs: list[str] | None = None,
        reason: str = "",
        timestamp: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, CrashEntry]:
        """
        Add a crash to the deduplicator.

        Returns:
            (is_new, entry) - is_new is True if this is a unique crash
        """
        # Analyze crash type
        crash_type, cwe_ids = analyze_crash_reason(reason)

        entry = CrashEntry(
            crash_path=crash_path,
            stack_hash=stack_hash,
            pcs=pcs or [],
            reason=reason,
            crash_type=crash_type,
            cwe_ids=cwe_ids,
            timestamp=timestamp,
            metadata=metadata or {},
        )

        # Check exact duplicate
        is_new = stack_hash not in self._seen_hashes
        if stack_hash:
            self._seen_hashes.add(stack_hash)

        self._entries.append(entry)

        # Add to cluster
        cluster_key = entry.cluster_key
        if cluster_key not in self._clusters:
            self._clusters[cluster_key] = CrashCluster(
                cluster_id=cluster_key,
                crash_type=crash_type,
                cwe_ids=cwe_ids,
            )
        self._clusters[cluster_key].entries.append(entry)

        return is_new, entry

    def is_duplicate(self, stack_hash: str) -> bool:
        """Check if this stack hash has been seen."""
        return stack_hash in self._seen_hashes

    def get_cluster(self, cluster_key: str) -> CrashCluster | None:
        """Get cluster by key."""
        return self._clusters.get(cluster_key)

    def get_clusters(self) -> list[CrashCluster]:
        """Get all clusters, sorted by count (descending)."""
        return sorted(self._clusters.values(), key=lambda c: c.count, reverse=True)

    def get_unique_crashes(self) -> list[CrashEntry]:
        """
        Get one representative crash per cluster.

        Useful for reducing LLM analysis workload.
        """
        return [c.representative for c in self.get_clusters() if c.representative]

    @property
    def total_count(self) -> int:
        """Total number of crashes added."""
        return len(self._entries)

    @property
    def unique_count(self) -> int:
        """Number of unique stack hashes."""
        return len(self._seen_hashes)

    @property
    def cluster_count(self) -> int:
        """Number of distinct clusters."""
        return len(self._clusters)

    def stats(self) -> dict[str, Any]:
        """Return deduplication statistics."""
        clusters = self.get_clusters()
        type_counts: dict[str, int] = defaultdict(int)
        for cluster in clusters:
            type_counts[cluster.crash_type] += cluster.count

        return {
            "total_crashes": self.total_count,
            "unique_hashes": self.unique_count,
            "clusters": self.cluster_count,
            "duplicates_skipped": self.total_count - self.unique_count,
            "by_type": dict(type_counts),
        }

    def summary(self) -> str:
        """Generate human-readable summary."""
        stats = self.stats()
        lines = [
            f"Crashes: {stats['total_crashes']} total, {stats['unique_hashes']} unique, {stats['clusters']} clusters",
            f"Duplicates skipped: {stats['duplicates_skipped']}",
        ]
        if stats["by_type"]:
            lines.append("By type:")
            for crash_type, count in sorted(stats["by_type"].items(), key=lambda x: -x[1]):
                lines.append(f"  - {crash_type}: {count}")
        return "\n".join(lines)


def compute_stack_hash(pcs: list[str], max_frames: int = 5) -> str:
    """
    Compute a stable hash from program counter addresses.

    Strips PAC bits for consistent hashing across runs.
    """
    normalized: list[str] = []
    for pc in pcs[:max_frames]:
        addr = parse_hex(pc)
        if addr is not None:
            normalized.append(f"0x{strip_pac_bits(addr):x}")

    if not normalized:
        return ""

    return hashlib.sha256("|".join(normalized).encode()).hexdigest()


def compute_fuzzy_hash(pcs: list[str], max_frames: int = 5, bucket_bits: int = 20) -> str:
    """
    Compute a fuzzy hash that groups nearby crashes.

    Buckets addresses to reduce sensitivity to ASLR variations.
    """
    bucket_mask = ~((1 << bucket_bits) - 1)  # Zero out low bits

    bucketed: list[str] = []
    for pc in pcs[:max_frames]:
        addr = parse_hex(pc)
        if addr is not None:
            stripped = strip_pac_bits(addr)
            bucketed.append(f"0x{stripped & bucket_mask:x}")

    if not bucketed:
        return ""

    return hashlib.md5("|".join(bucketed).encode()).hexdigest()


def dedupe_crash_files(
    crash_dir: Path,
    binary: Path | None = None,
) -> Iterator[tuple[Path, bool]]:
    """
    Iterate crash files in a directory, yielding (path, is_unique).

    Useful for batch processing crash directories.
    """
    deduper = CrashDeduplicator()

    for crash_file in sorted(crash_dir.iterdir()):
        if crash_file.is_file() and not crash_file.name.startswith("."):
            # For now, just use filename as pseudo-hash
            # In real usage, would need to run crash and get stack
            pseudo_hash = hashlib.sha256(crash_file.read_bytes()).hexdigest()
            is_new, _ = deduper.add_crash(
                crash_path=crash_file,
                stack_hash=pseudo_hash,
            )
            yield crash_file, is_new
