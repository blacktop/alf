"""Tests for alf.utils.stack_hash module."""

from __future__ import annotations

import pytest

from alf.utils.stack_hash import compute_fuzzy_hash, compute_stack_hash, stack_hash_from_frames


class TestComputeStackHash:
    """Tests for compute_stack_hash function."""

    def test_deterministic(self):
        """Same PCs should produce same hash."""
        pcs = ["0x100001000", "0x100002000", "0x100003000"]
        hash1 = compute_stack_hash(pcs)
        hash2 = compute_stack_hash(pcs)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex

    def test_different_pcs_different_hash(self):
        """Different PCs should produce different hash."""
        pcs1 = ["0x100001000", "0x100002000"]
        pcs2 = ["0x100001000", "0x100003000"]
        assert compute_stack_hash(pcs1) != compute_stack_hash(pcs2)

    def test_max_frames_limit(self):
        """Only first max_frames should be included."""
        pcs = [f"0x{i:08x}" for i in range(10)]
        hash_5 = compute_stack_hash(pcs, max_frames=5)
        hash_3 = compute_stack_hash(pcs, max_frames=3)
        assert hash_5 != hash_3

    def test_strips_pac_bits(self):
        """PAC-signed addresses should hash same as unsigned."""
        pcs_pac = ["0x8000000100001000"]
        pcs_normal = ["0x100001000"]
        assert compute_stack_hash(pcs_pac) == compute_stack_hash(pcs_normal)

    def test_empty_pcs_returns_empty(self):
        """Empty PC list should return empty string."""
        assert compute_stack_hash([]) == ""

    def test_invalid_pcs_skipped(self):
        """Invalid PCs should be skipped."""
        pcs = ["invalid", "0x100001000", "not_hex"]
        result = compute_stack_hash(pcs)
        # Should still produce a hash from the valid PC
        assert len(result) == 64

    def test_all_invalid_returns_empty(self):
        """All invalid PCs should return empty string."""
        pcs = ["invalid", "not_hex", "garbage"]
        assert compute_stack_hash(pcs) == ""


class TestComputeFuzzyHash:
    """Tests for compute_fuzzy_hash function."""

    def test_deterministic(self):
        """Same PCs should produce same fuzzy hash."""
        pcs = ["0x100001000", "0x100002000"]
        hash1 = compute_fuzzy_hash(pcs)
        hash2 = compute_fuzzy_hash(pcs)
        assert hash1 == hash2
        assert len(hash1) == 32  # MD5 hex

    def test_nearby_addresses_same_bucket(self):
        """Nearby addresses should hash to same bucket."""
        # These differ only in low bits, should bucket together
        pcs1 = ["0x100001234"]
        pcs2 = ["0x100001567"]
        assert compute_fuzzy_hash(pcs1, bucket_bits=20) == compute_fuzzy_hash(pcs2, bucket_bits=20)

    def test_distant_addresses_different_bucket(self):
        """Distant addresses should hash to different buckets."""
        pcs1 = ["0x100000000"]
        pcs2 = ["0x200000000"]
        assert compute_fuzzy_hash(pcs1) != compute_fuzzy_hash(pcs2)

    def test_empty_pcs_returns_empty(self):
        """Empty PC list should return empty string."""
        assert compute_fuzzy_hash([]) == ""


class TestStackHashFromFrames:
    """Tests for stack_hash_from_frames function."""

    def test_basic_frames(self):
        """Test with basic frame dictionaries."""
        frames = [
            {"instruction_pointer": "0x100001000"},
            {"instruction_pointer": "0x100002000"},
        ]
        hash_val, pcs = stack_hash_from_frames(frames)
        assert len(hash_val) == 64
        assert len(pcs) == 2
        assert pcs[0] == "0x100001000"

    def test_custom_pc_key(self):
        """Test with custom PC key."""
        frames = [
            {"pc": "0x100001000"},
            {"pc": "0x100002000"},
        ]
        hash_val, pcs = stack_hash_from_frames(frames, pc_key="pc")
        assert len(hash_val) == 64
        assert len(pcs) == 2

    def test_missing_pc_key_skipped(self):
        """Frames without PC key should be skipped."""
        frames = [
            {"instruction_pointer": "0x100001000"},
            {"name": "no_pc"},
            {"instruction_pointer": "0x100002000"},
        ]
        hash_val, pcs = stack_hash_from_frames(frames)
        assert len(pcs) == 2

    def test_empty_frames(self):
        """Empty frames should return empty hash and empty PCs."""
        hash_val, pcs = stack_hash_from_frames([])
        assert hash_val == ""
        assert pcs == []
