"""Tests for alf.utils.address module."""

from __future__ import annotations

import pytest

from alf.utils.address import parse_address, parse_hex, strip_pac


class TestParseHex:
    """Tests for parse_hex function."""

    @pytest.mark.parametrize(
        "input_val,expected",
        [
            ("0x1000", 0x1000),
            ("0X1000", 0x1000),
            ("0x0", 0),
            ("0xdeadbeef", 0xDEADBEEF),
            ("0xDEADBEEF", 0xDEADBEEF),
            (0x1000, 0x1000),
            (42, 42),
            (None, None),
            ("invalid", None),
            ("", None),
            ("  0x1000  ", 0x1000),  # Whitespace handling
        ],
    )
    def test_various_inputs(self, input_val, expected):
        assert parse_hex(input_val) == expected

    def test_large_address(self):
        """Test parsing a large 64-bit address."""
        assert parse_hex("0x8000000100001234") == 0x8000000100001234


class TestStripPac:
    """Tests for strip_pac function."""

    def test_strips_upper_bits(self):
        """PAC-signed pointer should have upper bits stripped."""
        pac_addr = 0x8000000100004000
        assert strip_pac(pac_addr) == 0x100004000

    def test_normal_address_unchanged(self):
        """Normal 48-bit address should be unchanged."""
        normal = 0x100004000
        assert strip_pac(normal) == normal

    def test_zero_address(self):
        """Zero address should remain zero."""
        assert strip_pac(0) == 0

    def test_max_48_bit(self):
        """Maximum 48-bit address should be unchanged."""
        max_48 = 0x0000FFFFFFFFFFFF
        assert strip_pac(max_48) == max_48

    def test_full_64_bit(self):
        """Full 64-bit address should be masked to 48 bits."""
        full_64 = 0xFFFFFFFFFFFFFFFF
        assert strip_pac(full_64) == 0x0000FFFFFFFFFFFF


class TestParseAddress:
    """Tests for parse_address function."""

    def test_simple_hex(self):
        """Parse simple hex address."""
        assert parse_address("0x100001234") == 0x100001234

    def test_embedded_address(self):
        """Extract address embedded in text."""
        assert parse_address("pointer at 0x100001234") == 0x100001234

    def test_multiple_addresses_returns_first(self):
        """Return first address when multiple present."""
        assert parse_address("from 0x1000 to 0x2000") == 0x1000

    def test_no_address(self):
        """Return None when no address found."""
        assert parse_address("no address here") is None

    def test_empty_string(self):
        """Return None for empty string."""
        assert parse_address("") is None

    def test_none_input(self):
        """Return None for None input."""
        assert parse_address(None) is None

    def test_lldb_output_format(self):
        """Parse address from LLDB-style output."""
        lldb_output = "  -> 0x0000000100004000: str x0, [x1]"
        assert parse_address(lldb_output) == 0x0000000100004000
