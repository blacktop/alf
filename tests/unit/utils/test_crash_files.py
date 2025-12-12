"""Tests for alf.utils.crash_files module."""

from __future__ import annotations

from pathlib import Path

import pytest

from alf.utils.crash_files import (
    CRASH_PREFIXES,
    EXCLUDE_EXTENSIONS,
    find_crash_files,
    infer_crash_type,
    is_crash_file,
    strip_crash_prefix,
)


class TestIsCrashFile:
    """Tests for is_crash_file function."""

    def test_crash_prefix(self, tmp_path):
        """Files with crash- prefix should match."""
        crash_file = tmp_path / "crash-abc123"
        crash_file.touch()
        assert is_crash_file(crash_file) is True

    def test_timeout_prefix(self, tmp_path):
        """Files with timeout- prefix should match."""
        timeout_file = tmp_path / "timeout-xyz"
        timeout_file.touch()
        assert is_crash_file(timeout_file) is True

    def test_oom_prefix(self, tmp_path):
        """Files with oom- prefix should match."""
        oom_file = tmp_path / "oom-memory"
        oom_file.touch()
        assert is_crash_file(oom_file) is True

    def test_slow_prefix(self, tmp_path):
        """Files with slow- prefix should match."""
        slow_file = tmp_path / "slow-unit-test"
        slow_file.touch()
        assert is_crash_file(slow_file) is True

    def test_json_excluded(self, tmp_path):
        """JSON files should be excluded."""
        json_file = tmp_path / "crash-abc123.json"
        json_file.touch()
        assert is_crash_file(json_file) is False

    def test_hidden_excluded(self, tmp_path):
        """Hidden files should be excluded."""
        hidden_file = tmp_path / ".crash-abc123"
        hidden_file.touch()
        assert is_crash_file(hidden_file) is False

    def test_random_file_excluded(self, tmp_path):
        """Random files without crash prefix should be excluded."""
        random_file = tmp_path / "random_file"
        random_file.touch()
        assert is_crash_file(random_file) is False

    def test_directory_excluded(self, tmp_path):
        """Directories should be excluded."""
        crash_dir = tmp_path / "crash-dir"
        crash_dir.mkdir()
        assert is_crash_file(crash_dir) is False


class TestFindCrashFiles:
    """Tests for find_crash_files function."""

    def test_finds_crash_files(self, tmp_path):
        """Find all crash files in directory."""
        (tmp_path / "crash-1").touch()
        (tmp_path / "crash-2").touch()
        (tmp_path / "timeout-1").touch()
        (tmp_path / "normal_file").touch()

        files = find_crash_files(tmp_path)
        assert len(files) == 3
        assert all(f.name.startswith(("crash-", "timeout-")) for f in files)

    def test_sorted_output(self, tmp_path):
        """Results should be sorted."""
        (tmp_path / "crash-z").touch()
        (tmp_path / "crash-a").touch()
        (tmp_path / "crash-m").touch()

        files = find_crash_files(tmp_path)
        names = [f.name for f in files]
        assert names == sorted(names)

    def test_excludes_json(self, tmp_path):
        """JSON files should be excluded."""
        (tmp_path / "crash-1").touch()
        (tmp_path / "crash-1.json").touch()

        files = find_crash_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "crash-1"

    def test_include_all_mode(self, tmp_path):
        """include_all should include non-crash files."""
        (tmp_path / "crash-1").touch()
        (tmp_path / "seed-1").touch()
        (tmp_path / "test.json").touch()

        files = find_crash_files(tmp_path, include_all=True)
        # Should include crash-1 and seed-1, but not test.json
        assert len(files) == 2

    def test_empty_directory(self, tmp_path):
        """Empty directory should return empty list."""
        assert find_crash_files(tmp_path) == []

    def test_nonexistent_directory(self, tmp_path):
        """Nonexistent directory should return empty list."""
        assert find_crash_files(tmp_path / "nonexistent") == []


class TestInferCrashType:
    """Tests for infer_crash_type function."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("crash-abc123", "crash"),
            ("crash_abc123", "crash"),
            ("timeout-xyz", "timeout"),
            ("timeout_xyz", "timeout"),
            ("oom-memory", "oom"),
            ("oom_memory", "oom"),
            ("slow-unit-test", "slow"),
            ("slow_unit_test", "slow"),
            ("random_file", "unknown"),
            ("", "unknown"),
        ],
    )
    def test_type_inference(self, filename, expected):
        assert infer_crash_type(filename) == expected


class TestStripCrashPrefix:
    """Tests for strip_crash_prefix function."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("crash-abc123", "abc123"),
            ("crash_abc123", "abc123"),
            ("timeout-xyz", "xyz"),
            ("oom-memory", "memory"),
            ("slow-unit", "unit"),
            ("random_file", "random_file"),
        ],
    )
    def test_prefix_stripping(self, filename, expected):
        assert strip_crash_prefix(filename) == expected


class TestConstants:
    """Tests for module constants."""

    def test_crash_prefixes_tuple(self):
        """CRASH_PREFIXES should be a tuple of strings."""
        assert isinstance(CRASH_PREFIXES, tuple)
        assert all(isinstance(p, str) for p in CRASH_PREFIXES)
        assert "crash-" in CRASH_PREFIXES
        assert "timeout-" in CRASH_PREFIXES

    def test_exclude_extensions_tuple(self):
        """EXCLUDE_EXTENSIONS should be a tuple of strings."""
        assert isinstance(EXCLUDE_EXTENSIONS, tuple)
        assert all(isinstance(e, str) for e in EXCLUDE_EXTENSIONS)
        assert ".json" in EXCLUDE_EXTENSIONS
