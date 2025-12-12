"""
Coverage feedback manager using llvm-cov.

This module provides tools to collect and analyze code coverage from binaries
instrumented with clang's source-based coverage.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CoveredFunction:
    """Statistics for a covered function."""

    name: str
    regions: int
    regions_covered: int
    lines: int
    lines_covered: int
    filename: str

    @property
    def percent(self) -> float:
        """Return percentage of regions covered."""
        return (self.regions_covered / self.regions * 100) if self.regions > 0 else 0.0


class CoverageManager:
    """Manages coverage collection and analysis."""

    def __init__(self, check_tools: bool = True):
        self._profdata_bin = "xcrun"
        self._llvm_cov_bin = "xcrun"
        if check_tools:
            self._check_tools()

    def _check_tools(self) -> None:
        """Verify availability of coverage tools."""
        try:
            subprocess.run(
                [self._profdata_bin, "llvm-profdata", "--version"],
                capture_output=True,
                check=True,
                timeout=5,
            )
            subprocess.run(
                [self._llvm_cov_bin, "llvm-cov", "--version"],
                capture_output=True,
                check=True,
                timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            print(
                "[Coverage] Warning: llvm-profdata or llvm-cov not found. Coverage feedback disabled.",
                file=sys.stderr,
            )

    async def merge_profiles(self, profiles: list[Path], output: Path) -> bool:
        """Merge multiple raw profiles into an indexed profile."""
        if not profiles:
            return False

        args = [
            self._profdata_bin,
            "llvm-profdata",
            "merge",
            "-sparse",
            "-o",
            str(output),
        ] + [str(p) for p in profiles]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                print(f"[Coverage] Merge failed: {stderr.decode()}", file=sys.stderr)
                return False
            return True
        except Exception as e:
            print(f"[Coverage] Merge error: {e}", file=sys.stderr)
            return False

    async def export_coverage(
        self, binary: Path, profdata: Path, objects: list[Path] | None = None
    ) -> dict[str, Any] | None:
        """Export coverage data to JSON summary."""
        args = [
            self._llvm_cov_bin,
            "llvm-cov",
            "export",
            "-format=text",  # We'll parse the summary text JSON
            str(binary),
            f"-instr-profile={profdata}",
            "-skip-expansions",  # optimization
            "-skip-functions",  # optimization
        ]

        # Add object files (dylibs) if provided
        if objects:
            for obj in objects:
                args.extend(["-object", str(obj)])

        try:
            # Use strict timeout as export can be slow on large binaries
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                limit=10 * 1024 * 1024,  # Increase buffer limit
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode != 0:
                # Common error: profile mismatch or no data
                return None

            try:
                return json.loads(stdout.decode())
            except json.JSONDecodeError:
                return None

        except asyncio.TimeoutError:
            print("[Coverage] Export timed out", file=sys.stderr)
            return None
        except Exception as e:
            print(f"[Coverage] Export error: {e}", file=sys.stderr)
            return None

    async def get_uncovered_functions(self, binary: Path, profdata: Path) -> list[CoveredFunction]:
        """Identify functions with low coverage."""
        # Note: 'export' gives a massive JSON.
        # Ideally we use 'show' or 'report' for lighter parsing, but export gives structure.
        # Let's try 'report' with -json first if available (llvm-cov >= 13).
        # Fallback to export.

        data = await self.export_coverage(binary, profdata)
        if not data:
            return []

        uncovered = []

        # Traverse JSON structure
        # Structure: data['data'][0]['functions'] -> list of dicts
        try:
            for datum in data.get("data", []):
                for func in datum.get("functions", []):
                    name = func.get("name")
                    regions = func.get("regions", 0)
                    regions_cov = func.get("regions_covered", 0)
                    lines = func.get("lines", 0)
                    lines_cov = func.get("lines_covered", 0)
                    filenames = func.get("filenames", [])
                    filename = filenames[0] if filenames else "?"

                    # Analyze: if regions > 0 and regions_covered == 0, it's totally uncovered.
                    # If regions_covered / regions < 0.5, it's partially covered.

                    if regions > 0 and regions_covered == 0:
                        uncovered.append(
                            CoveredFunction(
                                name=name,
                                regions=regions,
                                regions_covered=regions_cov,
                                lines=lines,
                                lines_covered=lines_cov,
                                filename=filename,
                            )
                        )
        except Exception:
            pass

        return uncovered
