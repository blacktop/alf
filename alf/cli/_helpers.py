"""CLI helper functions."""

from __future__ import annotations

import re
from pathlib import Path


def repo_root() -> Path:
    """Get the repository root directory."""
    # alf/cli/_helpers.py -> alf/cli/ -> alf/ -> repo root
    return Path(__file__).resolve().parents[2]


def infer_target(binary_path: Path) -> str:
    """Infer a target name from the binary path."""
    parts = binary_path.parts
    if "harnesses" in parts:
        idx = parts.index("harnesses")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return binary_path.stem


def safe_slug(text: str) -> str:
    """Convert text to a safe filename slug."""
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", text.strip())
    slug = slug.strip("._-")
    return slug or "model"
