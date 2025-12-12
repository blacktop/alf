"""
Lightweight source-code lookup helpers for Phase 1 "Program Model".

This is intentionally simple (ripgrep-backed) so it works without building
ctags/SQLite indexes. Future phases can replace this with tree-sitter or a
CodeQuery DB.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _default_source_root() -> Path:
    env_root = os.environ.get("ALF_SOURCE_ROOT")
    if env_root:
        return Path(env_root).expanduser()
    return Path.cwd()


def static_lookup(
    symbol: str,
    source_root: str | None = None,
    max_results: int = 40,
    context_lines: int = 2,
) -> str:
    """
    Search for `symbol` in source tree and return structured matches.

    - Uses `rg` if available, otherwise a Python fallback.
    - Returns JSON list of {"file","line","snippet"}.
    """
    if not symbol or not str(symbol).strip():
        return json.dumps({"error": "symbol must be non-empty"}, indent=2)

    root = Path(source_root).expanduser() if source_root else _default_source_root()
    if not root.exists():
        return json.dumps({"error": f"source_root does not exist: {root}"}, indent=2)

    matches: list[dict[str, Any]] = []

    if shutil.which("rg"):
        try:
            cmd = ["rg", "-n", "--no-heading", "--color", "never", symbol, str(root)]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=20.0)
            if proc.returncode not in (0, 1):  # 1 = no matches
                return json.dumps({"error": proc.stderr.strip() or "rg failed"}, indent=2)
            for ln in proc.stdout.splitlines():
                # format: path:line:col:text OR path:line:text
                parts = ln.split(":", 3)
                if len(parts) < 3:
                    continue
                path_str, line_str = parts[0], parts[1]
                text = parts[-1]
                try:
                    line_no = int(line_str)
                except ValueError:
                    continue
                snippet = _context_snippet(Path(path_str), line_no, context_lines)
                matches.append({"file": path_str, "line": line_no, "snippet": snippet or text})
                if max_results and len(matches) >= max_results:
                    break
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "rg timed out"}, indent=2)
    else:
        # Slow fallback scan.
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                content = path.read_text(errors="ignore").splitlines()
            except Exception:
                continue
            for idx, text in enumerate(content, start=1):
                if symbol in text:
                    snippet = _context_snippet(path, idx, context_lines)
                    matches.append({"file": str(path), "line": idx, "snippet": snippet or text})
                    if max_results and len(matches) >= max_results:
                        break
            if max_results and len(matches) >= max_results:
                break

    if not matches:
        return "Not found"
    return json.dumps({"matches": matches, "root": str(root)}, indent=2)


def _context_snippet(path: Path, line_no: int, context_lines: int) -> str | None:
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return None
    idx = max(0, line_no - 1)
    start = max(0, idx - context_lines)
    end = min(len(lines), idx + context_lines + 1)
    out = []
    for i in range(start, end):
        prefix = ">" if i == idx else " "
        out.append(f"{prefix}{i + 1:6d}: {lines[i]}")
    return "\n".join(out)
