"""Lightweight JSONL tracing for tool-call episodes (experimental)."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def hash_tools(tools: list[dict[str, Any]] | None) -> str | None:
    """Compute a stable hash of tool schemas for trace correlation."""
    if tools is None:
        return None
    payload = json.dumps(tools, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


@dataclass
class TraceLogger:
    """Append-only JSONL trace writer."""

    path: Path
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_version: int = 1

    def log(self, event: dict[str, Any]) -> None:
        record = {
            "run_id": self.run_id,
            "ts": _utc_now(),
            **event,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
