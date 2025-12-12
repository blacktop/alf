"""
High-frequency telemetry via FIFO (named pipe).

Phase-1 implementation uses os.mkfifo to avoid per-iteration disk I/O.
Injected SBAPI hooks write newline-delimited JSON/text to the pipe in
non-blocking mode; the MCP server reads and buffers recent events.
"""

from __future__ import annotations

import json
import os
import selectors
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TelemetrySession:
    """A FIFO-backed telemetry channel for a single fuzzing run."""

    pipe_path: Path
    max_events: int = 1000
    _events: list[dict[str, Any]] = field(default_factory=list, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)

    @classmethod
    def create(cls, root: Path, name: str = "telemetry") -> TelemetrySession:
        logs_dir = root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        pipe_path = logs_dir / f"{name}_{ts}.fifo"
        try:
            os.mkfifo(pipe_path)
        except FileExistsError:
            pass
        return cls(pipe_path=pipe_path)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._reader_loop, name="alf-telemetry", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        try:
            self.pipe_path.unlink(missing_ok=True)
        except Exception:
            pass

    def snapshot(self, limit: int = 200) -> str:
        """Return a JSON snapshot of recent telemetry events."""
        events = self._events[-limit:] if limit and limit > 0 else list(self._events)
        return json.dumps({"pipe": str(self.pipe_path), "events": events}, indent=2)

    def rate(self, window_sec: float = 5.0) -> dict[str, Any]:
        """Compute simple events/sec over the last window."""
        now = time.time()
        window = max(0.1, float(window_sec))
        cutoff = now - window
        recent = [e for e in self._events if float(e.get("ts", 0)) >= cutoff]
        by_event: dict[str, int] = {}
        for e in recent:
            ev = str(e.get("event") or "unknown")
            by_event[ev] = by_event.get(ev, 0) + 1
        total = len(recent)
        return {
            "pipe": str(self.pipe_path),
            "window_sec": window,
            "total_events": total,
            "events_per_sec": total / window if window else 0.0,
            "by_event": by_event,
        }

    def _reader_loop(self) -> None:
        sel = selectors.DefaultSelector()
        fd: int | None = None
        try:
            # Open FIFO for reading in non-blocking mode.
            fd = os.open(self.pipe_path, os.O_RDONLY | os.O_NONBLOCK)
            sel.register(fd, selectors.EVENT_READ)
            buf = b""
            while not self._stop.is_set():
                events = sel.select(timeout=0.5)
                if not events:
                    continue
                for key, _ in events:
                    try:
                        chunk = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        continue
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._ingest_line(line)
        finally:
            try:
                if fd is not None:
                    sel.unregister(fd)
            except Exception:
                pass
            try:
                sel.close()
            except Exception:
                pass
            try:
                if fd is not None:
                    os.close(fd)
            except Exception:
                pass

    def _ingest_line(self, line: bytes) -> None:
        text = line.decode("utf-8", errors="ignore").strip()
        if not text:
            return
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                if "ts" not in obj:
                    obj["ts"] = time.time()
                self._events.append(obj)
            else:
                self._events.append({"text": text, "ts": time.time()})
        except json.JSONDecodeError:
            self._events.append({"text": text, "ts": time.time()})
        if self.max_events and len(self._events) > self.max_events:
            self._events = self._events[-self.max_events :]
