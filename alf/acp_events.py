"""Helpers for parsing ACP session updates.

ACP agents (Gemini CLI / Codex / Claude Code) stream a loosely-typed sequence of
"session_update" payloads. We normalize these into a small set of event types so
both the plain CLI and optional TUI can render them consistently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ACPEvent:
    kind: str
    text: str | None
    tool: str | None
    status: str | None
    title: str | None
    payload: dict[str, Any]


def normalize_update(update: Any) -> dict[str, Any]:
    if hasattr(update, "model_dump"):
        try:
            dumped = update.model_dump()
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            pass
    if isinstance(update, dict):
        return update
    return {"value": str(update)}


def _first_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text = value.get("text")
        if isinstance(text, str) and text:
            return text
        inner = value.get("content")
        if inner is not None:
            found = _first_text(inner)
            if found:
                return found
        contents = value.get("contents")
        if contents is not None:
            found = _first_text(contents)
            if found:
                return found
        return None
    if isinstance(value, list):
        for item in value:
            found = _first_text(item)
            if found:
                return found
    return None


def _tool_name_from_call_id(call_id: str | None) -> str | None:
    if not isinstance(call_id, str) or not call_id:
        return None
    return call_id.split("-", 1)[0] or None


def parse_event(update: Any) -> ACPEvent:
    payload = normalize_update(update)

    update_type = payload.get("session_update") or payload.get("sessionUpdate")
    if isinstance(update_type, str):
        update_type = update_type.strip().lower()
    else:
        update_type = None

    if update_type in {"agent_thought_chunk", "agentthoughtchunk"}:
        return ACPEvent(
            kind="thought",
            text=_first_text(payload.get("content")),
            tool=None,
            status=None,
            title=None,
            payload=payload,
        )

    if update_type in {"agent_message_chunk", "agentmessagechunk"}:
        return ACPEvent(
            kind="message",
            text=_first_text(payload.get("content")),
            tool=None,
            status=None,
            title=None,
            payload=payload,
        )

    if update_type in {"tool_call", "toolcall"}:
        call_id = payload.get("tool_call_id") or payload.get("toolCallId")
        return ACPEvent(
            kind="tool_call",
            text=None,
            tool=_tool_name_from_call_id(call_id if isinstance(call_id, str) else None),
            status=payload.get("status") if isinstance(payload.get("status"), str) else None,
            title=payload.get("title") if isinstance(payload.get("title"), str) else None,
            payload=payload,
        )

    if update_type in {"tool_call_update", "toolcallupdate"}:
        call_id = payload.get("tool_call_id") or payload.get("toolCallId")
        return ACPEvent(
            kind="tool_call_update",
            text=_first_text(payload.get("content")),
            tool=_tool_name_from_call_id(call_id if isinstance(call_id, str) else None),
            status=payload.get("status") if isinstance(payload.get("status"), str) else None,
            title=payload.get("title") if isinstance(payload.get("title"), str) else None,
            payload=payload,
        )

    return ACPEvent(kind="raw", text=None, tool=None, status=None, title=None, payload=payload)
