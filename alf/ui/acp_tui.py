"""Textual-based TUI for ACP sessions (optional).

This module is only imported when the user passes `--ui tui` to `alf acp ...`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ..acp_events import ACPEvent


@dataclass(frozen=True)
class PermissionRequest:
    title: str
    kind: str | None
    detail: str | None


@dataclass(frozen=True)
class _PermissionEvent:
    request: PermissionRequest
    future: asyncio.Future[bool]


@dataclass(frozen=True)
class _StatusEvent:
    text: str


def _truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… (truncated)"


def _format_tool_line(event: ACPEvent) -> str:
    tool = event.tool or "tool"
    status = event.status or ""
    title = (event.title or "").strip()
    parts = [tool]
    if status:
        parts.append(f"[{status}]")
    if title:
        parts.append(title)
    return " ".join(parts)


class ACPUI:
    """A small wrapper around a Textual App for rendering ACP output."""

    def __init__(self) -> None:
        try:
            from textual import events
            from textual.app import App, ComposeResult
            from textual.containers import Horizontal, Vertical
            from textual.screen import ModalScreen
            from textual.widgets import Footer, Header, RichLog, Static
        except ImportError as e:  # noqa: PERF203
            raise RuntimeError("Textual not installed. Install with: uv sync --extra tui") from e

        self._queue: asyncio.Queue[ACPEvent | _PermissionEvent | _StatusEvent] = asyncio.Queue()

        class _PermissionScreen(ModalScreen[bool]):
            def __init__(self, req: PermissionRequest):
                super().__init__()
                self._req = req

            def compose(self) -> ComposeResult:  # type: ignore[name-defined]
                title = self._req.title
                kind = f"kind: {self._req.kind}\n" if self._req.kind else ""
                detail = (self._req.detail or "").strip()
                body = f"{kind}{detail}".strip() or "(no details)"
                yield Static(f"{title}\n\n{body}\n\nAllow? (y/n)", id="permission")  # type: ignore[name-defined]

            async def on_key(self, event: events.Key) -> None:  # noqa: N802 (Textual API)
                key = (event.key or "").lower()
                if key in {"y", "enter"}:
                    self.dismiss(True)
                elif key in {"n", "escape"}:
                    self.dismiss(False)

        class _ACPApp(App[None]):
            CSS = """
            #columns { height: 1fr; }
            #messages, #tools, #thoughts { height: 1fr; border: solid $panel; }
            #status { height: auto; padding: 0 1; }
            """

            BINDINGS = [("q", "quit", "Quit")]

            def __init__(self, ui_queue: asyncio.Queue[ACPEvent | _PermissionEvent | _StatusEvent]) -> None:
                super().__init__()
                self._ui_queue = ui_queue

            def compose(self) -> ComposeResult:  # type: ignore[name-defined]
                yield Header()
                with Horizontal(id="columns"):
                    with Vertical():
                        yield RichLog(id="messages", highlight=True, markup=False)
                        yield RichLog(id="tools", highlight=True, markup=False)
                    yield RichLog(id="thoughts", highlight=True, markup=False)
                yield Static("", id="status")
                yield Footer()

            def _messages(self) -> RichLog:  # type: ignore[name-defined]
                return self.query_one("#messages", RichLog)

            def _tools(self) -> RichLog:  # type: ignore[name-defined]
                return self.query_one("#tools", RichLog)

            def _thoughts(self) -> RichLog:  # type: ignore[name-defined]
                return self.query_one("#thoughts", RichLog)

            def _status(self) -> Static:  # type: ignore[name-defined]
                return self.query_one("#status", Static)

            async def on_mount(self) -> None:  # noqa: N802 (Textual API)
                self._status().update("Running…")
                self.run_worker(self._event_worker(), exclusive=True, group="events")

            async def _event_worker(self) -> None:
                while True:
                    item = await self._ui_queue.get()

                    if isinstance(item, ACPEvent):
                        if item.kind == "thought":
                            text = (item.text or "").strip()
                            if text:
                                self._thoughts().write(_truncate(text))
                        elif item.kind == "message":
                            text = (item.text or "").rstrip()
                            if text:
                                self._messages().write(text)
                        elif item.kind == "tool_call":
                            self._tools().write(_format_tool_line(item))
                        elif item.kind == "tool_call_update":
                            self._tools().write(_format_tool_line(item))
                            if item.text:
                                self._tools().write(_truncate(item.text.strip()))
                        else:
                            self._tools().write(str(item.payload))
                        continue

                    if isinstance(item, _StatusEvent):
                        self._status().update(item.text)
                        continue

                    if isinstance(item, _PermissionEvent):
                        dismiss_fut: asyncio.Future[bool] = asyncio.get_running_loop().create_future()

                        def _on_dismiss(value: bool | None, fut: asyncio.Future[bool] = dismiss_fut) -> None:
                            if not fut.done():
                                fut.set_result(bool(value))

                        self.push_screen(_PermissionScreen(item.request), _on_dismiss)
                        allowed = await dismiss_fut
                        if not item.future.done():
                            item.future.set_result(bool(allowed))
                        continue

        self._app: _ACPApp = _ACPApp(self._queue)

    def post_event(self, event: ACPEvent) -> None:
        self._queue.put_nowait(event)

    def post_status(self, text: str) -> None:
        self._queue.put_nowait(_StatusEvent(text=text))

    async def request_permission(self, request: PermissionRequest) -> bool:
        fut: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        self._queue.put_nowait(_PermissionEvent(request=request, future=fut))
        return await fut

    async def run(self) -> None:
        await self._app.run_async()

    def exit(self) -> None:
        self._app.exit()
