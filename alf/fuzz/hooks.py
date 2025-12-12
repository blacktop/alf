"""
Stop-hook management for in-process fuzzing.

Provides a high-level interface for installing mutation hooks and fork servers
via the LLDB MCP tools.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .session import FuzzSession


@dataclass
class HookConfig:
    """Configuration for a mutation hook."""

    ptr_reg: str = "x0"
    len_reg: str | None = None
    max_size: int = 4096
    telemetry_pipe: str | None = None


class HookManager:
    """Manages stop-hooks and fork servers for fuzzing.

    Usage:
        hooks = HookManager(session)
        await hooks.install_mutation_hook(symbol="parse_input", ptr_reg="x0")
        await hooks.install_fork_server(symbol="main")
    """

    def __init__(self, session: FuzzSession):
        self.session = session
        self._installed_hooks: list[dict[str, str]] = []
        self._fork_server_installed: bool = False
        self._hook_seq: int = 0

    def _next_callback_name(self, prefix: str, hint: str | None) -> str:
        """Return a unique, Python-identifier-safe callback name."""
        self._hook_seq += 1
        raw = (hint or "").strip()
        safe = re.sub(r"[^0-9a-zA-Z_]+", "_", raw)
        safe = re.sub(r"_+", "_", safe).strip("_")
        if not safe:
            safe = "hook"
        if safe[0].isdigit():
            safe = f"_{safe}"
        return f"{prefix}_{safe}_{self._hook_seq}"

    def _raise_on_error(self, result: str, *, action: str) -> None:
        text = (result or "").strip()
        if not text:
            raise RuntimeError(f"{action} failed: empty response")

        low = text.lower()
        if low.startswith("error:"):
            raise RuntimeError(f"{action} failed: {text}")

        if text.startswith("{"):
            try:
                import json

                obj = json.loads(text)
                if isinstance(obj, dict) and obj.get("error"):
                    raise RuntimeError(f"{action} failed: {obj.get('error')}")
            except Exception:
                pass

    @property
    def installed_hooks(self) -> list[dict[str, str]]:
        """List of installed hooks with their details."""
        return self._installed_hooks.copy()

    @property
    def has_fork_server(self) -> bool:
        """Whether a fork server is installed."""
        return self._fork_server_installed

    async def install_mutation_hook(
        self,
        symbol: str | None = None,
        address: str | None = None,
        config: HookConfig | None = None,
    ) -> str:
        """Install a mutation hook at a breakpoint.

        The hook will:
        1. Read a buffer pointer from the specified register
        2. Apply a random mutation from alf.mut.strategies
        3. Write the mutated buffer back
        4. Continue execution

        Args:
            symbol: Symbol name to break on (e.g., "parse_input").
            address: Address to break on (alternative to symbol).
            config: Hook configuration (defaults to x0 pointer, 4096 max size).

        Returns:
            Result message from the MCP server.
        """
        if not symbol and not address:
            raise ValueError("Must specify either symbol or address")

        config = config or HookConfig()

        name = self._next_callback_name("alf_stop_hook", symbol or address)
        hook_result = await self.session.install_stop_hook(
            function=symbol,
            address=address,
            ptr_reg=config.ptr_reg,
            len_reg=config.len_reg,
            max_size=config.max_size,
            name=name,
            telemetry_pipe=config.telemetry_pipe,
        )
        self._raise_on_error(hook_result, action="install_mutation_hook")

        self._installed_hooks.append(
            {
                "type": "mutation",
                "symbol": symbol or "",
                "address": address or "",
                "ptr_reg": config.ptr_reg,
                "callback": name,
                "hook_result": hook_result,
            }
        )

        return hook_result

    async def install_fork_server(
        self,
        symbol: str | None = None,
        address: str | None = None,
        telemetry_pipe: str | None = None,
    ) -> str:
        """Install a fork server at a breakpoint.

        The fork server avoids process restart overhead by forking at
        the entry point. The parent loops: fork -> waitpid -> repeat.
        The child continues execution normally.

        Args:
            symbol: Symbol name to install at (e.g., "main", "LLVMFuzzerTestOneInput").
            address: Address to install at (alternative to symbol).
            telemetry_pipe: Optional pipe path for execution telemetry.

        Returns:
            Result message from the MCP server.
        """
        name = self._next_callback_name("alf_fork_server", symbol or address)
        hook_result = await self.session.install_fork_server(
            function=symbol,
            address=address,
            name=name,
            telemetry_pipe=telemetry_pipe,
        )
        self._raise_on_error(hook_result, action="install_fork_server")

        self._fork_server_installed = True

        self._installed_hooks.append(
            {
                "type": "fork_server",
                "symbol": symbol or "",
                "address": address or "",
                "callback": name,
                "hook_result": hook_result,
            }
        )

        return hook_result

    async def clear_hooks(self) -> None:
        """Clear all installed hooks (requires session restart)."""
        # Hooks can't be removed easily in LLDB, would need to restart
        self._installed_hooks.clear()
        self._fork_server_installed = False
