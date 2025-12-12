"""
ALF Fuzzing Module - Autonomous AI-driven fuzzing via LLDB.

This module provides the infrastructure for LLM-driven fuzzing campaigns:
- Session management for LLDB/DAP connections
- Stop-hook installation for in-process mutation
- Autonomous fuzzing agent with coverage feedback
- Crash deduplication and corpus management

Usage:
    # CLI
    uv run alf fuzz /path/to/binary --mode auto --corpus /path/to/seeds

    # Programmatic
    from alf.fuzz import FuzzSession, FuzzAgent

    async with FuzzSession(binary="/path/to/bin") as session:
        agent = FuzzAgent(session, provider="anthropic")
        await agent.run(max_iterations=100)
"""

from .agent import FuzzAgent
from .hooks import HookManager
from .session import FuzzSession

__all__ = [
    "FuzzSession",
    "FuzzAgent",
    "HookManager",
]
