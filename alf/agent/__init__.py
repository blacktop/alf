"""Agentic (LLM-driven) clients that talk to the ALF MCP server."""

from .director import main as director_main

__all__ = ["director_main"]
