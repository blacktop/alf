#!/usr/bin/env python3
"""
LLM adapter CLI for ALF with multi-provider support.

This is used by `alf director` as an optional dependency. It implements the same
interface the director expects:

  alf-llm chat < payload.json > response.json

Configuration is via environment variables:
  - ALF_LLM_PROVIDER  (auto-detected from API keys if not set)
  - ANTHROPIC_API_KEY  (auto-selects anthropic provider)
  - OPENAI_API_KEY     (auto-selects openai provider)
  - ALF_LLM_BASE_URL  (for Ollama/LM Studio OpenAI-compat servers)
  - ALF_LLM_API_KEY   (fallback API key for local servers)

Provider auto-detection priority:
  1. ALF_LLM_PROVIDER env var (explicit)
  2. ANTHROPIC_API_KEY → anthropic (Claude)
  3. OPENAI_API_KEY → openai (GPT)
  4. ALF_LLM_BASE_URL → ollama (local OpenAI-compatible server)

For local models (Ollama / LM Studio) set:
  ALF_LLM_BASE_URL=http://127.0.0.1:11434/v1
  ALF_LLM_API_KEY=  # often unused locally
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


def _chat_with_providers(payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    """Send chat request using the providers package."""
    from alf.providers import ChatRequest, get_provider

    # Get provider (auto-detected from environment)
    provider = get_provider()

    # Convert payload to ChatRequest
    request = ChatRequest.from_openai_payload(payload)
    request.timeout = timeout

    # Make the request
    response = provider.chat(request)

    # Parse and return JSON object
    return response.to_json_object()


def chat_from_stdin(*, base_url: str, api_key: str | None, timeout: float) -> int:
    """Read chat payload from stdin, send to LLM, write JSON response to stdout."""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"invalid json input: {e}"}), file=sys.stderr)
        return 2

    try:
        # Use the providers package for multi-provider support
        obj = _chat_with_providers(payload, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1

    sys.stdout.write(json.dumps(obj))
    sys.stdout.write("\n")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="alf-llm",
        description="ALF LLM adapter with multi-provider support (Anthropic, OpenAI, Ollama).",
    )
    # Keep legacy args for backward compatibility (provider is auto-detected from env)
    p.add_argument(
        "--base-url",
        default=os.environ.get("ALF_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL"),
        help="[Legacy] Base URL for OpenAI-compatible servers. Use ALF_LLM_BASE_URL env var instead.",
    )
    p.add_argument(
        "--api-key",
        default=os.environ.get("ALF_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"),
        help="[Legacy] API key. Use provider-specific env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY).",
    )
    p.add_argument(
        "--provider",
        default=os.environ.get("ALF_LLM_PROVIDER"),
        choices=["anthropic", "openai", "google", "ollama"],
        help="LLM provider (auto-detected from API keys if not specified).",
    )
    p.add_argument("--timeout", type=float, default=180.0, help="HTTP timeout seconds.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("chat", help="Read chat payload JSON from stdin; write JSON object to stdout.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Set provider from CLI args if provided (for backward compat with scripts)
    if args.provider and not os.environ.get("ALF_LLM_PROVIDER"):
        os.environ["ALF_LLM_PROVIDER"] = args.provider
    if args.base_url and not os.environ.get("ALF_LLM_BASE_URL"):
        os.environ["ALF_LLM_BASE_URL"] = args.base_url
    if args.api_key and not os.environ.get("ALF_LLM_API_KEY"):
        os.environ["ALF_LLM_API_KEY"] = args.api_key

    if args.cmd == "chat":
        return chat_from_stdin(base_url=args.base_url, api_key=args.api_key, timeout=float(args.timeout))

    print(json.dumps({"error": f"unknown command: {args.cmd}"}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
