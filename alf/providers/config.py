"""Provider configuration and auto-detection.

Configuration precedence (highest to lowest):
1. Explicit `provider_name` argument
2. `.alf.toml` in current/parent directory
3. `~/.config/alf/config.toml`
4. Environment variables (ALF_LLM_PROVIDER, etc.)
5. Auto-detection (API keys, local server probing)
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import LLMProvider

# Default ports for local LLM servers
LOCAL_SERVER_PORTS = {
    11434: ("ollama", "http://127.0.0.1:11434/v1"),
    1234: ("lmstudio", "http://127.0.0.1:1234/v1"),
    8000: ("vllm", "http://127.0.0.1:8000/v1"),  # vLLM default
    8080: ("localai", "http://127.0.0.1:8080/v1"),  # LocalAI default
}


def _get_toml_config(provider_name: str | None = None) -> dict:
    """Get provider config from TOML files."""
    try:
        from ..config import get_provider_config

        return get_provider_config(provider_name)
    except Exception:
        return {}


def detect_local_server(timeout: float = 0.3) -> tuple[str, str] | None:
    """Detect which local LLM server is running by probing common ports.

    Args:
        timeout: Connection timeout in seconds.

    Returns:
        Tuple of (server_name, base_url) if a server is found, None otherwise.

    Checks ports in priority order:
    - 11434: Ollama (most common)
    - 1234: LM Studio
    - 8000: vLLM
    - 8080: LocalAI
    """
    for port, (name, base_url) in LOCAL_SERVER_PORTS.items():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
            s.close()
            return (name, base_url)
        except OSError:
            continue
    return None


@dataclass
class ProviderConfig:
    """Configuration for a specific provider."""

    name: str
    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None
    timeout: float = 180.0
    jit_ttl: int | None = None  # LM Studio JIT loading TTL in seconds


def detect_provider() -> str:
    """Auto-detect which LLM provider to use based on configuration.

    Detection priority:
    1. TOML config file (`.alf.toml` or `~/.config/alf/config.toml`)
    2. ALF_LLM_PROVIDER env var (explicit override)
    3. ANTHROPIC_API_KEY → "anthropic"
    4. OPENAI_API_KEY → "openai"
    5. GOOGLE_API_KEY or GEMINI_API_KEY → "google"
    6. ALF_LLM_BASE_URL → "ollama" (OpenAI-compatible local server)
    7. Auto-detect local server by probing ports (Ollama:11434, LM Studio:1234, etc.)
    8. Default → "ollama" (assumes local server at http://127.0.0.1:11434/v1)
    """
    # 1. Check TOML config first
    toml_config = _get_toml_config()
    if toml_config.get("name"):
        return toml_config["name"]

    # 2. Explicit env var override
    explicit = os.environ.get("ALF_LLM_PROVIDER", "").strip().lower()
    if explicit:
        return explicit

    # 3-5. Check for API keys in priority order
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"

    if os.environ.get("OPENAI_API_KEY"):
        return "openai"

    if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        return "google"

    # 6. If a custom base URL is set, assume OpenAI-compatible (ollama)
    if os.environ.get("ALF_LLM_BASE_URL"):
        return "ollama"

    # 7. Auto-detect local server by probing ports
    local = detect_local_server()
    if local:
        return local[0]  # Return server name (ollama, lmstudio, vllm, localai)

    # 8. Default to ollama (local server)
    return "ollama"


def get_config(provider_name: str | None = None) -> ProviderConfig:
    """Get configuration for the specified or auto-detected provider.

    Configuration precedence (highest to lowest):
    1. Explicit `provider_name` argument
    2. TOML config file (`.alf.toml` or `~/.config/alf/config.toml`)
    3. Environment variables

    Args:
        provider_name: Provider name, or None to auto-detect.

    Returns:
        ProviderConfig with merged settings.
    """
    # Get TOML config
    toml_config = _get_toml_config(provider_name)

    # Determine provider name
    name = provider_name or toml_config.get("name") or detect_provider()

    # Get values from TOML (may be None)
    toml_model = toml_config.get("model")
    toml_base_url = toml_config.get("base_url")
    toml_api_key = toml_config.get("api_key")
    toml_timeout = toml_config.get("timeout")
    toml_jit_ttl = toml_config.get("jit_ttl")

    # Common settings with fallback chain: TOML > env > default
    timeout = float(toml_timeout or os.environ.get("ALF_LLM_TIMEOUT", "180.0"))
    model = toml_model or os.environ.get("ALF_LLM_MODEL") or os.environ.get("LLDB_MCP_MODEL")

    # JIT TTL for LM Studio (TOML > env)
    jit_ttl_str = os.environ.get("ALF_LLM_JIT_TTL")
    jit_ttl = toml_jit_ttl if toml_jit_ttl is not None else (int(jit_ttl_str) if jit_ttl_str else None)

    if name == "anthropic":
        return ProviderConfig(
            name="anthropic",
            api_key=toml_api_key or os.environ.get("ANTHROPIC_API_KEY"),
            model=model or "claude-sonnet-4-5-20250929",
            timeout=timeout,
        )

    if name == "openai":
        return ProviderConfig(
            name="openai",
            api_key=toml_api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("ALF_LLM_API_KEY"),
            base_url=toml_base_url or os.environ.get("OPENAI_BASE_URL") or os.environ.get("ALF_LLM_BASE_URL"),
            model=model or "gpt-4o-mini",
            timeout=timeout,
        )

    if name == "google":
        return ProviderConfig(
            name="google",
            api_key=toml_api_key or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"),
            model=model or "gemini-2.5-flash",
            timeout=timeout,
        )

    # Local servers (OpenAI-compatible): ollama, lmstudio, vllm, localai
    # All use the same OllamaProvider but with different default URLs/models
    base_url = toml_base_url or os.environ.get("ALF_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL")

    # Set default base_url and model based on detected/specified server
    if name == "lmstudio":
        default_url = "http://127.0.0.1:1234/v1"
        default_model = "local-model"  # LM Studio uses generic names
    elif name == "vllm":
        default_url = "http://127.0.0.1:8000/v1"
        default_model = "default"  # vLLM model name depends on what's loaded
    elif name == "localai":
        default_url = "http://127.0.0.1:8080/v1"
        default_model = "default"
    else:
        # Default: ollama
        default_url = "http://127.0.0.1:11434/v1"
        default_model = "llama3.1:8b-instruct"

    return ProviderConfig(
        name="ollama",  # All local servers use OllamaProvider
        api_key=toml_api_key or os.environ.get("ALF_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"),
        base_url=base_url or default_url,
        model=model or default_model,
        timeout=timeout,
        jit_ttl=jit_ttl,
    )


def get_provider(name: str | None = None) -> LLMProvider:
    """Get an LLM provider instance.

    Args:
        name: Provider name, or None to auto-detect.

    Returns:
        Configured LLMProvider instance.

    Raises:
        ImportError: If required SDK is not installed.
        ValueError: If provider name is unknown.
    """
    from .factory import create_provider

    config = get_config(name)
    return create_provider(config)
