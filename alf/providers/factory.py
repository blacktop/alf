"""Provider factory for creating LLM provider instances."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import LLMProvider
    from .config import ProviderConfig


def create_provider(config: ProviderConfig) -> LLMProvider:
    """Create an LLM provider instance from configuration.

    Args:
        config: Provider configuration with name and settings.

    Returns:
        Configured LLMProvider instance.

    Raises:
        ImportError: If required SDK is not installed for the provider.
        ValueError: If provider name is unknown.
    """
    name = config.name.lower()

    if name == "anthropic":
        from .anthropic import AnthropicProvider

        return AnthropicProvider(
            api_key=config.api_key,
            model=config.model or "claude-sonnet-4-5-20250929",
            timeout=config.timeout,
        )

    if name == "openai":
        from .openai import OpenAIProvider

        return OpenAIProvider(
            api_key=config.api_key,
            base_url=config.base_url,
            model=config.model or "gpt-4o-mini",
            timeout=config.timeout,
        )

    if name in ("ollama", "local", "lmstudio", "vllm", "localai"):
        from .ollama import OllamaProvider

        # Use config values (already resolved by get_config with correct defaults)
        return OllamaProvider(
            base_url=config.base_url or "http://127.0.0.1:11434/v1",
            api_key=config.api_key,
            model=config.model or "llama3.1:8b-instruct",
            timeout=config.timeout,
            jit_ttl=config.jit_ttl,
        )

    if name in ("google", "gemini"):
        from .google import GoogleProvider

        return GoogleProvider(
            api_key=config.api_key,
            model=config.model or "gemini-2.5-flash",
            timeout=config.timeout,
        )

    raise ValueError(
        f"Unknown provider: {name}. "
        f"Supported providers: anthropic, openai, google, gemini, ollama, lmstudio, vllm, localai"
    )


def list_providers() -> list[str]:
    """List available provider names."""
    return ["anthropic", "openai", "google", "gemini", "ollama", "lmstudio", "vllm", "localai"]
