"""Multi-LLM provider abstraction for ALF.

This package provides a unified interface for interacting with various
LLM providers (Anthropic Claude, OpenAI GPT, Google Gemini, Ollama/local models).

Quick Start:
    from alf.providers import get_provider, ChatRequest, ChatMessage

    # Auto-detect provider from environment (checks API keys and local servers)
    provider = get_provider()

    # Or explicitly specify
    provider = get_provider("anthropic")
    provider = get_provider("lmstudio")  # LM Studio on port 1234
    provider = get_provider("ollama")    # Ollama on port 11434

    # Make a chat request
    request = ChatRequest(
        messages=[
            ChatMessage(role="system", content="You are a helpful assistant."),
            ChatMessage(role="user", content="Hello!"),
        ],
        model="claude-sonnet-4-20250514",
    )
    response = provider.chat(request)
    print(response.content)

    # For JSON responses
    json_obj = provider.chat_json(request)

Environment Variables:
    ALF_LLM_PROVIDER - Explicit provider override (anthropic, openai, google, ollama, lmstudio)
    ANTHROPIC_API_KEY - Anthropic API key (auto-selects anthropic provider)
    OPENAI_API_KEY    - OpenAI API key (auto-selects openai provider)
    GOOGLE_API_KEY    - Google API key (auto-selects google provider)
    GEMINI_API_KEY    - Alias for GOOGLE_API_KEY
    ALF_LLM_BASE_URL - Custom OpenAI-compatible endpoint (auto-selects ollama)
    ALF_LLM_MODEL    - Override default model
    ALF_LLM_TIMEOUT  - Request timeout in seconds (default: 180)

Local Server Auto-Detection:
    If no API keys are set, the system probes common local server ports:
    - Port 11434: Ollama (most common)
    - Port 1234: LM Studio
    - Port 8000: vLLM
    - Port 8080: LocalAI
"""

from .base import ChatMessage, ChatRequest, ChatResponse, LLMProvider, ModelNotFoundError
from .config import (
    LOCAL_SERVER_PORTS,
    ProviderConfig,
    detect_local_server,
    detect_provider,
    get_config,
    get_provider,
)
from .factory import create_provider, list_providers

__all__ = [
    # Base classes
    "LLMProvider",
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "ModelNotFoundError",
    # Config
    "ProviderConfig",
    "detect_provider",
    "detect_local_server",
    "LOCAL_SERVER_PORTS",
    "get_config",
    # Factory
    "get_provider",
    "create_provider",
    "list_providers",
]
