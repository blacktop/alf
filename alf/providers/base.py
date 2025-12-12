"""Abstract base class for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..tools.schema import ToolCall


@dataclass
class ChatMessage:
    """A single message in a chat conversation."""

    role: str  # "system", "user", "assistant"
    content: str | list[Any]  # Can be string or list of content blocks (Anthropic)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ChatMessage:
        """Create ChatMessage from dict, preserving complex content structures."""
        return cls(role=d.get("role", "user"), content=d.get("content", ""))


@dataclass
class ChatRequest:
    """Request parameters for chat completion."""

    messages: list[ChatMessage | dict[str, Any]]  # Accept both for flexibility
    model: str
    temperature: float = 0.0
    max_tokens: int | None = None
    json_output: bool = False
    timeout: float = 180.0
    extra: dict[str, Any] = field(default_factory=dict)

    # Tool calling support
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None  # "auto", "none", or specific tool

    def __post_init__(self) -> None:
        """Normalize messages to ChatMessage objects.

        Dict messages with special fields (tool_call_id, tool_calls, parts)
        are preserved as-is since they contain provider-specific structures
        that can't be represented in ChatMessage.
        """
        normalized: list[ChatMessage | dict[str, Any]] = []
        for msg in self.messages:
            if isinstance(msg, ChatMessage):
                normalized.append(msg)
            elif isinstance(msg, dict):
                # Preserve dicts with tool-related fields as-is
                # These have special structure that ChatMessage can't represent
                if any(k in msg for k in ("tool_call_id", "tool_calls", "parts", "function_call")):
                    normalized.append(msg)
                else:
                    normalized.append(ChatMessage.from_dict(msg))
            else:
                # Try to access .role and .content (duck typing)
                normalized.append(ChatMessage(role=getattr(msg, "role", "user"), content=getattr(msg, "content", "")))
        self.messages = normalized

    @classmethod
    def from_openai_payload(cls, payload: dict[str, Any]) -> ChatRequest:
        """Convert an OpenAI-format payload dict to a ChatRequest."""
        messages = [
            ChatMessage(role=m.get("role", "user"), content=m.get("content", "")) for m in payload.get("messages", [])
        ]
        excluded_keys = {
            "messages",
            "model",
            "temperature",
            "max_tokens",
            "response_format",
            "tools",
            "tool_choice",
        }
        return cls(
            messages=messages,
            model=payload.get("model", ""),
            temperature=payload.get("temperature", 0.0),
            max_tokens=payload.get("max_tokens"),
            json_output=payload.get("response_format", {}).get("type") == "json_object",
            tools=payload.get("tools"),
            tool_choice=payload.get("tool_choice"),
            extra={k: v for k, v in payload.items() if k not in excluded_keys},
        )


@dataclass
class ChatResponse:
    """Response from a chat completion."""

    content: str
    model: str
    finish_reason: str | None = None
    usage: dict[str, int] | None = None
    raw: dict[str, Any] | None = None

    # Tool calling support
    tool_calls: list[ToolCall] | None = None

    @property
    def has_tool_calls(self) -> bool:
        """Check if response contains tool calls."""
        return bool(self.tool_calls)

    def to_json_object(self) -> dict[str, Any]:
        """Parse content as JSON object.

        Falls back to extracting the outermost {...} if the content isn't
        pure JSON.
        """
        import json

        raw = (self.content or "").strip()
        if not raw:
            raise ValueError("empty model response")

        # Try direct parse first
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

        # Fallback: find the outermost {...} region
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = raw[start : end + 1]
            obj = json.loads(snippet)
            if isinstance(obj, dict):
                return obj

        raise ValueError("model did not return a JSON object")


class ModelNotFoundError(Exception):
    """Raised when the requested model is not available on the server.

    This exception includes the list of available models to help the user
    select a valid model.
    """

    def __init__(self, model: str, available: list[str], message: str = ""):
        self.model = model
        self.available = available
        if not message:
            if available:
                message = f"Model '{model}' not found. Available models: {', '.join(available)}"
            else:
                message = f"Model '{model}' not found on the server."
        super().__init__(message)


class RateLimitError(Exception):
    """Raised when the provider rate limit is exceeded."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class LLMProvider(ABC):
    """Abstract base class for LLM providers.

    All providers implement chat() which takes a ChatRequest and returns
    a ChatResponse. Providers handle their own authentication and API
    specifics.
    """

    name: str = "base"

    @abstractmethod
    def chat(self, request: ChatRequest) -> ChatResponse:
        """Send a chat completion request.

        Args:
            request: The chat request parameters.

        Returns:
            ChatResponse with the model's response.

        Raises:
            RuntimeError: On API errors.
            ValueError: On invalid responses.
        """
        pass

    def chat_json(self, request: ChatRequest) -> dict[str, Any]:
        """Convenience method: chat and parse response as JSON object.

        Requests a JSON object response (when supported) and parses it.
        """
        request.json_output = True
        response = self.chat(request)
        return response.to_json_object()

    @classmethod
    def from_env(cls) -> LLMProvider:
        """Create provider instance from environment variables.

        Subclasses should override to handle their specific env vars.
        """
        raise NotImplementedError(f"{cls.name} does not support from_env()")
