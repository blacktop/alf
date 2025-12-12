"""OpenAI provider using the official SDK."""

from __future__ import annotations

import os
from typing import Any

from .base import ChatRequest, ChatResponse, LLMProvider, RateLimitError


class OpenAIProvider(LLMProvider):
    """LLM provider for OpenAI's GPT models.

    Uses the official openai SDK for native integration.
    Requires: `uv sync --extra openai` (or `pip install openai`)
    """

    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "gpt-4o-mini",
        timeout: float = 180.0,
    ):
        """Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key. Falls back to OPENAI_API_KEY env var.
            base_url: Base URL for API (for Azure or compatible endpoints).
            model: Model name (default: gpt-4o-mini).
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self.model = model
        self.timeout = timeout
        self._client: Any = None

    @property
    def client(self) -> Any:
        """Lazy-initialize the OpenAI client."""
        if self._client is None:
            try:
                import openai
            except ImportError as e:
                raise ImportError("openai SDK not installed. Install with: uv sync --extra openai") from e

            if not self.api_key:
                raise ValueError("OPENAI_API_KEY not set. Set the environment variable or pass api_key.")

            kwargs = {
                "api_key": self.api_key,
                "timeout": self.timeout,
            }
            if self.base_url:
                kwargs["base_url"] = self.base_url

            self._client = openai.OpenAI(**kwargs)
        return self._client

    def chat(self, request: ChatRequest) -> ChatResponse:
        """Send a chat completion request to OpenAI.

        Args:
            request: Chat request parameters.

        Returns:
            ChatResponse with the model's response.

        Note:
            If tools are provided and the model requests tool use, the response
            will have tool_calls populated and finish_reason will be "tool_calls".
        """
        # Convert messages to OpenAI format
        # Handle both ChatMessage objects and raw dicts (tool messages, assistant with tool_calls)
        messages = []
        for msg in request.messages:
            if isinstance(msg, dict):
                # Preserve dict structure (includes tool_call_id, tool_calls, etc.)
                messages.append(msg)
            else:
                # Convert ChatMessage to dict
                messages.append({"role": msg.role, "content": msg.content})

        # Build request kwargs
        model = request.model or self.model
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }

        if request.max_tokens:
            kwargs["max_tokens"] = request.max_tokens

        if request.temperature > 0:
            kwargs["temperature"] = request.temperature

        if request.json_output:
            kwargs["response_format"] = {"type": "json_object"}

        # Add tools if provided
        if request.tools:
            kwargs["tools"] = request.tools

        # Add tool_choice if provided
        if request.tool_choice is not None:
            kwargs["tool_choice"] = request.tool_choice

        # Make the API call
        if request.timeout:
            kwargs["timeout"] = float(request.timeout)
        try:
            response = self.client.chat.completions.create(**kwargs)
        except Exception as e:  # noqa: BLE001
            import openai

            # Handle Rate Limiting (429)
            if isinstance(e, openai.RateLimitError):
                retry_after = None
                try:
                    headers = getattr(e, "response", None) and getattr(e.response, "headers", {})
                    if headers:
                        if "retry-after" in headers:
                            retry_after = float(headers["retry-after"])
                        elif "x-ratelimit-reset-seconds" in headers:
                            retry_after = float(headers["x-ratelimit-reset-seconds"])
                except Exception:
                    pass

                raise RateLimitError(
                    f"OpenAI API rate limit exceeded (429). Retry after {retry_after}s.", retry_after=retry_after
                ) from e

            # If the model name is wrong, query available models to help the user
            # pick a valid one next time.
            try:
                is_not_found = isinstance(e, openai.NotFoundError) or getattr(e, "status_code", None) == 404
                msg = str(e).lower()
                if "model" in msg and any(p in msg for p in ("not found", "does not exist", "model_not_found")):
                    is_not_found = True

                if is_not_found:
                    from .base import ModelNotFoundError

                    available = self.list_models()
                    if len(available) > 25:
                        shown = available[:25]
                        raise ModelNotFoundError(
                            model,
                            shown,
                            message=(
                                f"Model '{model}' not found. Showing first {len(shown)} of {len(available)} models: "
                                + ", ".join(shown)
                            ),
                        ) from e
                    raise ModelNotFoundError(model, available) from e
            except Exception:
                pass
            raise

        # Extract content and tool calls from response
        choice = response.choices[0] if response.choices else None
        content = choice.message.content if choice and choice.message else ""

        # Handle tool calls
        tool_calls = None
        if choice and choice.message and choice.message.tool_calls:
            from ..tools.schema import ToolCall

            tool_calls = [ToolCall.from_openai(tc) for tc in choice.message.tool_calls]

        return ChatResponse(
            content=content or "",
            model=response.model,
            finish_reason=choice.finish_reason if choice else None,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
            if response.usage
            else None,
            raw=response.model_dump() if hasattr(response, "model_dump") else None,
            tool_calls=tool_calls,
        )

    def list_models(self) -> list[str]:
        """List available model IDs for this account/endpoint.

        Returns:
            List of model IDs. Returns an empty list on errors.
        """
        try:
            page = self.client.models.list()
            models: list[str] = []
            data = getattr(page, "data", None)
            if isinstance(data, list):
                for m in data:
                    model_id = getattr(m, "id", None)
                    if isinstance(model_id, str) and model_id:
                        models.append(model_id)
            else:
                # SyncPage is iterable
                for m in page:
                    model_id = getattr(m, "id", None)
                    if isinstance(model_id, str) and model_id:
                        models.append(model_id)

            # Deduplicate preserving order
            seen: set[str] = set()
            out: list[str] = []
            for mid in models:
                if mid not in seen:
                    seen.add(mid)
                    out.append(mid)
            return out
        except Exception:
            return []

    @classmethod
    def from_env(cls) -> OpenAIProvider:
        """Create provider from environment variables."""
        return cls(
            api_key=os.environ.get("OPENAI_API_KEY") or os.environ.get("ALF_LLM_API_KEY"),
            base_url=os.environ.get("OPENAI_BASE_URL") or os.environ.get("ALF_LLM_BASE_URL"),
            model=os.environ.get("ALF_LLM_MODEL") or os.environ.get("LLDB_MCP_MODEL") or "gpt-4o-mini",
            timeout=float(os.environ.get("ALF_LLM_TIMEOUT", "180.0")),
        )
