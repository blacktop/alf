"""Anthropic Claude provider using the official SDK."""

from __future__ import annotations

import os
from typing import Any

from .base import ChatRequest, ChatResponse, LLMProvider, ModelNotFoundError, RateLimitError


class AnthropicProvider(LLMProvider):
    """LLM provider for Anthropic's Claude models.

    Uses the official anthropic SDK for native Claude integration.
    Requires: `uv sync --extra anthropic` (or `pip install anthropic`)
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-5-20250929",
        timeout: float = 180.0,
    ):
        """Initialize Anthropic provider.

        Args:
            api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
            model: Model name (default: claude-sonnet-4-20250514).
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.timeout = timeout
        self._client: Any = None

    @property
    def client(self) -> Any:
        """Lazy-initialize the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
            except ImportError as e:
                raise ImportError("anthropic SDK not installed. Install with: uv sync --extra anthropic") from e

            if not self.api_key:
                raise ValueError("ANTHROPIC_API_KEY not set. Set the environment variable or pass api_key.")

            self._client = anthropic.Anthropic(
                api_key=self.api_key,
                timeout=self.timeout,
            )
        return self._client

    def chat(self, request: ChatRequest) -> ChatResponse:
        """Send a chat completion request to Claude.

        Args:
            request: Chat request parameters.

        Returns:
            ChatResponse with Claude's response.

        Note:
            If tools are provided and Claude requests tool use, the response
            will have tool_calls populated and finish_reason will be "tool_use".
        """
        # Convert messages to Anthropic format
        # Anthropic separates system message from the messages list
        system_content: str | None = None
        messages = []

        for msg in request.messages:
            # Handle both ChatMessage objects and raw dicts
            if isinstance(msg, dict):
                role = msg.get("role", "user")
                content = msg.get("content", "")
            else:
                role = msg.role
                content = msg.content

            if role == "system":
                # System content must be string
                system_content = content if isinstance(content, str) else str(content)
            else:
                # Content can be string or list of content blocks (tool_use, tool_result)
                messages.append(
                    {
                        "role": role,
                        "content": content,
                    }
                )

        # Build request kwargs
        model = request.model or self.model
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": request.max_tokens or 4096,
        }

        if system_content:
            kwargs["system"] = system_content

        if request.temperature > 0:
            kwargs["temperature"] = request.temperature

        # Respect per-request timeout (some runs want shorter timeouts).
        if request.timeout:
            kwargs["timeout"] = float(request.timeout)

        # Add tools if provided
        if request.tools:
            kwargs["tools"] = request.tools

        # Add tool_choice if provided
        if request.tool_choice is not None:
            kwargs["tool_choice"] = request.tool_choice

        # Make the API call
        try:
            response = self.client.messages.create(**kwargs)
        except Exception as e:  # noqa: BLE001
            import anthropic

            # Handle Rate Limiting (429)
            if isinstance(e, anthropic.RateLimitError):
                retry_after = None
                # Anthropic sends 'retry-after' header (seconds) or 'retry-after-ms' (milliseconds)
                # But the python SDK might expose it on e.response.headers if available.
                try:
                    headers = getattr(e, "response", None) and getattr(e.response, "headers", {})
                    if headers:
                        if "retry-after" in headers:
                            retry_after = float(headers["retry-after"])
                        elif "retry-after-ms" in headers:
                            retry_after = float(headers["retry-after-ms"]) / 1000.0
                except Exception:
                    pass

                raise RateLimitError(
                    f"Anthropic API rate limit exceeded (429). Retry after {retry_after}s.", retry_after=retry_after
                ) from e

            # If the model name is wrong, query available models to help the user
            # pick a valid one next time.
            try:
                is_not_found = isinstance(e, anthropic.NotFoundError) or getattr(e, "status_code", None) == 404
                msg = str(e).lower()
                if "model" in msg and any(p in msg for p in ("not found", "does not exist", "model_not_found")):
                    is_not_found = True

                if is_not_found:
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
            except ModelNotFoundError:
                raise
            except Exception:
                pass
            raise

        # Extract content and tool calls from response
        content_parts = []
        tool_calls = []

        for block in response.content:
            block_type = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)

            if block_type == "text":
                text = block.get("text") if isinstance(block, dict) else getattr(block, "text", None)
                if isinstance(text, str) and text:
                    content_parts.append(text)

            elif block_type == "tool_use":
                # Extract tool call info
                from ..tools.schema import ToolCall

                tool_calls.append(ToolCall.from_anthropic(block))

        content = "\n".join(content_parts)

        return ChatResponse(
            content=content,
            model=response.model,
            finish_reason=response.stop_reason,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
            if response.usage
            else None,
            raw=response.model_dump() if hasattr(response, "model_dump") else None,
            tool_calls=tool_calls if tool_calls else None,
        )

    def list_models(self) -> list[str]:
        """List available model IDs for this account.

        Returns:
            List of model IDs. Returns an empty list on errors.
        """
        try:
            page = self.client.models.list()
            models: list[str] = []
            data = getattr(page, "data", None)
            if isinstance(data, list):
                for m in data:
                    model_id = getattr(m, "id", None) or getattr(m, "name", None)
                    if isinstance(model_id, str) and model_id:
                        models.append(model_id)
            else:
                for m in page:
                    model_id = getattr(m, "id", None) or getattr(m, "name", None)
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
    def from_env(cls) -> AnthropicProvider:
        """Create provider from environment variables."""
        return cls(
            api_key=os.environ.get("ANTHROPIC_API_KEY"),
            model=os.environ.get("ALF_LLM_MODEL") or os.environ.get("LLDB_MCP_MODEL") or "claude-sonnet-4-5-20250929",
            timeout=float(os.environ.get("ALF_LLM_TIMEOUT", "180.0")),
        )
