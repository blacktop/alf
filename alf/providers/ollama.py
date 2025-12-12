"""Ollama/LM Studio provider using OpenAI-compatible HTTP API.

This provider requires NO external dependencies - it uses stdlib urllib
to call any OpenAI-compatible endpoint (Ollama, LM Studio, vLLM, etc).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .base import ChatRequest, ChatResponse, LLMProvider


def _normalize_base_url(base_url: str) -> str:
    """Normalize base URL, ensuring no trailing slash."""
    base = (base_url or "").strip()
    if not base:
        return "http://127.0.0.1:11434/v1"
    return base.rstrip("/")


def _content_to_text(content: Any) -> str:
    """Convert various content formats to plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Some providers return [{type:"text", text:"..."}]
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)
    return str(content)


class OllamaProvider(LLMProvider):
    """LLM provider for OpenAI-compatible local servers.

    Works with Ollama, LM Studio, vLLM, and any server that exposes
    an OpenAI-compatible /v1/chat/completions endpoint.

    This provider uses only stdlib (urllib) - no SDK dependencies required.

    For LM Studio: Set jit_ttl to enable Just-In-Time model loading.
    This will automatically load the requested model if not already loaded.
    """

    name = "ollama"

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434/v1",
        api_key: str | None = None,
        model: str = "llama3.1:8b-instruct",
        timeout: float = 180.0,
        jit_ttl: int | None = None,
    ):
        """Initialize Ollama provider.

        Args:
            base_url: Base URL for the OpenAI-compatible API.
            api_key: API key (often not required for local servers).
            model: Model name (default: llama3.1:8b-instruct).
            timeout: Request timeout in seconds.
            jit_ttl: LM Studio JIT loading TTL in seconds. When set, the server
                will auto-load the requested model if not loaded. Set to 0 for
                the server's default TTL (usually 60 min).
        """
        self.base_url = _normalize_base_url(base_url)
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.jit_ttl = jit_ttl

    def list_models(self) -> list[str]:
        """Query the server for available models.

        Returns:
            List of model IDs/names available on the server.
            Returns an empty list if the server doesn't support listing
            or if an error occurs.
        """
        url = f"{self.base_url}/models"
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models: list[str] = []
                for m in data.get("data", []):
                    # OpenAI API format uses "id", some servers use "name"
                    model_id = m.get("id") or m.get("name") or m.get("model")
                    if model_id:
                        models.append(model_id)
                return models
        except Exception:
            return []

    def chat(self, request: ChatRequest) -> ChatResponse:
        """Send a chat completion request.

        Args:
            request: Chat request parameters.

        Returns:
            ChatResponse with the model's response.

        Raises:
            ModelNotFoundError: If the requested model is not available.
        """
        url = f"{self.base_url}/chat/completions"

        # Convert messages to OpenAI format, preserving tool-related fields
        messages: list[dict[str, Any]] = []
        for msg in request.messages:
            if isinstance(msg, dict):
                # Preserve dicts as-is (may contain tool_calls, tool_call_id, etc.)
                messages.append(msg)
            else:
                messages.append({"role": msg.role, "content": msg.content})

        # Build request payload
        model = request.model or self.model
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }

        if request.max_tokens:
            payload["max_tokens"] = request.max_tokens

        if request.temperature > 0:
            payload["temperature"] = request.temperature

        if request.json_output:
            payload["response_format"] = {"type": "json_object"}

        # LM Studio JIT loading: include ttl to auto-load requested model
        if self.jit_ttl is not None:
            payload["ttl"] = self.jit_ttl

        # Tool calling support (OpenAI-compatible format)
        if request.tools:
            payload["tools"] = request.tools
        if request.tool_choice:
            payload["tool_choice"] = request.tool_choice

        # Build headers
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        timeout = float(request.timeout) if request.timeout else float(self.timeout)

        # Make request with retry on response_format error
        try:
            raw_response = self._make_request(req, timeout=timeout)
        except RuntimeError as e:
            err_msg = str(e).lower()

            # Check for model not found error patterns
            # Different servers use different error messages:
            # - LM Studio: "not_found_error", "model: <name>"
            # - Ollama: "model not found", "pull first"
            # - vLLM: "Model not found"
            model_not_found_patterns = [
                "model not found",
                "model does not exist",
                "not_found_error",  # LM Studio format
                "no model",
                "unknown model",
                "pull first",
            ]
            # Also check for HTTP 404 + model reference
            is_404 = "http 404" in err_msg or "404" in err_msg
            has_model_ref = model.lower() in err_msg or "model:" in err_msg or "'model'" in err_msg

            if any(pattern in err_msg for pattern in model_not_found_patterns) or (is_404 and has_model_ref):
                from .base import ModelNotFoundError

                available = self.list_models()
                raise ModelNotFoundError(model, available) from e

            # Some local servers reject response_format; retry without it
            if "response_format" in err_msg and request.json_output:
                payload.pop("response_format", None)
                body = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                raw_response = self._make_request(req, timeout=timeout)
            else:
                raise

        # Parse response
        data = json.loads(raw_response)
        choices = data.get("choices") if isinstance(data, dict) else None
        if not isinstance(choices, list) or not choices:
            raise ValueError("invalid response: missing choices")

        msg = choices[0].get("message") if isinstance(choices[0], dict) else None
        if not isinstance(msg, dict):
            raise ValueError("invalid response: missing message")

        content = _content_to_text(msg.get("content", ""))

        # Parse tool calls if present (OpenAI-compatible format)
        tool_calls = None
        raw_tool_calls = msg.get("tool_calls")
        if raw_tool_calls and isinstance(raw_tool_calls, list):
            from ..tools.schema import ToolCall

            tool_calls = [ToolCall.from_openai_dict(tc) for tc in raw_tool_calls if isinstance(tc, dict)]

        return ChatResponse(
            content=content,
            model=data.get("model", model),
            finish_reason=choices[0].get("finish_reason"),
            usage=data.get("usage"),
            raw=data,
            tool_calls=tool_calls if tool_calls else None,
        )

    def _make_request(self, req: urllib.request.Request, *, timeout: float) -> str:
        """Make HTTP request and return response body."""
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {raw[:800]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(str(e)) from e

    @classmethod
    def from_env(cls) -> OllamaProvider:
        """Create provider from environment variables."""
        jit_ttl_str = os.environ.get("ALF_LLM_JIT_TTL")
        jit_ttl = int(jit_ttl_str) if jit_ttl_str else None
        return cls(
            base_url=os.environ.get("ALF_LLM_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
            or "http://127.0.0.1:11434/v1",
            api_key=os.environ.get("ALF_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            model=os.environ.get("ALF_LLM_MODEL") or os.environ.get("LLDB_MCP_MODEL") or "llama3.1:8b-instruct",
            timeout=float(os.environ.get("ALF_LLM_TIMEOUT", "180.0")),
            jit_ttl=jit_ttl,
        )
