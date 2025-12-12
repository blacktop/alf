"""Google Gemini provider using the official Gen AI SDK."""

from __future__ import annotations

import os
from typing import Any

from .base import ChatRequest, ChatResponse, LLMProvider, RateLimitError


class GoogleProvider(LLMProvider):
    """LLM provider for Google's Gemini models.

    Uses the official google-genai SDK for native integration.
    Requires: `uv sync --extra google` (or `pip install google-genai`)

    Note: The old google-generativeai SDK is deprecated (EOL Nov 2025).
    This provider uses the new unified Google Gen AI SDK.
    """

    name = "google"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.5-flash",
        timeout: float = 180.0,
        vertexai: bool = False,
        project: str | None = None,
        location: str | None = None,
    ):
        """Initialize Google Gemini provider.

        Args:
            api_key: Google API key. Falls back to GOOGLE_API_KEY or GEMINI_API_KEY env var.
            model: Model name (default: gemini-2.5-flash).
            timeout: Request timeout in seconds.
            vertexai: Use Vertex AI instead of Gemini Developer API.
            project: Google Cloud project ID (for Vertex AI).
            location: Google Cloud location (for Vertex AI).
        """
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        self.model = model
        self.timeout = timeout
        self.vertexai = vertexai or os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").lower() == "true"
        self.project = project or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self.location = location or os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
        self._client: Any = None

    @property
    def client(self) -> Any:
        """Lazy-initialize the Google Gen AI client."""
        if self._client is None:
            try:
                from google import genai
            except ImportError as e:
                raise ImportError("google-genai SDK not installed. Install with: uv sync --extra google") from e

            if self.vertexai:
                if not self.project:
                    raise ValueError("GOOGLE_CLOUD_PROJECT not set. Required for Vertex AI.")
                self._client = genai.Client(
                    vertexai=True,
                    project=self.project,
                    location=self.location,
                )
            else:
                if not self.api_key:
                    raise ValueError(
                        "GOOGLE_API_KEY or GEMINI_API_KEY not set. Set the environment variable or pass api_key."
                    )
                self._client = genai.Client(api_key=self.api_key)

        return self._client

    def chat(self, request: ChatRequest) -> ChatResponse:
        """Send a chat completion request to Gemini.

        Args:
            request: Chat request parameters.

        Returns:
            ChatResponse with Gemini's response.
        """

        def _content_to_text(content: Any) -> str:
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                # Some callers use content blocks: [{"type":"text","text":"..."}]
                parts: list[str] = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if isinstance(text, str) and text:
                            parts.append(text)
                if parts:
                    return "\n".join(parts)
            if content is None:
                return ""
            return str(content)

        # Convert messages to Gemini format
        # google-genai uses systemInstruction on the config, with contents as Content/ContentDict.
        system_instruction: str | None = None
        contents: list[dict[str, Any]] = []

        for msg in request.messages:
            if isinstance(msg, dict):
                # Preserve already-structured Gemini messages (tool loop uses parts/function_call/function_response).
                if "parts" in msg:
                    role = msg.get("role")
                    if role == "system":
                        # Best-effort: collapse system parts to text and use systemInstruction.
                        system_instruction = _content_to_text(msg.get("content") or msg.get("parts") or "")
                        continue
                    contents.append(msg)
                    continue

                role = msg.get("role", "user")
                content = _content_to_text(msg.get("content", ""))
            else:
                role = msg.role
                content = _content_to_text(msg.content)

            if role == "system":
                system_instruction = content
            else:
                # Gemini uses "user" and "model" roles
                role = "model" if role == "assistant" else "user"
                contents.append(
                    {
                        "role": role,
                        "parts": [{"text": content}],
                    }
                )

        # Build generation config
        model = request.model or self.model
        config_kwargs: dict[str, Any] = {}

        if request.temperature > 0:
            config_kwargs["temperature"] = float(request.temperature)

        if request.max_tokens:
            # google-genai uses maxOutputTokens (camelCase)
            config_kwargs["maxOutputTokens"] = int(request.max_tokens)

        if request.json_output:
            config_kwargs["responseMimeType"] = "application/json"

        if system_instruction:
            config_kwargs["systemInstruction"] = system_instruction

        # Tool calling (Phase 1): convert tool schemas to google-genai FunctionDeclarations.
        if request.tools:
            try:
                from google.genai import types as genai_types

                def _type_to_json_schema(t: str | None) -> str:
                    mapping = {
                        "OBJECT": "object",
                        "STRING": "string",
                        "INTEGER": "integer",
                        "NUMBER": "number",
                        "BOOLEAN": "boolean",
                        "ARRAY": "array",
                        "object": "object",
                        "string": "string",
                        "integer": "integer",
                        "number": "number",
                        "boolean": "boolean",
                        "array": "array",
                    }
                    return mapping.get((t or "string"), "string")

                def _gemini_params_to_json_schema(params: Any) -> dict[str, Any]:
                    if not isinstance(params, dict):
                        return {"type": "object", "properties": {}}
                    t = params.get("type")
                    # If it's already JSON Schema-ish, keep it.
                    if isinstance(t, str) and t.lower() in (
                        "object",
                        "array",
                        "string",
                        "integer",
                        "number",
                        "boolean",
                    ):
                        return params
                    schema: dict[str, Any] = {"type": _type_to_json_schema(t)}
                    if "properties" in params and isinstance(params["properties"], dict):
                        props: dict[str, Any] = {}
                        for key, val in params["properties"].items():
                            if isinstance(val, dict):
                                v: dict[str, Any] = {"type": _type_to_json_schema(val.get("type"))}
                                if isinstance(val.get("description"), str):
                                    v["description"] = val["description"]
                                if isinstance(val.get("enum"), list):
                                    v["enum"] = val["enum"]
                                if "default" in val:
                                    v["default"] = val.get("default")
                                if v["type"] == "array" and isinstance(val.get("items"), dict):
                                    items = val["items"]
                                    v["items"] = {
                                        **items,
                                        "type": _type_to_json_schema(items.get("type")),
                                    }
                                props[key] = v
                        schema["properties"] = props
                    if isinstance(params.get("required"), list):
                        schema["required"] = params["required"]
                    return schema

                decls: list[genai_types.FunctionDeclaration] = []
                for tool in request.tools:
                    if not isinstance(tool, dict):
                        continue
                    # Accept both our Gemini schema (name/description/parameters) and OpenAI wrapper.
                    if "function" in tool and isinstance(tool.get("function"), dict):
                        func = tool["function"]
                        name = func.get("name")
                        desc = func.get("description")
                        params = func.get("parameters")
                        json_schema = params if isinstance(params, dict) else {"type": "object", "properties": {}}
                    else:
                        name = tool.get("name")
                        desc = tool.get("description")
                        params = tool.get("parameters") or tool.get("input_schema")
                        json_schema = _gemini_params_to_json_schema(params)

                    if not isinstance(name, str) or not name:
                        continue
                    decls.append(
                        genai_types.FunctionDeclaration(
                            name=name,
                            description=str(desc) if desc is not None else None,
                            parametersJsonSchema=json_schema,
                        )
                    )

                if decls:
                    config_kwargs["tools"] = [genai_types.Tool(functionDeclarations=decls)]
            except Exception:
                # If tool conversion fails, proceed without tools (model will respond in text).
                pass

        config_obj: Any | None = None
        if config_kwargs:
            from google.genai import types as genai_types

            config_obj = genai_types.GenerateContentConfig(**config_kwargs)

        # Make the API call
        try:
            response = self.client.models.generate_content(
                model=model,
                contents=contents,
                config=config_obj,
            )
        except Exception as e:  # noqa: BLE001
            from google import genai

            # Handle Rate Limiting (429 RESOURCE_EXHAUSTED)
            if isinstance(e, genai.errors.ClientError):
                code = getattr(e, "code", None)
                status = getattr(e, "status", None)
                if code == 429 or status == "RESOURCE_EXHAUSTED":
                    # Try to parse retry delay from error message or details
                    import re

                    retry_after = None
                    msg = str(e)
                    # Look for "Please retry in X.Xs"
                    match = re.search(r"retry in (\d+(\.\d+)?)s", msg)
                    if match:
                        retry_after = float(match.group(1))

                    raise RateLimitError(
                        f"Google API rate limit exceeded (429). Retry after {retry_after}s.", retry_after=retry_after
                    ) from e

            # If the model name is wrong, query available models to help the user
            # pick a valid one next time.
            try:
                is_not_found = False
                if isinstance(e, genai.errors.APIError):
                    code = getattr(e, "code", None)
                    if code == 404:
                        is_not_found = True
                msg = str(e).lower()
                if "not found" in msg and "model" in msg:
                    is_not_found = True

                if is_not_found:
                    from .base import ModelNotFoundError

                    available = self.list_models()
                    # Avoid massive error messages if the account has many models.
                    if len(available) > 25:
                        shown = available[:25]
                        raise ModelNotFoundError(
                            model,
                            shown,
                            message=(
                                f"Model '{model}' not found. Showing first {len(shown)} of {len(available)} models: "
                                + ", ".join(shown)
                                + ". If you intended to use a local OpenAI-compatible server, use "
                                "--provider lmstudio/ollama."
                            ),
                        ) from e
                    raise ModelNotFoundError(model, available) from e
            except ModelNotFoundError:
                raise
            except Exception:
                pass
            raise

        # Extract content and tool calls from response
        content_parts: list[str] = []
        tool_calls = []
        finish_reason = None

        candidates = getattr(response, "candidates", None) or []
        for cand in candidates:
            finish_reason = finish_reason or getattr(cand, "finish_reason", None) or getattr(cand, "finishReason", None)
            cand_content = getattr(cand, "content", None)
            parts = []
            if cand_content is not None:
                parts = getattr(cand_content, "parts", None) or getattr(cand_content, "parts", None) or []
            for part in parts or []:
                text = getattr(part, "text", None)
                if isinstance(text, str) and text:
                    content_parts.append(text)
                fn = getattr(part, "function_call", None) or getattr(part, "functionCall", None)
                if fn is not None:
                    from ..tools.schema import ToolCall

                    thought_signature = getattr(part, "thought_signature", None) or getattr(
                        part, "thoughtSignature", None
                    )
                    tool_calls.append(ToolCall.from_gemini(fn, thought_signature=thought_signature))

        # Avoid calling response.text when the response is tool-call-only. The google-genai SDK emits a
        # warning when non-text parts exist (e.g., function_call) and .text is accessed.
        if content_parts:
            content = "\n".join(content_parts)
        elif tool_calls:
            content = ""
        else:
            content = getattr(response, "text", "") or ""

        # Build usage info if available
        usage = None
        usage_meta = getattr(response, "usage_metadata", None) or getattr(response, "usageMetadata", None)
        if usage_meta:
            usage = {
                "prompt_tokens": getattr(usage_meta, "prompt_token_count", 0),
                "completion_tokens": getattr(usage_meta, "candidates_token_count", 0),
                "total_tokens": getattr(usage_meta, "total_token_count", 0),
            }

        return ChatResponse(
            content=content,
            model=model,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
            usage=usage,
            raw=response.to_dict() if hasattr(response, "to_dict") else None,
            tool_calls=tool_calls if tool_calls else None,
        )

    def list_models(self) -> list[str]:
        """List available model IDs for this account.

        Returns:
            List of model names/IDs. Returns an empty list on errors.
        """
        try:
            pager = self.client.models.list()
            names: list[str] = []
            for m in pager:
                name = getattr(m, "name", None)
                if isinstance(name, str) and name:
                    names.append(name)
                    if name.startswith("models/"):
                        names.append(name.removeprefix("models/"))
            # Deduplicate preserving order
            seen: set[str] = set()
            out: list[str] = []
            for n in names:
                if n not in seen:
                    seen.add(n)
                    out.append(n)
            return out
        except Exception:
            return []

    @classmethod
    def from_env(cls) -> GoogleProvider:
        """Create provider from environment variables."""
        return cls(
            api_key=os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"),
            model=os.environ.get("ALF_LLM_MODEL") or os.environ.get("LLDB_MCP_MODEL") or "gemini-2.5-flash",
            timeout=float(os.environ.get("ALF_LLM_TIMEOUT", "180.0")),
            vertexai=os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").lower() == "true",
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location=os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1"),
        )
