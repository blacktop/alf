"""Agentic tool loop pattern.

Provides a unified tool loop that works with any LLM provider supporting
tool calling (Anthropic, OpenAI, Gemini).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..log import logger
from .executor import ToolExecutor
from .registry import ToolRegistry
from .schema import ToolResult
from .trace import TraceLogger, hash_tools

if TYPE_CHECKING:
    from ..providers.base import ChatResponse, LLMProvider


class AgenticLoop:
    """Provider-agnostic agentic tool loop.

    Handles the tool use loop pattern:
    1. Send request with tools to LLM
    2. Check if LLM wants to use tools
    3. If yes: execute tools, send results, go to step 1
    4. If no: return final response

    Works with Anthropic, OpenAI, and Gemini providers.

    Usage:
        loop = AgenticLoop(
            provider=anthropic_provider,
            executor=ToolExecutor(session=fuzz_session),
        )
        response = await loop.run(messages=messages, model="claude-sonnet-4-20250514")
    """

    def __init__(
        self,
        provider: LLMProvider,
        executor: ToolExecutor,
        max_turns: int = 10,
        verbose: bool = False,
        trace_output: str | Path | None = None,
    ):
        """Initialize the agentic loop.

        Args:
            provider: LLM provider instance.
            executor: Tool executor instance.
            max_turns: Maximum tool use iterations (safety limit).
            verbose: Print tool calls and results to stderr.
        """
        self.provider = provider
        self.executor = executor
        self.max_turns = max_turns
        self.verbose = verbose
        self.trace_output = Path(trace_output).expanduser() if trace_output else None

    async def run(
        self,
        messages: list[dict[str, Any]],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        """Run the tool loop until completion or max turns.

        Args:
            messages: Conversation history (will be modified in place).
            model: Model name to use.
            tools: Tool schemas (defaults to all registered tools for provider).
            tool_choice: Tool choice parameter (provider-specific).
            **kwargs: Additional arguments passed to provider.chat().

        Returns:
            Final ChatResponse when tool loop completes.

        Raises:
            RuntimeError: If max_turns is exceeded.
        """
        from ..providers.base import ChatRequest

        # Auto-initialize registry with canonical tools if empty
        if ToolRegistry.count() == 0:
            ToolRegistry.initialize_canonical_tools()

        # Get tools in provider's format if not provided
        if tools is None:
            tools = ToolRegistry.for_provider(self.provider.name)

        trace = TraceLogger(self.trace_output) if self.trace_output else None
        tools_hash = hash_tools(tools) if trace else None
        if trace:
            trace.log(
                {
                    "event": "loop_start",
                    "trace_version": trace.trace_version,
                    "provider": self.provider.name,
                    "model": model,
                    "tools": tools,
                    "tools_hash": tools_hash,
                    "tool_choice": tool_choice,
                    "max_turns": self.max_turns,
                    "kwargs": _serialize_simple(kwargs),
                }
            )

        current_turn = 0
        for turn in range(self.max_turns):
            current_turn = turn + 1
            # Build request
            request = ChatRequest(
                messages=messages.copy(),
                model=model,
                tools=tools,
                tool_choice=tool_choice,
                **kwargs,
            )
            request_messages = _serialize_messages(request.messages)

            # Call LLM
            try:
                response = self.provider.chat(request)
            except Exception as e:
                if trace:
                    trace.log(
                        {
                            "event": "error",
                            "tools_hash": tools_hash,
                            "turn": current_turn,
                            "phase": "llm_request",
                            "error": str(e),
                        }
                    )
                raise

            # Check if LLM wants to use tools
            if not response.tool_calls:
                if trace:
                    trace.log(
                        {
                            "event": "final_response",
                            "tools_hash": tools_hash,
                            "turn": current_turn,
                            "request": {
                                "messages": request_messages,
                                "model": model,
                                "tool_choice": tool_choice,
                            },
                            "response": _serialize_response(response),
                        }
                    )
                return response

            if self.verbose:
                logger.debug(f"Turn {turn + 1}: {len(response.tool_calls)} tool call(s)")

            # Add assistant message to history
            messages.append(self._format_assistant_message(response))

            # Execute tools
            try:
                results = await self.executor.execute_many(response.tool_calls)
            except Exception as e:
                if trace:
                    trace.log(
                        {
                            "event": "error",
                            "tools_hash": tools_hash,
                            "turn": current_turn,
                            "phase": "tool_execution",
                            "request": {
                                "messages": request_messages,
                                "model": model,
                                "tool_choice": tool_choice,
                            },
                            "response": _serialize_response(response),
                            "error": str(e),
                        }
                    )
                raise

            if trace:
                trace.log(
                    {
                        "event": "tool_turn",
                        "tools_hash": tools_hash,
                        "turn": current_turn,
                        "request": {
                            "messages": request_messages,
                            "model": model,
                            "tool_choice": tool_choice,
                        },
                        "response": _serialize_response(response),
                        "tool_results": _serialize_tool_results(results),
                    }
                )

            if self.verbose:
                for call, result in zip(response.tool_calls, results, strict=False):
                    status = "error" if result.is_error else "ok"
                    # Show truncated arguments and result preview
                    args_str = str(call.arguments)[:100]
                    if len(str(call.arguments)) > 100:
                        args_str += "..."
                    result_preview = result.content[:200].replace("\n", " ")
                    if len(result.content) > 200:
                        result_preview += "..."
                    logger.debug(f"  {call.name}({args_str}) -> {status}")
                    logger.debug(f"  Result: {result_preview}")

            # Add tool results to history
            self._append_tool_results(messages, results)

        raise RuntimeError(
            f"Tool loop exceeded {self.max_turns} turns. Consider increasing max_turns or investigating infinite loops."
        )

    def _format_assistant_message(self, response: ChatResponse) -> dict[str, Any]:
        """Format assistant message with tool calls for history.

        Args:
            response: The LLM response.

        Returns:
            Assistant message dict.
        """
        provider = self.provider.name

        if provider == "anthropic":
            # Anthropic: assistant message with content blocks
            content = []
            if response.content:
                content.append({"type": "text", "text": response.content})
            for call in response.tool_calls or []:
                content.append(
                    {
                        "type": "tool_use",
                        "id": call.id,
                        "name": call.name,
                        "input": call.arguments,
                    }
                )
            return {"role": "assistant", "content": content}

        elif provider in ("openai", "ollama"):
            # OpenAI: assistant message with tool_calls field
            tool_calls = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": (
                            call.arguments
                            if isinstance(call.arguments, str)
                            else __import__("json").dumps(call.arguments)
                        ),
                    },
                }
                for call in (response.tool_calls or [])
            ]
            return {
                "role": "assistant",
                "content": response.content or None,
                "tool_calls": tool_calls,
            }

        elif provider in ("gemini", "google"):
            # Gemini: handled differently by SDK
            parts: list[dict[str, Any]] = []
            if response.content:
                parts.append({"text": response.content})
            return {
                "role": "model",
                "parts": parts
                + [
                    {
                        "function_call": {
                            "name": call.name,
                            "args": call.arguments,
                        },
                        **(
                            {"thought_signature": call.thought_signature}
                            if getattr(call, "thought_signature", None) is not None
                            else {}
                        ),
                    }
                    for call in (response.tool_calls or [])
                ],
            }

        else:
            # Fallback: simple message
            return {
                "role": "assistant",
                "content": response.content or "",
            }

    def _append_tool_results(
        self,
        messages: list[dict[str, Any]],
        results: list[ToolResult],
    ) -> None:
        """Append tool results to message history.

        Args:
            messages: Message history to append to.
            results: Tool execution results.
        """
        provider = self.provider.name

        if provider == "anthropic":
            # Anthropic: single user message with tool_result blocks
            messages.append(
                {
                    "role": "user",
                    "content": [r.to_anthropic() for r in results],
                }
            )

        elif provider in ("openai", "ollama"):
            # OpenAI: separate tool messages for each result
            for result in results:
                messages.append(result.to_openai())

        elif provider in ("gemini", "google"):
            # Gemini: function_response parts
            messages.append(
                {
                    "role": "user",
                    "parts": [{"function_response": r.to_gemini()} for r in results],
                }
            )

        else:
            # Fallback: add results as user message
            content = "\n\n".join(f"Tool {r.tool_call_id}: {r.content}" for r in results)
            messages.append({"role": "user", "content": content})


def _serialize_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """Convert messages to JSON-serializable dicts for tracing."""
    serialized: list[dict[str, Any]] = []
    for msg in messages:
        if isinstance(msg, dict):
            serialized.append(msg)
            continue
        role = getattr(msg, "role", "user")
        content = getattr(msg, "content", "")
        serialized.append({"role": role, "content": content})
    return serialized


def _serialize_tool_results(results: list[ToolResult]) -> list[dict[str, Any]]:
    return [
        {
            "tool_call_id": result.tool_call_id,
            "content": result.content,
            "is_error": result.is_error,
        }
        for result in results
    ]


def _serialize_response(response: ChatResponse) -> dict[str, Any]:
    return {
        "content": response.content,
        "model": response.model,
        "finish_reason": response.finish_reason,
        "usage": response.usage,
        "tool_calls": [
            {
                "id": call.id,
                "name": call.name,
                "arguments": call.arguments,
                "thought_signature": getattr(call, "thought_signature", None),
            }
            for call in (response.tool_calls or [])
        ],
    }


def _serialize_simple(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items()}


async def run_tool_loop(
    provider: LLMProvider,
    messages: list[dict[str, Any]],
    model: str,
    session: Any | None = None,
    context: Any | None = None,
    max_turns: int = 10,
    verbose: bool = False,
    trace_output: str | Path | None = None,
    **kwargs: Any,
) -> ChatResponse:
    """Convenience function to run a tool loop.

    Args:
        provider: LLM provider instance.
        messages: Conversation history.
        model: Model name.
        session: Optional FuzzSession for MCP execution.
        context: Context for local handlers (e.g., LLDBDirector).
        max_turns: Maximum tool iterations.
        verbose: Print debug info.
        **kwargs: Additional args for provider.

    Returns:
        Final ChatResponse.
    """
    executor = ToolExecutor(session=session, context=context)
    loop = AgenticLoop(
        provider=provider,
        executor=executor,
        max_turns=max_turns,
        verbose=verbose,
        trace_output=trace_output,
    )
    return await loop.run(messages=messages, model=model, **kwargs)
