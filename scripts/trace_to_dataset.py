#!/usr/bin/env python3
"""
Convert ALF tool-loop trace JSONL into training-friendly JSONL.

This is intentionally experimental and standalone (not wired into core CLI).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


def _load_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[!] Skipping line {idx}: {exc}", file=sys.stderr)


def _trim_text(value: Any, max_chars: int) -> Any:
    if max_chars <= 0:
        return value
    if isinstance(value, str):
        return value[:max_chars]
    if isinstance(value, list):
        trimmed: list[Any] = []
        for item in value:
            if isinstance(item, dict):
                item = dict(item)
                if "text" in item and isinstance(item["text"], str):
                    item["text"] = item["text"][:max_chars]
                if "content" in item and isinstance(item["content"], str):
                    item["content"] = item["content"][:max_chars]
                trimmed.append(item)
            else:
                trimmed.append(item)
        return trimmed
    return value


def _redact_text(value: str, prefixes: list[str], replacement: str) -> str:
    redacted = value
    for prefix in prefixes:
        if prefix:
            redacted = redacted.replace(prefix, replacement)
    return redacted


def _redact_data(value: Any, prefixes: list[str], replacement: str) -> Any:
    if not prefixes:
        return value
    if isinstance(value, str):
        return _redact_text(value, prefixes, replacement)
    if isinstance(value, list):
        return [_redact_data(item, prefixes, replacement) for item in value]
    if isinstance(value, dict):
        return {key: _redact_data(val, prefixes, replacement) for key, val in value.items()}
    return value


def _trim_messages(messages: list[Any], max_messages: int, max_chars: int) -> list[dict[str, Any]]:
    if max_messages > 0:
        messages = messages[-max_messages:]
    trimmed: list[dict[str, Any]] = []
    for msg in messages:
        if isinstance(msg, dict):
            msg = dict(msg)
            if "content" in msg:
                msg["content"] = _trim_text(msg["content"], max_chars)
            trimmed.append(msg)
        else:
            role = getattr(msg, "role", "user")
            content = _trim_text(getattr(msg, "content", ""), max_chars)
            trimmed.append({"role": role, "content": content})
    return trimmed


def _tool_call_success(event: dict[str, Any]) -> bool:
    results = event.get("tool_results") or []
    return not any(result.get("is_error") for result in results if isinstance(result, dict))


def _build_record(
    event: dict[str, Any],
    tools: list[dict[str, Any]] | None,
    *,
    max_messages: int,
    max_chars: int,
    include_results: bool,
    format_name: str,
    redact_prefixes: list[str],
    redact_replacement: str,
) -> dict[str, Any]:
    request = event.get("request") or {}
    response = event.get("response") or {}
    tools = tools or []

    if redact_prefixes:
        request = _redact_data(request, redact_prefixes, redact_replacement)
        response = _redact_data(response, redact_prefixes, redact_replacement)
        tools = _redact_data(tools, redact_prefixes, redact_replacement)

    messages = _trim_messages(request.get("messages") or [], max_messages, max_chars)
    tool_choice = request.get("tool_choice")

    if format_name == "openai":
        assistant_message = {
            "role": "assistant",
            "content": response.get("content") or None,
            "tool_calls": response.get("tool_calls") or [],
        }
        record = {
            "messages": messages + [assistant_message],
            "tools": tools,
            "tool_choice": tool_choice,
            "metadata": _event_metadata(event),
        }
    elif format_name == "functiongemma":
        normalized_tools = _normalize_tools(tools)
        normalized_messages = _normalize_messages(messages)
        prompt = _render_functiongemma_prompt(normalized_messages, normalized_tools)
        completion = _render_functiongemma_completion(response)
        record = {
            "prompt": prompt,
            "response": completion,
            "metadata": _event_metadata(event),
        }
    else:
        record = {
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice,
            "expected": {
                "content": response.get("content") or None,
                "tool_calls": response.get("tool_calls") or [],
            },
            "metadata": _event_metadata(event),
        }

    if include_results:
        record["tool_results"] = event.get("tool_results") or []

    return record


def _event_metadata(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": event.get("run_id"),
        "turn": event.get("turn"),
        "event": event.get("event"),
        "tools_hash": event.get("tools_hash"),
        "ts": event.get("ts"),
    }


def _normalize_tools(raw_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for tool in raw_tools:
        if not isinstance(tool, dict):
            continue
        if tool.get("type") == "function" and isinstance(tool.get("function"), dict):
            fn = tool["function"]
            normalized.append(
                {
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "parameters": fn.get("parameters") or {},
                }
            )
            continue
        if "input_schema" in tool:
            normalized.append(
                {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema") or {},
                }
            )
            continue
        if "parameters" in tool and "name" in tool:
            normalized.append(
                {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters") or {},
                }
            )
            continue
    return normalized


def _normalize_messages(raw_messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    tool_id_to_name: dict[str, str] = {}

    for msg in raw_messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "user")

        if role in ("assistant", "model"):
            content, tool_calls = _extract_assistant_content_and_calls(msg)
            normalized.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
            for call in tool_calls:
                call_id = call.get("id")
                if call_id:
                    tool_id_to_name[call_id] = call.get("name", "")
            continue

        if role == "tool":
            tool_name = tool_id_to_name.get(msg.get("tool_call_id", ""), "")
            normalized.append({"role": "tool", "tool_name": tool_name, "content": msg.get("content", "")})
            continue

        if role == "user":
            if isinstance(msg.get("content"), list):
                tool_blocks = [b for b in msg.get("content", []) if isinstance(b, dict)]
                if tool_blocks and any(b.get("type") == "tool_result" for b in tool_blocks):
                    for block in tool_blocks:
                        if block.get("type") != "tool_result":
                            continue
                        tool_name = tool_id_to_name.get(block.get("tool_use_id", ""), "")
                        normalized.append({"role": "tool", "tool_name": tool_name, "content": block.get("content", "")})
                    continue
            if "parts" in msg:
                parts = msg.get("parts") or []
                text_parts: list[str] = []
                for part in parts:
                    if not isinstance(part, dict):
                        continue
                    if "text" in part and isinstance(part["text"], str):
                        text_parts.append(part["text"])
                    if "function_response" in part and isinstance(part["function_response"], dict):
                        fr = part["function_response"]
                        tool_name = fr.get("name", "")
                        response = fr.get("response", "")
                        normalized.append({"role": "tool", "tool_name": tool_name, "content": response})
                if text_parts:
                    normalized.append({"role": "user", "content": "".join(text_parts)})
                continue

            normalized.append({"role": "user", "content": msg.get("content", "")})
            continue

        normalized.append({"role": role, "content": msg.get("content", "")})

    return normalized


def _extract_assistant_content_and_calls(msg: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    content = msg.get("content") or ""
    tool_calls: list[dict[str, Any]] = []

    if "tool_calls" in msg and isinstance(msg.get("tool_calls"), list):
        for call in msg.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") or {}
            arguments = fn.get("arguments")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"_raw": arguments}
            tool_calls.append(
                {
                    "id": call.get("id"),
                    "name": fn.get("name", ""),
                    "arguments": arguments if isinstance(arguments, dict) else {"_raw": arguments},
                }
            )
        return content if isinstance(content, str) else "", tool_calls

    if isinstance(content, list):
        text_parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            if block.get("type") == "tool_use":
                tool_calls.append(
                    {
                        "id": block.get("id"),
                        "name": block.get("name", ""),
                        "arguments": block.get("input") or {},
                    }
                )
        return "".join(text_parts), tool_calls

    if "parts" in msg:
        parts = msg.get("parts") or []
        text_parts: list[str] = []
        for part in parts:
            if not isinstance(part, dict):
                continue
            if "text" in part and isinstance(part["text"], str):
                text_parts.append(part["text"])
            if "function_call" in part and isinstance(part["function_call"], dict):
                fc = part["function_call"]
                tool_calls.append(
                    {
                        "id": fc.get("name"),
                        "name": fc.get("name", ""),
                        "arguments": fc.get("args") or {},
                    }
                )
        return "".join(text_parts), tool_calls

    return content if isinstance(content, str) else "", tool_calls


def _render_functiongemma_prompt(messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> str:
    default_system = "You can do function calling with the following functions:"
    sb: list[str] = ["<bos>"]

    system_message = ""
    loop_messages = messages
    if messages and messages[0].get("role") in ("system", "developer"):
        system_message = str(messages[0].get("content", "")).strip()
        loop_messages = messages[1:]

    if system_message or tools:
        sb.append("<start_of_turn>developer\n")
        if system_message:
            sb.append(system_message)
        if tools:
            if system_message:
                sb.append("\n")
            if system_message.strip() != default_system:
                sb.append(default_system)
            for tool in tools:
                sb.append(_render_function_declaration(tool))
        sb.append("<end_of_turn>\n")

    prev_message_type = ""
    for idx, message in enumerate(loop_messages):
        role = message.get("role", "user")
        if role == "assistant":
            if prev_message_type != "tool_response":
                sb.append("<start_of_turn>model\n")
            prev_message_type = ""
            content = str(message.get("content", "") or "")
            if content:
                sb.append(content.strip())
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                for call in tool_calls:
                    sb.append(_render_function_call(call))
                next_role = None
                if idx + 1 < len(loop_messages):
                    next_role = loop_messages[idx + 1].get("role")
                if next_role == "tool":
                    sb.append("<start_function_response>")
                    prev_message_type = "tool_call"
                else:
                    sb.append("<end_of_turn>\n")
            else:
                sb.append("<end_of_turn>\n")
        elif role == "user":
            if prev_message_type != "tool_response":
                sb.append("<start_of_turn>user\n")
            prev_message_type = ""
            content = str(message.get("content", "") or "")
            sb.append(content.strip())
            sb.append("<end_of_turn>\n")
        elif role == "tool":
            tool_name = message.get("tool_name", "")
            if prev_message_type != "tool_call":
                sb.append("<start_function_response>")
            sb.append(f"response:{tool_name}{{{_format_fg_value(message.get('content'))}}}<end_function_response>")
            prev_message_type = "tool_response"
        else:
            sb.append(f"<start_of_turn>{role}\n")
            sb.append(str(message.get("content", "") or "").strip())
            sb.append("<end_of_turn>\n")

    if prev_message_type != "tool_response":
        sb.append("<start_of_turn>model\n")

    return "".join(sb)


def _render_functiongemma_completion(response: dict[str, Any]) -> str:
    content = str(response.get("content") or "")
    tool_calls = response.get("tool_calls") or []
    sb: list[str] = []
    if content:
        sb.append(content.strip())
    if tool_calls:
        for call in tool_calls:
            sb.append(_render_function_call(call))
    else:
        sb.append("<end_of_turn>\n")
    return "".join(sb)


def _render_function_declaration(tool: dict[str, Any]) -> str:
    name = tool.get("name", "")
    description = tool.get("description", "")
    params = tool.get("parameters") or {}
    sb: list[str] = [f"<start_function_declaration>declaration:{name}{{"]
    sb.append(f"description:<escape>{description}<escape>")

    if params.get("properties") or params.get("type"):
        sb.append(",parameters:{")
        needs_comma = False
        properties = params.get("properties") or {}
        if properties:
            sb.append("properties:{")
            sb.append(_render_function_properties(properties))
            sb.append("}")
            needs_comma = True
        required = params.get("required") or []
        if required:
            if needs_comma:
                sb.append(",")
            sb.append("required:[")
            for idx, req in enumerate(required):
                if idx > 0:
                    sb.append(",")
                sb.append(f"<escape>{req}<escape>")
            sb.append("]")
            needs_comma = True
        param_type = _normalize_type(params.get("type"))
        if param_type:
            if needs_comma:
                sb.append(",")
            sb.append(f"type:<escape>{param_type}<escape>")
        sb.append("}")
    sb.append("}<end_function_declaration>")
    return "".join(sb)


def _render_function_properties(properties: dict[str, Any]) -> str:
    items: list[str] = []
    for name in sorted(properties.keys()):
        prop = properties.get(name) or {}
        desc = prop.get("description", "")
        ptype = _normalize_type(prop.get("type"))
        segment = [f"{name}:{{description:<escape>{desc}<escape>"]
        if ptype:
            segment.append(f",type:<escape>{ptype}<escape>")
        segment.append("}")
        items.append("".join(segment))
    return ",".join(items)


def _render_function_call(call: dict[str, Any]) -> str:
    name = call.get("name", "")
    args = call.get("arguments") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {"_raw": args}
    if not isinstance(args, dict):
        args = {"_raw": args}

    sb: list[str] = [f"<start_function_call>call:{name}{{"]
    keys = sorted(args.keys())
    first = True
    for key in keys:
        if not first:
            sb.append(",")
        first = False
        sb.append(f"{key}:{_format_fg_value(args[key])}")
    sb.append("}<end_function_call>")
    return "".join(sb)


def _normalize_type(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if value else ""
    if isinstance(value, str):
        return value.upper()
    return str(value).upper()


def _format_fg_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, str):
        return f"<escape>{value}<escape>"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            parts.append(f"{key}:{_format_fg_value(value[key])}")
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_format_fg_value(item) for item in value) + "]"
    return f"<escape>{value}<escape>"


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert ALF trace JSONL to training-friendly JSONL.")
    parser.add_argument("input", help="Path to trace JSONL.")
    parser.add_argument("output", help="Path to output JSONL.")
    parser.add_argument(
        "--format",
        choices=["dataset", "openai", "functiongemma"],
        default="dataset",
        help=(
            "Output format. 'dataset' keeps expected output separate; "
            "'openai' appends assistant tool_calls; "
            "'functiongemma' emits tokenized prompt/response."
        ),
    )
    parser.add_argument(
        "--max-messages",
        type=int,
        default=20,
        help="Max messages to keep from the end of the history (0 = keep all).",
    )
    parser.add_argument(
        "--max-content-chars",
        type=int,
        default=4000,
        help="Max characters to keep per message content (0 = keep all).",
    )
    parser.add_argument(
        "--include-results",
        action="store_true",
        help="Include tool_results from the trace in each record.",
    )
    parser.add_argument(
        "--include-final",
        action="store_true",
        help="Include final_response events (no tool calls) as training records.",
    )
    parser.add_argument(
        "--only-success",
        action="store_true",
        help="Only include tool_turn events where all tool results succeeded.",
    )
    parser.add_argument(
        "--redact-prefix",
        action="append",
        default=[],
        help="String prefix to redact from outputs (repeatable).",
    )
    parser.add_argument(
        "--redact-replacement",
        default="<PATH>",
        help="Replacement string for redacted prefixes (default: <PATH>).",
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    tools_by_run: dict[str, list[dict[str, Any]] | None] = {}

    records: list[dict[str, Any]] = []

    for event in _load_jsonl(input_path):
        if not isinstance(event, dict):
            continue
        run_id = event.get("run_id")
        event_name = event.get("event")

        if event_name == "loop_start" and run_id:
            tools_by_run[run_id] = event.get("tools")
            continue

        if event_name == "tool_turn":
            if args.only_success and not _tool_call_success(event):
                continue
            tools = tools_by_run.get(run_id)
            record = _build_record(
                event,
                tools,
                max_messages=args.max_messages,
                max_chars=args.max_content_chars,
                include_results=args.include_results,
                format_name=args.format,
                redact_prefixes=args.redact_prefix,
                redact_replacement=args.redact_replacement,
            )
            records.append(record)
            continue

        if event_name == "final_response" and args.include_final:
            tools = tools_by_run.get(run_id)
            record = _build_record(
                event,
                tools,
                max_messages=args.max_messages,
                max_chars=args.max_content_chars,
                include_results=args.include_results,
                format_name=args.format,
                redact_prefixes=args.redact_prefix,
                redact_replacement=args.redact_replacement,
            )
            records.append(record)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")

    print(f"[+] Wrote {len(records)} records to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
