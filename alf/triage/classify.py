#!/usr/bin/env python3
"""
Classify sanitizer/LLDB crashes with optional LLM assistance.

Flow:
1. Gather crash artifacts (triage logs, DAP JSON, etc.).
2. Write the exact LLM prompt under prompts/YYYYMMDD_target_classify_model.txt.
3. Call an LLM adapter (or fallback heuristics) to obtain a JSON verdict.
4. Persist the structured result under logs/YYYYMMDD_target_classify_model.json.

Usage with config objects:
    from alf.triage.config import ClassifyConfig
    from alf.triage.classify import run_classify

    config = ClassifyConfig(binary=Path("./fuzz"), crash=Path("./crash-abc"))
    result = run_classify(config)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..providers.config import get_config
from .exploitability import ExploitabilityResult, score_exploitability

if TYPE_CHECKING:
    from .config import ClassifyConfig, ClassifyResult

DEFAULT_ADAPTER = os.environ.get("ALF_LLM_ADAPTER_BIN", "alf-llm")


def _get_default_model() -> str:
    """Get default model from config (TOML > env > fallback)."""
    config = get_config()
    return config.model or "gpt-4o-mini"


PROMPT_HEAD = "System Prompt:\n"
USER_HEAD = "\n\nUser Prompt:\n"


def repo_root_from_path(path: Path) -> Path:
    """Resolve repo root. Defaults to CWD if .git not found."""
    cur = path.resolve()
    for parent in [cur, *cur.parents]:
        if (parent / ".git").is_dir():
            return parent
    return Path.cwd()


def infer_target(binary_path: Path) -> str:
    """Infer fuzz target name from binary path."""
    parts = binary_path.parts
    if "harnesses" in parts:
        idx = parts.index("harnesses")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return binary_path.stem


def tail_excerpt(path: Path, max_lines: int = 200) -> str:
    """Return the last max_lines lines from a text file."""
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return ""
    lines = text.splitlines()
    excerpt = "\n".join(lines[-max_lines:])
    return excerpt.strip()


def load_json(path: Path, max_keys: int = 8) -> str:
    """Render a compact preview of JSON triage logs."""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return ""

    def _shorten(obj: Any, depth: int = 0) -> Any:
        if depth > 2:
            return "... (truncated)"
        if isinstance(obj, dict):
            items = list(obj.items())[:max_keys]
            return {k: _shorten(v, depth + 1) for k, v in items}
        if isinstance(obj, list):
            return [_shorten(v, depth + 1) for v in obj[:max_keys]]
        if isinstance(obj, str) and len(obj) > 240:
            return obj[:240] + "... (truncated)"
        return obj

    shortened = _shorten(data)
    return json.dumps(shortened, indent=2)


def heuristic_classify(log_blobs: list[str]) -> tuple[str, float, list[str]]:
    """Basic classifier if MCP is unavailable."""
    joined = "\n".join(log_blobs).lower()
    mapping = [
        ("pointer_overflow", 0.6, [r"pointer overflow", r"ubsan"]),
        ("heap_use_after_free", 0.55, [r"use-after-free", r"heap-use-after-free"]),
        ("stack_buffer_overflow", 0.55, [r"stack-buffer-overflow"]),
        ("null_dereference", 0.5, [r"null pointer", r"nullptr"]),
        ("out_of_bounds_read", 0.45, [r"out-of-bounds", r"heap-buffer-overflow"]),
    ]
    for label, confidence, patterns in mapping:
        if all(re.search(pattern, joined) for pattern in patterns):
            return label, confidence, patterns
        if any(re.search(pattern, joined) for pattern in patterns):
            return label, confidence - 0.1, patterns
    return "unclassified", 0.2, []


def build_prompts(
    metadata: dict[str, Any],
    triage_snippets: list[str],
    model: str,
    exploitability: ExploitabilityResult | None = None,
) -> tuple[str, str]:
    """Craft system + user prompts for the LLM."""
    system_prompt = (
        "You are an LLDB and sanitizer triage expert. Classify crashes, identify root causes, "
        "and recommend next automation steps. Respond ONLY in JSON with keys: "
        "classification (string), confidence (0-1 float), summary (string), "
        "key_signals (array of short strings), recommended_actions (array of strings), "
        "reproduction (string), patch_hint (string)."
    )
    body_lines = [
        f"Timestamp: {metadata['timestamp']}",
        f"Target: {metadata['target']}",
        f"Binary: {metadata['binary']}",
        f"Crash input: {metadata['crash']}",
        f"Suggested repro: {metadata['repro_cmd']}",
        f"Host OS: {metadata['host']}",
        f"Model: {model}",
    ]
    if metadata.get("tag"):
        body_lines.append(f"Tag: {metadata['tag']}")

    # Include exploitability analysis if available
    if exploitability:
        body_lines.append(
            f"\nExploitability: {exploitability.classification.value} (confidence {exploitability.confidence:.2f})"
        )
        if exploitability.crash_type:
            body_lines.append(f"Crash Type: {exploitability.crash_type}")
        if exploitability.cwe_ids:
            body_lines.append(f"CWE IDs: {', '.join(exploitability.cwe_ids)}")
        if exploitability.reasons:
            body_lines.append("Analysis:")
            for reason in exploitability.reasons[:5]:  # Limit to top 5 reasons
                body_lines.append(f"  - {reason}")

    for snippet in triage_snippets:
        if snippet:
            body_lines.append("\n--- LOG SNIPPET ---\n" + snippet)
    body_lines.append("\nReturn the JSON object now.")
    user_prompt = "\n".join(body_lines)
    return system_prompt, user_prompt


def _sanitize_model_name(model: str) -> str:
    """Sanitize model name for use in filenames."""
    # Replace slashes and other problematic chars with underscore
    return model.replace("/", "_").replace("\\", "_").replace(":", "_")


def write_prompt_file(
    prompts_dir: Path,
    stamp: str,
    target: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> Path:
    """Persist the prompts for auditability."""
    prompts_dir.mkdir(parents=True, exist_ok=True)
    safe_model = _sanitize_model_name(model)
    filename = f"{stamp}_{target}_classify_{safe_model}.txt"
    path = prompts_dir / filename
    with path.open("w", encoding="utf-8") as fp:
        fp.write(PROMPT_HEAD)
        fp.write(system_prompt)
        fp.write(USER_HEAD)
        fp.write(user_prompt)
    return path


def call_lldb_mcp(adapter: str, payload: dict[str, Any], timeout: int) -> tuple[dict[str, Any] | None, str]:
    """Invoke the configured LLM adapter with JSON payload; return parsed JSON or raw output."""
    adapter_cmd: list[str] | None = None
    found = shutil.which(adapter)
    if found:
        adapter_cmd = [found]
    elif adapter in ("alf-llm", "alf.llm_adapter"):
        adapter_cmd = [sys.executable, "-m", "alf.llm_adapter"]
    if adapter_cmd is None:
        return None, f"LLM adapter '{adapter}' not found."
    try:
        proc = subprocess.run(
            [*adapter_cmd, "chat"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "LLM adapter call timed out."
    except FileNotFoundError:
        return None, f"LLM adapter '{adapter}' not found."

    stdout = proc.stdout.strip()
    if proc.returncode != 0:
        return None, f"LLM adapter failed: {proc.stderr.strip() or stdout}"
    try:
        return json.loads(stdout), stdout
    except json.JSONDecodeError:
        return None, stdout


def write_result_file(logs_dir: Path, stamp: str, target: str, model: str, result: dict[str, Any]) -> Path:
    """Persist classifier output."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    safe_model = _sanitize_model_name(model)
    path = logs_dir / f"{stamp}_{target}_classify_{safe_model}.json"
    with path.open("w", encoding="utf-8") as fp:
        json.dump(result, fp, indent=2)
        fp.write("\n")
    return path


def build_metadata(args: argparse.Namespace, binary: Path, crash: Path, repo_root: Path, target: str) -> dict[str, Any]:
    """Assemble metadata dict for prompts/result."""
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    host = os.uname().sysname + " " + os.uname().release
    return {
        "timestamp": timestamp,
        "target": target,
        "binary": str(binary),
        "crash": str(crash),
        "repo_root": str(repo_root),
        "tag": args.tag,
        "repro_cmd": f"{binary} -runs=1 {crash}",
        "host": host,
    }


def _build_metadata_from_config(config: ClassifyConfig, repo_root: Path, target: str) -> dict[str, Any]:
    """Assemble metadata dict from config object."""
    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    host = os.uname().sysname + " " + os.uname().release
    return {
        "timestamp": timestamp,
        "target": target,
        "binary": str(config.binary),
        "crash": str(config.crash),
        "repo_root": str(repo_root),
        "tag": config.tag,
        "repro_cmd": f"{config.binary} -runs=1 {config.crash}",
        "host": host,
    }


def run_classify(config: ClassifyConfig) -> ClassifyResult:
    """Run classification from a ClassifyConfig object.

    Args:
        config: Classification configuration with paths and options.

    Returns:
        ClassifyResult with success status and classification data.
    """
    from .config import ClassifyResult

    # Validate paths
    if not config.binary.exists():
        return ClassifyResult(success=False, error=f"binary not found: {config.binary}")
    if not config.crash.exists():
        return ClassifyResult(success=False, error=f"crash input not found: {config.crash}")

    # Resolve model from config if not specified
    model = config.model or _get_default_model()

    repo_root = repo_root_from_path(config.binary)
    prompts_dir = repo_root / "prompts"
    logs_dir = repo_root / "logs"
    target = infer_target(config.binary)
    metadata = _build_metadata_from_config(config, repo_root, target)

    # Gather triage snippets
    triage_snippets: list[str] = []
    for log_path in config.triage_logs:
        snippet = tail_excerpt(log_path, config.max_log_lines)
        if snippet:
            triage_snippets.append(snippet)
    for dap_path in config.dap_logs:
        snippet = load_json(dap_path)
        if snippet:
            triage_snippets.append("DAP JSON excerpt:\n" + snippet)
    triage_snippets.extend(config.extra_notes)

    # Compute exploitability if enabled and crash context is available
    exploitability_result: ExploitabilityResult | None = None
    if config.exploitability and config.crash_context and config.crash_context.exists():
        try:
            crash_ctx = json.loads(config.crash_context.read_text())
            exploitability_result = score_exploitability(crash_ctx)
        except Exception:
            pass  # Silently skip exploitability on error

    system_prompt, user_prompt = build_prompts(metadata, triage_snippets, model, exploitability_result)
    prompt_file = write_prompt_file(prompts_dir, metadata["timestamp"], target, model, system_prompt, user_prompt)

    heuristic_label, heuristic_conf, patterns = heuristic_classify(triage_snippets)
    heuristic_summary: dict[str, Any] = {
        "classification": heuristic_label,
        "confidence": heuristic_conf,
        "summary": "Heuristic fallback classification.",
        "key_signals": patterns,
        "recommended_actions": [
            "Inspect sanitizer log manually.",
            "Run `alf analyze triage` for detailed LLDB output.",
        ],
        "reproduction": metadata["repro_cmd"],
        "patch_hint": "Review offending frames and add bounds checks.",
        "source": "heuristic",
    }
    if exploitability_result:
        heuristic_summary["exploitability"] = exploitability_result.to_dict()

    def _write_result(result_data: dict[str, Any]) -> Path:
        if config.output:
            config.output.parent.mkdir(parents=True, exist_ok=True)
            config.output.write_text(json.dumps(result_data, indent=2) + "\n", encoding="utf-8")
            return config.output
        return write_result_file(logs_dir, metadata["timestamp"], target, model, result_data)

    if config.dry_run:
        result_path = _write_result(heuristic_summary)
        return ClassifyResult(
            success=True,
            classification=heuristic_label,
            confidence=heuristic_conf,
            source="heuristic",
            json_path=result_path,
            prompt_path=prompt_file,
            exploitability=exploitability_result.to_dict() if exploitability_result else None,
        )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    mcp_result, raw_output = call_lldb_mcp(config.adapter, payload, config.timeout)

    if mcp_result is None:
        combined = heuristic_summary
        combined["source"] = "heuristic-fallback"
        source = "heuristic-fallback"
    else:
        combined = {
            "classification": mcp_result.get("classification", "unknown"),
            "confidence": float(mcp_result.get("confidence", heuristic_conf)),
            "summary": mcp_result.get("summary", ""),
            "key_signals": mcp_result.get("key_signals", []),
            "recommended_actions": mcp_result.get("recommended_actions", []),
            "reproduction": mcp_result.get("reproduction", metadata["repro_cmd"]),
            "patch_hint": mcp_result.get("patch_hint", ""),
            "source": "llm-adapter",
            "raw_response": mcp_result,
        }
        if exploitability_result:
            combined["exploitability"] = exploitability_result.to_dict()
        source = "llm-adapter"

    result_path = _write_result(combined)

    return ClassifyResult(
        success=True,
        classification=combined["classification"],
        confidence=combined["confidence"],
        source=source,
        json_path=result_path,
        prompt_path=prompt_file,
        exploitability=exploitability_result.to_dict() if exploitability_result else None,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify fuzz crashes (optional LLM adapter).")
    parser.add_argument("--binary", required=True, help="Path to fuzz binary (absolute or relative).")
    parser.add_argument("--crash", required=True, help="Path to crashing input.")
    parser.add_argument("--triage-log", action="append", default=[], help="Path to sanitizer/LLDB triage logs.")
    parser.add_argument("--dap-log", action="append", default=[], help="Path to DAP JSON logs.")
    parser.add_argument("--tag", default="triage", help="Tag/identifier for this classification run.")
    parser.add_argument("--model", default=None, help="LLM model for the adapter (default: from config).")
    parser.add_argument("--adapter", default=DEFAULT_ADAPTER, help="LLM adapter binary (default: alf-llm).")
    parser.add_argument("--timeout", type=int, default=180, help="LLM adapter timeout in seconds.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip LLM call; output heuristic classification only.",
    )
    parser.add_argument("--output", default=None, help="Write classification JSON to this path (default logs/).")
    parser.add_argument("--max-log-lines", type=int, default=200, help="Max lines to include per log snippet.")
    parser.add_argument("--extra-note", action="append", default=[], help="Additional context strings for the prompt.")
    parser.add_argument(
        "--exploitability",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Include exploitability analysis (default: enabled).",
    )
    parser.add_argument(
        "--crash-context",
        default=None,
        help="Path to crash context JSON for exploitability analysis.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point - parses args and delegates to run_classify."""
    from .config import ClassifyConfig

    args = parse_args(argv)

    config = ClassifyConfig(
        binary=Path(args.binary),
        crash=Path(args.crash),
        triage_logs=[Path(p) for p in args.triage_log],
        dap_logs=[Path(p) for p in args.dap_log],
        tag=args.tag,
        model=args.model,
        adapter=args.adapter,
        timeout=args.timeout,
        dry_run=args.dry_run,
        output=Path(args.output) if args.output else None,
        max_log_lines=args.max_log_lines,
        extra_notes=list(args.extra_note),
        exploitability=args.exploitability,
        crash_context=Path(args.crash_context) if args.crash_context else None,
    )

    result = run_classify(config)

    if not result.success:
        print(f"[-] {result.error}", file=sys.stderr)
        return 1

    if config.dry_run:
        print(f"[dry-run] Stored heuristic classification at {result.json_path}")
        print(f"[dry-run] Prompt saved to {result.prompt_path}")
    else:
        print(f"[+] Prompt saved to {result.prompt_path}")
        print(f"[+] Classification saved to {result.json_path}")
        print(f"[+] Result: {result.classification} (confidence {result.confidence:.2f})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
