#!/usr/bin/env python3
"""
Generate a Markdown Root Cause Analysis (RCA) report from ALF crash artifacts.

Inputs:
- A `lldb_crash_context` JSON file, OR
- A full MCP triage JSON log produced by `alf analyze triage` (it embeds crash_context).

Optionally merges a classifier JSON (from `alf analyze classify`) to fill in vulnerability type.

Usage with config objects:
    from alf.triage.config import ReportConfig
    from alf.triage.report import run_report

    config = ReportConfig(context_json=Path("triage.json"))
    result = run_report(config)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .exploitability import format_exploitability_section, score_exploitability

if TYPE_CHECKING:
    from .config import ReportConfig, ReportResult


def repo_root_from_path(path: Path) -> Path:
    cur = path.resolve()
    for parent in [cur, *cur.parents]:
        if (parent / ".git").is_dir():
            return parent
        # Fallback for Docker/Archive: look for key directories
        if (parent / "alf").is_dir() and (parent / "logs").is_dir():
            return parent
    return Path.cwd()


def load_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except Exception as e:  # noqa: BLE001
        return {"error": f"failed to load json: {e}", "raw_path": str(path)}


def load_crash_context(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Returns (crash_context, metadata).
    Accepts either a direct crash_context JSON or a triage JSON containing playbook.
    """
    data = load_json_file(path)
    if "frames" in data or "stack_hash" in data or "registers" in data:
        return data, {}

    playbook = data.get("playbook")
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    if isinstance(playbook, dict) and "crash_context" in playbook:
        ctx_text = playbook.get("crash_context", "")
        if isinstance(ctx_text, str):
            try:
                return json.loads(ctx_text), metadata
            except Exception:
                return {"raw_crash_context": ctx_text}, metadata

    return data, metadata


def load_classification(path: Path | None) -> dict[str, Any]:
    if not path:
        return {}
    return load_json_file(path)


def parse_registers(raw: str) -> dict[str, str]:
    regs: dict[str, str] = {}
    for line in (raw or "").splitlines():
        m = re.match(r"^\s*([a-z0-9]+)\s*=\s*(0x[0-9a-fA-F]+)", line)
        if not m:
            continue
        name = m.group(1).lower()
        val = m.group(2)
        regs[name] = val
    return regs


def infer_function(frames: list[dict[str, Any]] | None) -> str:
    if not frames:
        return "unknown_function"
    for f in frames:
        name = str(f.get("name") or "").strip()
        if name and name != "??":
            return name.split("(")[0].strip()
    return "unknown_function"


def generate_markdown(
    crash_ctx: dict[str, Any],
    classification: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    *,
    include_exploitability: bool = True,
) -> str:
    classification = classification or {}
    metadata = metadata or {}

    frames = crash_ctx.get("frames")
    frames_list: list[dict[str, Any]] = frames if isinstance(frames, list) else []
    func_name = infer_function(frames_list)

    vuln_type = str(classification.get("classification") or "unclassified")
    confidence = classification.get("confidence")
    conf_str = f"{confidence:.2f}" if isinstance(confidence, (float, int)) else "n/a"

    reason = crash_ctx.get("reason") or crash_ctx.get("stop", {}).get("reason") or "unknown"
    pcs = crash_ctx.get("pcs") if isinstance(crash_ctx.get("pcs"), list) else []
    fault_pc = pcs[0] if pcs else None
    stack_hash = crash_ctx.get("stack_hash") or ""

    regs_raw = str(crash_ctx.get("registers") or "")
    regs = parse_registers(regs_raw)
    disasm = str(crash_ctx.get("disassemble") or "")
    stack_bytes = str(crash_ctx.get("stack_bytes") or "")

    ts = metadata.get("timestamp") or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = metadata.get("target") or metadata.get("binary") or "unknown_target"
    binary = metadata.get("binary") or ""
    crash_input = metadata.get("crash") or ""
    if metadata.get("repro_cmd"):
        repro_cmd = str(metadata["repro_cmd"])
    elif binary and crash_input:
        repro_cmd = f"{binary} -runs=1 {crash_input}".strip()
    else:
        repro_cmd = ""

    lines: list[str] = []
    lines.append(f"# Root Cause Analysis: in `{func_name}`")
    lines.append("")
    lines.append(f"Date: {ts}")
    lines.append(f"Target: `{target}`")
    lines.append(f"Vulnerability Type: {vuln_type} (confidence {conf_str})")
    if stack_hash:
        lines.append(f"Stack Hash: `{stack_hash}`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(f"The process stopped with reason `{reason}`" + (f" at `{fault_pc}`." if fault_pc else "."))
    if pcs:
        lines.append(f"Top PCs: {', '.join(pcs[:5])}")
    if classification.get("summary"):
        lines.append("")
        lines.append(str(classification["summary"]).strip())
    lines.append("")

    lines.append("## Technical Details")
    lines.append("")
    lines.append("### Register State (arm64e)")
    if regs:
        lines.append("| Register | Value |")
        lines.append("|:--|:--|")
        for key in ("pc", "sp", "x0", "x1", "x2", "x3"):
            if key in regs:
                lines.append(f"| `{key}` | `{regs[key]}` |")
        lines.append("")
    lines.append("```")
    lines.append(regs_raw.strip() or "(no registers captured)")
    lines.append("```")
    lines.append("")

    lines.append("### Faulting Instruction")
    lines.append("```")
    lines.append(disasm.strip() or "(no disassembly captured)")
    lines.append("```")
    lines.append("")

    lines.append("### Stack Trace")
    if frames_list:
        for idx, f in enumerate(frames_list):
            name = f.get("name", "??")
            pc = f.get("pc")
            loc = ""
            if f.get("file") and f.get("line"):
                loc = f" at {f.get('file')}:{f.get('line')}"
            lines.append(f"{idx + 1}. `{name}` ({pc}){loc}")
    else:
        lines.append("(no frames captured)")
    lines.append("")

    lines.append("### Stack Bytes")
    lines.append("```")
    lines.append(stack_bytes.strip() or "(no stack bytes captured)")
    lines.append("```")
    lines.append("")

    # Exploitability assessment
    if include_exploitability:
        exploit_result = score_exploitability(crash_ctx, reason=reason)
        lines.append(format_exploitability_section(exploit_result))

    lines.append("## Reproduction")
    if repro_cmd:
        lines.append("```bash")
        lines.append(repro_cmd)
        lines.append("```")
    else:
        lines.append("Repro command unavailable; see metadata in triage logs.")
    lines.append("")

    if classification.get("recommended_actions"):
        lines.append("## Recommended Actions")
        recs = classification["recommended_actions"]
        if isinstance(recs, list):
            for r in recs:
                lines.append(f"- {r}")
        else:
            lines.append(str(recs))
        lines.append("")

    if classification.get("patch_hint"):
        lines.append("## Patch Hint")
        lines.append(str(classification["patch_hint"]).strip())
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def run_report(config: ReportConfig) -> ReportResult:
    """Generate RCA report from a ReportConfig object.

    Args:
        config: Report configuration with paths and options.

    Returns:
        ReportResult with success status and output path.
    """
    from .config import ReportResult

    if not config.context_json.exists():
        return ReportResult(success=False, error=f"context json not found: {config.context_json}")

    crash_ctx, metadata = load_crash_context(config.context_json)
    classification = load_classification(config.classification_json)

    md = generate_markdown(crash_ctx, classification, metadata, include_exploitability=config.exploitability)

    repo_root = repo_root_from_path(config.context_json)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    target = metadata.get("target") or Path(metadata.get("binary", "unknown")).stem

    if config.output:
        out_path = config.output
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        logs_dir = repo_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        out_path = logs_dir / f"{stamp}_{target}_rca_{config.tag}.md"

    out_path.write_text(md, encoding="utf-8")
    return ReportResult(success=True, output_path=out_path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate a Markdown RCA report from ALF logs.")
    p.add_argument(
        "--context-json",
        help="Path to lldb_crash_context JSON (or triage JSON embedding it).",
        required=True,
    )
    p.add_argument(
        "--classification-json",
        help="Optional classification JSON from `alf analyze classify`.",
        default=None,
    )
    p.add_argument("--output", help="Write Markdown to this path (default logs/).", default=None)
    p.add_argument("--tag", help="Tag for output filename.", default="rca")
    p.add_argument(
        "--exploitability",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Include exploitability assessment (default: enabled).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point - parses args and delegates to run_report."""
    from .config import ReportConfig

    args = parse_args(argv)

    config = ReportConfig(
        context_json=Path(args.context_json),
        classification_json=Path(args.classification_json) if args.classification_json else None,
        output=Path(args.output) if args.output else None,
        tag=args.tag,
        exploitability=args.exploitability,
    )

    result = run_report(config)

    if not result.success:
        print(f"[-] {result.error}", file=sys.stderr)
        return 1

    print(f"[+] Wrote RCA report: {result.output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
