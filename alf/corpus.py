#!/usr/bin/env python3
"""
Corpus/seed generation from crash inputs.

Generates new fuzzer seeds based on crash analysis using heuristics
and optionally LLM-guided mutation suggestions.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import Any


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def infer_target(binary_path: Path) -> str:
    parts = binary_path.parts
    if "harnesses" in parts:
        idx = parts.index("harnesses")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return binary_path.stem


def crash_hash(crash_path: Path) -> str:
    name = crash_path.name
    name = name.replace("crash-", "").replace("timeout-", "")
    return name[:12] if name else "unknown"


def ascii_tokens(data: bytes) -> list[str]:
    """Extract ASCII tokens (4+ printable chars) from binary data."""
    toks = re.findall(rb"[ -~]{4,}", data)
    out: list[str] = []
    for t in toks:
        try:
            out.append(t.decode("ascii"))
        except Exception:
            continue
    return out


def heuristic_mutations(data: bytes) -> list[tuple[str, bytes]]:
    """Generate heuristic corpus mutations from crash input.

    Returns list of (name, bytes) tuples for new seeds.
    """
    corpus: list[tuple[str, bytes]] = []

    # Binary plist format: BPLIST10 + 4-byte length
    if data.startswith(b"BPLIST10") and len(data) >= 12:
        cur_len = int.from_bytes(data[8:12], "big")
        for delta in (-1, 0, 1, 4, 16):
            new_len = max(0, cur_len + delta)
            mutated = bytearray(data)
            mutated[8:12] = new_len.to_bytes(4, "big")
            corpus.append((f"bplist_len_{new_len}", bytes(mutated)))

    # CRSH magic (test format)
    if data.startswith(b"CRSH") and len(data) >= 5:
        for ch in (b"A", b"B", b"C", b"Z"):
            mutated = bytearray(data)
            mutated[4:5] = ch
            corpus.append((f"crsh_{ch.decode()}", bytes(mutated)))

    # XPC/plist-like markers
    if b"bplist" in data.lower() or b"<?xml" in data:
        # Try truncating at various points
        for frac in (0.25, 0.5, 0.75):
            cut = max(1, int(len(data) * frac))
            corpus.append((f"trunc_{int(frac * 100)}pct", data[:cut]))

    # Generic mutations if nothing format-specific matched
    if not corpus:
        corpus.append(("orig", data))
        corpus.append(("trunc_half", data[: max(1, len(data) // 2)]))
        corpus.append(("extend_null", data + b"\x00"))
        corpus.append(("extend_8A", data + b"A" * 8))
        if data:
            mutated = bytearray(data)
            mutated[0] ^= 0xFF
            corpus.append(("flip_byte0", bytes(mutated)))
        if len(data) > 1:
            mutated = bytearray(data)
            mutated[-1] ^= 0xFF
            corpus.append(("flip_last", bytes(mutated)))

    # Boundary mutations
    if len(data) >= 4:
        # Insert max int values at start
        corpus.append(("prepend_ffff", b"\xff\xff\xff\xff" + data))
        corpus.append(("prepend_7fff", b"\x7f\xff\xff\xff" + data))

    return corpus[:16]  # Limit to 16 seeds


def extract_dict_tokens(data: bytes) -> list[bytes]:
    """Extract tokens suitable for fuzzer dictionary."""
    tokens: list[bytes] = []

    # ASCII strings
    for tok in ascii_tokens(data):
        if 4 <= len(tok) <= 64:
            tokens.append(tok.encode("utf-8"))

    # Magic bytes patterns (first 4/8 bytes if they look meaningful)
    if len(data) >= 4 and not all(b == 0 for b in data[:4]):
        tokens.append(data[:4])
    if len(data) >= 8 and not all(b == 0 for b in data[:8]):
        tokens.append(data[:8])

    # Deduplicate while preserving order
    seen: set[bytes] = set()
    unique: list[bytes] = []
    for tok in tokens:
        if tok not in seen:
            seen.add(tok)
            unique.append(tok)

    return unique[:32]  # Limit to 32 tokens


def dict_line(token_bytes: bytes) -> str:
    """Format a token for AFL/libFuzzer dictionary format."""
    printable = all(32 <= b < 127 and b not in (34, 92) for b in token_bytes)
    if printable:
        return f'"{token_bytes.decode("ascii")}"'
    return '"' + "".join(f"\\x{b:02x}" for b in token_bytes) + '"'


def write_corpus(
    out_dir: Path,
    seeds: list[tuple[str, bytes]],
) -> list[Path]:
    """Write corpus seeds to directory.

    Returns list of written file paths.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for i, (name, blob) in enumerate(seeds):
        path = out_dir / f"seed-{i:03d}_{name}"
        path.write_bytes(blob)
        written.append(path)
    return written


def write_dict(dict_path: Path, tokens: list[bytes]) -> int:
    """Append tokens to fuzzer dictionary file.

    Returns number of new tokens added.
    """
    dict_path.parent.mkdir(parents=True, exist_ok=True)

    existing: set[str] = set()
    if dict_path.exists():
        for line in dict_path.read_text(errors="ignore").splitlines():
            existing.add(line.strip())

    new_lines: list[str] = []
    for tok in tokens:
        line = dict_line(tok)
        if line not in existing:
            new_lines.append(line)
            existing.add(line)

    if new_lines:
        with dict_path.open("a", encoding="utf-8") as fp:
            for line in new_lines:
                fp.write(line + "\n")

    return len(new_lines)


def generate_corpus(
    binary: str,
    crash: str,
    output_dir: str | None = None,
    dict_path: str | None = None,
    use_llm: bool = False,
    model: str = "gpt-4o-mini",
    provider: str | None = None,
) -> dict[str, Any]:
    """Generate corpus seeds and dictionary tokens from a crash.

    Args:
        binary: Path to target binary.
        crash: Path to crash input file.
        output_dir: Directory for corpus seeds (default: corpora/<target>/generated/).
        dict_path: Path for dictionary file (default: corpora/<target>/crash.dict).
        use_llm: Use LLM to suggest additional mutations.
        model: LLM model name.
        provider: LLM provider name (auto-detected if not specified).

    Returns:
        Dict with generation results.
    """
    binary_path = Path(binary).resolve()
    crash_path = Path(crash).resolve()

    if not binary_path.exists():
        return {"error": f"binary not found: {binary_path}"}
    if not crash_path.exists():
        return {"error": f"crash input not found: {crash_path}"}

    # Read crash data
    crash_data = crash_path.read_bytes()
    if len(crash_data) > 1024 * 1024:  # 1MB limit
        crash_data = crash_data[: 1024 * 1024]

    root = repo_root()
    target = infer_target(binary_path)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    hsh = crash_hash(crash_path)

    # Generate heuristic mutations
    seeds = heuristic_mutations(crash_data)
    tokens = extract_dict_tokens(crash_data)

    # Optionally use LLM for additional suggestions
    llm_seeds: list[tuple[str, bytes]] = []
    llm_tokens: list[bytes] = []
    if use_llm:
        try:
            llm_result = _llm_suggest_mutations(crash_data, model, provider)
            llm_seeds = llm_result.get("seeds", [])
            llm_tokens = llm_result.get("tokens", [])
        except Exception as e:
            print(f"[!] LLM suggestion failed: {e}", file=sys.stderr)

    # Combine results
    all_seeds = seeds + llm_seeds
    all_tokens = tokens + llm_tokens

    # Determine output paths
    if output_dir:
        corpus_dir = Path(output_dir).resolve()
    else:
        corpus_dir = root / "corpora" / target / "generated" / f"{stamp}_{hsh}"

    if dict_path:
        dict_file = Path(dict_path).resolve()
    else:
        dict_file = root / "corpora" / target / "crash.dict"

    # Write outputs
    written_seeds = write_corpus(corpus_dir, all_seeds)
    new_dict_count = write_dict(dict_file, all_tokens)

    return {
        "target": target,
        "crash": str(crash_path),
        "crash_hash": hsh,
        "corpus_dir": str(corpus_dir),
        "seeds_written": len(written_seeds),
        "seed_names": [s.name for s in written_seeds],
        "dict_path": str(dict_file),
        "dict_tokens_added": new_dict_count,
        "used_llm": use_llm and bool(llm_seeds or llm_tokens),
    }


def _llm_suggest_mutations(
    crash_data: bytes,
    model: str,
    provider: str | None,
) -> dict[str, Any]:
    """Use LLM to suggest additional mutations (optional)."""
    from alf.providers import ChatMessage, ChatRequest, get_provider

    llm = get_provider(provider)

    # Prepare crash summary for LLM
    crash_hex = crash_data[:256].hex()
    ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in crash_data[:128])

    prompt = f"""Analyze this crash input and suggest mutations for fuzzing.

Crash input (first 256 bytes, hex): {crash_hex}
ASCII preview: {ascii_preview}
Total size: {len(crash_data)} bytes

Respond with JSON:
{{
  "corpus_suggestions": [
    {{"name": "descriptive_name", "hex": "hexbytes"}},
    ...
  ],
  "dict_suggestions": ["token1", "token2", ...]
}}

Focus on:
- Format-specific mutations (headers, length fields, magic bytes)
- Boundary values (0, 1, -1, max int, etc.)
- Truncations and extensions
- ASCII tokens that might be keywords
"""

    request = ChatRequest(
        messages=[
            ChatMessage(role="system", content="You are a fuzzing expert. Suggest mutations for crash inputs."),
            ChatMessage(role="user", content=prompt),
        ],
        model=model,
        json_output=True,
        temperature=0.3,
    )

    response = llm.chat(request)

    try:
        result = json.loads(response.content)
    except json.JSONDecodeError:
        return {"seeds": [], "tokens": []}

    seeds: list[tuple[str, bytes]] = []
    for item in result.get("corpus_suggestions", []):
        if isinstance(item, dict):
            name = str(item.get("name", f"llm_{len(seeds)}"))
            hex_str = str(item.get("hex", "")).replace(" ", "")
            try:
                seeds.append((f"llm_{name}", bytes.fromhex(hex_str)))
            except ValueError:
                continue

    tokens: list[bytes] = []
    for tok in result.get("dict_suggestions", []):
        if isinstance(tok, str):
            tokens.append(tok.encode("utf-8"))

    return {"seeds": seeds, "tokens": tokens}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate corpus seeds and dictionary from crash input.")
    parser.add_argument("binary", help="Path to target binary")
    parser.add_argument("crash", help="Path to crash input file")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for seeds (default: corpora/<target>/generated/)",
    )
    parser.add_argument(
        "--dict",
        dest="dict_path",
        default=None,
        help="Path for dictionary file (default: corpora/<target>/crash.dict)",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use LLM to suggest additional mutations",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="LLM model name (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--provider",
        default=None,
        choices=["anthropic", "openai", "google", "ollama", "lmstudio"],
        help="LLM provider (auto-detected if not specified)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args(argv)

    result = generate_corpus(
        binary=args.binary,
        crash=args.crash,
        output_dir=args.output_dir,
        dict_path=args.dict_path,
        use_llm=args.llm,
        model=args.model,
        provider=args.provider,
    )

    if "error" in result:
        print(f"[-] {result['error']}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[+] Target: {result['target']}")
        print(f"[+] Crash: {result['crash']} ({result['crash_hash']})")
        print(f"[+] Corpus: {result['corpus_dir']} ({result['seeds_written']} seeds)")
        for name in result["seed_names"]:
            print(f"    - {name}")
        print(f"[+] Dictionary: {result['dict_path']} (+{result['dict_tokens_added']} tokens)")
        if result.get("used_llm"):
            print("[+] LLM suggestions included")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
