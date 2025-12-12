# toy_bug harness

Tiny, intentionally-buggy parser used as a fast demo target for ALF.

## What it fuzzes

`parse_buggy()` in `buggy_parser.c` has two deliberate issues:

1. **Heap off-by-one write** when the input starts with `BPLIST10` and the 4-byte
   length field at offset `0x08` is large enough to trigger `memcpy(len + 1)`.

2. **Integer divide-by-zero** when the input starts with `CRSH` and the 5th byte
   is `'A'` (making `z == 0`).

## Pre-built Binary

The `out/toy_bug_fuzz` binary is pre-built for arm64 macOS with ASan/UBSan enabled.

## Build from Source

```bash
./build.sh
```

Requires Xcode Command Line Tools and fish shell.

## Reproduce a Crash

```bash
# Divide-by-zero
examples/toy_bug/out/toy_bug_fuzz examples/toy_bug/crashes/crash_div0

# Heap overflow
examples/toy_bug/out/toy_bug_fuzz examples/toy_bug/crashes/crash_heap_overflow
```

## Analyze with ALF

```bash
# Full triage pipeline
uv run alf analyze --pipeline \
  --binary examples/toy_bug/out/toy_bug_fuzz \
  --crash examples/toy_bug/crashes/crash_div0

# Individual steps
uv run alf analyze triage \
  --binary examples/toy_bug/out/toy_bug_fuzz \
  --crash examples/toy_bug/crashes/crash_div0

uv run alf analyze classify \
  --binary examples/toy_bug/out/toy_bug_fuzz \
  --crash examples/toy_bug/crashes/crash_div0 \
  --dry-run
```

## Fuzz with ALF

```bash
# Autonomous fuzzing with LLM
uv run alf fuzz examples/toy_bug/out/toy_bug_fuzz \
  --corpus examples/toy_bug/corpus \
  --mode auto

# Human-in-the-loop mode
uv run alf fuzz examples/toy_bug/out/toy_bug_fuzz \
  --corpus examples/toy_bug/corpus \
  --mode researcher
```

The demo corpus contains **non-crashing** seeds (so fuzzing can discover new
crashes rather than immediately replaying one). Known crash reproducers live in
`examples/toy_bug/crashes/`.
