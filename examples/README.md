# ALF Examples

This directory contains example fuzzing harnesses and crash inputs for testing ALF.

## Available Examples

### toy_bug (Recommended for testing)

A minimal, intentionally-buggy parser with two deliberate vulnerabilities:
1. **Heap off-by-one write** - triggered by `BPLIST10` prefix with crafted length
2. **Integer divide-by-zero** - triggered by `CRSHA` input

This is the fastest way to test ALF's crash analysis and fuzzing capabilities.

```bash
# Reproduce the divide-by-zero crash
examples/toy_bug/out/toy_bug_fuzz examples/toy_bug/crashes/crash_div0

# Analyze with ALF
uv run alf analyze triage --binary examples/toy_bug/out/toy_bug_fuzz --crash examples/toy_bug/crashes/crash_div0

# Run autonomous fuzzing
uv run alf fuzz examples/toy_bug/out/toy_bug_fuzz --corpus examples/toy_bug/corpus
```

### libplist

A real-world harness targeting the libplist binary/XML parser. Requires building
libplist with sanitizers first (see `libplist/build.sh`).

## Directory Structure

Each example follows this structure:
```
example_name/
├── *.c              # Source files (harness + target)
├── build.sh         # Build script
├── README.md        # Example-specific documentation
├── out/             # Compiled binaries
├── crashes/         # Known crash inputs
└── corpus/          # Seed corpus for fuzzing
```

## Building Examples

The `out/` directories contain pre-built arm64 macOS binaries. To rebuild:

```bash
cd examples/toy_bug
./build.sh
```

Requirements:
- Xcode Command Line Tools (for clang with ASan/UBSan)
- fish shell (for some helper scripts)

## Using with ALF

### Crash Analysis
```bash
# Full pipeline
uv run alf analyze --pipeline --binary examples/toy_bug/out/toy_bug_fuzz --crash examples/toy_bug/crashes/crash_div0

# Individual steps
uv run alf analyze triage --binary examples/toy_bug/out/toy_bug_fuzz --crash examples/toy_bug/crashes/crash_div0
uv run alf analyze classify --binary examples/toy_bug/out/toy_bug_fuzz --crash examples/toy_bug/crashes/crash_div0 --dry-run
```

### Autonomous Fuzzing
```bash
# Basic fuzzing
uv run alf fuzz examples/toy_bug/out/toy_bug_fuzz --corpus examples/toy_bug/corpus

# With specific provider
uv run alf fuzz examples/toy_bug/out/toy_bug_fuzz --corpus examples/toy_bug/corpus --provider anthropic
```

### MCP Server Testing
```bash
# Start server
uv run alf server --transport stdio

# In Claude Desktop or another MCP client, use:
# lldb_launch with binary: examples/toy_bug/out/toy_bug_fuzz, crash_input: examples/toy_bug/crashes/crash_div0
```
