# LLDB-MCP Quick Start Guide

Get the LLM-driven crash analysis working in under 5 minutes.

## Prerequisites

- `lldb-dap` available (Xcode 16+ on macOS).
- A fuzz binary and a crashing input file.
  - For a ready‑made demo target, use the companion `fuzzlab` repo (`harnesses/toy_bug/`).

Before you start, verify your machine can launch debuggees under LLDB:

```bash
uv run alf doctor
```

```bash
# Verify lldb-dap is available
xcrun lldb-dap --help

# Example crash repro (replace with your paths)
<fuzz_bin> -runs=1 <crash_input>
```

## Step 1: Install LLM Provider SDK

```bash
# Choose one (or all)
uv sync --extra anthropic   # Claude (recommended)
uv sync --extra openai      # GPT
uv sync --extra google      # Gemini
uv sync --extra all-providers  # All of the above
```

Set your API key:
```bash
export ANTHROPIC_API_KEY=sk-ant-...  # or OPENAI_API_KEY, GOOGLE_API_KEY
```

## Step 2: Start LLDB-MCP Server

The server now **spawns lldb-dap automatically** - no manual setup needed:

```bash
# Simplest: spawns lldb-dap and speaks MCP over stdio
uv run alf server --transport stdio

# For web clients (SSE transport)
uv run alf server --transport sse --listen-port 7777
```

**Advanced:** If you need to use your own lldb-dap instance:
```bash
xcrun lldb-dap --port 12345 &
uv run alf server --no-spawn-dap --dap-port 12345 --transport stdio
```

## Step 3: Quick Crash Analysis

```bash
# Full automated pipeline (triage → classify → report)
uv run alf analyze --pipeline --binary /path/to/fuzz_bin --crash /path/to/crash_input

# Or run the AI director for interactive analysis
uv run alf director --binary /path/to/fuzz_bin --crash /path/to/crash_input --mode auto
```

## Step 4: Corpus Generation

Generate new fuzzer seeds from a crash:
```bash
# Heuristic mutations (no LLM needed)
uv run alf analyze corpus /path/to/fuzz_bin /path/to/crash_input

# With LLM-guided mutations
uv run alf analyze corpus /path/to/fuzz_bin /path/to/crash_input --llm --provider anthropic
```

Minimize a crash:
```bash
uv run alf analyze minimize /path/to/fuzz_bin /path/to/crash_input
```

## Step 5: Interactive MCP Test (Advanced)

In a separate Python shell or script, send MCP requests:

```python
#!/usr/bin/env python3
"""Test MCP client for LLDB-MCP server."""
import json
import subprocess
import sys

# Start MCP server as subprocess
proc = subprocess.Popen(
    ["python3", "-m", "alf.server", "--dap-port", "12345"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=sys.stderr,
    text=True,
)

def send_request(method, params=None, req_id=1):
    """Send JSON-RPC 2.0 request to MCP server."""
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "id": req_id,
    }
    if params:
        request["params"] = params

    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()

    response_line = proc.stdout.readline()
    return json.loads(response_line)

# Test 1: Initialize
resp = send_request("initialize", {"protocolVersion": "2024-11-05"})
print("Initialize:", json.dumps(resp, indent=2))

# Test 2: List tools
resp = send_request("tools/list")
print("\nAvailable tools:")
for tool in resp["result"]["tools"]:
    print(f"  - {tool['name']}: {tool['description']}")

# Test 3: Launch target
# Note: Ensure you have a crash file available.
# Run: printf "CRSHA" > harnesses/toy_bug/crashes/crash_div0
resp = send_request(
    "tools/call",
    {
        "name": "lldb_launch",
        "arguments": {
            "binary": "harnesses/toy_bug/out/toy_bug_fuzz",
            "crash_input": "harnesses/toy_bug/crashes/crash_div0",
        },
    },
    req_id=3,
)
print("\\nLaunch Result:")
if resp and "result" in resp:
    print(resp["result"]["content"][0]["text"])
else:
    print("Launch failed:", resp)

# Test 4: Execute LLDB command (backtrace)
resp = send_request(
    "tools/call",
    {
        "name": "lldb_execute",
        "arguments": {"command": "bt"},
    },
    req_id=4,
)
print("\\nBacktrace:")
print(resp["result"]["content"][0]["text"])

# Test 5: Read registers
resp = send_request(
    "tools/call",
    {
        "name": "lldb_execute",
        "arguments": {"command": "register read"},
    },
    req_id=5,
)
print("\\nRegisters:")
print(resp["result"]["content"][0]["text"])

# Test 6: Disassemble around crash
resp = send_request(
    "tools/call",
    {
        "name": "lldb_disassemble",
        "arguments": {"address": "--pc", "count": 10},
    },
    req_id=6,
)
print("\\nDisassembly:")
print(resp["result"]["content"][0]["text"])

proc.stdin.close()
proc.wait()
```

Save as `test_mcp_client.py` and run:

```bash
python3 test_mcp_client.py
```

## Step 6: Claude Desktop Integration

To use with Claude Desktop, add to your MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "lldb-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/alf", "alf", "server", "--transport", "stdio"]
    }
  }
}
```

The server will automatically spawn and manage lldb-dap.

Then in Claude Desktop:

```
User: I have a crash at /path/to/crash_input.
      Can you use LLDB to analyze the root cause?

Claude: I'll use the lldb_mcp tools to explore this crash.
        First, let me get a backtrace...

        [Uses lldb_backtrace tool]
        [Analyzes output]
        [Uses lldb_read_memory to examine buffer]
        [Uses lldb_disassemble to check crash site]

        Root cause: Buffer overflow in parse_buggy() at offset 0x2a.
        The input contains 0x41414141 pattern causing heap corruption.
```

## Troubleshooting

### Issue: `lldb run` fails with status -1

**Symptom**: LLDB shows `process exited with status -1 (no such process)` when you run a target.

**Fix**: macOS debugging is not enabled. Run `uv run alf doctor` and follow its steps:
enable **Developer Mode** (requires reboot) and enable DevToolsSecurity.

### Issue: DAP connection timeout

**Symptom**: `ConnectionError: failed to connect to 127.0.0.1:12345`

**Fix**: Ensure lldb-dap is running and listening:
```bash
lsof -i :12345  # Should show lldb-dap process
xcrun lldb-dap --port 12345 &  # Restart if needed
```

### Issue: "initialized" event timeout

**Symptom**: `TimeoutError: timed out waiting for event 'initialized'`

**Fix**: This is a known issue with Xcode 16's lldb-dap. The MCP server has a workaround (continues anyway), but if crashes persist:

```bash
# Try using VS Code's bundled lldb-dap instead
# Install VS Code C++ extension, then:
/Applications/Visual\ Studio\ Code.app/Contents/Resources/app/extensions/ms-vscode.cpptools-*/debugAdapters/bin/lldb-dap --port 12345
```

### Issue: MCP server hangs waiting for stdin

**Symptom**: Server starts but no output

**Fix**: MCP protocol requires JSON-RPC 2.0 over stdin. Either:
1. Use a proper MCP client (Claude Desktop, test script above)
2. Manually send JSON:
```bash
echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | PYTHONPATH=. python3 -m alf.server --dap-port 12345
```

## Next Steps

Once the MCP server is working:

1. **Multi-turn exploration**: Have Claude interactively explore crashes with 5-10 LLDB commands
2. **Corpus generation**: Use crash analysis to synthesize new test inputs
3. **Automated triage**: Integrate with fswatch to auto-analyze new crashes
4. **Harness evolution**: Let Claude propose improvements to fuzzing harnesses
5. **Autonomous fuzzing**: Use `alf fuzz` for LLM-driven fuzzing campaigns

### Autonomous Fuzzing

Run a fully autonomous fuzzing campaign:
```bash
# Basic usage
uv run alf fuzz /path/to/binary --mode auto

# With initial corpus
uv run alf fuzz /path/to/binary --corpus /path/to/seeds --provider anthropic

# Human-in-the-loop mode
uv run alf fuzz /path/to/binary --mode researcher --max-iterations 50
```

The agent will:
1. Analyze the target binary to identify interesting functions
2. Install mutation hooks at strategic breakpoints
3. Run fuzzing iterations with corpus inputs
4. Collect and deduplicate crashes using stack hashing
5. Generate new corpus seeds based on coverage/crashes

See [AUTONOMOUS_FUZZING.md](AUTONOMOUS_FUZZING.md) for the full roadmap.

## Demo Script

For a reproducible demo:

```bash
# Generate crash
harnesses/toy_bug/out/toy_bug_fuzz -runs=1 crashes/toy_bug/demo_crash

# Full pipeline (triage → classify → report)
uv run alf analyze --pipeline \
  --binary harnesses/toy_bug/out/toy_bug_fuzz \
  --crash crashes/toy_bug/demo_crash \
  --tag demo

# Or classify only (heuristics, no LLM needed)
uv run alf analyze classify \
  --binary harnesses/toy_bug/out/toy_bug_fuzz \
  --crash crashes/toy_bug/demo_crash \
  --tag demo \
  --dry-run

# Review structured analysis
cat logs/$(ls logs/*demo*classify*.json | tail -1)
```
