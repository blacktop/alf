# alf backend selection

alf ships four debugger backends behind a common interface. Most agents won't pick one per tool call — the user picks at `alf server` launch time with `--backend`. But when the user asks "which should I use?", here's how to answer.

## Comparison

| Backend | Flag | Throughput | Works for kernel (gdb-remote)? | Requires | Best for |
|---|---|---|---|---|---|
| `dap` | `--backend dap` (default) | Moderate | **Yes** | `lldb-dap` binary (Xcode 16+ or LLVM 20+) | Everything, default choice |
| `sbapi` | `--backend sbapi` | **10-100×** faster | No | `lldb` Python module | Batch crash triage, big corpus |
| `lldb_mcp` | `--backend lldb_mcp` | Moderate | No | Native LLDB MCP protocol server | Experimental, future-leaning |
| `mock` | `--backend mock` | N/A | Simulated | Nothing | CI/tests without an LLDB install |

## How to pick

1. **Need kernel / remote / hypervisor / JTAG?** → `dap`. Only backend that implements `attach_gdb_remote`. No choice.
2. **Running a fuzzing campaign with thousands of crash inputs through the triage pipeline?** → `sbapi`. The SBAPI backend is 10-100× faster than DAP because it skips the DAP-protocol round trips and calls LLDB in-process.
3. **Writing unit tests or CI for code that uses the alf MCP surface?** → `mock`. Returns deterministic fake data for every tool without needing an LLDB install.
4. **Everything else (crash triage, interactive exploration, ACP with Claude Code, jackalope, local fuzzing)?** → `dap`. Portable, the default, well-tested path.

## Under the hood

- **`dap`** (`alf/backend/dap.py`) speaks the Debug Adapter Protocol to `lldb-dap`. alf spawns the adapter itself (`--connection listen://host:port`), runs a readiness probe, and caches `initialize` capabilities (e.g. `supportsWriteMemoryRequest`). Detach-safe teardown: attach/gdb-remote sessions detach on `lldb_terminate`, launched sessions kill.
- **`sbapi`** (`alf/backend/sbapi.py`) uses `import lldb` from Xcode's Python. Much faster because there's no DAP protocol overhead, but requires the lldb module to be importable by the Python running alf, and doesn't implement gdb-remote kernel attach.
- **`lldb_mcp`** (`alf/backend/lldb_mcp.py`) connects to LLDB's own MCP protocol server. Experimental; only interesting if you're already running that protocol-server in your setup.
- **`mock`** (`alf/backend/mock.py`) fakes every backend method with fixed returns. Used for alf's own tests and any downstream code that wants to assert the MCP surface works without LLDB.

## Switching mid-flight

You can't swap backends within a running `alf server` — restart with a different `--backend`. If you find yourself wanting both speed (sbapi) and kernel support (dap), run two alf servers in parallel under different MCP names.
