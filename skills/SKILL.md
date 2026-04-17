---
name: alf
description: Agentic LLDB fuzzer and crash-triage toolkit for Apple Mach-O on arm64(e). Use this skill whenever a user mentions alf, wants an AI agent to drive LLDB over MCP, asks about triaging a crash on macOS, wants to fuzz a Mach-O target with LLM guidance, is debugging a macOS kernel via Virtualization.framework / KDP / gdb-remote, references `alf analyze`/`alf fuzz`/`alf server`/`alf director`, or needs to wire alf into Claude Code / Codex / Gemini CLI via ACP. Invoke even when the user just describes the task ("I have a crash input from my fuzzer", "I want to break on smb2_rq_decompress_read in the VM kernel", "set up an agent to fuzz this IOKit method") without naming the tool.
---

# alf — Agentic LLDB Fuzzer

alf lets an AI agent drive LLDB over MCP to analyze crashes, fuzz targets, and debug kernels. **Target: Apple Mach-O, arm64(e).** Agent-first design: every capability is an MCP tool call.

## Choose the entry point by goal

| Goal | Entry point |
|---|---|
| Post-mortem analysis of a single crash | [Crash triage](#crash-triage) |
| LLM-driven fuzzing campaign | [Fuzzing](#fuzzing) |
| Kernel / remote-stub debugging (VZ, QEMU, KDP) | [Kernel debugging](#kernel-debugging) |
| Let an agent freely explore a live target | [Interactive exploration](#interactive-exploration) |
| Plug alf into Claude Code / Codex / Gemini CLI | [ACP integration](#acp-integration) |

When in doubt: **`alf server --transport stdio`** exposes every capability as MCP tools. Everything else is a higher-level orchestrator around that same tool surface.

Before anything else, verify the host is configured: `uv run alf doctor`. A failing `lldb_launch` check almost always means macOS Developer Mode is off — see [Gotchas](#gotchas).

---

## Crash triage

**Use when:** the user has a binary and a crashing input (from libFuzzer, AFL++, Jackalope, etc.) and wants to understand the root cause, classify it, and/or generate a minimized/expanded corpus.

Three levels, pick by how much autonomy the agent should have:

| Level | Command | When |
|---|---|---|
| Fully scripted pipeline | `uv run alf analyze --pipeline --binary <bin> --crash <input>` | Same output every run; good for CI |
| LLM-in-the-loop director | `uv run alf director --binary <bin> --crash <input> --mode auto` | Need the agent to pick which commands to run |
| Raw MCP surface | `alf server` + `lldb_launch` → `lldb_crash_context` → ... | Building a custom workflow, or an outer agent already orchestrates |

Sub-commands (`alf analyze <subcommand>`):
- `triage` — capture backtrace, registers, disassembly → `logs/*.json`
- `classify` — heuristic exploitability + LLM bucketing
- `report` — render a markdown RCA from a triage JSON
- `minimize` — shrink a crash input while preserving the stack hash
- `corpus` — synthesize new seeds from a crash (add `--llm` for LLM-guided)

**Agent recipe (raw MCP):**
1. `lldb_launch(binary, crash_input=...)` — auto-runs to the stop
2. `lldb_crash_context()` — one JSON with reason, registers, top frames, disasm, stack bytes, stack hash
3. If you need more: `lldb_backtrace_json(max_frames=32)`, `lldb_read_memory("$x0", size=64)`, `lldb_disassemble("--pc", count=20)`
4. `lldb_stack_hash()` for deduplication against previous crashes

One-call-gets-most-of-it: `lldb_crash_context` is the fastest path to a full picture.

---

## Fuzzing

**Use when:** the user wants alf to run a campaign, not just analyze an existing crash.

| Mode | Command | Fits when |
|---|---|---|
| `auto` | `alf fuzz auto <bin> --corpus <seeds>` | LLM picks functions, installs stop-hooks, mutates live. Works on any Mach-O. |
| `hybrid` | `alf fuzz hybrid <bin> --corpus <seeds> --max-time 3600` | libFuzzer does the volume, alf does the cold-start + triage. Best bang-for-buck on libFuzzer harnesses. |
| `jackalope` | `alf fuzz jackalope <harness> --instrument-module <M> --target-method <m>` | macOS framework fuzzing (ImageIO, AVFoundation, etc.) via TinyInst. Requires a Jackalope build. |

**Agent recipe for in-process mutation (raw MCP, after `lldb_launch`):**
1. `lldb_lookup_symbol(query="parse_", regex_search=True, as_json=True)` — find candidate parsers
2. `lldb_install_stop_hook(function="parse_foo", ptr_reg="x0", len_reg="x1")` — mutate the buffer at entry
3. `lldb_generate_fuzz_script(function=..., skip_conditions=[...])` — scripted IOUserClient `externalMethod` filtering
4. `telemetry_rate()` / `telemetry_snapshot()` — exec/s visibility while the hook runs
5. `lldb_poll_crashes()` — deduplicated crash events surfaced by the stop hook

---

## Kernel debugging

**Use when:** the debug target is **not a local process** — a macOS guest kernel under Virtualization.framework, a QEMU gdbstub, a JTAG bridge, an iOS device over KDP.

This is a first-class path in alf as of the kernel-debug update. Do **not** try to use `lldb_launch`/`lldb_attach` for kernels; they are for local userspace processes.

**Agent recipe:**
```
# Attach to the stub (required first step)
lldb_gdb_remote(
    port=8864,                                   # VZ hypervisor default varies; whatever your stub exposes
    host="127.0.0.1",                            # default
    target="/Library/Developer/KDKs/KDK_*.kdk/System/Library/Kernels/kernel.release.vmapple",
    arch="arm64e",                               # optional; some stubs omit it
    plugin="kdp-remote",                         # "kdp-remote" for macOS; omit for QEMU/JTAG
)

# Pull in xnu's lldb macros (auto-detects KDK / ~/src/xnu / ALF_XNU_LLDBMACROS)
lldb_load_xnu_macros()

# Add a kext whose symbols aren't in the main kernel
lldb_add_module(path="/path/to/com.apple.MyKext.kext/Contents/MacOS/MyKext", dsym="...")

# Set breakpoints two ways
lldb_set_breakpoint(function="smb2_rq_decompress_read")              # by symbol (after macros loaded)
lldb_set_breakpoint(static_addr="0xfffffe000a5ec4c8",                # by link-time addr from IDA/disassembly
                    module="kernel.release.vmapple")                 # resolved against the runtime slide

# Work the stop
lldb_continue(wait=True)
lldb_register_read("x0")
lldb_read_memory("$x0+0x620", size=4)

# Poke the guest without fully halting it (single atomic pause/write/continue)
lldb_write_memory(address="_smbfs_loglevel", data="ffff0000",
                  encoding="hex", resume=True)

# Clean teardown — keeps the remote inferior running (attach/gdb_remote is detach-safe)
lldb_terminate()
```

**Key rules:**
- `static_addr` + `module` is the correct way to break on an IDA address. `lldb_set_breakpoint(address=...)` is for *runtime* addresses and will miss under KASLR.
- `lldb_write_memory(resume=True)` is the kernel-debug primitive: one round trip, guest SSH barely blips.
- `lldb_terminate` on an attach/gdb-remote session detaches (does **not** kill the inferior). Launched processes are killed. Trust it.
- `lldb_slide(module=...)` returns `None` if lldb hasn't resolved a slide yet (target not attached / unloaded module) — that is a legitimate answer, not an error; retry after attach.
- If the server says "No active session" vs "Session ended": the first means you never attached; the second means the adapter died and you should gather what you have and report.

See [references/workflows.md](references/workflows.md) for the full VZ gdbstub recipe including KDK path discovery.

---

## Interactive exploration

**Use when:** the agent should freely poke at a live target without a fixed workflow — answering "how does this work?" or "what does this function do on this input?"

```bash
uv run alf server --transport stdio     # preferred for Claude Desktop / Claude Code
uv run alf server --transport sse --listen-port 7777   # for web clients
```

The server spawns `lldb-dap` automatically — no manual port juggling. It also runs a readiness probe and surfaces actionable spawn errors (missing binary, port in use, code-signing refusal). If you see "lldb-dap exited with code 0 before binding", the installed adapter doesn't accept `--port`; alf has already moved to `--connection listen://host:port` for this reason.

Tool families the agent has access to (~50 tools):
- **Session** — `lldb_launch`, `lldb_attach`, `lldb_gdb_remote`, `lldb_load_core`, `lldb_status`, `lldb_terminate`
- **Execution** — `lldb_execute` (raw LLDB), `lldb_continue`, `lldb_step`, `lldb_set_breakpoint`, `lldb_watchpoint`
- **Inspection** — `lldb_backtrace`, `lldb_disassemble`, `lldb_read_memory`, `lldb_register_read/write`, `lldb_memory_search`, `lldb_frame_*`, `lldb_thread_*`
- **Crash** — `lldb_crash_context`, `lldb_stack_hash`, `lldb_poll_crashes`
- **Symbols** — `lldb_lookup_symbol` (with `as_json=True` for structured output), `lldb_dump_symtab`, `lldb_read_source`
- **Kernel** — `lldb_add_module`, `lldb_slide`, `lldb_load_xnu_macros`, `lldb_write_memory`
- **Instrumentation** — `lldb_install_stop_hook`, `lldb_install_fork_server`, `lldb_generate_fuzz_script`, `telemetry_rate`, `telemetry_snapshot`
- **Static analysis** (no target required) — `macho_*` for load commands, entitlements, dylibs, Swift symbols; `static_lookup`
- **ObjC runtime** — `runtime_objc_classes`, `runtime_objc_class_dump`, `runtime_objc_object_dump`
- **Capabilities** — `heap_check`, `heap_inspect`, `objc_inspect`, `monitor_trace`, `xpc_sniff`, `xpc_send`

Full one-line descriptions in [references/mcp-tool-catalog.md](references/mcp-tool-catalog.md).

---

## ACP integration

ACP (Agent Client Protocol) is how alf drives agent CLIs (Claude Code, Codex, Gemini CLI) that authenticate via a user's subscription instead of an API key. The inverse is also true: those CLIs can consume alf as an MCP server.

### Using alf from Claude Code / Codex / Gemini CLI

Add alf to the client's MCP config. For Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "alf": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/alf", "alf", "server", "--transport", "stdio"]
    }
  }
}
```

Claude Code's project-local `.mcp.json` takes the same shape. Gemini CLI: pass via `--experimental-acp` with an equivalent config. The server auto-spawns `lldb-dap` — no side setup.

### Driving an agent CLI from alf

`alf`'s ACP bridge (`alf acp run`) launches an external agent with alf already attached as an MCP server. Useful when you want alf to orchestrate Claude Code (for example, to run a multi-turn triage under subscription auth). Example:

```bash
uv run alf acp run --agent claude --prompt "Triage crash at /tmp/crash_input against /tmp/fuzz_bin"
```

Agents: `claude` (via `claude-code-acp`), `codex` (via `codex-acp`), `gemini` (via `gemini --experimental-acp`). alf discovers Zed-installed agents under `~/Library/Application Support/Zed/external_agents/` automatically.

---

## Backend selection

alf supports four debugger backends. For an agent making MCP tool calls, the backend is almost always chosen by whoever started `alf server` — you don't pick it per call. But if the user asks:

| Backend | Flag | Use when |
|---|---|---|
| `dap` (default) | `--backend dap` | Anywhere. Portable. Required for `lldb_gdb_remote`. |
| `sbapi` | `--backend sbapi` | Batch crash triage, need 10-100× throughput, don't need gdb-remote |
| `lldb_mcp` | `--backend lldb_mcp` | Experimental native LLDB MCP protocol |
| `mock` | `--backend mock` | Tests/CI without an LLDB install |

Default is `dap`. If the user is doing kernel / remote work, they need `dap` (only backend with `attach_gdb_remote`).

---

## Gotchas

- **`process exited with status -1`** on launch → macOS Developer Mode is off. `uv run alf doctor` will print the fix (System Settings → Privacy & Security → Developer Mode; `DevToolsSecurity --enable`; reboot).
- **`lldb_execute` returns "No active session"** → the agent never called a session-opening tool. Tell it to call `lldb_launch`, `lldb_attach`, `lldb_load_core`, or `lldb_gdb_remote` first.
- **`lldb_execute` returns "Session ended"** → the adapter died mid-flight. Don't retry — collect what you have from `lldb_crash_context` / `lldb_status` and report.
- **`lldb-dap exited with code 0 before binding <port>`** → the installed adapter doesn't accept `--port`; you're on a build old enough that alf's `--connection listen://...` spawn still failed. Upgrade Xcode command-line tools or LLVM.
- **Breakpoint set on a kernel address never fires** → you used `address=` with a link-time address. Use `static_addr=` + `module=` instead so alf applies the runtime slide.
- **`lldb_slide` returns null** → either the target isn't attached yet, or lldb hasn't resolved the module. Both are retryable; it's not an error.
- **Symbols look wrong / macros missing** in a kernel session → call `lldb_add_module` for the KDK kernel and `lldb_load_xnu_macros` before trying to use `zprint`/`showallkmods`/etc.
- **`alf doctor` reports `xnu_lldbmacros: WARN`** → advisory only. Not needed for userspace. Install a KDK or set `ALF_XNU_LLDBMACROS` if you're doing kernel work.

---

## Reference files

- [references/mcp-tool-catalog.md](references/mcp-tool-catalog.md) — every MCP tool, one line each, grouped by category.
- [references/workflows.md](references/workflows.md) — end-to-end recipes: kernel bp-on-parser loop, crash triage from cold, stop-hook-driven fuzzing, ACP orchestration.
- [references/backends.md](references/backends.md) — detailed backend comparison and when each wins.
