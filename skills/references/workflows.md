# alf — end-to-end workflows

Concrete recipes an agent can follow top-to-bottom for common goals. Each maps user intent to an ordered sequence of MCP tool calls or CLI commands.

## Table of contents

- [W1. Crash triage from cold](#w1-crash-triage-from-cold)
- [W2. Kernel breakpoint on a parser (VZ / KDP)](#w2-kernel-breakpoint-on-a-parser-vz--kdp)
- [W3. Stop-hook-driven in-process fuzzing](#w3-stop-hook-driven-in-process-fuzzing)
- [W4. Jackalope + libFuzzer hybrid campaign](#w4-jackalope--libfuzzer-hybrid-campaign)
- [W5. ACP orchestration (Claude Code drives alf)](#w5-acp-orchestration-claude-code-drives-alf)
- [W6. Static-only Mach-O inspection (no target)](#w6-static-only-mach-o-inspection-no-target)

---

## W1. Crash triage from cold

**Intent:** "I have a binary and a crashing input. Tell me what happened."

### Fast path — single command

```bash
uv run alf analyze --pipeline --binary <fuzz_bin> --crash <crash_input>
```

Runs triage → classify → report, writes markdown + JSON under `logs/`. Works in CI.

### Agent path — MCP tool calls

1. `lldb_launch(binary=<fuzz_bin>, crash_input=<crash_input>)`  
   Auto-runs to first crash. Returns `{status: "stopped", reason: ..., thread_id, frame_id}`.
2. `lldb_crash_context()` — one call, returns everything: stop reason, stack hash, top frames, registers, disassembly around `$pc`, stack bytes. **Stop here if that's enough.**
3. If the stop hash looks familiar: `lldb_stack_hash(max_frames=5)` — compare against a known-crashes set for dedup.
4. Drill down:
   - `lldb_read_memory(address="$x0", size=128)` — examine a suspicious register
   - `lldb_lookup_symbol(query="parse_", regex_search=True, as_json=True)` — find related code
   - `lldb_disassemble(address="0x...", count=40)` — wider view of the crash site
5. `lldb_terminate()` when done. For a launched binary, this kills the child.

**Signals you need a different workflow:** multiple unique stack hashes → graduate to [W3](#w3-stop-hook-driven-in-process-fuzzing); no crash in `lldb_launch` → the input doesn't actually crash, don't start analyzing.

---

## W2. Kernel breakpoint on a parser (VZ / KDP)

**Intent:** "Break on `smb2_rq_decompress_read` in a macOS 26 guest running under Virtualization.framework; inspect the mbuf chain."

### Prerequisites

- A running VM with hypervisor gdbstub exposed on a known port (e.g. 8864).
- A matching KDK installed: `/Library/Developer/KDKs/KDK_<version>.kdk/System/Library/Kernels/kernel.release.vmapple`.
- alf MCP server running: `uv run alf server --transport stdio`.

### Recipe

```python
# 1. Attach to the gdbstub with the kernel as the symbol target
lldb_gdb_remote(
    port=8864,
    target="/Library/Developer/KDKs/KDK_26.3.2_25D2140.kdk/System/Library/Kernels/kernel.release.vmapple",
    arch="arm64e",
    plugin="kdp-remote",     # macOS VZ / KDP; omit for QEMU gdbstub
)

# 2. Load xnu's debugging macros so `zprint`, `showallkmods`, `paniclog` etc. work
lldb_load_xnu_macros()

# 3. Confirm the symbol resolves
lldb_lookup_symbol(query="smb2_rq_decompress_read", regex_search=False, as_json=True)

# 4. Set the breakpoint
lldb_set_breakpoint(function="smb2_rq_decompress_read")
# -- OR, from a static disassembly address --
lldb_set_breakpoint(static_addr="0xfffffe000a5ec4c8",
                    module="kernel.release.vmapple")

# 5. Let the guest run
lldb_continue(wait=False)

# 6. External trigger: the user sends a crafted SMB compressed packet from another host.
#    The bp fires; lldb_continue's next call returns stopped.

# 7. At the stop, inspect the entry-gate state
lldb_status()                                        # confirm stopped
lldb_register_read("x0")                             # sessionp on arm64 AAPCS
lldb_read_memory(address="$x0+0x620", size=4)        # negotiated compression algo
lldb_read_memory(address="$x0+0x120", size=8)        # chained-mode flag

# 8. Optional: mutate guest state without fully halting
lldb_write_memory(address="_smbfs_loglevel",
                  data="ffff0000", encoding="hex", resume=True)

# 9. Resume and hunt for more stops
lldb_continue(wait=True)

# 10. Detach cleanly (the guest keeps running)
lldb_terminate()
```

### Common pitfalls

- Don't use `lldb_attach(pid=...)` for this. PIDs are local-userspace only.
- If `lldb_set_breakpoint(function=...)` returns no locations, the symbol probably isn't loaded — double-check step 3, then verify the KDK kernel matches the guest build with `image list -b`.
- `lldb_slide(module="kernel.release.vmapple")` returning `None` means lldb hasn't resolved the KASLR slide yet — call `lldb_continue(wait=True)` once to give the stub time to report it, then retry.

---

## W3. Stop-hook-driven in-process fuzzing

**Intent:** "Fuzz an IOKit `externalMethod` handler by mutating arg buffers at function entry, without restarting the process each time."

### Recipe

```python
# 1. Launch the target (userspace this time)
lldb_launch(binary="/System/Library/.../SomeDaemon", stop_on_entry=True)

# 2. Find candidate entry points
lldb_lookup_symbol(query="externalMethod|doCommand|process", regex_search=True, as_json=True)

# 3. Install a mutating stop hook at the chosen function.
#    ptr_reg points at the input buffer, len_reg at its length.
lldb_install_stop_hook(
    function="IOUserClient::externalMethod",
    ptr_reg="x1",
    len_reg="x2",
    max_size=4096,
    name="fuzz_externalMethod",
)

# 4. (Optional) Generate a targeted fuzz script with selector filtering
lldb_generate_fuzz_script(
    function="IOUserClient::externalMethod",
    skip_conditions=["selector != 0xA", "selector != 0xC"],   # only fuzz these
)

# 5. Run
lldb_continue(wait=False)

# 6. Watch exec rate + pending crashes while it runs
telemetry_rate()                     # {"rate_per_sec": 1423.8, "window_sec": 5}
telemetry_snapshot()                 # full counters from the hook
lldb_poll_crashes(limit=20)          # each entry is deduplicated by stack hash
```

### When to switch to `alf fuzz` CLI

If the agent is going to run this for more than a few minutes or needs LLM-guided mutation selection, prefer `alf fuzz auto` or `alf fuzz hybrid` — they already have the outer loop, corpus management, and crash collection wired up.

---

## W4. Jackalope + libFuzzer hybrid campaign

**Intent:** "Fuzz an ImageIO codepath through a synthetic harness."

Jackalope/TinyInst is the right tool for macOS framework fuzzing because in-process coverage without source is hard otherwise. alf's `jackalope` subcommand wraps it with LLM-driven triage on crashes.

```bash
uv run alf fuzz jackalope <harness_binary> \
    --fuzzer /path/to/jackalope/Fuzzer \
    --corpus ./seeds_in \
    --instrument-module ImageIO \
    --target-method _fuzz \
    --persist --delivery shmem --threads 4
```

Prerequisites are in `docs/JACKALOPE.md` in the alf repo. Expect to build Jackalope from source.

---

## W5. ACP orchestration (Claude Code drives alf)

**Intent:** "Set up Claude Code (or Gemini CLI, or Codex) with alf available as MCP tools."

### Option A — client config (the client launches alf)

Add alf to the client's MCP config.

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

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

**Claude Code** — same shape in `.mcp.json` at the project root.

**Gemini CLI** — `--experimental-acp` with an equivalent config file; see Gemini's docs.

After restart, the client exposes all `lldb_*` / `telemetry_*` / `macho_*` / `runtime_*` tools to the model. No extra work on the alf side.

### Option B — alf drives the agent CLI

Inverse direction: alf starts an external agent CLI with itself attached as MCP. Useful for scripted multi-turn runs using subscription auth:

```bash
uv run alf acp run --agent claude \
  --prompt "Triage the crash at /tmp/crash_input against /tmp/fuzz_bin and generate a minimized reproducer"

uv run alf acp run --agent codex --prompt "..."
uv run alf acp run --agent gemini --prompt "..."
```

Binaries:
- `claude` → `claude-code-acp` (also finds Zed-installed builds under `~/Library/Application Support/Zed/external_agents/`)
- `codex` → `codex-acp`
- `gemini` → `gemini --experimental-acp`

Override with env vars: `ACP_CLAUDE_BIN`, `ACP_CODEX_BIN`, `ACP_GEMINI_BIN`.

---

## W6. Static-only Mach-O inspection (no target)

**Intent:** "Look at a binary without running it — entitlements, linked dylibs, ObjC classes."

No session required. These tools work against a file path directly.

```python
macho_info_plist(path="/Applications/Foo.app/Contents/MacOS/Foo")
macho_entitlements(path="/Applications/Foo.app/Contents/MacOS/Foo")
macho_linked_dylibs(path="...")
macho_load_commands(path="...")
macho_list_objc_classes(path="...")
macho_swift_symbols(path="...")
static_lookup(path="...", address="0x100001000")
```

Pair with `lldb_lookup_symbol(as_json=True)` once a session is open if you need dynamic addresses too.
