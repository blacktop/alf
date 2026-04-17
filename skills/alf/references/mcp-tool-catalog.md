# alf MCP tool catalog

Every tool the alf MCP server exposes, grouped by category. One line per tool.
Use this as a lookup when deciding which tool to call — **don't call a tool just because it exists, pick the one that maps to the goal**.

## Table of contents

- [Session lifecycle](#session-lifecycle) — open/close a debug session
- [Execution control](#execution-control) — run/stop, breakpoints, watchpoints
- [Inspection](#inspection) — registers, memory, backtrace, disassembly
- [Crash analysis](#crash-analysis) — fingerprint, context bundle, pending crashes
- [Symbols & source](#symbols--source) — name lookup, symtab, source windows
- [Kernel / remote helpers](#kernel--remote-helpers) — slide math, dSYMs, xnu macros, non-halting memory writes
- [Instrumentation](#instrumentation) — stop hooks, fuzz scripts, telemetry
- [Static analysis](#static-analysis-no-target-required) — Mach-O inspection without a live process
- [ObjC runtime](#objc-runtime) — class/object dumps against a live target
- [Capabilities](#capabilities) — heap check, XPC sniff, monitor trace
- [Scripting & meta](#scripting--meta)

---

## Session lifecycle

| Tool | Purpose |
|---|---|
| `lldb_launch` | Launch a local binary under the debugger with optional crash input. Use for userspace triage/fuzzing. |
| `lldb_attach` | Attach to a running PID. Use when the process is already up (daemon, long-running). |
| `lldb_gdb_remote` | Attach to a gdb-remote stub (VZ hypervisor, QEMU gdbstub, KDP). **Required for kernel debugging.** Params: `port`, `host`, `target` (KDK path), `arch`, `plugin` ("kdp-remote" / "gdb-remote"). |
| `lldb_load_core` | Load a core dump for post-mortem analysis without a running process. |
| `lldb_status` | Return session state: connected, mode, thread/frame IDs, pending crash count. Cheap; call first if unsure what state you're in. |
| `lldb_process_info` | `process info` — PID, arch, run state. |
| `lldb_help` | LLDB built-in help. Call before `lldb_execute` with an obscure command to confirm syntax. |
| `lldb_terminate` | Cleanly end the session. Detaches for attach/gdb-remote; kills for launched processes. |
| `lldb_kill` | Kill the debuggee but keep the debug session alive. Rarely needed — use `lldb_terminate`. |

## Execution control

| Tool | Purpose |
|---|---|
| `lldb_execute` | Raw LLDB command passthrough. Use for anything not covered by a specialized tool. |
| `lldb_continue` | Resume execution. Emits MCP `notifications/message` on crash. `wait=True` blocks until next stop. |
| `lldb_step` | `into` / `over` / `out` / `instruction`, optional `count`. |
| `lldb_set_breakpoint` | By `function`, `address`, `file`+`line`, or **`static_addr`+`module`** (resolves runtime slide for you — use this for kernel IDA addresses). Supports `condition`. |
| `lldb_breakpoint_list` | List current breakpoints with IDs for deletion. |
| `lldb_breakpoint_delete` | Delete by numeric ID. |
| `lldb_remove_all_breakpoints` | Nuke all breakpoints — useful between scenarios. |
| `lldb_watchpoint` | Data breakpoint on read / write / read_write. |

## Inspection

| Tool | Purpose |
|---|---|
| `lldb_backtrace` | Textual backtrace. Use when you want to show a user. |
| `lldb_backtrace_json` | Structured frames with PAC-stripped PCs. Use when you'll parse it. |
| `lldb_disassemble` | Around `$pc` or explicit address. Default `count=20`. |
| `lldb_read_memory` | Bytes at address. Supports symbolic expressions: `"$x0+0x620"`. Default `size=64`, format `x`. |
| `lldb_deref` | Follow a pointer register or expression. |
| `lldb_memory_search` | Scan memory for a hex/ASCII pattern starting at an address. |
| `lldb_register_read` | Single register (`"x0"`) or all. |
| `lldb_register_write` | `register_name`, `value`. |
| `lldb_thread_list` | Threads with IDs. |
| `lldb_thread_select` | Make a thread current for subsequent frame/register ops. |
| `lldb_frame_select` | Pick a stack frame by index. |
| `lldb_frame_variables` | Local variables in the current frame. |
| `lldb_evaluate` | Expression evaluator (C/Swift/ObjC). |

## Crash analysis

| Tool | Purpose |
|---|---|
| `lldb_crash_context` | **One-shot comprehensive dump:** reason, stop body, stack hash, PCs, frames, registers, disassembly, stack bytes. Fastest "tell me what happened" tool. |
| `lldb_stack_hash` | SHA256 of top-N PCs (PAC-stripped) for deduplication across crashes. |
| `lldb_poll_crashes` | Drain the pending-crash queue that stop hooks and `lldb_continue` populate. Use in a loop when running a campaign. |

## Symbols & source

| Tool | Purpose |
|---|---|
| `lldb_lookup_symbol` | `image lookup -rn/-n`. Pass `as_json=True` for structured matches (addr, module, name, offset). Parses Objective-C selectors and C++ operators correctly. |
| `lldb_dump_symtab` | Full symtab with optional regex filter. Heavier — prefer `lookup_symbol`. |
| `lldb_read_source` | Source lines around a given line number. Reads from disk, not from the debugger. |

## Kernel / remote helpers

| Tool | Purpose |
|---|---|
| `lldb_add_module` | `target modules add <path>` + optional `target symbols add <dsym>` + optional slide/load_addr placement. Paths with spaces are quoted automatically. |
| `lldb_slide` | Runtime ASLR/KASLR slide for a module. Returns `None` when lldb hasn't resolved a real slide (target not attached / module unloaded) — retry after attach. |
| `lldb_load_xnu_macros` | Import Apple's xnu lldbmacros (`zprint`, `showallkmods`, `paniclog`, `whatis`, `pmap_walk`). Auto-detects KDK dSYM, `$ALF_XNU_LLDBMACROS`, `~/src/xnu`, `~/Developer/xnu`. |
| `lldb_write_memory` | Write bytes. `resume=True` (default) does atomic interrupt→write→continue so a running guest barely blips. Encodings: `hex`, `ascii`, `base64`. |

## Instrumentation

| Tool | Purpose |
|---|---|
| `lldb_install_stop_hook` | In-kernel or in-process mutation at a function entry. `ptr_reg`/`len_reg` point at a buffer; alf mutates it and continues without round-tripping. The primary primitive for fuzzing parsers / IOKit externalMethod handlers. |
| `lldb_install_fork_server` | Stand up a fork-server-style harness for coverage-guided fuzzing. |
| `lldb_generate_fuzz_script` | Emit a tailored Python stop-hook script. `skip_conditions` filter on selectors / arg values (e.g. only fuzz `externalMethod` with selector 0xA). |
| `telemetry_rate` | Per-second exec rate from an in-target telemetry pipe. |
| `telemetry_snapshot` | Full counter snapshot from a stop hook. |

## Static analysis (no target required)

Pure Mach-O file inspection. Works without a session.

| Tool | Purpose |
|---|---|
| `macho_info_plist` | Embedded `Info.plist`. |
| `macho_entitlements` | Code-signing entitlements blob. |
| `macho_linked_dylibs` | `LC_LOAD_DYLIB` etc. |
| `macho_load_commands` | All load commands structured. |
| `macho_list_objc_classes` | ObjC class list from `__objc_classlist`. |
| `macho_objc_segment` | Dump a specific `__DATA_CONST,__objc_*` section. |
| `macho_swift_symbols` | Swift-specific demangled symbols. |
| `static_lookup` | Best-effort address → symbol without a running debugger. |

## ObjC runtime

Requires a live target (launched / attached). Queries the in-process ObjC runtime.

| Tool | Purpose |
|---|---|
| `runtime_objc_classes` | All loaded ObjC classes. |
| `runtime_objc_class_dump` | Methods + ivars of a class (header-style dump). |
| `runtime_objc_object_dump` | Dump an ObjC object pointer: class, ivars, description. |
| `runtime_nsobject_to_json` | Convert an NSObject pointer to JSON (walks description + class info). |

## Capabilities

Higher-level checks built on the lower-level tools.

| Tool | Purpose |
|---|---|
| `heap_check` | Validate an allocation / detect heap corruption at a pointer. |
| `heap_inspect` | Dump alloc size, refcount, zone for a pointer. |
| `objc_inspect` | Shortcut for class+object info on an ObjC pointer. |
| `monitor_trace` | Trace entry/exit of a function with arg logging. |
| `xpc_sniff` | Intercept XPC messages in/out of a process. |
| `xpc_send` | Synthesize and send an XPC message. |

## Scripting & meta

| Tool | Purpose |
|---|---|
| `lldb_script` | Inject a Python script into LLDB's script interpreter. Escape hatch for anything not covered by a tool. |
| `list_tool_categories` | Introspection: what tool groups does this server expose? |
| `tool_search` | Search tool descriptions by keyword. |
| `server_subscribe` | Subscribe to server notifications (crash events) over MCP SSE. |
