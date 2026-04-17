# alf skills

Claude / Claude Code skills bundled with alf. A "skill" is a small
prompt + reference package that tells an AI agent how to use alf
effectively — which tool for which goal, when to pick `alf analyze`
vs `alf fuzz` vs `alf server`, kernel-debug sequencing, ACP wiring,
backend selection, and common gotchas.

## Skills in this repo

| Skill | What it covers |
|---|---|
| [`alf/`](alf/) | End-to-end alf usage — crash triage, fuzzing, kernel debugging via `lldb_gdb_remote`, interactive MCP exploration, ACP setup, backend selection |

## Install

### Claude Code (user-level)

```bash
cp -r skills/alf ~/.claude/skills/
```

The skill auto-loads on next Claude Code start. Triggers when a user
asks anything involving alf, LLDB crash triage on macOS, agentic
Mach-O fuzzing, kernel debugging via gdb-remote / KDP /
Virtualization.framework, or references `alf analyze` / `alf fuzz` /
`alf server` / `alf director`.

### Claude Code (project-level)

Drop into `.claude/skills/` at the root of any project that uses alf:

```bash
mkdir -p .claude/skills
cp -r /path/to/alf/skills/alf .claude/skills/
```

### Claude.ai (web / desktop)

Package as a `.skill` bundle and upload:

```bash
# From an environment that has the skill-creator plugin installed:
python -m scripts.package_skill skills/alf
# Produces skills/alf.skill — upload that in Claude.ai.
```

## Skill layout

```
alf/
├── SKILL.md                     # Main prompt (goal-oriented decision tree)
└── references/
    ├── mcp-tool-catalog.md      # Every MCP tool, one line each
    ├── workflows.md             # End-to-end recipes
    └── backends.md              # DAP / SBAPI / lldb_mcp / mock picker
```

The main `SKILL.md` stays under 250 lines so it fits comfortably in
context. Deep material lives under `references/` and is loaded on
demand.
