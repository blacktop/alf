# ALF Architecture

This document describes the architecture of ALF (Agentic LLDB Fuzzer).

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           User Interface                             │
│                                                                      │
│    CLI (alf/cli/)           ACP Agents              Direct API       │
│    ├── analyze              ├── Claude Code         └── Python       │
│    ├── fuzz                 ├── Gemini CLI              imports      │
│    ├── server               └── Codex                                │
│    └── director                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         LLM Provider Layer                           │
│                                                                      │
│    alf/providers/                                                    │
│    ├── anthropic.py (Claude)                                         │
│    ├── openai.py (GPT)                                               │
│    ├── google.py (Gemini)                                            │
│    └── ollama.py (Ollama/LM Studio/vLLM)                             │
│                                                                      │
│    Auto-detection: API keys → local server probes                    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Tool/MCP Layer                               │
│                                                                      │
│    alf/tools/                    alf/server/                         │
│    ├── definitions/              ├── app.py (FastMCP server)         │
│    │   └── lldb.py (40+ tools)   ├── lldb.py (session manager)       │
│    ├── registry.py               └── runtime/ (memory, ObjC)         │
│    └── agentic_loop.py                                               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Backend Layer                                 │
│                                                                      │
│    alf/backend/                                                      │
│    ├── base.py (abstract interface)                                  │
│    ├── dap.py (Debug Adapter Protocol)                               │
│    ├── sbapi.py (direct LLDB Python API - fastest)                   │
│    └── lldb_mcp.py (native LLDB MCP protocol)                        │
│                                                                      │
│    All backends provide: launch, backtrace, registers, memory,       │
│    breakpoints, continue, step, stack hash computation               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         LLDB Layer                                   │
│                                                                      │
│    lldb-dap                      LLDB Python Module (lldb.py)        │
│    (Debug Adapter Protocol)      (SBAPI - Script Bridge API)         │
│                                                                      │
│    Target: Apple Mach-O arm64(e)                                     │
│    PAC support: Pointer Authentication Code stripping                │
└─────────────────────────────────────────────────────────────────────┘
```

## Three User Stories

ALF is designed around three primary workflows:

### 1. Crash Triage (`alf analyze`)

**Purpose:** Post-mortem analysis of crashes found by fuzzers.

**Data Flow:**
```
crash input → LLDB backend → crash context JSON → classifier → RCA report
```

**Key Components:**
- `alf/triage/once.py` - One-shot MCP-based triage
- `alf/triage/classify.py` - LLM-based crash classification
- `alf/triage/exploitability.py` - Heuristic exploitability scoring
- `alf/triage/dedupe.py` - Stack hash-based deduplication
- `alf/triage/report.py` - Markdown report generation

**Backends:**
- DAP (default) - Uses lldb-dap, works everywhere
- SBAPI - Direct LLDB Python API, 10-100x faster
- LLDB MCP - Native LLDB protocol-server

### 2. Autonomous Fuzzing (`alf fuzz`)

**Purpose:** LLM-driven fuzzing with strategic hook placement.

**Data Flow:**
```
binary → LLM analysis → hook installation → mutation loops → crash collection
                ↑                                   │
                └─────── corpus evolution ──────────┘
```

**Key Components:**
- `alf/fuzz/agent.py` - Main fuzzing agent with LLM loop
- `alf/fuzz/session.py` - LLDB session management
- `alf/fuzz/hooks.py` - Stop-hook and fork-server management
- `alf/fuzz/orchestrator.py` - Hybrid fuzzing with libFuzzer

**Modes:**
- `auto` - Fully autonomous decision-making
- `researcher` - Human-in-the-loop prompting style

### 3. Interactive Exploration (`alf server`)

**Purpose:** MCP server for agentic LLDB access.

**Data Flow:**
```
Claude/Gemini/GPT → MCP protocol → ALF server → lldb-dap → target process
```

**Key Components:**
- `alf/server/app.py` - FastMCP server with tool registration
- `alf/server/lldb.py` - DAP session wrapper
- `alf/server/runtime/` - In-process interrogation (ObjC, memory)
- `alf/server/static/` - Static analysis (Mach-O, symbols)
- `alf/tools/definitions/lldb.py` - 40+ LLDB tools

## Key Design Decisions

### 1. Multi-Provider LLM Support
ALF abstracts LLM providers behind a common interface (`alf/providers/base.py`):
- Automatic provider detection from environment variables
- Consistent tool calling across providers
- Local model support (Ollama, LM Studio, vLLM)

### 2. Backend Abstraction
The backend layer (`alf/backend/`) allows swapping debugger implementations:
- **DAP**: Standard Debug Adapter Protocol, portable
- **SBAPI**: Direct LLDB Python bindings, fastest for batch operations
- **LLDB MCP**: Native LLDB protocol-server, experimental

### 3. Centralized Utilities
Common operations are centralized in `alf/utils/`:
- `address.py` - PAC bit stripping, hex parsing
- `stack_hash.py` - Deterministic crash fingerprinting
- `crash_files.py` - Fuzzer output file detection

### 4. CLI Package Structure
The CLI (`alf/cli/`) is split by command group for maintainability:
- Each file contains related commands
- Shared helpers in `_helpers.py`
- Main entry point in `__init__.py`

## File Size Guidelines

To maintain code quality, aim for:
- **<500 lines**: Individual command files
- **<1000 lines**: Complex modules (orchestrator, agentic_loop)
- **Split when**: A file exceeds 1500 lines or has 3+ distinct concerns

## Testing Strategy

Tests live in `tests/` with structure mirroring `alf/`:
```
tests/
├── conftest.py          # Shared fixtures
├── unit/
│   ├── utils/           # Pure function tests (no mocking needed)
│   ├── triage/          # Exploitability, deduplication logic
│   └── providers/       # Provider configuration tests
└── integration/         # End-to-end tests (require LLDB)
```

**What to Mock:**
- LLM API calls (anthropic, openai, google-genai SDKs)
- Network connections (socket probing)
- LLDB/DAP sessions (in unit tests)

**What Not to Mock:**
- Pure functions (address parsing, stack hashing)
- File I/O (use pytest's `tmp_path`)
- Configuration loading

## Adding New Features

### Adding a New CLI Command
1. Create command file in `alf/cli/` (e.g., `mycommand.py`)
2. Import and add to `alf/cli/__init__.py`
3. Add tests in `tests/unit/cli/`

### Adding a New Backend
1. Inherit from `alf/backend/base.py:LLDBBackend`
2. Implement required abstract methods
3. Add to backend factory (when created)
4. Update CLI backend choices

### Adding a New LLM Provider
1. Inherit from `alf/providers/base.py:BaseProvider`
2. Implement `create_chat_completion()` and tool conversion
3. Add detection logic to `alf/providers/config.py`
4. Update CLI provider choices
