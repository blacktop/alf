"""Configuration dataclasses for triage workflows.

These dataclasses provide typed configuration for triage operations,
replacing argv-based interfaces with structured objects.

Usage:
    from alf.triage.config import TriageConfig
    from alf.triage.once import run_triage

    config = TriageConfig(binary=Path("./fuzz"), crash=Path("./crash-abc"))
    result = run_triage(config)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class TriageConfig:
    """Configuration for single crash triage via MCP server.

    Attributes:
        binary: Path to the fuzz target binary.
        crash: Path to the crashing input file.
        tag: Short identifier for artifact naming.
        dap_path: Explicit lldb-dap binary path (auto-detected if None).
        dap_port: DAP server port (0 = auto-select free port).
        timeout: DAP/MCP operation timeout in seconds.
        log_level: Logging verbosity level.
        output: Custom output path (auto-generated in logs/ if None).
        no_markdown: Skip generating markdown report.
    """

    binary: Path
    crash: Path
    tag: str = "triage"
    dap_path: str | None = None
    dap_port: int = 0
    timeout: float = 30.0
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "ERROR"
    output: Path | None = None
    no_markdown: bool = False

    def __post_init__(self) -> None:
        """Ensure paths are Path objects and resolved."""
        if isinstance(self.binary, str):
            self.binary = Path(self.binary)
        if isinstance(self.crash, str):
            self.crash = Path(self.crash)
        if isinstance(self.output, str):
            self.output = Path(self.output)

        self.binary = self.binary.expanduser().resolve()
        self.crash = self.crash.expanduser().resolve()
        if self.output:
            self.output = self.output.expanduser().resolve()


@dataclass
class ClassifyConfig:
    """Configuration for crash classification with optional LLM assistance.

    Attributes:
        binary: Path to the fuzz target binary.
        crash: Path to the crashing input file.
        triage_logs: List of triage log file paths.
        dap_logs: List of DAP JSON log paths.
        tag: Short identifier for artifact naming.
        model: LLM model name (from config if None).
        adapter: LLM adapter binary name.
        timeout: LLM adapter timeout in seconds.
        dry_run: Skip LLM call, use heuristics only.
        output: Custom output path (auto-generated in logs/ if None).
        max_log_lines: Maximum lines to include per log snippet.
        extra_notes: Additional context strings for LLM prompt.
        exploitability: Include exploitability analysis.
        crash_context: Path to crash context JSON for exploitability.
    """

    binary: Path
    crash: Path
    triage_logs: list[Path] = field(default_factory=list)
    dap_logs: list[Path] = field(default_factory=list)
    tag: str = "triage"
    model: str | None = None
    adapter: str = "alf-llm"
    timeout: int = 180
    dry_run: bool = False
    output: Path | None = None
    max_log_lines: int = 200
    extra_notes: list[str] = field(default_factory=list)
    exploitability: bool = True
    crash_context: Path | None = None

    def __post_init__(self) -> None:
        """Ensure paths are Path objects and resolved."""
        if isinstance(self.binary, str):
            self.binary = Path(self.binary)
        if isinstance(self.crash, str):
            self.crash = Path(self.crash)
        if isinstance(self.output, str):
            self.output = Path(self.output)
        if isinstance(self.crash_context, str):
            self.crash_context = Path(self.crash_context)

        self.binary = self.binary.expanduser().resolve()
        self.crash = self.crash.expanduser().resolve()
        if self.output:
            self.output = self.output.expanduser().resolve()
        if self.crash_context:
            self.crash_context = self.crash_context.expanduser().resolve()

        # Convert string paths in lists to Path objects
        self.triage_logs = [Path(p).expanduser().resolve() if isinstance(p, str) else p for p in self.triage_logs]
        self.dap_logs = [Path(p).expanduser().resolve() if isinstance(p, str) else p for p in self.dap_logs]


@dataclass
class ReportConfig:
    """Configuration for RCA report generation.

    Attributes:
        context_json: Path to crash context JSON (or triage JSON embedding it).
        classification_json: Optional classification JSON from classify step.
        output: Custom output path (auto-generated in logs/ if None).
        tag: Short identifier for artifact naming.
        exploitability: Include exploitability assessment section.
    """

    context_json: Path
    classification_json: Path | None = None
    output: Path | None = None
    tag: str = "rca"
    exploitability: bool = True

    def __post_init__(self) -> None:
        """Ensure paths are Path objects and resolved."""
        if isinstance(self.context_json, str):
            self.context_json = Path(self.context_json)
        if isinstance(self.classification_json, str):
            self.classification_json = Path(self.classification_json)
        if isinstance(self.output, str):
            self.output = Path(self.output)

        self.context_json = self.context_json.expanduser().resolve()
        if self.classification_json:
            self.classification_json = self.classification_json.expanduser().resolve()
        if self.output:
            self.output = self.output.expanduser().resolve()


@dataclass
class BatchTriageConfig:
    """Configuration for batch crash triage.

    Attributes:
        binary: Path to the fuzz target binary.
        crash_dir: Directory containing crash files.
        tag: Short identifier for artifact naming.
        backend: Triage backend to use.
        output_dir: Output directory for results (default: crash_dir/triage).
        dap_path: Explicit lldb-dap binary path (for dap backend).
        dap_port: DAP server port (for dap backend).
        timeout: Operation timeout in seconds.
        log_level: Logging verbosity level.
        mcp_host: MCP server host (for lldb_mcp backend).
        mcp_port: MCP server port (for lldb_mcp backend).
    """

    binary: Path
    crash_dir: Path
    tag: str = "triage"
    backend: Literal["dap", "sbapi", "lldb_mcp"] = "dap"
    output_dir: Path | None = None
    dap_path: str | None = None
    dap_port: int = 0
    timeout: float = 30.0
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "ERROR"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 59999

    def __post_init__(self) -> None:
        """Ensure paths are Path objects and resolved."""
        if isinstance(self.binary, str):
            self.binary = Path(self.binary)
        if isinstance(self.crash_dir, str):
            self.crash_dir = Path(self.crash_dir)
        if isinstance(self.output_dir, str):
            self.output_dir = Path(self.output_dir)

        self.binary = self.binary.expanduser().resolve()
        self.crash_dir = self.crash_dir.expanduser().resolve()
        if self.output_dir:
            self.output_dir = self.output_dir.expanduser().resolve()


@dataclass
class TriageResult:
    """Result from a triage operation.

    Attributes:
        success: Whether triage completed successfully.
        json_path: Path to generated JSON output.
        markdown_path: Path to generated Markdown report (if any).
        stack_hash: Crash stack hash (if computed).
        error: Error message if triage failed.
        metadata: Additional metadata from triage.
    """

    success: bool
    json_path: Path | None = None
    markdown_path: Path | None = None
    stack_hash: str | None = None
    error: str | None = None
    metadata: dict | None = None


@dataclass
class ClassifyResult:
    """Result from a classification operation.

    Attributes:
        success: Whether classification completed successfully.
        classification: Crash classification label.
        confidence: Classification confidence (0-1).
        source: Classification source (llm-adapter, heuristic, etc).
        json_path: Path to generated JSON output.
        prompt_path: Path to saved LLM prompt.
        error: Error message if classification failed.
        exploitability: Exploitability assessment data.
    """

    success: bool
    classification: str = "unknown"
    confidence: float = 0.0
    source: str = "unknown"
    json_path: Path | None = None
    prompt_path: Path | None = None
    error: str | None = None
    exploitability: dict | None = None


@dataclass
class ReportResult:
    """Result from a report generation operation.

    Attributes:
        success: Whether report generation completed successfully.
        output_path: Path to generated Markdown report.
        error: Error message if generation failed.
    """

    success: bool
    output_path: Path | None = None
    error: str | None = None


__all__ = [
    "TriageConfig",
    "ClassifyConfig",
    "ReportConfig",
    "BatchTriageConfig",
    "TriageResult",
    "ClassifyResult",
    "ReportResult",
]
