"""Crash triage clients and helpers.

This module provides crash triage workflows:
- MCP-based triage via lldb-dap
- Crash classification with optional LLM assistance
- RCA report generation

Config-based API (preferred):
    from alf.triage import ClassifyConfig, ReportConfig, run_classify, run_report

    config = ClassifyConfig(binary=Path("./fuzz"), crash=Path("./crash-abc"))
    result = run_classify(config)

CLI entry points:
    from alf.triage import classify_main, report_main, triage_main
"""

from __future__ import annotations

# CLI entry points
from .classify import main as classify_main

# Run functions (config-based API)
from .classify import run_classify

# Config classes
from .config import (
    BatchTriageConfig,
    ClassifyConfig,
    ClassifyResult,
    ReportConfig,
    ReportResult,
    TriageConfig,
    TriageResult,
)
from .dap import main as dap_main
from .once import main as triage_main
from .once import run_triage
from .report import main as report_main
from .report import run_report

# Legacy alias: `alf.triage.main` -> MCP triage once.
main = triage_main

__all__ = [
    # Config classes
    "TriageConfig",
    "ClassifyConfig",
    "ReportConfig",
    "BatchTriageConfig",
    "TriageResult",
    "ClassifyResult",
    "ReportResult",
    # Run functions
    "run_triage",
    "run_classify",
    "run_report",
    # CLI entry points
    "main",
    "triage_main",
    "dap_main",
    "classify_main",
    "report_main",
]
