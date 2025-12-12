#!/usr/bin/env python3
"""
Compatibility wrapper for `alf.triage.report`.

Allows `python -m alf.report` and old import paths.
"""

from __future__ import annotations

from .triage.report import *  # noqa: F403

if __name__ == "__main__":
    from .triage.report import main

    raise SystemExit(main())
