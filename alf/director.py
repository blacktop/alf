#!/usr/bin/env python3
"""
Compatibility wrapper for `alf.agent.director`.

The implementation moved to the agent package; this module keeps the
old import path and `python -m alf.director` working.
"""

from __future__ import annotations

from .agent.director import *  # noqa: F403

if __name__ == "__main__":
    from .agent.director import main

    raise SystemExit(main())
