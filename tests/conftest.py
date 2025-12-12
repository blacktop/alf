"""Shared pytest fixtures and configuration."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_crash_context() -> dict:
    """Sample crash context for exploitability tests."""
    return {
        "reason": "EXC_BAD_ACCESS",
        "registers": """
x0 = 0x0000000000000000
x1 = 0x0000000100008000
pc = 0x0000000100004000
sp = 0x000000016f000100
lr = 0x0000000100003f00
""",
        "pcs": ["0x100004000", "0x100003f00", "0x100002000"],
        "disassemble": """
->  0x100004000: str x0, [x1]
    0x100004004: ret
""",
        "stop": {
            "reason": "exception",
            "description": "EXC_BAD_ACCESS (code=2, address=0x100008000)",
        },
    }


@pytest.fixture
def sample_toml_config(tmp_path):
    """Create a sample .alf.toml config file."""
    content = '''
[provider]
name = "anthropic"
model = "claude-3-opus"
timeout = 300

[provider.anthropic]
api_key = "test-key"

[lldb]
dap_path = "/usr/bin/lldb-dap"
timeout = 60

[director]
mode = "auto"
max_turns = 10
'''
    config_file = tmp_path / ".alf.toml"
    config_file.write_text(content)
    return config_file
