"""Handler-level tests for new kernel tool definitions."""

from __future__ import annotations

import base64
import json

import pytest

from alf.backend.mock import MockBackend
from alf.server.lldb import LLDBDirector
from alf.tools.definitions.lldb.kernel import (
    _lldb_add_module_handler,
    _lldb_load_xnu_macros_handler,
    _lldb_slide_handler,
    _lldb_write_memory_handler,
)


@pytest.fixture
def director() -> LLDBDirector:
    mock = MockBackend()
    director = LLDBDirector(dap_host="mock", dap_port=0, backend=mock)
    # Establish a session so write_memory_atomic can engage its resume path.
    director.gdb_remote_session(host="127.0.0.1", port=8864, target="/tmp/kernel")
    return director


def test_add_module_roundtrip(director: LLDBDirector) -> None:
    out = _lldb_add_module_handler(
        director,
        path="/tmp/kernel",
        dsym="/tmp/kernel.dSYM",
        slide=0x1000,
    )
    parsed = json.loads(out)
    assert parsed["loaded"] is True
    assert parsed["path"] == "/tmp/kernel"
    assert parsed["dsym"] == "/tmp/kernel.dSYM"


def test_slide_handler_returns_hex(director: LLDBDirector) -> None:
    out = _lldb_slide_handler(director, module="kernel.release.vmapple")
    parsed = json.loads(out)
    assert parsed["module"] == "kernel.release.vmapple"
    assert parsed["slide"] == "0x100000"
    assert parsed["slide_int"] == 0x100000


def test_load_xnu_macros_missing_returns_actionable(director: LLDBDirector, tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ALF_XNU_LLDBMACROS", raising=False)
    out = _lldb_load_xnu_macros_handler(director, path=str(tmp_path))
    parsed = json.loads(out)
    assert parsed["loaded"] is False
    assert "xnu lldbmacros" in parsed.get("error", "")


def test_load_xnu_macros_uses_explicit_path(director: LLDBDirector, tmp_path) -> None:
    (tmp_path / "xnu.py").write_text("# stub\n")
    out = _lldb_load_xnu_macros_handler(director, path=str(tmp_path))
    parsed = json.loads(out)
    # Mock execute_command returns non-error output, so loaded=True.
    assert parsed["loaded"] is True
    assert parsed["path"] == str(tmp_path)
    assert parsed["script"].endswith("xnu.py")


def test_write_memory_hex_encoding(director: LLDBDirector) -> None:
    out = _lldb_write_memory_handler(
        director,
        address="0x10000",
        data="deadbeef",
        encoding="hex",
        resume=False,
    )
    parsed = json.loads(out)
    assert parsed["bytes_written"] == 4


def test_write_memory_base64_encoding(director: LLDBDirector) -> None:
    data = base64.b64encode(b"ABCD").decode("ascii")
    out = _lldb_write_memory_handler(
        director,
        address="0x10000",
        data=data,
        encoding="base64",
        resume=False,
    )
    parsed = json.loads(out)
    assert parsed["bytes_written"] == 4


def test_write_memory_ascii_encoding(director: LLDBDirector) -> None:
    out = _lldb_write_memory_handler(
        director,
        address="0x10000",
        data="hi",
        encoding="ascii",
        resume=False,
    )
    parsed = json.loads(out)
    assert parsed["bytes_written"] == 2


def test_write_memory_invalid_encoding(director: LLDBDirector) -> None:
    out = _lldb_write_memory_handler(
        director,
        address="0x10000",
        data="garbage",
        encoding="nope",
        resume=False,
    )
    parsed = json.loads(out)
    assert "invalid data" in parsed["error"] or "unknown encoding" in parsed["error"]


def test_write_memory_empty_payload(director: LLDBDirector) -> None:
    out = _lldb_write_memory_handler(
        director,
        address="0x10000",
        data="",
        encoding="hex",
        resume=False,
    )
    parsed = json.loads(out)
    assert parsed.get("error") == "empty payload"
