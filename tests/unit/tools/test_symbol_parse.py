"""Targeted tests for `_parse_lookup_output` covering names with spaces."""

from __future__ import annotations

from alf.tools.definitions.lldb.symbols import _parse_lookup_output


def test_parses_c_symbol_with_offset() -> None:
    raw = (
        "1 match found in /bin/ls:\n"
        "        Address: /bin/ls[0x0000000100000328] (/bin/ls.__TEXT.__text + 200)\n"
        "        Summary: /bin/ls`main + 16\n"
    )
    matches = _parse_lookup_output(raw)
    assert len(matches) == 1
    assert matches[0]["addr"] == "0x0000000100000328"
    assert matches[0]["module"] == "/bin/ls"
    assert matches[0]["name"] == "main"
    assert matches[0]["offset"] == 16


def test_parses_objc_selector_with_spaces() -> None:
    raw = (
        "        Address: /AppKit[0x0000000180aabbcc]\n"
        "        Summary: AppKit`-[NSApplication run] + 48\n"
    )
    matches = _parse_lookup_output(raw)
    assert len(matches) == 1
    assert matches[0]["name"] == "-[NSApplication run]"
    assert matches[0]["offset"] == 48


def test_parses_cpp_operator_without_offset() -> None:
    raw = (
        "        Address: libfoo[0x0000000100000400]\n"
        "        Summary: libfoo`std::operator<<(std::ostream&, char const*)\n"
    )
    matches = _parse_lookup_output(raw)
    assert len(matches) == 1
    assert matches[0]["name"] == "std::operator<<(std::ostream&, char const*)"
    assert "offset" not in matches[0]


def test_parses_multiple_matches_regex() -> None:
    raw = (
        "        Address: /lib[0x0000000100000100]\n"
        "        Summary: lib`parse_foo + 0\n"
        "        Address: /lib[0x0000000100000200]\n"
        "        Summary: lib`parse_bar + 12\n"
    )
    matches = _parse_lookup_output(raw)
    assert len(matches) == 2
    assert [m["name"] for m in matches] == ["parse_foo", "parse_bar"]
