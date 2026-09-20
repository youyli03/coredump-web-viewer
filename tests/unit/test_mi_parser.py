"""Unit tests for the MI record parser — no gdb needed.

The fixtures are **verbatim** lines captured from a real gdb (Arm GNU Toolchain 13.3, `--interpreter=mi3`)
while it was reading a real aarch64 core. That matters: the shapes below are what gdb actually sends, not
what the manual says it sends, and the parser is only worth anything if it matches reality.
"""

from __future__ import annotations

import pytest

from analysis.gdb.mi import (
    MiParseError,
    _labelled,
    _tid_from_target_id,
    parse_record,
    parse_records,
)

# --- stream records ------------------------------------------------------------------ #
def test_console_record_decodes_escapes() -> None:
    # The path only has to be one gdb would print; the practice bundle's own root keeps the fixture free of any
    # other machine's layout.
    line = r'~"Reading symbols from /home/lyy/cdwv-practice/out/crash_target...\n"'
    record = parse_record(line)
    assert record["kind"] == "console"
    assert record["text"] == "Reading symbols from /home/lyy/cdwv-practice/out/crash_target...\n"


def test_log_record_is_kept_separate_from_console() -> None:
    """`&` is gdb's own log stream; mixing it into console output would misreport warnings as results."""
    record = parse_record(r'&"warning: "')
    assert record["kind"] == "log"
    assert record["text"] == "warning: "


# --- result records ------------------------------------------------------------------ #
def test_result_record_with_a_tuple() -> None:
    line = '^done,frame={level="0",addr="0x0000007f87b9078c",func="??",args=[],arch="aarch64"}'
    record = parse_record(line)
    assert record["kind"] == "result"
    assert record["class"] == "done"
    frame = record["results"]["frame"]
    assert frame["addr"] == "0x0000007f87b9078c"
    assert frame["args"] == []


def test_result_record_with_a_list_of_tuples() -> None:
    line = (
        '^done,threads=[{id="1",target-id="LWP 2804926",'
        'frame={level="0",func="plugin_crash",line="29",arch="aarch64"},state="stopped"},'
        '{id="2",target-id="LWP 2804927",frame={level="0",func="??"},state="stopped"}],'
        'current-thread-id="1"'
    )
    results = parse_record(line)["results"]
    assert results["current-thread-id"] == "1"
    assert [t["id"] for t in results["threads"]] == ["1", "2"]
    assert results["threads"][0]["frame"]["func"] == "plugin_crash"
    assert results["threads"][1]["target-id"] == "LWP 2804927"


def test_labelled_list_elements_are_unwrapped_by_the_helper() -> None:
    """`stack=[frame={…}]` parses to `[{"frame": {…}}]`; the label must come off before reading fields."""
    line = '^done,stack=[frame={level="0",func="plugin_crash"},frame={level="1",func="descend"}]'
    stack = parse_record(line)["results"]["stack"]
    assert stack == [
        {"frame": {"level": "0", "func": "plugin_crash"}},
        {"frame": {"level": "1", "func": "descend"}},
    ]
    assert _labelled(stack[0], "frame") == {"level": "0", "func": "plugin_crash"}
    assert _labelled({"other": 1}, "frame") == {"other": 1}  # never guess


def test_register_names_and_values() -> None:
    names = parse_record('^done,register-names=["","x0","x1","pc"]')["results"]["register-names"]
    assert names == ["", "x0", "x1", "pc"]
    values = parse_record(
        '^done,register-values=[{number="0",value="0x0"},{number="1",value="0xdead0000dead0000"}]'
    )["results"]["register-values"]
    assert values[1]["value"] == "0xdead0000dead0000"


def test_empty_tuple_and_list() -> None:
    results = parse_record("^done,args=[],frame={}")["results"]
    assert results["args"] == []
    assert results["frame"] == {}


def test_error_record_keeps_the_message() -> None:
    line = r'^error,msg="No symbol table is loaded.  Use the \"file\" command."'
    record = parse_record(line)
    assert record["class"] == "error"
    assert record["results"]["msg"] == 'No symbol table is loaded.  Use the "file" command.'


def test_notify_and_async_records() -> None:
    notify = parse_record('=library-loaded,id="/lib/aarch64-linux-gnu/libc.so.6",symbols-loaded="0"')
    assert (notify["kind"], notify["class"]) == ("notify", "library-loaded")
    assert notify["results"]["symbols-loaded"] == "0"

    stopped = parse_record('*stopped,reason="signal-received",signal-name="SIGSEGV"')
    assert (stopped["kind"], stopped["class"]) == ("exec", "stopped")
    assert stopped["results"]["signal-name"] == "SIGSEGV"

    bare = parse_record("=thread-created,id=\"1\",group-id=\"i1\"")
    assert bare["class"] == "thread-created"


def test_token_is_parsed_when_present() -> None:
    assert parse_record('7^done,value="1"')["token"] == 7
    assert parse_record("^done")["token"] is None


def test_unpaired_prompt_line_is_not_a_record() -> None:
    with pytest.raises(MiParseError):
        parse_record("(gdb) ")


def test_unterminated_string_is_rejected() -> None:
    with pytest.raises(MiParseError):
        parse_record('~"never closed')


def test_parse_records_is_just_a_map() -> None:
    records = parse_records(['=thread-created,id="1"', "^done"])
    assert [r["kind"] for r in records] == ["notify", "result"]


# --- target-id → tid ------------------------------------------------------------------ #
@pytest.mark.parametrize(
    ("target_id", "expected"),
    [
        ("LWP 2804926", 2804926),
        ("Thread 0x7f895def80 (LWP 2804937)", 2804937),
        ("process 1234", 1234),
        (None, None),
        ("", None),
        ("no digits here", None),
        # A named thread with no LWP must not yield the tail of its hex address.
        ("Thread 0x7f895def80", None),
    ],
)
def test_tid_from_target_id(target_id: str | None, expected: int | None) -> None:
    assert _tid_from_target_id(target_id) == expected
