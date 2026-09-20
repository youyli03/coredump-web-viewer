"""Unit tests for frame arguments and locals — no gdb needed.

Fixtures are **verbatim** replies from the real cross gdb reading a real aarch64 core, so the shapes are
what gdb actually sends. Two of them carry the distinctions the whole stack view depends on:

* a frame's arguments come back with the symbol attached (`0x7f87b906a4 <plugin_crash>`), which is a value
  the UI can jump to *and* a name worth reading;
* an aggregate argument (`volatile int [32]`) comes back with a type and **no `value= field at all**,
  which is neither an empty string nor a read that failed.
"""

from __future__ import annotations

import pytest

from analysis.gdb.mi import MiTransport, _variable, parse_records

# --- verbatim replies ----------------------------------------------------------------- #
FRAME0_VARIABLES = (
    '^done,variables=[{name="head",arg="1",type="struct node *",value="0x55658ee2a0"},'
    '{name="n",type="struct node *",value="0x55658ee2e0"},{name="hops",type="int",value="4"},'
    '{name="stray",type="struct node *",value="0xdead0000dead0000"}]'
)
FRAME1_VARIABLES = (
    '^done,variables=[{name="n",arg="1",type="struct node *",value="0x55658ee2a0"},'
    '{name="depth",arg="1",type="int",value="0"},{name="crash",arg="1",'
    'type="void (*)(struct node *)",value="0x7f87b906a4 <plugin_crash>"},'
    '{name="pad",type="volatile int [32]"}]'
)
STACK_ARGS = (
    '^done,stack-args=[frame={level="0",args=[{name="head",type="struct node *",'
    'value="0x55658ee2a0"}]},frame={level="1",args=[{name="n",type="struct node *",'
    'value="0x55658ee2a0"},{name="depth",type="int",value="0"},{name="crash",'
    'type="void (*)(struct node *)",value="0x7f87b906a4 <plugin_crash>"}]},'
    'frame={level="2",args=[{name="n",type="struct node *",value="0x55658ee2a0"},'
    '{name="depth",type="int",value="1"},{name="crash",type="void (*)(struct node *)",'
    'value="0x7f87b906a4 <plugin_crash>"}]}]'
)


def _bare_transport(commands: list[str]) -> MiTransport:
    """Not started, and never will be: gdb is replaced by a table of canned replies."""
    transport = MiTransport(gdb_path="gdb", core_path="core")

    def fake_exec(command: str, *, timeout: float | None = None) -> list[dict]:
        commands.append(command)
        if command.startswith("-stack-list-arguments"):
            return parse_records([STACK_ARGS])
        if command.startswith("-stack-list-variables"):
            return parse_records([FRAME0_VARIABLES])
        return parse_records(["^done"])

    transport._exec = fake_exec  # type: ignore[method-assign]
    return transport


# --- one variable --------------------------------------------------------------------- #
def test_an_argument_is_marked_and_a_local_is_not() -> None:
    reply = parse_records([FRAME0_VARIABLES])[0]["results"]["variables"]
    variables = [_variable(raw) for raw in reply]
    assert [v["name"] for v in variables] == ["head", "n", "hops", "stray"]
    assert [v["is_arg"] for v in variables] == [True, False, False, False]
    assert variables[0]["type"] == "struct node *"
    # The local that killed the program is a plain value here; walking it is the memory view's job.
    assert variables[3]["value"] == "0xdead0000dead0000"


def test_a_missing_value_is_not_an_empty_value() -> None:
    """`--simple-values` leaves an aggregate out entirely. That is not "unreadable" and not NULL."""
    reply = parse_records([FRAME1_VARIABLES])[0]["results"]["variables"]
    pad = _variable(reply[3])
    assert pad["type"] == "volatile int [32]"
    assert pad["value"] is None, "no value= field means gdb did not read it"
    assert pad["is_arg"] is False

    empty = _variable({"name": "x", "type": "int", "value": ""})
    assert empty["value"] == ""
    assert empty["value"] is not None, "an empty string is a value gdb sent and could not read"


def test_a_function_pointer_keeps_its_symbol() -> None:
    reply = parse_records([FRAME1_VARIABLES])[0]["results"]["variables"]
    crash = _variable(reply[2])
    assert crash["value"] == "0x7f87b906a4 <plugin_crash>"
    assert crash["type"] == "void (*)(struct node *)"


def test_an_unknown_shape_does_not_crash() -> None:
    assert _variable("garbage")["name"] is None


# --- a range of frames, in one query --------------------------------------------------- #
def test_frame_arguments_are_grouped_by_level() -> None:
    commands: list[str] = []
    transport = _bare_transport(commands)
    transport._frames = lambda thread_num: [{"level": 0}, {"level": 1}, {"level": 2}]  # type: ignore[method-assign]
    transport._select_thread = lambda thread_num: None  # type: ignore[method-assign]

    arguments = transport.frame_arguments(1)
    assert sorted(arguments) == [0, 1, 2]
    assert [a["name"] for a in arguments[0]] == ["head"]
    assert [a["name"] for a in arguments[1]] == ["n", "depth", "crash"]
    # One query for the whole range, not one per frame — that is the point of the range form.
    assert len([c for c in commands if c.startswith("-stack-list-arguments")]) == 1
    # gdb 13 refuses the command without PRINT_VALUES, so it is never optional.
    assert commands[-1] == "-stack-list-arguments --simple-values 0 2"
    assert all(a["is_arg"] for a in arguments[1]), "everything this command lists is an argument"


def test_frame_arguments_ask_for_the_whole_stack_by_default() -> None:
    commands: list[str] = []
    transport = _bare_transport(commands)
    transport._frames = lambda thread_num: [{"level": level} for level in range(27)]  # type: ignore[method-assign]
    transport._select_thread = lambda thread_num: None  # type: ignore[method-assign]
    transport.frame_arguments(1)
    assert commands[-1].endswith(" 0 26")


# --- one frame's arguments and locals -------------------------------------------------- #
def test_frame_variables_include_locals() -> None:
    commands: list[str] = []
    transport = _bare_transport(commands)
    transport._select_thread = lambda thread_num: None  # type: ignore[method-assign]

    variables = transport.frame_variables(1, 0)
    assert [v["name"] for v in variables] == ["head", "n", "hops", "stray"]
    assert [v["is_arg"] for v in variables] == [True, False, False, False]


def test_frame_variables_select_the_frame_they_are_about() -> None:
    """The frame selection is transport state, so asking about frame 1 has to move it there."""
    commands: list[str] = []
    transport = _bare_transport(commands)
    transport._select_thread = lambda thread_num: None  # type: ignore[method-assign]

    transport.frame_variables(1, 3)
    assert "-stack-select-frame 3" in commands
    # Frame 0 is the default and needs no selection at all.
    commands.clear()
    transport.frame_variables(1)
    assert not [c for c in commands if c.startswith("-stack-select-frame")]


@pytest.mark.parametrize("level", [0, 1])
def test_the_thread_is_selected_before_its_frames_are_read(level: int) -> None:
    commands: list[str] = []
    transport = _bare_transport(commands)
    selected: list[int] = []
    transport._select_thread = lambda thread_num: selected.append(thread_num)  # type: ignore[method-assign]
    transport.frame_variables(2, level)
    assert selected == [2], "reading frame variables must not answer about another thread"
