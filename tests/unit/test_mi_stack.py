"""Unit tests for stack-memory parsing — no gdb needed.

The subject is the *stack* as memory, not the backtrace: which bytes each frame owns, what its frame
record says, and which variables actually live in those bytes.

The frame list, the `sp`/`fp` values and the frame-record bytes are **verbatim** from the real cross gdb
reading a real aarch64 core, so the arithmetic is the arithmetic the transport really meets. Two parts are
**constructed**, and they are marked where they appear: the fake gdb's memory of which frame is selected
(real gdb has that state; a canned reply table does not), and the `&head` refusal that exercises the
register-resident path — on the practice core that argument happens to be spilled, so the refusal is a real
gdb answer for a case this particular core does not contain.

Two things here are worth more than the rest:

* the fake keeps the *selected frame*, because `$sp` and `$fp` are answers about whichever frame is
  selected — a fixture that ignored that would pass while the transport read the wrong frame;
* a frame record is only believed when it agrees with the next frame gdb found, so the tests pin both the
  verified and the unverifiable case. A record nobody can corroborate is a pair of numbers, not a chain.
"""

from __future__ import annotations

from typing import Any

from analysis.gdb.mi import (
    FRAME_RECORDS,
    MiTransport,
    _frame_record,
    _no_record,
    _verify_record,
    parse_records,
)

# --- verbatim replies ----------------------------------------------------------------- #
# The first three frames of the crashed thread. `addr` is the pc; sp/fp are not in this reply at all —
# that is the whole reason `stack_frames` has to ask frame by frame.
STACK_FRAMES = (
    '^done,stack=[frame={level="0",addr="0x0000007f94e2078c",func="plugin_crash",'
    'file="/home/lyy/cdwv-practice/src/libplugin.c",fullname="/home/lyy/cdwv-practice/src/libplugin.c",'
    'line="29",arch="aarch64"},frame={level="1",addr="0x000000555c921198",func="descend",'
    'file="/home/lyy/cdwv-practice/src/crash_target.c",fullname="/home/lyy/cdwv-practice/src/crash_target.c",'
    'line="41",arch="aarch64"},frame={level="2",addr="0x000000555c921188",func="descend",'
    'file="/home/lyy/cdwv-practice/src/crash_target.c",fullname="/home/lyy/cdwv-practice/src/crash_target.c",'
    'line="41",arch="aarch64"}]'
)

# `sp`/`fp` per level. Level 2 answers `$fp` in *decimal*, which gdb really does for some registers
# (`$lr` came back as `547958687624` in the probe) — an address that is read as a decimal number is a bug
# waiting to happen, so one of them is here on purpose.
REGISTERS_BY_LEVEL: dict[int, dict[str, str]] = {
    0: {"$sp": "0x7feb1f9e20", "$fp": "0x7feb1f9e20"},
    1: {"$sp": "0x7feb1f9e60", "$fp": "0x7feb1f9f10"},
    2: {"$sp": "0x7feb1f9f20", "$fp": "549405564880"},
}

# The frame records, little-endian, as they sit at each frame's `fp`:
#   #0 at 0x7feb1f9e20 → saved fp 0x7feb1f9f10 (= frame 1's fp), return address 0x555c921198 (= frame 1's pc)
#   #1 at 0x7feb1f9f10 → saved fp 0x7feb1f9fd0 (= frame 2's fp), return address 0x555c921188 (= frame 2's pc)
RECORD_BY_ADDRESS: dict[str, str] = {
    "0x7feb1f9e20": "109f1feb7f000000" + "9811925c55000000",
    "0x7feb1f9f10": "d09f1feb7f000000" + "8811925c55000000",
    # Frame 2's own record, with no frame 3 in the fixture to corroborate it.
    "0x7feb1f9fd0": "90201feb7f000000" + "8811925c55000000",
}

# Frame 0's variables: two locals with stack slots, one argument in a register (no address at all).
FRAME0_VARIABLES = (
    '^done,variables=[{name="head",arg="1",type="struct node *",value="0x55658ee2a0"},'
    '{name="hops",type="int",value="4"},{name="stray",type="struct node *",'
    'value="0xdead0000dead0000"},{name="seed",type="static int",value="7"}]'
)

# `info address` for the same variables — **verbatim shapes** from the real gdb, including the
# multi-location form an optimised build produces. `hops` is frame-relative memory (`DW_OP_fbreg`, which is
# what "in this frame" means); `head` was refused an address above and is in a register; `seed` is a static
# at a fixed address. The last one is multi-location on purpose: a variable's location is a function of the
# pc, and the range containing *this* frame's pc is the answer.
LOCATION_BY_NAME: dict[str, str] = {
    "hops": 'Symbol "hops" is a complex DWARF expression:\n    0: DW_OP_fbreg -20\n.\n',
    "head": 'Symbol "head" is a variable in $x0.\n',
    "stray": 'Symbol "stray" is a complex DWARF expression:\n    0: DW_OP_fbreg -8\n.\n',
    "seed": 'Symbol "seed" is a complex DWARF expression:\n    0: DW_OP_addr 0x555c932150\n.\n',
}

def _mi_stream(text: str) -> list[dict[str, Any]]:
    """A console record carrying `text`, escaped the way MI really carries it.

    A fixture is only worth what its *line* is worth: gdb escapes the quotes and the newlines inside a
    stream record (`~"Symbol \\"hops\\" is a variable at …\\n"`), and a fixture that puts them in raw
    produces a line the parser splits at the first inner quote — the test then fails for a reason that has
    nothing to do with the code under test.
    """
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return parse_records([f'~"{escaped}"', "^done"])


FRAME_0 = 0
FRAME_1 = 1
FRAME_2 = 2


class FakeGdb:
    """A canned gdb that remembers which frame is selected, because `$sp` depends on it."""

    def __init__(self, *, frame_apply: bool = True) -> None:
        self.commands: list[str] = []
        self.selected = 0
        self.frame_apply = frame_apply
        """Whether this gdb knows `frame apply` (gdb 8.1 and later). False models an older one, which the
        transport has to answer one frame at a time rather than refusing to answer at all."""

    def exec(self, command: str, *, timeout: float | None = None) -> list[dict[str, Any]]:
        self.commands.append(command)
        if command.startswith("-stack-list-frames"):
            return parse_records([STACK_FRAMES])
        if command.startswith("-stack-select-frame"):
            self.selected = int(command.rsplit(" ", 1)[-1])
            return parse_records(["^done"])
        if command.startswith("-stack-list-variables"):
            return parse_records([FRAME0_VARIABLES])
        if command.startswith("-interpreter-exec console") and "frame apply level" in command:
            if not self.frame_apply:
                return parse_records(['^error,msg="Undefined command: \"frame\"."'])
            span = command.split("frame apply level ", 1)[1].split(" ", 1)[0]
            first, _, last = span.partition("-")
            # The shape gdb really prints, captured from a session on the practice core: a `#<level> …` header
            # before each frame's output, then the line the command printed. The header is what makes this
            # self-describing — a frame whose registers cannot be read leaves a gap that shifts nothing.
            lines = []
            for level in range(int(first), int(last) + 1):
                registers = REGISTERS_BY_LEVEL[level]
                lines.append(f"#{level} 0x0000c585b55d0e38 in descend (depth={level}) at big.c:114")
                lines.append(f"{registers['$sp']} {registers['$fp']}")
            return _mi_stream("\n".join(lines) + "\n")
        if command.startswith("-interpreter-exec console"):
            name = command.split("info address ", 1)[-1].rstrip('"')
            if name in LOCATION_BY_NAME:
                return _mi_stream(LOCATION_BY_NAME[name])
            return _mi_stream(f'No symbol "{name}" in current context.\n')
        if command.startswith("-data-evaluate-expression"):
            expression = command.split(" ", 1)[1].strip().strip('"')
            if expression in ("$sp", "$fp"):
                value = REGISTERS_BY_LEVEL[self.selected][expression]
                return parse_records([f'^done,value="{value}"'])
            if expression == "&(head)":
                # CONSTRUCTED, not captured: gdb has no address for a variable that lives in a register,
                # and this is the shape of that refusal. The practice core has this argument spilled, so
                # the case cannot be captured from it — but the branch has to exist, because the question
                # "where is this variable" can legitimately have no address for an answer.
                return parse_records(['^error,msg="Address of \\"head\\" requested"'])
            if expression == "&(hops)":
                return parse_records(['^done,value="(int *) 0x7feb1f9e4c"'])
            if expression == "&(stray)":
                return parse_records(['^done,value="(struct node **) 0x7feb1f9e58"'])
            if expression == "&(seed)":
                # A `static` has an address, but not in this frame: it is in .bss.
                return parse_records(['^done,value="(int *) 0x555c932150"'])
            if expression.startswith("sizeof("):
                return parse_records(['^done,value="4"'])
        if command.startswith("-data-read-memory-bytes"):
            address = command.split(" ")[1]
            if address in RECORD_BY_ADDRESS:
                return parse_records([f'^done,memory=[{{begin="{address}",offset="0x0",end="0x10",'
                                      f'contents="{RECORD_BY_ADDRESS[address]}"}}]'])
            return parse_records([f'^error,msg="Unable to read memory."'])
        return parse_records(["^done"])


def _transport(*, frame_apply: bool = True) -> tuple[MiTransport, FakeGdb]:
    transport = MiTransport(gdb_path="gdb", core_path="core")
    fake = FakeGdb(frame_apply=frame_apply)
    transport._exec = fake.exec  # type: ignore[method-assign]
    return transport, fake


# --- the frame record itself --------------------------------------------------------- #
def test_the_table_is_keyed_by_architecture_not_by_operating_system() -> None:
    """QNX on aarch64 is AAPCS64 and QNX on x86_64 is SysV, so one table has to cover both platforms."""
    assert FRAME_RECORDS["aarch64"].return_address_at == 8
    assert FRAME_RECORDS["x86_64"].return_address_at == 8
    assert FRAME_RECORDS["arm"].return_address_at == 4
    assert FRAME_RECORDS["i386"].size == 8


def test_a_record_is_decoded_where_the_abi_puts_its_two_words() -> None:
    record = _frame_record("aarch64", 0x7FEB1F9E20, bytes.fromhex(RECORD_BY_ADDRESS["0x7feb1f9e20"]))
    assert record is not None
    assert record["saved_fp"] == "0x7feb1f9f10"
    assert record["return_address"] == "0x555c921198"
    assert record["verified"] is False, "decoding is not verification"


def test_an_unknown_architecture_gets_no_record_rather_than_a_guess() -> None:
    assert _frame_record("riscv:rv64", 0x1000, bytes(16)) is None


def test_a_record_the_dump_does_not_hold_is_none_not_a_zero_record() -> None:
    assert _frame_record("aarch64", 0x1000, b"\x00" * 8) is None, "half a record is not a record"


def test_an_architecture_variant_matches_its_family() -> None:
    record = _frame_record("x86_64:x86-64", 0x1000, bytes.fromhex("0010000000000000" + "0020000000000000"))
    assert record is not None and record["saved_fp"] == "0x1000" and record["return_address"] == "0x2000"


def test_a_record_is_verified_only_against_the_next_frame() -> None:
    record = _frame_record("aarch64", 0x7FEB1F9E20, bytes.fromhex(RECORD_BY_ADDRESS["0x7feb1f9e20"]))
    assert record is not None
    caller = {"level": 1, "pc": "0x000000555c921198"}
    good = _verify_record(record, {"sp": 0x7FEB1F9E60, "fp": 0x7FEB1F9F10}, caller)
    assert good["verified"] is True
    assert good["checks"] == {"saved_fp": True, "return_address": True}
    assert "agrees" in good["why"]

    # The return address is right, the saved frame pointer is not: a frame record that half agrees. The
    # *reason* has to name the frame pointer, because that is what tells a broken chain from overwritten
    # bytes — the two failures mean different things to whoever is reading the dump.
    half = _verify_record(record, {"sp": 0x7FEB1F9E60, "fp": 0x7FEB1FA000}, caller)
    assert half["verified"] is False
    assert half["checks"] == {"saved_fp": False, "return_address": True}
    assert "frame pointer does not point at the next frame" in half["why"]

    # ...and the other way round names the return address.
    other = _verify_record(record, {"sp": 0x7FEB1F9E60, "fp": 0x7FEB1F9F10}, {"level": 1, "pc": "0x999"})
    assert other["checks"] == {"saved_fp": True, "return_address": False}
    assert "return address is not where gdb says" in other["why"]

    # A missing check is `None`, not `False` and not a pass: one check on its own still decides, but
    # *nothing* to check against is not verification, and has to come out False rather than "no objection".
    one_check = _verify_record(record, {}, caller)
    assert one_check["checks"] == {"saved_fp": None, "return_address": True}
    assert one_check["verified"] is True
    nothing = _verify_record(record, {}, None)
    assert nothing["checks"] == {"saved_fp": None, "return_address": None}
    assert nothing["verified"] is False
    assert "no next frame" in nothing["why"]


def test_an_absent_record_is_still_a_record_with_a_reason() -> None:
    """`record` is never `None`: a caller should not have to branch on the shape as well as the answer."""
    absent = _no_record("the frame record is not in this dump")
    assert absent["at"] is None and absent["saved_fp"] is None
    assert absent["verified"] is False
    assert absent["checks"] == {"saved_fp": None, "return_address": None}
    assert "not in this dump" in absent["why"]


# --- frames as memory ----------------------------------------------------------------- #
def test_every_frame_gets_the_memory_between_its_own_sp_and_its_callers() -> None:
    transport, _ = _transport()
    frames = transport.stack_frames(1, low=0, high=2)
    assert [frame["start"] for frame in frames] == ["0x7feb1f9e20", "0x7feb1f9e60", "0x7feb1f9f20"]
    assert [frame["end"] for frame in frames] == ["0x7feb1f9e60", "0x7feb1f9f20", None]
    assert frames[0]["record"]["verified"] is True
    assert frames[1]["record"]["verified"] is True
    # The last frame in the slice has no caller here, so its end is an honest hole — not `fp + 16`.
    assert frames[2]["end"] is None
    assert frames[2]["record"] is not None, "its record was decoded; it just could not be corroborated"


def test_the_frame_pointer_is_read_as_an_address_however_gdb_prints_it() -> None:
    transport, _ = _transport()
    frames = transport.stack_frames(1, low=2, high=2)
    # gdb answered `$fp` for this frame in decimal: 549958280912 == 0x7feb1f9fd0.
    assert frames[0]["fp"] == "0x7feb1f9fd0"


def test_a_slice_still_ends_its_last_frame_at_the_caller_it_did_not_show() -> None:
    transport, _ = _transport()
    frames = transport.stack_frames(1, low=0, high=0)
    assert len(frames) == 1
    assert frames[0]["end"] == "0x7feb1f9e60", "the caller's sp is known even though the caller is not shown"


def test_a_frame_record_on_a_missing_page_says_why_rather_than_saying_nothing() -> None:
    transport, _ = _transport()
    transport._located[1] = {
        0: {"sp": 0x7FEB1F9E20, "fp": 0x7FEB1F9E20},
        1: {"sp": 0x7FEB1F9E60, "fp": 0x7FEB1F9F10},
        2: {"sp": 0x7FEB1F9F20, "fp": 0x7FEB1F9FD0},
    }
    # Ask for frame 0 only, and pretend its record page is not in the dump.
    transport._read_frame_record = lambda frame, fp: None  # type: ignore[method-assign]
    frames = transport.stack_frames(1, low=0, high=0)
    assert frames[0]["record"]["at"] is None
    assert frames[0]["record"]["verified"] is False
    assert "not in this dump" in frames[0]["record"]["why"]
    assert frames[0]["end"] == "0x7feb1f9e60"
    assert transport.warnings == [], "a record on a missing page is not worth a warning per frame"


def test_an_unknown_architecture_says_which_architecture_it_does_not_know() -> None:
    transport, _ = _transport()
    transport._stacks[1] = [
        {"level": 0, "func": "f", "pc": "0x1000", "arch": "riscv:rv64"},
        {"level": 1, "func": "main", "pc": "0x2000", "arch": "riscv:rv64"},
    ]
    transport._frame_locations = lambda thread, first, upto: {  # type: ignore[method-assign]
        0: {"sp": 0x8000, "fp": 0x8000},
        1: {"sp": 0x8100, "fp": 0x8100},
    }
    frames = transport.stack_frames(1, low=0, high=1)
    assert frames[0]["record"]["at"] is None
    assert "riscv:rv64" in frames[0]["record"]["why"]
    # The extent does not depend on knowing the record layout, so it still says something useful.
    assert frames[0]["start"] == "0x8000" and frames[0]["end"] == "0x8100"


def test_an_extent_that_does_not_grow_is_not_a_range_and_says_so() -> None:
    """A frame that allocated nothing owns no bytes — and so does a chain that repeats the same `sp`."""
    transport, _ = _transport()
    transport._stacks[1] = [
        {"level": 0, "func": "leaf", "pc": "0x1000", "arch": "aarch64"},
        {"level": 1, "func": "main", "pc": "0x2000", "arch": "aarch64"},
    ]
    transport._frame_locations = lambda thread, first, upto: {  # type: ignore[method-assign]
        0: {"sp": 0x9000, "fp": 0x9000},
        1: {"sp": 0x9000, "fp": 0x9000},
    }
    frames = transport.stack_frames(1, low=0, high=1)
    assert frames[0]["start"] == "0x9000" and frames[0]["end"] is None
    assert "not above" in frames[0]["extent_why"]
    # The outermost frame of the slice has no caller at all, which is a different sentence.
    assert frames[1]["end"] is None
    assert "caller is not in this dump" in frames[1]["extent_why"]


def test_asking_about_frames_selects_each_of_them_once() -> None:
    """The fallback path, for a gdb without `frame apply` (older than 8.1).

    Every frame is selected once, and the second call selects nothing because `sp`/`fp` are cached — which is
    what the batched path replaced with a single command, without changing this behaviour for a gdb that has
    no batch to offer.
    """
    transport, fake = _transport(frame_apply=False)
    transport.stack_frames(1, low=0, high=2)
    selects = [command for command in fake.commands if command.startswith("-stack-select-frame")]
    assert selects == ["-stack-select-frame 0", "-stack-select-frame 1", "-stack-select-frame 2"]
    # Again: the `sp`/`fp` of every frame are already cached.
    transport.stack_frames(1, low=0, high=2)
    assert [c for c in fake.commands if c.startswith("-stack-select-frame")] == selects


# --- variables as bytes --------------------------------------------------------------- #
def test_a_local_with_a_slot_gets_its_address_and_size() -> None:
    transport, _ = _transport()
    slots = {slot["name"]: slot for slot in transport.frame_slots(1, level=0)}
    assert slots["hops"]["address"] == "0x7feb1f9e4c"
    assert slots["hops"]["size"] == 4
    assert slots["hops"]["slot"] is True
    assert slots["hops"]["where"] == "stack"
    assert slots["hops"]["inside"] is True, "the frame's extent corroborates what the location says"
    assert slots["hops"]["value"] == "4", "the value is still there; the slot is the new part"


def test_a_variable_in_a_register_is_named_rather_than_dropped() -> None:
    """The address is gone, but the variable is not: gdb knows which register holds it.

    This is the case an optimised build produces constantly, and a viewer that only draws what it can place
    would silently show a frame with fewer variables than it has.
    """
    transport, _ = _transport()
    slots = {slot["name"]: slot for slot in transport.frame_slots(1, level=0)}
    head = slots["head"]
    assert head["value"] == "0x55658ee2a0"
    assert head["address"] is None, "gdb refused `&head`; None is not zero"
    assert head["slot"] is False and head["size"] is None
    assert head["where"] == "register"
    assert head["register"] == "x0", "the register is a fact from the DWARF location, not a guess"


def test_a_static_has_an_address_but_it_is_not_in_this_frame() -> None:
    transport, _ = _transport()
    slots = {slot["name"]: slot for slot in transport.frame_slots(1, level=0)}
    assert slots["seed"]["address"] == "0x555c932150"
    assert slots["seed"]["where"] == "static", "`DW_OP_addr` is a fixed address, not a frame-relative one"
    assert slots["seed"]["slot"] is False, "a `static` lives in .bss, so it is not part of the stack bytes"


def test_slots_come_back_for_arguments_and_locals_alike() -> None:
    transport, _ = _transport()
    slots = transport.frame_slots(1, level=0)
    assert [slot["name"] for slot in slots] == ["head", "hops", "stray", "seed"]
    assert next(slot for slot in slots if slot["name"] == "head")["is_arg"] is True


def test_a_variable_with_no_stack_slot_still_says_where_it_is() -> None:
    """Every variable comes back with a place, even when the place is not a byte range."""
    transport, _ = _transport()
    for slot in transport.frame_slots(1, level=0):
        assert slot["where"] in ("stack", "register", "static", "computed", "unavailable")
        if slot["where"] != "stack":
            assert slot["slot"] is False
            assert slot["value"] is not None or slot["location"] is not None


def test_a_range_of_frames_is_asked_for_in_one_command() -> None:
    """`frame apply level A-B`: one command for a window, instead of two per frame.

    Selecting a frame is O(its depth) *inside gdb*, and `-thread-select` resets that cache, so a window of a
    deep stack used to cost the depth twice over — measured on a 30 000-frame core, 21 frames took 549 ms for
    the first selection and a window at offset 20 000 cost 52.7 seconds and 45 321 commands. One `frame apply`
    answers the whole range in one pass: 22 commands, 0.10 s, on the same core.
    """
    transport, fake = _transport()
    frames = transport.stack_frames(1, low=0, high=2)

    applies = [command for command in fake.commands if "frame apply level" in command]
    assert len(applies) == 1, f"a three-frame window should be one command, not {len(applies)}"
    assert "level 0-2" in applies[0], applies[0]
    assert not [c for c in fake.commands if c.startswith("-stack-select-frame")], (
        "the per-frame path is the fallback, and it was not needed here"
    )
    # And the values are the ones the per-frame path answers, because both read gdb's `$sp`/`$fp`.
    assert frames[0]["sp"] == REGISTERS_BY_LEVEL[0]["$sp"]
    assert frames[0]["fp"] == REGISTERS_BY_LEVEL[0]["$fp"]
    assert frames[2]["sp"] == REGISTERS_BY_LEVEL[2]["$sp"]

    # Again: cached, so not even the one command is sent.
    before = len(fake.commands)
    transport.stack_frames(1, low=0, high=2)
    assert not [c for c in fake.commands[before:] if "frame apply" in c or "stack-select-frame" in c]
