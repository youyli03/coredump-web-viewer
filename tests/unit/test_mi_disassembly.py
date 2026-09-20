"""`-data-disassemble`, decoded.

The fixtures are the shapes GDB 13.3 (Arm GNU Toolchain) actually produced against the practice core, so
the tests are about our parser and our *policies*, not about a documentation example that this gdb refuses
anyway (`-a ADDRESS -c COUNT` is answered with `Unknown option 'c'`).

Two policies are pinned here because getting them wrong is silent:

* an address with no function is a **reason**, never a range that decodes whatever bytes were there — on
  the real heap address that comes back as a plausible `udf #1`;
* a reply is **bounded**, and truncation is reported, because "there is more" and "that is all" are
  different answers.
"""

from __future__ import annotations

import pytest

from analysis.gdb.base import GdbError, Unsupported
from analysis.gdb.mi import MiTransport, parse_records

# --------------------------------------------------------------------------- #
# Verbatim answers
# --------------------------------------------------------------------------- #
# Mode 0 for the crash address: the enclosing function, named and offset. No `opcodes`.
FLAT_MODE_0 = (
    "^done,asm_insns=["
    '{address="0x0000007fb189078c",func-name="plugin_crash",offset="232",inst="ldr\\tw0, [x0]"},'
    '{address="0x0000007fb1890790",func-name="plugin_crash",offset="236",inst="mov\\tw1, w0"},'
    '{address="0x0000007fb1890794",func-name="plugin_crash",offset="240",inst="adrp\\tx0, 0x7fb1890000"},'
    '{address="0x0000007fb189079c",func-name="plugin_crash",offset="248",inst="bl\\t0x7fb18905a0 <printf@plt>"},'
    '{address="0x0000007fb18907a8",func-name="plugin_crash",offset="260",inst="ret"}]'
)

# Mode 1 for the same function: grouped by source line. Note `line="15"` carries an empty
# `line_asm_insn=[]` — a real reply, because a declaration line compiles to nothing.
GROUPED_MODE_1 = (
    "^done,asm_insns=["
    "{src_and_asm_line={line=\"15\","
    'file="/home/lyy/cdwv-practice/src/libplugin.c",'
    'fullname="/home/lyy/cdwv-practice/src/libplugin.c",'
    "line_asm_insn=[]}},"
    "{src_and_asm_line={line=\"24\","
    'file="/home/lyy/cdwv-practice/src/libplugin.c",'
    'fullname="/home/lyy/cdwv-practice/src/libplugin.c",'
    "line_asm_insn=["
    '{address="0x0000007fb189074c",func-name="plugin_crash",offset="168",inst="mov\\tx0, #0x0"},'
    '{address="0x0000007fb1890750",func-name="plugin_crash",offset="172",inst="movk\\tx0, #0xdead, lsl #16"}]}},'
    "{src_and_asm_line={line=\"29\","
    'file="/home/lyy/cdwv-practice/src/libplugin.c",'
    'fullname="/home/lyy/cdwv-practice/src/libplugin.c",'
    "line_asm_insn=["
    '{address="0x0000007fb189078c",func-name="plugin_crash",offset="232",inst="ldr\\tw0, [x0]"}]}}]'
)

# Mode 2: the same instructions with the raw bytes GDB printed (`00 00 40 b9` for `ldr w0, [x0]`).
FLAT_MODE_2 = (
    "^done,asm_insns=["
    '{address="0x0000007fb189078c",func-name="plugin_crash",offset="232",opcodes="00 00 40 b9",inst="ldr\\tw0, [x0]"},'
    '{address="0x0000007fb1890790",func-name="plugin_crash",offset="236",opcodes="01 00 00 2A",inst="mov\\tw1, w0"}]'
)

# A range over libc: instructions, and no symbol fields at all.
RANGE_NO_SYMBOL = (
    "^done,asm_insns=["
    '{address="0x0000007fb1759df8",inst="svc\\t#0x0"},'
    '{address="0x0000007fb1759dfc",inst="cmn\\tw0, #0x1"}]'
)

NO_FUNCTION = '^error,msg="No function contains specified address."'
NO_MEMORY = '^error,msg="Cannot access memory at address 0xdead0000dead0000"'
NO_COMMAND = '^error,msg="Undefined MI command: data-disassemble"'


class FakeGdb:
    """A canned gdb that answers each form with its own fixture and remembers what it was asked."""

    def __init__(self, *, address_form: str = FLAT_MODE_0, range_form: str = RANGE_NO_SYMBOL) -> None:
        self.address_form = address_form
        self.range_form = range_form
        self.commands: list[str] = []

    def exec(self, command: str, *, timeout: float | None = None) -> list[dict]:
        self.commands.append(command)
        if command.startswith("-data-disassemble -a"):
            return parse_records([self.address_form])
        if command.startswith("-data-disassemble -s"):
            return parse_records([self.range_form])
        return parse_records(["^done"])

    @property
    def used_range_form(self) -> bool:
        return any(command.startswith("-data-disassemble -s") for command in self.commands)


def _transport(fake: FakeGdb) -> MiTransport:
    transport = MiTransport(gdb_path="gdb", core_path="core")
    transport._exec = fake.exec  # type: ignore[method-assign]
    return transport


# --------------------------------------------------------------------------- #
# The shapes
# --------------------------------------------------------------------------- #
def test_a_flat_answer_becomes_one_kind_of_instruction() -> None:
    transport = _transport(FakeGdb())
    reply = transport.disassemble("0x0000007fb189078c")
    assert reply["function"] == {"name": "plugin_crash", "offset": 232}
    assert reply["symbolized"] is True
    assert reply["lines"] == [], "no source was asked for, so there is no grouping to report"
    assert reply["truncated"] is False
    assert reply["reason"] is None
    first = reply["instructions"][0]
    assert first == {
        "address": "0x7fb189078c",
        "text": "ldr\tw0, [x0]",
        "offset": 232,
        "func": "plugin_crash",
    }
    assert len(reply["instructions"]) == 5


def test_the_range_end_is_only_claimed_when_the_bytes_were_asked_for() -> None:
    """Without opcodes nothing says how long an instruction is, so no end is invented."""
    flat = _transport(FakeGdb()).disassemble("0x0000007fb189078c")
    assert flat["range"]["end"] is None
    assert flat["range"]["last"] == "0x7fb18907a8"

    with_opcodes = _transport(FakeGdb(address_form=FLAT_MODE_2)).disassemble(
        "0x0000007fb189078c", opcodes=True
    )
    # `mov w1, w0` is `01 00 00 2A`: four bytes, so the range ends four bytes after its address.
    assert with_opcodes["range"]["end"] == hex(0x7FB1890790 + 4)
    assert with_opcodes["instructions"][1]["bytes"] == "01 00 00 2a"


def test_opcode_bytes_are_normalised_not_respelled() -> None:
    reply = _transport(FakeGdb(address_form=FLAT_MODE_2)).disassemble("0x0000007fb189078c", opcodes=True)
    assert reply["instructions"][0]["bytes"] == "00 00 40 b9"
    assert reply["instructions"][0]["text"] == "ldr\tw0, [x0]"


def test_a_source_grouped_answer_carries_both_shapes() -> None:
    reply = _transport(FakeGdb(address_form=GROUPED_MODE_1)).disassemble("0x0000007fb189078c", source=True)
    assert [group["line"] for group in reply["lines"]] == [15, 24, 29]
    assert reply["lines"][0]["instructions"] == [], "a line that compiled to nothing is still a line"
    assert [instruction["line"] for instruction in reply["instructions"]] == [24, 24, 29]
    assert reply["instructions"][0]["text"] == "mov\tx0, #0x0"
    assert reply["lines"][1]["file"] == "/home/lyy/cdwv-practice/src/libplugin.c"
    assert reply["lines"][1]["fullname"].endswith("libplugin.c")


def test_source_grouping_is_not_reported_when_it_was_not_asked_for() -> None:
    reply = _transport(FakeGdb(address_form=GROUPED_MODE_1)).disassemble("0x0000007fb189078c")
    assert reply["lines"] == []


# --------------------------------------------------------------------------- #
# The two silent-failure policies
# --------------------------------------------------------------------------- #
def test_an_address_with_no_function_is_a_reason_not_a_range() -> None:
    """The hazard: a range would happily decode data. Measured on the heap: `udf #1`."""
    fake = FakeGdb(address_form=NO_FUNCTION)
    reply = _transport(fake).disassemble("0x00000055ac5bf2a0")
    assert reply["instructions"] == []
    assert reply["reason"] and "No function contains" in reply["reason"]
    assert reply["symbolized"] is False
    assert fake.used_range_form is False, "the range form must not be used without the caller's say-so"


def test_an_unsymbolized_range_is_opt_in_and_says_it_has_no_symbols() -> None:
    fake = FakeGdb(address_form=NO_FUNCTION)
    reply = _transport(fake).disassemble("0x0000007fb1759df8", allow_unsymbolized=True)
    assert fake.used_range_form is True
    assert reply["function"] is None
    assert reply["symbolized"] is False
    assert reply["reason"] is None
    assert reply["instructions"][0] == {"address": "0x7fb1759df8", "text": "svc\t#0x0"}


def test_an_unmapped_address_keeps_gdbs_own_reason() -> None:
    fake = FakeGdb(address_form=NO_FUNCTION, range_form=NO_MEMORY)
    reply = _transport(fake).disassemble("0xdead0000dead0000", allow_unsymbolized=True)
    assert reply["instructions"] == []
    assert reply["reason"] and "Cannot access memory" in reply["reason"]


def test_a_reply_is_bounded_and_says_when_it_was_cut() -> None:
    reply = _transport(FakeGdb()).disassemble("0x0000007fb189078c", limit=2)
    assert len(reply["instructions"]) == 2
    assert reply["truncated"] is True


def test_a_gdb_without_the_command_is_unsupported_rather_than_empty() -> None:
    """A missing capability is a greyed-out control; a dump that cannot answer is a reason."""
    with pytest.raises(Unsupported):
        _transport(FakeGdb(address_form=NO_COMMAND)).disassemble("0x0000007fb189078c")


def test_a_non_address_is_a_programming_error() -> None:
    with pytest.raises(GdbError):
        _transport(FakeGdb()).disassemble("plugin_crash")
