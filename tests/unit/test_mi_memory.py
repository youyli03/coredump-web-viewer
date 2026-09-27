"""Unit tests for the memory and typed-value operations — no gdb needed.

The fixtures are **verbatim** replies captured from the real cross gdb (Arm GNU Toolchain 13.3,
`--interpreter=mi3`) reading a real aarch64 core, so the parsing is checked against what gdb actually
sends. The one exception is `test_a_hole_between_chunks_is_reported`: gdb *truncates* a partly readable
range instead of splitting it, so the split shape is taken from the MI manual — the arithmetic that
turns either shape into a hole is the same, and a hole is the thing that must never be papered over.
"""

from __future__ import annotations

import pytest

from analysis.gdb.base import GdbError, Unreadable, Unsupported
from analysis.gdb.mi import (
    MiParseError,
    MiTransport,
    _child,
    _field_of,
    _memory_reply,
    _mi_quote,
)

# --- verbatim replies ----------------------------------------------------------------- #
SP = "0x7ff029f130"

STACK_READ = (
    '^done,memory=[{begin="0x0000007ff029f130",offset="0x0000000000000000",'
    'end="0x0000007ff029f170",contents='
    '"20f229f07f000000200f615d5500000040e25d897f000000a0e28e6555000000'
    '00000000000000000000000004000000e0e28e65550000000000adde0000adde"}]'
)
NODE_READ = (
    '^done,memory=[{begin="0x00000055658ee2a0",offset="0x0000000000000000",'
    'end="0x00000055658ee300",contents="01000000616c706861000000000000000000000000000000e0e28e6555000000"}]'
)
CHILDREN = (
    '^done,numchild="5",children=[child={name="var1.id",exp="id",numchild="0",value="1",type="int",'
    'thread-id="1"},child={name="var1.name",exp="name",numchild="16",value="[16]",type="char [16]",'
    'thread-id="1"},child={name="var1.next",exp="next",numchild="5",value="0x55658ee2e0",'
    'type="struct node *",thread-id="1"},child={name="var1.peer",exp="peer",numchild="5",value="0x0",'
    'type="struct node *",thread-id="1"},child={name="var1.payload",exp="payload",numchild="3",'
    'value="0x0",type="struct blob *",thread-id="1"}],has_more="0"'
)


def _memory(line: str) -> list[dict]:
    from analysis.gdb.mi import parse_record

    return parse_record(line)["results"]["memory"]


# --- reading memory ------------------------------------------------------------------- #
def test_a_full_read_has_no_holes() -> None:
    reply = _memory_reply(_memory(STACK_READ), SP, 64)
    assert reply["address"] == SP
    assert reply["unread"] == []
    assert [chunk["length"] for chunk in reply["chunks"]] == [64]
    # The spilled `stray` pointer is visible in the raw bytes: this is the hex view's whole point.
    assert reply["chunks"][0]["bytes"].endswith("0000adde0000adde")


def test_bytes_are_lowercase_hex_without_separators() -> None:
    reply = _memory_reply(_memory(NODE_READ), "0x55658ee2a0", 48)
    assert reply["chunks"][0]["bytes"].startswith("01000000616c706861")


def test_a_truncated_read_reports_the_missing_tail() -> None:
    """gdb answers a partly readable range by returning fewer bytes, not by failing."""
    reply = _memory_reply(_memory(STACK_READ), SP, 8192)
    assert reply["chunks"][0]["length"] == 64
    assert reply["unread"] == [{"address": "0x7ff029f170", "length": 8192 - 64}]


def test_a_hole_between_chunks_is_reported() -> None:
    """Spec shape: `memory` carries one entry per readable run, so the gap between two is a hole."""
    two_runs = [
        {"begin": "0x0000000000001000", "offset": "0x0", "end": "0x0000000000001010", "contents": "aa" * 16},
        {"begin": "0x0000000000002000", "offset": "0x0", "end": "0x0000000000002010", "contents": "bb" * 16},
    ]
    reply = _memory_reply(two_runs, "0x1000", 0x1010)
    assert [chunk["length"] for chunk in reply["chunks"]] == [16, 16]
    assert reply["unread"] == [{"address": "0x1010", "length": 0xFF0}]


def test_chunks_are_sorted_by_address() -> None:
    two_runs = [
        {"begin": "0x2000", "contents": "bb" * 4},
        {"begin": "0x1000", "contents": "aa" * 4},
    ]
    reply = _memory_reply(two_runs, "0x1000", 0x1004)
    assert [chunk["address"] for chunk in reply["chunks"]] == ["0x1000", "0x2000"]
    # The two runs are 0x1000 apart, so the gap between them is a hole like any other.
    assert reply["unread"] == [{"address": "0x1004", "length": 0x2000 - 0x1004}]


@pytest.mark.parametrize("contents", ["abc", "zz", ""])
def test_contents_that_are_not_hex_are_refused(contents: str) -> None:
    """An odd count or a non-hex digit is a protocol surprise, and guessing would hide it."""
    entries = [{"begin": "0x1000", "contents": contents}] if contents else []
    if not entries:
        assert _memory_reply(entries, "0x1000", 16)["chunks"] == []
        return
    with pytest.raises(MiParseError):
        _memory_reply(entries, "0x1000", 16)


def test_a_negative_length_is_a_caller_bug() -> None:
    with pytest.raises(ValueError):
        _memory_reply([], SP, 0)


def test_a_bad_address_is_refused() -> None:
    with pytest.raises(MiParseError):
        _memory_reply([], "not-an-address", 16)


# --- a refusal is not a hole ---------------------------------------------------------- #
def _bare_transport() -> MiTransport:
    """Not started, and never will be: every gdb call is replaced."""
    return MiTransport(gdb_path="gdb", core_path="core")


def test_unreadable_memory_is_unreadable_not_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _bare_transport()
    monkeypatch.setattr(
        MiTransport,
        "_exec",
        lambda self, command, timeout=None: (_ for _ in ()).throw(
            GdbError("gdb refused the command: Unable to read memory.")
        ),
    )
    with pytest.raises(Unreadable) as caught:
        transport.read_memory("0xdead0000dead0000", 16)
    assert "0xdead0000dead0000" in str(caught.value)
    assert "not in this dump" in str(caught.value)
    assert "Unable to read memory." in str(caught.value)


def test_a_refusal_is_reported_in_gdbs_own_words() -> None:
    """`^error,msg="…"` is a sentence for the user; a dict repr is not."""
    from analysis.gdb.mi import _refusal, parse_record

    record = parse_record('^error,msg="Unable to read memory."')
    assert _refusal(record) == "Unable to read memory."
    # A refusal with no `msg` still says something rather than nothing.
    assert _refusal({"results": {}}) == "{}"


# --- the walk: a window is asked for until every byte is answered or refused ----------- #
class WindowGdb:
    """A gdb with a hole in a window, and the two quirks the real one has (both measured).

    `holes` are the ranges this fake cannot read. `refuse_over` is the length above which it refuses *any*
    request that starts inside or before a hole, which is what the real gdb does on the practice core's
    partly-resident text mapping: 896 bytes answer, 1 024 refuse, at the same address.
    """

    def __init__(self, base: int, length: int, *, holes: list[tuple[int, int]], refuse_over: int | None = None):
        self.base = base
        self.length = length
        self.holes = holes
        self.refuse_over = refuse_over
        self.commands: list[tuple[int, int]] = []

    def exec(self, command: str, *, timeout: float | None = None) -> list[dict]:
        from analysis.gdb.mi import parse_records

        if not command.startswith("-data-read-memory-bytes"):
            return parse_records(["^done"])
        _, address, length = command.split(" ")
        start, want = int(address, 16), int(length)
        self.commands.append((start, want))
        end = start + want
        # Find the first readable byte at or after `start`, the way gdb scans forward.
        if self.refuse_over is not None and want > self.refuse_over:
            return parse_records(['^error,msg="Unable to read memory."'])
        run = start
        while run < end and any(low <= run < high for low, high in self.holes):
            run += 1
        if run >= end:
            return parse_records(['^error,msg="Unable to read memory."'])
        stop = run
        while stop < end and not any(low <= stop < high for low, high in self.holes):
            stop += 1
        contents = "ab" * (stop - run)
        return parse_records(
            [f'^done,memory=[{{begin="{hex(run)}",offset="{hex(run - start)}",end="{hex(stop)}",'
             f'contents="{contents}"}}]']
        )


def _walking_transport(fake: WindowGdb) -> MiTransport:
    transport = _bare_transport()
    transport._exec = fake.exec  # type: ignore[method-assign]
    return transport


def test_a_window_is_asked_for_again_after_a_hole() -> None:
    """**The regression this pins.** gdb stops at the first byte it cannot reach; everything after it used to
    be reported as "not in this dump" while being readable.

    Measured on the practice core, and the reason the transport walks: asked for 8 192 bytes of the `crash_target`
    text mapping, gdb stopped at `0x…6115d5`, and the reply called the remaining 2 603 bytes missing — asked
    again from that address, gdb skipped three bytes and handed over 253 more.
    """
    base = 0x1000
    fake = WindowGdb(base, 0x100, holes=[(base + 8, base + 16)])
    window = _walking_transport(fake).read_memory(hex(base), 0x100)

    assert [chunk["address"] for chunk in window["chunks"]] == [hex(base), hex(base + 16)]
    assert window["unread"] == [{"address": hex(base + 8), "length": 8}]
    assert sum(chunk["length"] for chunk in window["chunks"]) == 0x100 - 8
    assert len(fake.commands) > 1, "one command cannot see past a hole"


def test_a_long_refusal_is_not_believed_about_a_shorter_range() -> None:
    """The second quirk, and the reason the walk subdivides instead of stopping: measured, gdb refuses a
    1 024-byte request and answers a 896-byte one at the very same address.

    The first request is still the whole window — that is the fast path a contiguous window needs, and it is one
    command. What must not happen is the refusal being read as "these bytes are not in the dump".
    """
    base = 0x2000
    fake = WindowGdb(base, 0x400, holes=[], refuse_over=0x200)
    window = _walking_transport(fake).read_memory(hex(base), 0x400)

    assert window["unread"] == [], "refusing the whole window is not a statement that its bytes are missing"
    assert sum(chunk["length"] for chunk in window["chunks"]) == 0x400
    assert fake.commands[0] == (base, 0x400), "the whole window is worth one command: it usually answers"
    assert any(0 < want <= 0x200 for _start, want in fake.commands), (
        f"after the refusal it has to ask for less, or it never learns anything: {fake.commands}"
    )


def test_a_range_that_is_really_missing_is_reported_missing() -> None:
    """A hole survives the walk as a hole — and only after gdb was asked about exactly those bytes."""
    base = 0x3000
    fake = WindowGdb(base, 0x100, holes=[(base + 0x40, base + 0x100)])
    window = _walking_transport(fake).read_memory(hex(base), 0x100)

    assert window["unread"] == [{"address": hex(base + 0x40), "length": 0xC0}]
    assert sum(chunk["length"] for chunk in window["chunks"]) == 0x40
    # The last question asked was about the missing range itself, not about something that contains it.
    assert (base + 0x40, 0xC0) in fake.commands or any(
        start >= base + 0x40 for start, _want in fake.commands
    )


def test_the_walk_stops_at_its_ceiling_and_says_not_read() -> None:
    """A window may not cost an unbounded number of commands, and what the ceiling cuts off is `not_read`:
    "this viewer stopped asking", which a caller can act on — never `unread`, which means the dump is empty."""
    from analysis.gdb.mi import _READ_ROUNDS

    base = 0x4000
    size = 4096
    # One missing byte every sixteen: 256 readable runs in the window, far more than the ceiling can establish.
    holes = [(base + offset + 15, base + offset + 16) for offset in range(0, size, 16)]
    fake = WindowGdb(base, size, holes=holes)
    window = _walking_transport(fake).read_memory(hex(base), size)

    assert "not_read" in window, "the ceiling has to show up in the answer, or it is a silent truncation"
    assert all(item["length"] > 0 for item in window["not_read"]), "and it names real ranges, not empty ones"
    accounted = (
        sum(chunk["length"] for chunk in window["chunks"])
        + sum(item["length"] for item in window["unread"])
        + sum(item["length"] for item in window["not_read"])
    )
    assert accounted == size, "every byte of the window is accounted for exactly once, in one of three states"
    assert len(fake.commands) <= _READ_ROUNDS, f"the ceiling is a ceiling: {len(fake.commands)} commands"


@pytest.mark.parametrize(
    ("dressed", "expected"),
    [
        ("0x7ff029f130", "0x7ff029f130"),
        ("(struct wide *) 0x555c932018", "0x555c932018"),
        ("0x7f87b906a4 <plugin_crash>", "0x7f87b906a4"),
        ("(struct node **) 0x55658ee2a0", "0x55658ee2a0"),
        ("no address here", None),
        (None, None),
        ("", None),
    ],
)
def test_an_address_is_read_out_of_whatever_gdb_printed(dressed: str | None, expected: str | None) -> None:
    """Every value the UI shows is gdb's own printing, so the transport has to accept it dressed."""
    from analysis.gdb.mi import _address

    assert _address(dressed) == expected


def test_an_unknown_command_is_unsupported_not_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    """`this gdb cannot` and `this dump has not` are different answers and must not merge."""
    transport = _bare_transport()
    monkeypatch.setattr(
        MiTransport,
        "_exec",
        lambda self, command, timeout=None: (_ for _ in ()).throw(
            GdbError("gdb refused the command: Undefined MI command: data-read-memory-bytes")
        ),
    )
    with pytest.raises(Unsupported):
        transport.read_memory("0x1000", 16)


# --- typed children ------------------------------------------------------------------- #
def test_children_keep_the_field_name_type_and_pointer() -> None:
    from analysis.gdb.mi import _labelled, parse_record

    raw = parse_record(CHILDREN)["results"]["children"]
    children = [
        _child(_labelled(entry, "child"), parent="head", parent_type="struct node *") for entry in raw
    ]
    assert [child["field"] for child in children] == ["id", "name", "next", "peer", "payload"]
    assert [child["type"] for child in children] == [
        "int",
        "char [16]",
        "struct node *",
        "struct node *",
        "struct blob *",
    ]
    # The next query is composed from the parent's shape, not guessed by the caller.
    assert children[2]["expression"] == "head->next"
    assert children[0]["expression"] == "head->id"
    # A NULL field stays a value with nothing to expand: the UI must not offer a jump for it.
    peer = children[3]
    assert peer["value"] == "0x0"
    assert peer["num_children"] == 5
    # The full name is kept, because that is what the next query has to be built from.
    assert children[2]["variable"] == "var1.next"


@pytest.mark.parametrize(
    ("parent", "parent_type", "field", "expected"),
    [
        ("head", "struct node *", "next", "head->next"),
        ("head->next->payload", "struct blob *", "data", "head->next->payload->data"),
        ("head->next", "struct node", "id", "head->next.id"),
        ("head->name", "char [16]", "3", "head->name[3]"),
        ("objects", "struct blob [4]", "0", "objects[0]"),
    ],
)
def test_the_next_expression_follows_the_parents_shape(
    parent: str, parent_type: str, field: str, expected: str
) -> None:
    from analysis.gdb.mi import _step

    assert _step(parent, parent_type, field) == expected



@pytest.mark.parametrize(
    ("variable", "expected"),
    [("var3.next.payload", "payload"), ("payload", "payload"), (None, None), ("", None)],
)
def test_field_falls_back_to_the_variable_name(variable: object, expected: str | None) -> None:
    assert _field_of(variable) == expected


def test_child_without_an_exp_uses_the_variable_name() -> None:
    child = _child({"name": "var9.next", "type": "struct node *", "numchild": "5"})
    assert child["field"] == "next"


def test_child_tolerates_a_shape_we_do_not_know() -> None:
    """An unexpected element must not become a crash: unknown shapes produce an empty child."""
    assert _child("garbage")["field"] is None


# --- quoting -------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("expression", "quoted"),
    [
        ("head", '"head"'),
        ("head->next", '"head->next"'),
        ('sizeof(struct node)', '"sizeof(struct node)"'),
        ('a->name[0] == "x"', '"a->name[0] == \\"x\\""'),
        ("back\\slash", '"back\\\\slash"'),
    ],
)
def test_expressions_are_quoted_as_mi_cstrings(expression: str, quoted: str) -> None:
    assert _mi_quote(expression) == quoted
