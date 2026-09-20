"""Unit tests for field layout: where a field sits inside its parent, in bytes — no gdb needed.

Two things are being pinned down here:

* gdb answers `&((T *)0)->field` with hex and `sizeof` with decimal, and both mean a number;
* a field whose address cannot be taken (a bit-field, a pointer's own pointee) keeps `None` instead of a
  guessed position — a structure drawn at the wrong offset is worse than one not drawn.
"""

from __future__ import annotations

import pytest

from analysis.gdb.mi import (
    MiTransport,
    _array_element,
    _int_literal,
    _pointee,
    parse_records,
)


def _layout_transport(answers: dict[str, str], calls: list[str]) -> MiTransport:
    """A transport whose gdb is a table of constant-expression answers."""
    transport = MiTransport(gdb_path="gdb", core_path="core")

    def fake_exec(command: str, *, timeout: float | None = None) -> list[dict]:
        calls.append(command)
        for expression, value in answers.items():
            if expression in command:
                return parse_records([f'^done,value="{value}"'])
        return parse_records(['^error,msg="there is no such field"'])

    transport._exec = fake_exec  # type: ignore[method-assign]
    return transport


# --- reading gdb's numbers ------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("value", "expected"),
    [("0x18", 24), ("0x0", 0), ("48", 48), ("0", 0), (None, None), ("<unavailable>", None), ("", None)],
)
def test_an_address_is_hex_and_a_size_is_decimal(value: object, expected: int | None) -> None:
    assert _int_literal(value) == expected


@pytest.mark.parametrize(
    ("type_string", "expected"),
    [
        ("struct node *", "struct node"),
        ("struct node **", "struct node"),
        ("struct node", "struct node"),
        ("char [16]", "char [16]"),
        ("void (*)(struct node *)", "void (*)(struct node *)"),
        (None, None),
    ],
)
def test_only_a_trailing_pointer_is_stripped(type_string: str | None, expected: str | None) -> None:
    """A pointer's children are the pointee's fields, so the offset is asked about the pointee."""
    assert _pointee(type_string) == expected


@pytest.mark.parametrize(
    ("type_string", "expected"),
    [
        ("char [16]", "char"),
        ("volatile int [32]", "volatile int"),
        ("struct node *", None),
        ("void (*)(struct node *)", None),
    ],
)
def test_an_array_parent_is_recognised(type_string: str, expected: str | None) -> None:
    assert _array_element(type_string) == expected


# --- placing the children -------------------------------------------------------------- #
def test_offsets_and_sizes_come_from_gdb() -> None:
    calls: list[str] = []
    transport = _layout_transport(
        {
            "&((struct node *)0)->id": "0x0",
            "&((struct node *)0)->next": "0x18",
            "sizeof(int)": "4",
            "sizeof(struct node *)": "8",
        },
        calls,
    )
    children = [
        {"field": "id", "type": "int"},
        {"field": "next", "type": "struct node *"},
    ]
    transport._with_layout(children, "struct node *")

    assert [child["offset"] for child in children] == [0, 24]
    assert [child["size"] for child in children] == [4, 8]
    assert len(calls) == 4, "one offset query per field, one size query per type"

    # A second structure of the same type costs nothing: a layout does not change during a session.
    transport._with_layout([{"field": "id", "type": "int"}], "struct node *")
    assert len(calls) == 4


def test_an_array_child_is_placed_by_its_index() -> None:
    calls: list[str] = []
    transport = _layout_transport({"sizeof(char)": "1"}, calls)
    children = [{"field": str(index), "type": "char"} for index in range(16)]
    transport._with_layout(children, "char [16]")

    assert [child["offset"] for child in children] == list(range(16))
    assert all(child["size"] == 1 for child in children)
    assert not [call for call in calls if "->" in call], "an array element has no field to take"


def test_a_field_whose_address_cannot_be_taken_keeps_no_offset() -> None:
    """A bit-field has no address. Refusing beats inventing a position for it."""
    calls: list[str] = []
    transport = _layout_transport({"sizeof(unsigned int)": "4"}, calls)
    children = [{"field": "flags", "type": "unsigned int"}]
    transport._with_layout(children, "struct gate *")

    assert children[0]["offset"] is None
    assert children[0]["size"] == 4, "its size is still known, and still useful"

    # The refusal is remembered, so a broken field is not asked about on every expansion.
    transport._with_layout([{"field": "flags", "type": "unsigned int"}], "struct gate *")
    assert len([call for call in calls if "->flags" in call]) == 1


def test_a_child_that_is_not_a_field_gets_no_offset() -> None:
    """`expand("&head")` answers with `*head`: a pointee, not a field, and there is no offset for it."""
    calls: list[str] = []
    transport = _layout_transport({}, calls)
    children = [{"field": "*head", "type": "struct node *"}]
    transport._with_layout(children, "struct node **")

    assert children[0]["offset"] is None
    # Its size is still asked for — size does not depend on the position — but no address is taken.
    assert not [call for call in calls if "->" in call], "`*head` is not a field to take the address of"


def test_a_type_gdb_cannot_spell_costs_one_query_and_no_more() -> None:
    calls: list[str] = []
    transport = _layout_transport({}, calls)
    children = [{"field": "thing", "type": "<anonymous struct>"}]
    transport._with_layout(children, "struct holder *")

    assert children[0]["size"] is None
    transport._with_layout([{"field": "other", "type": "<anonymous struct>"}], "struct holder *")
    assert len([call for call in calls if "anonymous" in call]) == 1


# --- where the object lives ------------------------------------------------------------ #
def test_a_pointer_carries_its_own_address() -> None:
    """A pointer's `value=` is the address; asking `&head` would give the address of the variable."""
    calls: list[str] = []
    transport = _layout_transport({}, calls)
    created = {"type": "struct node *", "value": "0x55658ee2a0"}
    assert transport._object_address("head", created) == "0x55658ee2a0"
    assert not calls, "a pointer needs no query at all"


def test_a_value_is_asked_where_it_lives() -> None:
    """A struct prints as `{...}` and an array as `[16]`: a shape with no position, so ask for `&`."""
    calls: list[str] = []
    transport = _layout_transport({"&(g_wide)": "(struct wide *) 0x555c932018"}, calls)
    created = {"type": "struct wide", "value": "{...}"}
    assert transport._object_address("g_wide", created) == "0x555c932018"
    assert calls == ['-data-evaluate-expression "&(g_wide)"']


def test_an_address_that_cannot_be_taken_is_no_address() -> None:
    calls: list[str] = []
    transport = _layout_transport({}, calls)
    assert transport._object_address("gone", {"type": "struct wide", "value": "{...}"}) is None
