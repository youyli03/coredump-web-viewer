"""The typed walk: which objects it expands, and which it leaves as a link back.

`requirements.md` C5 asks for "pointer chains with cycle detection (the same address reached again is reported
as a cycle, not followed)", and `architecture.md` states the same rule for the traversal. The walk used to obey
it by *expression* alone, so it detected `head` twice and followed `head->next->next->next` — the same
three-node ring under a longer name. Measured on the practice core's `head`, that was six of fourteen objects
and 20 of 64 commands doing the walk twice.

No gdb here: `expand` is faked, so what is asserted is the traversal's decisions — which expressions it asks
about, and what it does with the answer — rather than anything gdb says.
"""

from __future__ import annotations

from analysis.report import MAX_CHILDREN, typed_objects

A, B, C = "0x1000", "0x2000", "0x3000"


def _pointer(name: str, expression: str, value: str, *, children: int = 3) -> dict:
    return {
        "field": name,
        "expression": expression,
        "type": "struct node *",
        "value": value,
        "num_children": children,
        "offset": 8,
        "size": 8,
    }


def _scalar(name: str, expression: str, *, type_: str = "int", children: int = 0) -> dict:
    return {
        "field": name,
        "expression": expression,
        "type": type_,
        "value": "1",
        "num_children": children,
        "offset": 0,
        "size": 4,
    }


class FakeExpand:
    """A transport that answers `expand` from a table of nodes, and remembers what it was asked."""

    def __init__(self, nodes: dict[str, dict]) -> None:
        self.nodes = nodes
        self.asked: list[str] = []

    def expand(self, expression: str) -> dict:
        self.asked.append(expression)
        if expression not in self.nodes:
            raise AssertionError(f"the walk expanded something that does not exist: {expression}")
        return self.nodes[expression]


def _node(expression: str, address: str, *children: dict) -> dict:
    return {
        "expression": expression,
        "type": "struct node *",
        "value": address,
        "size": 48,
        "address": address,
        "children": list(children),
    }


def test_a_pointer_that_lands_on_a_walked_address_is_a_cycle_not_new_ground() -> None:
    """`a → b → c → a`: three expansions, and the edge that closes the ring says where it came from."""
    nodes = {
        "a": _node("a", A, _pointer("next", "a->next", B), _scalar("id", "a->id")),
        "a->next": _node("a->next", B, _pointer("next", "a->next->next", C)),
        "a->next->next": _node("a->next->next", C, _pointer("next", "a->next->next->next", A)),
    }
    fake = FakeExpand(nodes)
    index = typed_objects(fake, ["a"])  # type: ignore[arg-type]

    assert fake.asked == ["a", "a->next", "a->next->next"], "the ring is not walked a second time"
    assert sorted(index) == ["a", "a->next", "a->next->next"]
    closing = nodes["a->next->next"]["children"][0]
    assert closing["cycle"] == "a", "the edge back to a known address names the expansion it already has"
    assert "cycle" not in nodes["a->next"]["children"][0], "a fresh address is not a cycle"


def test_a_null_pointer_is_not_a_cycle() -> None:
    """`0x0` is not an address the walk has been to, and saying "cycle" about it would be nonsense."""
    nodes = {
        "a": _node("a", A, _pointer("peer", "a->peer", "0x0"), _pointer("next", "a->next", B)),
        "a->next": _node("a->next", B),
    }
    fake = FakeExpand(nodes)
    index = typed_objects(fake, ["a"])  # type: ignore[arg-type]

    assert index["a"]["children"][0].get("cycle") is None, "`peer` is NULL, not a ring"
    assert fake.asked == ["a", "a->next"], "and there is nothing behind NULL to expand"


def test_a_field_at_offset_zero_is_not_a_cycle() -> None:
    """A nested struct can start at the same address as its parent. That is layout, not a pointer travel.

    The traversal keys its path on the addresses *pointers* land on; a value field is inside its parent's bytes
    by definition, so a `struct wide` whose first member sits at offset 0 still has to open.
    """
    nested = {
        "field": "inner",
        "expression": "w.inner",
        "type": "struct inner",
        "value": "{...}",
        "num_children": 2,
        "offset": 0,
        "size": 16,
    }
    nodes = {
        "w": {
            "expression": "w",
            "type": "struct wide",
            "value": "{...}",
            "size": 64,
            "address": A,
            "children": [nested],
        },
        "w.inner": {
            "expression": "w.inner",
            "type": "struct inner",
            "value": "{...}",
            "size": 16,
            "address": A,  # the same address: it *is* the parent's first field
            "children": [_scalar("x", "w.inner.x")],
        },
    }
    fake = FakeExpand(nodes)
    index = typed_objects(fake, ["w"])  # type: ignore[arg-type]

    assert fake.asked == ["w", "w.inner"], "a field at the parent's own address is still walked"
    assert nested.get("cycle") is None


def test_the_walk_still_stops_at_its_bounds() -> None:
    """The cycle rule joins the bounds rather than replacing them: a wide aggregate is left opaque."""
    wide = _pointer("many", "a->many", B, children=MAX_CHILDREN + 1)
    nodes = {"a": _node("a", A, wide)}
    fake = FakeExpand(nodes)
    typed_objects(fake, ["a"])  # type: ignore[arg-type]

    assert fake.asked == ["a"], "an aggregate wider than the bound is one opaque box, not a walk"


def test_a_root_is_asked_about_even_when_its_address_is_already_walked() -> None:
    """A root is an explicit ask — the caller named it — so it is expanded; the cycle rule is about *children*.

    `head` and `head->alias` are the same struct under two names. The child that points back is left as a link,
    but a caller who names the alias as a root gets its expansion: refusing to answer a question that was asked
    because of a guess about its address would be the traversal deciding what the reader meant.
    """
    nodes = {
        "head": _node("head", A, _pointer("alias", "head->alias", A)),
        "head->alias": _node("head->alias", A, _scalar("id", "head->alias->id")),
    }
    fake = FakeExpand(nodes)
    index = typed_objects(fake, ["head", "head->alias"])  # type: ignore[arg-type]

    assert fake.asked == ["head", "head->alias"]
    assert sorted(index) == ["head", "head->alias"]
    assert nodes["head"]["children"][0]["cycle"] == "head", "as a child it is a link, not another copy"
    assert nodes["head->alias"]["children"][0].get("cycle") is None, "and its scalar field is not a cycle either"
