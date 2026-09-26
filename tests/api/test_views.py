"""The endpoints P3 adds, and the §13 acceptance items they make reachable.

Two of requirements §13's seven were not reachable over HTTP at all before this:

* **§13.2** — "clicking a frame shows its registers". The summary carried registers for the *crashed* thread
  only, and no endpoint served another thread's, so the promise held for exactly one thread out of three;
* **§13.5** — the typed walk. `describe()` replaced the typed index with `{"on_demand": true}` and nothing
  served that request, so the live page could re-root a tree and never walk one level down. Only the static
  fixture, which pre-fetches five levels, appeared to work.

Each test below asserts the *promise*, not the shape of today's dictionary.
"""

from __future__ import annotations

import pytest


def _crashed(summary: dict) -> int:
    return next(t["num"] for t in summary["threads"] if t["is_crashed"])


# --------------------------------------------------------------------------- #
# §13.2: registers for any frame's thread
# --------------------------------------------------------------------------- #
def test_registers_are_served_for_every_thread_not_only_the_crashed_one(live, open_session) -> None:
    body = open_session(live, sample="crash_target")
    summary = body["summary"]
    session = body["id"]
    crashed = _crashed(summary)
    others = [t["num"] for t in summary["threads"] if t["num"] != crashed]
    assert others, "the practice target starts extra threads on purpose, so this is testable at all"

    for number in [crashed, *others]:
        reply = live.get(f"/api/sessions/{session}/threads/{number}/registers")
        assert reply.status_code == 200, reply.text
        assert reply.json()["thread"] == number
        assert reply.json()["registers"], "a thread in a core has registers"
        assert reply.json()["registers"]["pc"].startswith("0x")

    # The crashed thread's registers are the ones the first screen already carried: one answer, two ways to
    # ask for it, and they must agree.
    assert live.get(f"/api/sessions/{session}/threads/{crashed}/registers").json()["registers"] == (
        summary["detail"][str(crashed)]["registers"]
    )


def test_registers_of_a_thread_that_does_not_exist_is_not_found(live, open_session) -> None:
    """Nothing is invented for a thread that is not in the dump."""
    body = open_session(live, sample="crash_target")
    reply = live.get(f"/api/sessions/{body['id']}/threads/99/registers")
    assert reply.status_code == 404
    assert reply.json()["error"] == "not-found"
    assert "99" in reply.json()["detail"]


# --------------------------------------------------------------------------- #
# requirements §5: a stack that pages, and says what it left out
# --------------------------------------------------------------------------- #
def test_the_stack_pages_and_reports_the_total(live, open_session) -> None:
    """`limit`/`offset` with an honest total.

    A response that returned three of twenty-eight frames without saying so is a hole the reader cannot tell
    from the end of the stack — the same mistake `stack_detail`'s docstring refuses for the whole-stack case.
    """
    body = open_session(live, sample="crash_target")
    session = body["id"]
    thread = _crashed(body["summary"])

    everything = live.get(f"/api/sessions/{session}/stack", params={"thread": thread}).json()
    total = everything["total"]
    assert total == len(everything["frames"]) > 3, "the practice core's crash thread is deep on purpose"
    assert everything["truncated"] is False
    assert everything["offset"] == 0 and everything["limit"] is None

    window = live.get(f"/api/sessions/{session}/stack", params={"thread": thread, "offset": 1, "limit": 2}).json()
    assert [frame["level"] for frame in window["frames"]] == [1, 2]
    assert window["total"] == total, "a window still says how many there are"
    assert window["truncated"] is True, "and that it is a window"
    assert window["frames"] == everything["frames"][1:3], "the same frames, not a second interpretation"

    # Every page together is the whole stack, once.
    levels = []
    for offset in range(0, total, 7):
        page = live.get(f"/api/sessions/{session}/stack", params={"thread": thread, "offset": offset, "limit": 7}).json()
        levels.extend(frame["level"] for frame in page["frames"])
    assert levels == list(range(total))


@pytest.mark.parametrize(
    ("params", "status"),
    [
        ({"thread": 99}, 404),
        ({"offset": -1}, 400),
        ({"limit": 0}, 400),
        ({"levels": 3}, 400),
    ],
)
def test_a_stack_question_that_cannot_be_answered_says_why(live, open_session, params, status) -> None:
    """An unknown thread is 404, an impossible window is 400, and the retired `levels` is refused rather than
    silently ignored — a parameter that is dropped answers a different question than the one that was asked."""
    body = open_session(live, sample="crash_target")
    reply = live.get(f"/api/sessions/{body['id']}/stack", params=params)
    assert reply.status_code == status, reply.text
    assert reply.json()["detail"]


# --------------------------------------------------------------------------- #
# C4: what an address belongs to
# --------------------------------------------------------------------------- #
def test_symbolize_names_the_mapping_and_the_function(live, open_session) -> None:
    body = open_session(live, sample="crash_target")
    summary = body["summary"]
    session = body["id"]
    crashed = _crashed(summary)
    frame = summary["detail"][str(crashed)]["frames"][0]

    crash_site = live.get(f"/api/sessions/{session}/symbolize", params={"address": frame["pc"]}).json()
    assert crash_site["segment"], "the crash pc is in the dump"
    assert crash_site["function"]["name"] == frame["func"], (
        "the disassembly and the backtrace must agree about which function the crash is in"
    )
    assert crash_site["function"]["offset"] >= 0, "and how far into it the address is"

    # The mapping a frame's stack pointer is in belongs to the thread that owns it.
    sp = summary["detail"][str(crashed)]["registers"]["sp"]
    in_stack = live.get(f"/api/sessions/{session}/symbolize", params={"address": sp}).json()
    assert in_stack["segment"], "a stack pointer is in the dump"
    assert in_stack["thread"] == crashed
    assert in_stack["function"] is None and "function" in in_stack["why"], (
        "a stack address is not code, and the refusal says so instead of naming a function"
    )


def test_symbolize_answers_about_an_address_that_is_nowhere(live, open_session) -> None:
    """The deliberate stray pointer: three absences, three reasons, and no invented answer."""
    body = open_session(live, sample="crash_target")
    answer = live.get(f"/api/sessions/{body['id']}/symbolize", params={"address": "0xdead0000dead0000"}).json()
    assert answer["segment"] is None and answer["function"] is None and answer["thread"] is None
    assert set(answer["why"]) == {"segment", "function", "thread"}, "each absence says why in words"
    assert "not in this dump" in answer["why"]["segment"]


# --------------------------------------------------------------------------- #
# §13.5: one typed step
# --------------------------------------------------------------------------- #
def test_expand_walks_one_level_and_composes_the_expression(live, open_session) -> None:
    """The typed walk, with the type named by the caller — the "interpret as…" of requirements §4.

    The API composes the expression, so the caller never writes C: `*(struct node *)0x…`, then
    `(*(struct node *)0x…).next`, and with `follow` the pointee of that field. That is `parent->next` written
    the long way round, which is what `architecture.md` §4 means by one structured step.
    """
    body = open_session(live, sample="crash_target")
    summary = body["summary"]
    session = body["id"]
    crashed = _crashed(summary)
    head = next(
        argument["value"]
        for argument in summary["detail"][str(crashed)]["frames"][0]["args"]
        if argument["name"] == "head"
    )

    node = live.post(f"/api/sessions/{session}/expand", json={"address": head, "type": "struct node"})
    assert node.status_code == 200, node.text
    walked = node.json()
    assert walked["type"] == "struct node"
    assert walked["expression"] == f"*(struct node *){hex(int(head, 16))}"
    fields = [child["field"] for child in walked["children"]]
    assert fields, "the practice struct has fields"
    assert {"id", "name", "next", "peer", "payload"} <= set(fields), fields
    for child in walked["children"]:
        assert child["expression"], "every child carries the expression that expands it — that is the walk"

    # One step further: follow `next`, and get another node rather than a pointer to one.
    step = live.post(
        f"/api/sessions/{session}/expand",
        json={"address": head, "type": "struct node", "field": "next", "follow": True},
    )
    assert step.status_code == 200, step.text
    assert step.json()["expression"] == f"*((*(struct node *){hex(int(head, 16))}).next)"
    assert "struct node" in (step.json()["type"] or ""), "the second hop is a node, not a pointer"


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ({"address": "0xc9bc79ad42a0", "type": "struct node; rm -rf /"}, "compose"),
        ({"address": "0xc9bc79ad42a0", "type": "struct node", "field": "next; drop"}, "compose"),
        ({"address": "not-an-address", "type": "struct node"}, "hexadecimal"),
    ],
)
def test_expand_refuses_to_compose_an_expression_from_junk(live, open_session, body, why) -> None:
    """The API builds the expression, so the two pieces that go into it are checked first.

    `architecture.md` §4: "expressions are composed by us, not by the user" — a type or a field that is not
    shaped like one is a refusal, never something handed to gdb in the hope that it only errors.
    """
    opened = open_session(live, sample="crash_target")
    reply = live.post(f"/api/sessions/{opened['id']}/expand", json=body)
    assert reply.status_code == 400, reply.text
    assert reply.json()["error"] == "bad-request"
    assert why in reply.json()["detail"]


def test_expand_refuses_a_dump_that_has_no_types(live, stripped_bundle, core_for, bundle) -> None:
    """§13.6 with §13.7's first answer: no DWARF is stated, and the typed walk answers **501**.

    A stripped target still has threads, a stack, registers, memory and disassembly — so it loads and is
    readable. What it cannot do is walk a type, and the API says which capability is missing rather than
    returning an empty structure tree that looks like an object with no fields.
    """
    opened = live.post(
        "/api/sessions",
        json={
            "core": str(core_for("crash_target")),
            "exe": str(stripped_bundle / "crash_target"),
            "sysroot": str(bundle / "sysroot"),
            "solib_search_path": str(stripped_bundle),
        },
    )
    assert opened.status_code == 201, opened.text
    session = opened.json()["id"]
    loaded = live.get(f"/api/sessions/{session}", params={"wait": 60}).json()
    assert loaded["state"] == "ready", f"a stripped dump is still readable: {loaded.get('error')}"

    # The capability says what is absent, in words...
    capabilities = live.get(f"/api/sessions/{session}/capabilities").json()
    assert capabilities["capabilities"]["dwarf_types"] is False
    assert "DWARF" in (capabilities["capabilities"]["notes"].get("dwarf_types") or "")

    # ...and the typed endpoint refuses with it, rather than answering an empty tree.
    refused = live.post(f"/api/sessions/{session}/expand", json={"address": "0x0", "type": "int"})
    assert refused.status_code == 501, refused.text
    assert refused.json()["error"] == "unsupported"
    assert "DWARF" in refused.json()["detail"], "the refusal names the capability, not just the failure"

    # Everything that does not need DWARF still works on the same session.
    assert live.get(f"/api/sessions/{session}/stack", params={"thread": _crashed(loaded["summary"])}).status_code == 200
