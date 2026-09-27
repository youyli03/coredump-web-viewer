"""The memory window's two readings: the ASCII column beside the hex, and the word-by-word decode.

`requirements.md` C3 asks the memory view for "raw bytes on the left (address gutter, 16 bytes, ASCII), and what
those bytes *mean* on the right — the DWARF fields when a type is known there, the plain word-by-word reading
when it is not". The typed half is `/expand` and the stack's `slots`; this file is the other half, and it is
asserted over HTTP rather than in the browser because it is a *claim about the dump*: which byte order this
core's words are in, and whether a word straddling a hole was left out rather than zero-filled.

Every address here is discovered from the API itself — no fixture constants — because the answers are addresses,
and the point of the endpoint is that they need no prior knowledge of the core.
"""

from __future__ import annotations

import pytest


def _crashed(summary: dict) -> int:
    return next(t["num"] for t in summary["threads"] if t["is_crashed"])


def _window(client, session: str, address: str, **params) -> dict:
    reply = client.get(f"/api/sessions/{session}/memory", params={"address": address, **params})
    assert reply.status_code == 200, reply.text
    return reply.json()


@pytest.mark.gdb
def test_the_core_says_which_byte_order_its_words_are_in(live, open_session) -> None:
    """The decode parameters come from the core's own ELF header, not from the machine running the viewer.

    This machine is little-endian arm64; so is the practice core, which is exactly why the assertion has to be
    about *where the fact comes from* — the big-endian case is in `test_foreign.py`, on a core of another
    architecture, where a guess would be caught.
    """
    body = open_session(live, sample="crash_target")
    summary = body["summary"]
    assert summary["memory_map"]["arch"] == "aarch64"
    assert summary["memory_map"]["word_size"] == 8
    assert summary["memory_map"]["byte_order"] == "little"

    frame = summary["detail"][str(_crashed(summary))]["frames"][0]
    window = _window(live, body["id"], frame["pc"], length=16)
    assert window["arch"] == "aarch64"
    assert window["byte_order"] == "little"
    assert window["word_size"] == 8
    assert window["width"] == 8, "the default unit is the target's own word size"


@pytest.mark.gdb
def test_a_window_carries_the_ascii_column_beside_its_bytes(live, open_session) -> None:
    """The heap node's own string is readable in the column, and the column lines up with the bytes."""
    body = open_session(live, sample="crash_target")
    heap = next(w for w in body["summary"]["memory"]["windows"] if w.get("name") == "heap")
    window = _window(live, body["id"], heap["address"], length=64)

    chunk = window["chunks"][0]
    assert len(chunk["ascii"]) == chunk["length"], "one character per byte, or the column does not line up"
    assert "alpha" in chunk["ascii"], f"the node's name is in these bytes: {chunk['ascii']!r}"
    # And the column is a *reading* of the bytes in the same reply, not a second opinion about them.
    assert len(bytes.fromhex(chunk["bytes"])) == chunk["length"]


@pytest.mark.gdb
def test_words_are_decoded_from_the_bytes_that_are_there(live, open_session) -> None:
    """Every unit is eight bytes of the reply's own hex, read in the reply's own byte order."""
    body = open_session(live, sample="crash_target")
    heap = next(w for w in body["summary"]["memory"]["windows"] if w.get("name") == "heap")
    window = _window(live, body["id"], heap["address"], length=32)

    raw = bytes.fromhex(window["chunks"][0]["bytes"])
    assert window["words"], "a window with bytes in it decodes to words"
    for word in window["words"]:
        offset = int(word["address"], 16) - int(window["address"], 16)
        assert word["size"] == 8
        assert word["hex"] == hex(int.from_bytes(raw[offset : offset + 8], window["byte_order"]))
        assert int(word["unsigned"]) == int(word["hex"], 16)
        assert int(word["signed"]) == (int(word["unsigned"]) - 2**64 if word["hex"].startswith("0x") and int(word["hex"], 16) >= 2**63 else int(word["unsigned"]))


@pytest.mark.gdb
def test_the_unit_width_is_the_caller_s(live, open_session) -> None:
    """`width` is how the window is *read*, and only the sizes a reader asks about are accepted."""
    body = open_session(live, sample="crash_target")
    heap = next(w for w in body["summary"]["memory"]["windows"] if w.get("name") == "heap")

    for width in (1, 2, 4, 8, 16):
        window = _window(live, body["id"], heap["address"], length=32, width=width)
        assert window["width"] == width
        assert all(word["size"] == width for word in window["words"])
        assert len(window["words"]) == 32 // width

    # A width nobody means is refused rather than silently rounded to one that works.
    refused = live.get(
        f"/api/sessions/{body['id']}/memory", params={"address": heap["address"], "length": 32, "width": 3}
    )
    assert refused.status_code == 400
    assert "width" in refused.json()["detail"]


@pytest.mark.gdb
def test_the_three_states_partition_the_window(live, open_session) -> None:
    """Bytes, `unread` and `not_read` are three disjoint states that add up to the window — exactly once each.

    This is the invariant that keeps the window honest, and it is checked on the *partly resident* text mapping,
    the only window in the practice bundle that exercises all three at once: 2 389 bytes of it are in the dump,
    1 137 are not, and 570 were left unasked when the walk hit its round ceiling.

    It is also the check that caught the first version of the walk: `_memory_reply` had always computed `unread`
    as "everything no chunk covers", which double-counted every byte the walk had skipped — 7 666 bytes
    accounted for in a 4 096-byte window.
    """
    body = open_session(live, sample="crash_target")
    summary = body["summary"]
    region = next(
        r
        for r in summary["memory_map"]["regions"]
        if r.get("path", "").endswith("crash_target") and r["perms"].startswith("r-x")
    )
    page, size = 4096, 4096
    start, end = int(region["start"], 16), int(region["end"], 16)
    windows = [
        _window(live, body["id"], hex(address), length=min(page, end - address))
        for address in range(start, end, page)
    ]
    holey = next(w for w in windows if w["unread"])

    held = sum(chunk["length"] for chunk in holey["chunks"])
    missing = sum(item["length"] for item in holey["unread"])
    unasked = sum(item["length"] for item in holey.get("not_read") or [])
    assert held + missing + unasked == holey["length"], (
        f"{held} held + {missing} missing + {unasked} unasked != {holey['length']}: a byte is in two states"
    )
    assert held and missing and unasked, "this window is the one that exercises all three"

    # The readings cover the bytes and only the bytes: no ASCII cell and no word is drawn out of a hole.
    assert sum(len(chunk["ascii"]) for chunk in holey["chunks"]) == held
    for word in holey["words"]:
        address = int(word["address"], 16)
        assert any(
            int(chunk["address"], 16) <= address
            and address + word["size"] <= int(chunk["address"], 16) + chunk["length"]
            for chunk in holey["chunks"]
        ), f"the word at {word['address']} is not wholly inside any chunk of this window"

    # And "not in this dump" is a measurement, not an inference: the smallest hole is asked for directly.
    smallest = min(holey["unread"], key=lambda item: item["length"])
    if int(smallest["length"]) <= 64:
        asked = live.get(
            f"/api/sessions/{body['id']}/memory",
            params={"address": smallest["address"], "length": smallest["length"]},
        )
        assert asked.status_code == 422, (
            f"{smallest['address']} for {smallest['length']} bytes was called missing, and asked for exactly "
            f"it answers {asked.status_code}: {asked.text}"
        )


@pytest.mark.gdb
def test_a_word_the_window_does_not_hold_is_not_decoded(live, open_session) -> None:
    """The hole in the practice core's text page: bytes are absent, and no word is invented across them.

    Measured on this core: the `crash_target` text mapping is 8 192 bytes with 2 603 of them unbacked starting
    at an offset inside it — a page-backed region the core does not carry. A window over that boundary has to
    come back with the bytes it has, the hole it does not, and **no word** spanning the two: a zero there would
    be a claim the dump is not making.
    """
    body = open_session(live, sample="crash_target")
    # The case under test is *found*, not assumed: this core's text mapping is 8 192 bytes with 2 603 of them
    # unbacked, so one of its pages carries the hole. The pages are asked for one at a time because the byte
    # ceiling (the live fixture's `max_limit`) is smaller than the mapping.
    region = next(
        r
        for r in body["summary"]["memory_map"]["regions"]
        if r.get("path", "").endswith("crash_target") and r["perms"].startswith("r-x")
    )
    start, end, page = int(region["start"], 16), int(region["end"], 16), 4096
    window = None
    for address in range(start, end, page):
        candidate = _window(live, body["id"], hex(address), length=min(page, end - address))
        if candidate["unread"]:
            window = candidate
            break
    assert window is not None, "this mapping carries an unbacked hole: without one this test proves nothing"

    assert sum(chunk["length"] for chunk in window["chunks"]) < window["length"]
    for chunk in window["chunks"]:
        assert len(chunk["ascii"]) == chunk["length"], "the column lines up with the bytes in the same reply"

    # Every decoded word is a whole word of one chunk: nothing was decoded across the gap.
    held = set()
    for chunk in window["chunks"]:
        low = int(chunk["address"], 16)
        high = low + chunk["length"]
        aligned = low + (-low) % 8
        held.update(range(aligned, high - 7, 8))
    assert window["words"], "the bytes that are there still decode"
    for word in window["words"]:
        assert int(word["address"], 16) in held

    # And a window wholly inside a hole is the *other* honest answer of `docs/api.md` §3.2: `422 unreadable`,
    # with gdb's own words in the detail — not a 200 full of holes, and not an empty 200.
    hole = window["unread"][0]
    inside = int(hole["address"], 16)
    refused = live.get(
        f"/api/sessions/{body['id']}/memory", params={"address": hex(inside), "length": min(64, hole["length"])}
    )
    assert refused.status_code == 422, refused.text
    assert refused.json()["error"] == "unreadable"
    assert hex(inside) in refused.json()["detail"]
    assert "Unable to read memory" in refused.json()["detail"], "the refusal carries gdb's own sentence"
