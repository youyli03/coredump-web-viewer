"""The live half: the same API, against a real aarch64 core and a real cross gdb.

Skipped cleanly when either is missing (`-m gdb` selects these, `-m "not gdb"` the rest).

Two things these tests do that the offline half cannot: they read a real dump, and they **discover every
address from the API itself**. A core's addresses change on every build, so a test that hard-codes one is a
test that passes exactly once.
"""

from __future__ import annotations

import hashlib
import pathlib
import time

import pytest

pytestmark = pytest.mark.gdb


def _sha256(path: pathlib.Path) -> str:
    """The whole file, because "did anything touch the core" is not a question about its mtime."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()

STRANDED = "0xdead0000dead0000"
"""The marker the practice target dereferences on purpose (`practice/src/crash_target.c`).

It is deliberately *not* in the dump: "this address is not in this dump" is a normal answer this viewer has to
give, and the only way to test that is with an address that really is nowhere.
"""


def _crashed(summary: dict) -> dict:
    crashed = [thread for thread in summary["threads"] if thread["is_crashed"]]
    assert len(crashed) == 1, "exactly one thread crashed, and the first screen has to know which"
    return crashed[0]


def _frame0(summary: dict, thread: int) -> dict:
    payload = summary["detail"][str(thread)]
    assert payload["frames"], "a crashed thread has at least one frame"
    return payload["frames"][0]


def _arg(frame: dict, name: str) -> str:
    for argument in frame.get("args") or []:
        if argument["name"] == name:
            return argument["value"]
    raise AssertionError(f"frame {frame['func']!r} has no argument {name!r}: {[a['name'] for a in frame.get('args') or []]}")


# --------------------------------------------------------------------------- #
# The first screen
# --------------------------------------------------------------------------- #
def test_the_first_screen_is_the_crashed_thread_carrying_registers(live, open_session) -> None:
    """requirements.md §13.1: the thread list, with the crashed thread's stack already open.

    "Already open" means the summary *is* that screen: the crashed thread's frames and its registers arrive
    with the first answer, so the page does not issue a second request to paint it.
    """
    body = open_session(live, sample="crash_target")
    assert body["state"] == "ready", body.get("error")
    summary = body["summary"]
    assert summary, "a ready session carries its summary"

    crashed = _crashed(summary)
    payload = summary["detail"][str(crashed["num"])]
    assert payload["frames"], "the crashed thread's frames come with the first screen"
    assert payload["total"] >= len(payload["frames"])
    assert payload.get("registers"), "§13.1 also promises the registers of the crash point"


def test_the_stack_records_are_verified_against_the_next_frame(live, open_session) -> None:
    """The frame record is decoded *and* corroborated, or it says why not.

    `architecture.md` §3: a decoded record is verified against gdb before it is believed — the saved frame
    pointer must equal the next frame's `fp`, the return address the next frame's `pc`. A frame where nobody
    could corroborate it must carry `verified: false` and a reason, never a chain that is not there. The
    practice core's crash thread is an intact stack, so the first frame has to pass both checks.
    """
    body = open_session(live, sample="crash_target")
    crashed = _crashed(body["summary"])

    stack = live.get(f"/api/sessions/{body['id']}/stack", params={"thread": crashed["num"], "levels": 3}).json()
    assert stack["thread"] == crashed["num"]
    first = stack["frames"][0]
    record = first["record"]
    assert record["verified"] is True, f"an intact frame must verify: {record}"
    assert record["checks"] == {"saved_fp": True, "return_address": True}
    assert record["saved_fp"] and record["return_address"], "a verified record names what it checked"
    assert first["extent_why"] is None, "a frame gdb can walk has an extent"

    # Every frame either carries a verified record or says, in words, why there is none — never a blank.
    for frame in stack["frames"]:
        assert frame["record"].get("why") or frame["record"].get("verified") is not None


def test_a_frame_asks_gdb_for_its_own_locals(live, open_session) -> None:
    """`/frames/{level}` is a live query, and it answers with the frame's own arguments.

    This endpoint exists because the backend used to walk every frame of every thread up front — measured at
    5.5 seconds of a 5.6-second load — and the summary no longer carries locals at all.
    """
    body = open_session(live, sample="crash_target")
    crashed = _crashed(body["summary"])
    frame = _frame0(body["summary"], crashed["num"])

    locals_ = live.get(f"/api/sessions/{body['id']}/frames/0", params={"thread": crashed["num"]}).json()
    assert locals_, "the crash frame has variables"
    names = {variable["name"] for variable in locals_}
    assert "head" in names, f"the crash frame's argument is missing: {sorted(names)}"

    head = _arg(frame, "head")
    assert any(variable["value"] == head for variable in locals_), (
        "the argument the summary printed and the local gdb read now are the same value"
    )


# --------------------------------------------------------------------------- #
# Code and bytes: what is there, and what is not
# --------------------------------------------------------------------------- #
def test_the_crash_site_is_named_in_the_page_of_code(live, open_session) -> None:
    """§13.1 again, one level down: the instruction that faulted belongs to a named function.

    The endpoint answers the whole page — one request per function, because the range form of a disassembly
    invents instructions for data (`architecture.md` §2, measured: 178 of 228 fabricated for the plugin's
    page). So the test asks which unit *contains* the pc, rather than assuming the first.
    """
    body = open_session(live, sample="crash_target")
    crashed = _crashed(body["summary"])
    frame = _frame0(body["summary"], crashed["num"])
    pc = int(frame["pc"], 16)

    page = live.get(f"/api/sessions/{body['id']}/disassemble", params={"address": frame["pc"]}).json()
    assert page["units"], f"the crash pc is in code, so the page has functions: {page.get('reason')}"
    containing = [
        unit
        for unit in page["units"]
        if unit["instructions"] and int(unit["instructions"][0]["address"], 16) <= pc
        <= int(unit["instructions"][-1]["address"], 16)
    ]
    assert containing, "exactly one function contains the pc"
    assert containing[0]["symbol"] == frame["func"], (
        "the disassembly and the backtrace must agree about which function the crash is in"
    )


def test_an_address_in_data_is_stated_as_data(live, open_session) -> None:
    """The refusal is a *reason*, not an empty answer.

    A heap address has no function containing it. Answering `units: []` with an explanation is the honest
    result; decoding bytes into instructions because they happen to be in an executable *page* is the mistake
    `architecture.md` §2 measured.
    """
    body = open_session(live, sample="crash_target")
    crashed = _crashed(body["summary"])
    head = _arg(_frame0(body["summary"], crashed["num"]), "head")

    page = live.get(f"/api/sessions/{body['id']}/disassemble", params={"address": head})
    assert page.status_code == 200, page.text
    assert page.json()["units"] == []
    assert "not an executable mapping" in page.json()["reason"]


def test_bytes_outside_the_dump_are_refused_with_a_reason(live, open_session) -> None:
    """§13.7 in its most ordinary form: a pointer that is nowhere is a normal answer, and it says so.

    `requirements.md` §4: an address in no mapping at all is reported as "not in this dump" — not a crash, not
    an empty window. The transport reaches gdb, gdb refuses, and the refusal is the answer, carried with the
    address it is about.
    """
    body = open_session(live, sample="crash_target")
    reply = live.get(
        f"/api/sessions/{body['id']}/memory", params={"address": STRANDED, "length": 16}
    )
    assert reply.status_code == 422, reply.text
    assert reply.json()["error"] == "unreadable"
    assert STRANDED in reply.json()["detail"], "the answer names the address it could not read"
    assert "not in this dump" in reply.json()["detail"], "and says which of the two it is"

    # The same fact, as data, in the summary the first screen already has.
    missing = body["summary"]["memory"].get("missing") or {}
    assert missing.get("address") == STRANDED and missing.get("reason")


def test_bytes_that_are_in_the_dump_are_returned_whole(live, open_session) -> None:
    """The other half of the same rule: a window the core really carries has no holes in it.

    Confusing "no bytes" with "no mapping" is how a viewer lies, so the two cases are asserted next to each
    other: this one is 200 with `unread: []`, the previous one is a refusal that names its reason.
    """
    body = open_session(live, sample="crash_target")
    crashed = _crashed(body["summary"])
    registers = body["summary"]["detail"][str(crashed["num"])]["registers"]

    reply = live.get(
        f"/api/sessions/{body['id']}/memory", params={"address": registers["sp"], "length": 64}
    )
    assert reply.status_code == 200, reply.text
    window = reply.json()
    assert window["unread"] == [], "the stack of the crashed thread is in the dump"
    assert sum(chunk["length"] for chunk in window["chunks"]) == 64


def test_the_ceiling_refuses_a_read_that_is_too_large(live_tight, open_session) -> None:
    """A policy a caller can hit, with the number in the message.

    `max_limit` is 16 in this app and 4096 in the running service: the ceiling is configuration, and the only
    way to test the refusal is to inject a small one rather than ask a real deployment for a gigabyte.
    """
    body = open_session(live_tight, sample="crash_target")
    crashed = _crashed(body["summary"])
    registers = body["summary"]["detail"][str(crashed["num"])]["registers"]

    too_much = live_tight.get(
        f"/api/sessions/{body['id']}/memory", params={"address": registers["sp"], "length": 17}
    )
    assert too_much.status_code == 400, too_much.text
    assert too_much.json()["error"] == "bad-request"
    assert "1..16" in too_much.json()["detail"], "the refusal names the ceiling it hit"

    allowed = live_tight.get(
        f"/api/sessions/{body['id']}/memory", params={"address": registers["sp"], "length": 16}
    )
    assert allowed.status_code == 200, allowed.text


@pytest.mark.xfail(
    strict=True,
    reason="the live summary builds no typed index, so /object can only serve what the fixture pre-fetched "
    "(docs/api.md §2.1 #4); C5 needs the expand endpoint of §6 — this test is the reminder",
)
def test_a_typed_object_can_be_found_by_address(live, open_session) -> None:
    """§13.5: a pointer the viewer shows should be *resolvable* as a type.

    The fixture makes this look like it works, because `scripts/dump-fixture.py` pre-fetches the typed tree.
    The live session does not (`build_summary(include_typed=False)`), and `describe()` replaces the index with
    `{"on_demand": True}` — while nothing serves that on-demand request yet.
    """
    body = open_session(live, sample="crash_target")
    crashed = _crashed(body["summary"])
    head = _arg(_frame0(body["summary"], crashed["num"]), "head")

    found = live.get(f"/api/sessions/{body['id']}/object", params={"address": head})
    assert found.status_code == 200, found.text
    assert found.json()["type"], "the object at that address has a type"


# --------------------------------------------------------------------------- #
# Lifetime, policy and honesty about the evidence
# --------------------------------------------------------------------------- #
def test_capacity_is_one_and_the_evicted_session_is_gone(live, open_session) -> None:
    """The policy of §6: a second core closes the first, and the first really is gone.

    "Gone" has to mean 404 rather than a session that still answers from a gdb nobody is reading any more —
    which is the whole reason the capacity rule is enforced in the manager instead of assumed in the browser.
    """
    first = open_session(live, sample="crash_target")
    second = open_session(live, sample="opt_target")
    assert first["id"] != second["id"]
    assert live.get(f"/api/sessions/{first['id']}").status_code == 404
    assert live.get(f"/api/sessions/{second['id']}").status_code == 200


def test_a_session_closed_while_loading_does_not_leave_a_gdb(live, monkeypatch) -> None:
    """The lifetime race: capacity is one and sessions can be closed, so "closed" and "still loading"
    genuinely coincide.

    The transport is opened *inside* the load thread, so a session closed before it lands used to assign the
    fresh gdb after `close()` had already looked — and that process stayed alive for the rest of the run,
    making §6's "shutdown kills every child gdb" true only for the sessions that finished loading first. This
    was found by running the HTTP suite against the lifetime path, not by reading the code.

    The loader is held for a moment on purpose, so the close really does arrive mid-load rather than whenever
    the machine happens to be fast.
    """
    import analysis.report as report

    started: list = []
    real = report.open_transport

    def slow_open(*args, **kwargs):
        time.sleep(1.0)  # widen the window the race lives in, so the test cannot pass by timing luck
        transport = real(*args, **kwargs)
        started.append(transport)
        return transport

    monkeypatch.setattr(report, "open_transport", slow_open)

    created = live.post("/api/sessions", json={"sample": "crash_target"})
    assert created.status_code == 201
    session_id = created.json()["id"]
    assert live.delete(f"/api/sessions/{session_id}").status_code == 204, "closed while it was still loading"

    deadline = time.monotonic() + 30
    while not started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert started, "the load thread opened a transport even though the session was already closed"

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and any(transport.alive for transport in started):
        time.sleep(0.1)
    assert not any(transport.alive for transport in started), (
        "a session closed mid-load kept its gdb running — nobody will ever close it now"
    )


def test_closing_a_session_makes_it_gone(live, open_session) -> None:
    body = open_session(live, sample="crash_target")
    assert live.delete(f"/api/sessions/{body['id']}").status_code == 204
    assert live.get(f"/api/sessions/{body['id']}").status_code == 404
    assert live.delete(f"/api/sessions/{body['id']}").status_code == 404
    assert live.get("/api/health").json()["sessions"] == []


def test_the_core_file_is_never_written(live, open_session, core_for) -> None:
    """A viewer that edits the evidence is the one failure nobody forgives (requirements §5: read-only).

    The hash is taken around a *full* walk — threads, stack, locals, registers, bytes, disassembly — because
    the risk is not the load, it is one of the readers deciding to rewrite something in place.
    """
    core = core_for("crash_target")
    before = _sha256(core)

    body = open_session(live, sample="crash_target")
    crashed = _crashed(body["summary"])
    frame = _frame0(body["summary"], crashed["num"])
    head = _arg(frame, "head")
    session = body["id"]
    for path, params in (
        ("stack", {"thread": crashed["num"]}),
        ("frames/0", {"thread": crashed["num"]}),
        ("memory", {"address": head, "length": 128}),
        ("disassemble", {"address": frame["pc"]}),
        ("objects", {"address": head, "length": 64}),
    ):
        live.get(f"/api/sessions/{session}/{path}", params=params)
    live.delete(f"/api/sessions/{session}")

    assert _sha256(core) == before, "the core was modified by reading it"


def test_the_same_core_answers_the_same_way_twice(live, open_session) -> None:
    """Reproducibility, which `practice/README.md` designs the bundle for: one command, same core, every time.

    Two fresh sessions on the same core must produce the same thread list and the same frames — including the
    addresses, which is what makes every other test in this file able to discover them rather than invent them.
    """
    def fingerprint() -> tuple:
        body = open_session(live, sample="crash_target")
        crashed = _crashed(body["summary"])
        frames = body["summary"]["detail"][str(crashed["num"])]["frames"]
        return (
            [(thread["num"], thread["state"], thread["frame_count"]) for thread in body["summary"]["threads"]],
            [(frame["level"], frame["func"], frame["pc"]) for frame in frames],
            body["summary"]["memory_map"]["regions"][0]["start"],
        )

    assert fingerprint() == fingerprint()
