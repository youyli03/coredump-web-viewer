"""What a request cost, and which of the four answers a failure is.

`docs/api.md` §4 is the design being tested: two promises of the other documents — "the core is loaded once"
(§1) and "on-demand results are cached per session" (§4) — were unobservable from outside, so a request that
cost nothing and a request that cost ten commands looked identical. Now they do not.

The second half is requirements §13.7's four answers. They used to collapse: a killed debugger, a core that
never loaded and a session still loading all answered 409 `not-ready` with the session's state as the whole
explanation, which is exactly how the v1 prototype's `{"threads": []}` came to look like a success. Each kind
of failure now has its own status, and each one is asserted here.
"""

from __future__ import annotations

import os
import signal
import time

import pytest


# --------------------------------------------------------------------------- #
# The cost of a request
# --------------------------------------------------------------------------- #
def test_a_request_reports_what_it_cost(live, open_session) -> None:
    """The headers are the promise made readable: `X-Gdb-Commands` is this request's delta, `cached` is "zero".

    Two stack requests are the case `architecture.md` §4 names in words ("asking for the same thread's stack
    twice must not send a second command to gdb"), and measured 2026-09-26 the second cost 64 commands before
    the per-frame caches were added.
    """
    body = open_session(live, sample="crash_target")
    session = body["id"]

    first = live.get(f"/api/sessions/{session}/stack", params={"thread": 1, "limit": 3})
    assert first.status_code == 200, first.text
    asked = int(first.headers["x-gdb-commands"])
    assert asked > 0, "the first answer has to be asked for"
    assert first.headers["x-gdb-cached"] == "false"

    again = live.get(f"/api/sessions/{session}/stack", params={"thread": 1, "limit": 3})
    assert again.headers["x-gdb-commands"] == "0", "the same question went back to gdb"
    assert again.headers["x-gdb-cached"] == "true"
    assert again.json() == first.json(), "and it answered the same thing, from the session"

    # The poll of an already-ready session is the summary the session is holding: no gdb command at all.
    poll = live.get(f"/api/sessions/{session}")
    assert poll.headers["x-gdb-commands"] == "0"


def test_the_stats_say_the_core_was_loaded_once(live, open_session) -> None:
    """§1's whole decision, as a number: one resident gdb, one load, however many questions follow."""
    body = open_session(live, sample="crash_target")
    session = body["id"]
    for path, params in (
        ("stack", {"thread": 1, "limit": 2}),
        ("frames/0", {"thread": 1}),
        ("memory", {"address": "0x0", "length": 8}),
        ("disassemble", {"address": body["summary"]["detail"]["1"]["frames"][0]["pc"]}),
    ):
        assert live.get(f"/api/sessions/{session}/{path}", params=params).status_code in (200, 422)

    stats = live.get(f"/api/sessions/{session}/stats").json()
    assert stats["core_loads"] == 1, "the core was loaded more than once"
    assert stats["commands_sent"] > 0, "the commands it did send are counted"
    assert stats["commands_by_op"], "and by which command, so a cost can be blamed on something"
    assert stats["state"] == "ready" and stats["failure"] is None
    assert stats["gdb_alive"] is True and stats["gdb_pid"], "the resident debugger is named"
    assert stats["cache_hits"] >= 1 and stats["cache_misses"] >= 1, "both kinds of answer were observed"


def test_the_process_counts_what_the_sessions_did(offline, not_a_core) -> None:
    """The capacity policy of §6, visible: two opens, one eviction, and both loads failed on purpose here."""
    for _ in range(2):
        assert offline.post(
            "/api/sessions", json={"core": str(not_a_core), "exe": str(not_a_core)}
        ).status_code == 201

    stats = offline.get("/api/stats").json()
    assert stats["sessions_created"] == 2
    assert stats["capacity_evictions"] == 1, "capacity is one: the second open closes the first"
    assert stats["sessions_failed"] == 2, "every failed load was counted, not inferred from a 404"
    assert stats["sessions_open"] == 1
    assert stats["contract"]


def test_a_request_that_is_not_about_a_session_has_no_cost_headers(offline) -> None:
    """The headers mean "what this request cost", so a request about nothing must not invent a zero."""
    reply = offline.get("/api/sessions/nope")
    assert reply.status_code == 404
    assert "x-gdb-commands" not in reply.headers
    assert "x-gdb-commands" not in offline.get("/api/health").headers


# --------------------------------------------------------------------------- #
# The four answers (§13.7)
# --------------------------------------------------------------------------- #
def test_a_killed_gdb_answers_gdb_died(live, open_session) -> None:
    """§13.7: "gdb died" is its own answer, with gdb's absence stated rather than papered over.

    This used to be a 409 whose whole explanation was `session is failed`, which is the same sentence a
    loading session gets. The kernel is asked to kill the process by pid, because that is what a debugger
    dying looks like from here — and the reason the pid is in `/stats` is that a test (or a user) has to be
    able to say *which* debugger it is talking about.
    """
    body = open_session(live, sample="crash_target")
    session = body["id"]
    pid = live.get(f"/api/sessions/{session}/stats").json()["gdb_pid"]
    assert pid, "the session must be able to name its gdb"

    os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 10
    reply = None
    while time.monotonic() < deadline:
        reply = live.get(f"/api/sessions/{session}/memory", params={"address": "0x0", "length": 8})
        if reply.status_code == 502:
            break
        time.sleep(0.1)

    assert reply is not None and reply.status_code == 502, reply.text if reply else "no reply"
    assert reply.json()["error"] == "gdb-died", reply.text
    assert reply.json()["detail"], "and the answer says what happened"

    polled = live.get(f"/api/sessions/{session}").json()
    assert polled["state"] == "failed"
    assert "exited" in (polled["error"] or ""), "the session's own words say the debugger is gone"
    assert live.get(f"/api/sessions/{session}/stats").json()["gdb_alive"] in (False, None)


def test_a_missed_deadline_answers_timeout_then_a_dead_debugger(live, open_session) -> None:
    """§13.7's "timeout", and §6's consequence of it.

    The deadline is shortened on the live transport rather than injected as configuration, and the reason is
    worth stating: the *load* uses commands too, so a session configured with a one-microsecond deadline never
    becomes ready — it fails while loading, which is a different path (asserted below). The interesting path is
    a ready session whose next command misses its deadline.

    After it, the debugger is dead by design (a stream that is out of step cannot be resynchronised), so the
    session answers `gdb-died` from then on, and never an answer read out of a misaligned stream.
    """
    body = open_session(live, sample="crash_target")
    session = body["id"]
    transport = live.app.state.sessions.get(session).transport
    transport._proc.command_timeout_s = 1e-6

    timed_out = live.get(f"/api/sessions/{session}/memory", params={"address": "0x0", "length": 8})
    assert timed_out.status_code == 504, timed_out.text
    assert timed_out.json()["error"] == "timeout"
    assert "deadline" in timed_out.json()["detail"]

    after = live.get(f"/api/sessions/{session}/memory", params={"address": "0x0", "length": 8})
    assert after.status_code == 502, f"a gdb that missed a deadline must not be used again: {after.text}"
    assert after.json()["error"] == "gdb-died"
    assert live.get(f"/api/sessions/{session}").json()["state"] == "failed"


def test_a_load_that_missed_its_deadline_is_not_ready_with_the_reason(live_impatient) -> None:
    """The "not ready yet" answer still has to say *why*, or it is the v1 prototype's empty success again.

    Here the deadline is too short for the probe, so the core never loads: the session is failed, its reason
    names the missed deadline, and a query is refused with that reason in the body rather than with a bare
    `session is failed`.
    """
    created = live_impatient.post("/api/sessions", json={"sample": "crash_target"})
    session = created.json()["id"]
    polled = live_impatient.get(f"/api/sessions/{session}", params={"wait": 30}).json()
    assert polled["state"] == "failed", polled.get("error")
    assert "deadline" in (polled["error"] or "") or "interpreter" in (polled["error"] or "")

    refused = live_impatient.get(f"/api/sessions/{session}/stack")
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"] == "not-ready"
    assert polled["error"].split(":")[-1][:20] in refused.json()["detail"], (
        "the refusal carries the session's own words, not just its state"
    )


def test_a_session_that_is_still_loading_is_not_ready_and_says_so(offline, not_a_core) -> None:
    """The fourth answer, and the one that is easiest to get wrong: loading is not an error, it is "not yet"."""
    session = offline.post(
        "/api/sessions", json={"core": str(not_a_core), "exe": str(not_a_core)}
    ).json()["id"]
    reply = offline.get(f"/api/sessions/{session}/memory", params={"address": "0x0", "length": 8})
    assert reply.status_code == 409, reply.text
    assert reply.json()["error"] == "not-ready"
    assert "session is" in reply.json()["detail"]


@pytest.mark.parametrize(
    ("endpoint", "params"),
    [
        ("stack", {"thread": 1}),
        ("frames/0", {"thread": 1}),
        ("memory", {"address": "0x0", "length": 8}),
        ("disassemble", {"address": "0x0"}),
    ],
)
def test_a_question_that_needs_the_debugger_is_refused_the_same_way(live, open_session, endpoint, params) -> None:
    """One rule, not four: whichever question needs the dead debugger, the answer is the same answer."""
    body = open_session(live, sample="crash_target")
    session = body["id"]
    pid = live.get(f"/api/sessions/{session}/stats").json()["gdb_pid"]
    os.kill(pid, signal.SIGKILL)

    reply = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        reply = live.get(f"/api/sessions/{session}/{endpoint}", params=params)
        if reply.status_code != 200:
            break
        time.sleep(0.1)
    assert reply is not None and reply.status_code == 502, reply.text if reply else "no reply"
    assert reply.json()["error"] == "gdb-died"


def test_what_was_loaded_outlives_the_debugger(live, open_session) -> None:
    """And the other half of the rule: the death of a process does not unload a dump.

    The summary is in memory, the core cannot change, and what it says is still true — so the poll, the
    capabilities and the typed lookups go on answering with *exactly* what they answered before, while every
    question that needs gdb answers 502. Refusing those three as well would be throwing away a correct answer
    because a process died, and this project would rather show the data it has.
    """
    body = open_session(live, sample="crash_target")
    session = body["id"]
    before = {
        "capabilities": live.get(f"/api/sessions/{session}/capabilities").json(),
        "objects": live.get(f"/api/sessions/{session}/objects", params={"address": "0x0", "length": 64}).json(),
    }

    os.kill(live.get(f"/api/sessions/{session}/stats").json()["gdb_pid"], signal.SIGKILL)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and live.get(f"/api/sessions/{session}").json()["state"] != "failed":
        time.sleep(0.1)
    assert live.get(f"/api/sessions/{session}").json()["state"] == "failed"

    assert live.get(f"/api/sessions/{session}/capabilities").json() == before["capabilities"]
    assert live.get(f"/api/sessions/{session}/objects", params={"address": "0x0", "length": 64}).json() == before["objects"]
    assert live.get(f"/api/sessions/{session}").json()["summary"], "the first screen is still there to read"
    assert live.get(f"/api/sessions/{session}/stats").json()["failure"] == "died"
