"""The offline half: what the API answers with no core, no gdb, and nothing written into the checkout.

These are the cheapest tests in the repository and they cover the part of the API that a browser hits first —
the health line, the bundle listing, the form's defaults, the history — plus the whole failure vocabulary.

The interesting ones are the failures. requirements.md §13.7 is explicit that an error must say *which* of
four it is, and the lesson behind it is the v1 prototype answering `{"threads": []}` for a core that never
loaded: a dump that cannot be read must never look like a dump with nothing in it.
"""

from __future__ import annotations

import json
import pathlib
import time

import pytest


# --------------------------------------------------------------------------- #
# The reads that need nothing at all
# --------------------------------------------------------------------------- #
def test_health_names_the_gdb_it_will_run(offline) -> None:
    """The one line that says whether this backend can read the cores at all.

    It reports the *configured* gdb rather than the one on `PATH`, because the difference is exactly what a
    user has to fix: a native gdb reads an aarch64 ELF executable and then refuses the core itself.
    """
    reply = offline.get("/api/health")
    assert reply.status_code == 200
    body = reply.json()
    assert body["ok"] is True
    assert body["gdb"] == "/nonexistent-gdb-for-tests"
    assert body["sessions"] == []


def test_an_empty_bundle_offers_no_samples(offline) -> None:
    """Discovered, not declared: no cores on disk means no samples, not a hard-coded list."""
    reply = offline.get("/api/samples")
    assert reply.status_code == 200
    assert reply.json() == []


def test_defaults_are_measured_not_guessed(offline, tmp_path: pathlib.Path) -> None:
    """Every suggested path is checked before it is offered, and the root is the app's own.

    A default that is not there must be *shown* as missing; typing in a path that does not exist is how a form
    teaches the user to distrust it.
    """
    body = offline.get("/api/defaults").json()
    assert body["root"] == str(tmp_path)
    assert set(body["valid"]) == {"core", "exe", "gdb", "sysroot", "solib_search_path"}
    assert body["valid"]["core"] is False, "an empty bundle has no core to offer"
    assert body["valid"]["exe"] is False
    assert body["valid"]["sysroot"] is False, "an empty bundle has no sysroot either"
    assert body["valid"]["solib_search_path"] is True, (
        "the bundle *directory* exists — which is the point: each field is measured on its own, not inferred "
        "from whether the bundle is any good"
    )
    # An empty string is how "there is nothing to offer" is said; every path that *is* offered must be
    # absolute, because the frontend shows it to a user who will paste it back.
    assert all(
        pathlib.Path(body[key]).is_absolute() for key, ok in body["valid"].items() if ok or body[key]
    )


def test_the_history_is_read_where_the_app_was_pointed(offline, tmp_path: pathlib.Path) -> None:
    """The state file lives beside the checkout, and this app was pointed somewhere else.

    Without this the suite would write into a developer's real `.coredump-viewer.json` — and, worse, read it:
    a test that asserts against the machine it runs on is a test that fails on Monday for no reason.
    """
    entry = {"core": str(tmp_path / "ghost.core"), "openedAt": "2026-01-01T00:00:00+00:00"}
    (tmp_path / ".coredump-viewer.json").write_text(json.dumps({"recent": [entry]}), encoding="utf-8")

    listed = offline.get("/api/recent").json()
    assert [item["core"] for item in listed] == [entry["core"]]
    assert listed[0]["valid"]["core"] is False, "validity is measured now, and that core does not exist"

    assert offline.delete("/api/recent/0").status_code == 204
    assert offline.get("/api/recent").json() == []


# --------------------------------------------------------------------------- #
# Opening something that cannot be opened
# --------------------------------------------------------------------------- #
def test_a_core_that_is_not_there_is_not_found(offline, tmp_path: pathlib.Path) -> None:
    reply = offline.post("/api/sessions", json={"core": str(tmp_path / "missing.core")})
    assert reply.status_code == 404
    assert reply.json()["error"] == "not-found"
    assert "missing.core" in reply.json()["detail"], "the body must name the path that was wrong"


def test_an_unknown_sample_is_not_found(offline) -> None:
    reply = offline.post("/api/sessions", json={"sample": "no_such_target"})
    assert reply.status_code == 404
    assert reply.json()["error"] == "not-found"


def test_a_file_that_is_not_a_core_fails_the_session_with_a_reason(
    offline, open_session, not_a_core: pathlib.Path
) -> None:
    """The most expensive lesson in this project, pinned.

    A dump that cannot be read is a **failed session carrying the reason**, never a ready session with an empty
    thread list. Here the reason is that there is no gdb to run at all — which is the point: the API reports
    what went wrong instead of inventing an empty answer.
    """
    body = open_session(offline, core=str(not_a_core), exe=str(not_a_core))
    assert body["state"] == "failed", f"expected a failed load, got {body['state']!r}: {body['error']}"
    assert body["error"], "a failure must say something"
    assert body["summary"] is None, "no summary is not the same as an empty summary"


def test_a_session_that_failed_refuses_queries_with_not_ready(offline, not_a_core: pathlib.Path) -> None:
    session_id = offline.post(
        "/api/sessions", json={"core": str(not_a_core), "exe": str(not_a_core)}
    ).json()["id"]
    # No `?wait=`: the point is that a query against a session that is still loading — or already failed — is
    # refused, not that it waits. Either state is a refusal, and both are 409.
    reply = offline.get(f"/api/sessions/{session_id}/memory", params={"address": "0x0", "length": 8})
    assert reply.status_code == 409
    assert reply.json()["error"] == "not-ready"
    assert "session is" in reply.json()["detail"]


def test_waiting_ends_on_the_state_not_on_the_clock(offline, open_session, not_a_core: pathlib.Path) -> None:
    """`?wait=` waits for a *transition*, and a session that has already stopped costs no waiting at all.

    A `wait=30` that slept for thirty seconds regardless would make the frontend hang and every test slow. The
    bound is loose on purpose: it only has to prove the wait ended because the state changed rather than
    because the timer ran out. Both waits run on the *same* session, because capacity is one and a second open
    would evict the first.
    """
    session_id = offline.post(
        "/api/sessions", json={"core": str(not_a_core), "exe": str(not_a_core)}
    ).json()["id"]

    started = time.monotonic()
    first = offline.get(f"/api/sessions/{session_id}", params={"wait": 30})
    waited = time.monotonic() - started
    assert first.status_code == 200
    assert first.json()["state"] in {"failed", "ready"}, "the wait must end in a terminal state"

    started = time.monotonic()
    again = offline.get(f"/api/sessions/{session_id}", params={"wait": 30})
    repeated = time.monotonic() - started
    assert again.status_code == 200
    assert repeated < 5, f"an already-finished session cost {repeated:.1f}s of waiting"
    assert repeated <= waited + 5, "the second wait must not be the slower one"


def test_closing_every_session_is_idempotent(offline) -> None:
    assert offline.delete("/api/sessions").status_code == 204
    assert offline.delete("/api/sessions").status_code == 204
    assert offline.get("/api/health").json()["sessions"] == []


# --------------------------------------------------------------------------- #
# One shape for every failure
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("method", "path", "params", "status", "code"),
    [
        ("get", "/api/sessions/nope", None, 404, "not-found"),
        ("get", "/api/sessions/nope/memory", {"address": "0x0", "length": 8}, 404, "not-found"),
        ("get", "/api/no-such-route", None, 404, "not-found"),
        ("delete", "/api/sessions/nope", None, 404, "not-found"),
        ("get", "/api/sessions/s1/memory", {"address": "0x0", "length": "abc"}, 422, "invalid-parameter"),
        ("delete", "/api/recent/not-a-number", None, 422, "invalid-parameter"),
    ],
)
def test_every_failure_has_one_body_shape(offline, method, path, params, status, code) -> None:
    """`{"error", "detail", "status"}` — one vocabulary, whichever layer refused.

    Three shapes used to coexist: the transport handlers, an `HTTPException` falling through to FastAPI, and an
    unparseable query parameter answering FastAPI's 422 *list*. A machine consumer cannot branch on three.
    400 and the two transport-specific codes (`unreadable`, `unsupported`) are not reachable from here — they
    need a ready session — and are covered in `test_live.py`.
    """
    reply = getattr(offline, method)(path, params=params) if params else getattr(offline, method)(path)
    assert reply.status_code == status, reply.text
    body = reply.json()
    assert set(body) == {"error", "detail", "status"}, body
    assert body["status"] == status
    assert body["error"] == code
    assert isinstance(body["detail"], str) and body["detail"]
