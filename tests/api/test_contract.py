"""The contract, tested as a contract.

`docs/api.md` §1 states the rule these tests enforce: a test may assert **promises**, not the key set a
particular dictionary happens to have this week. That only works if the shapes are declared somewhere the
tests can read — which is `src/schema.py`, the module `requirements.md` §8 asks for.

Three things are checked here:

* the served OpenAPI *is* the documented surface — an endpoint renamed or dropped without the document saying
  so is a contract break, whether or not a test happened to cover it;
* the answers validate against their models, including the one endpoint whose shape is documented but not
  enforced at runtime (the poll, for the reasons in its docstring);
* **the two producers agree.** A live session and `scripts/dump-fixture.py` build the same JSON from the same
  function; if they ever disagree, the page's offline fallback is a lie, and this is the test that says so.
"""

from __future__ import annotations

import pathlib

import pytest

from config import CONFIG
from schema import CONTRACT, ErrorBody, SessionDetail, Summary

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "ui" / "data"

DOCUMENTED_PATHS = {
    "/api/health",
    "/api/samples",
    "/api/defaults",
    "/api/recent",
    "/api/recent/{index}",
    "/api/sessions",
    "/api/sessions/{session_id}",
    "/api/stats",
    "/api/sessions/{session_id}/capabilities",
    "/api/sessions/{session_id}/stats",
    "/api/sessions/{session_id}/memory",
    "/api/sessions/{session_id}/disassemble",
    "/api/sessions/{session_id}/object",
    "/api/sessions/{session_id}/objects",
    "/api/sessions/{session_id}/stack",
    "/api/sessions/{session_id}/frames/{level}",
}
"""The surface `docs/api.md` describes. Written out rather than derived from the app, so that *discovering*
what exists cannot pass for agreeing with what was specified."""


# --------------------------------------------------------------------------- #
# The document and the server agree about what exists
# --------------------------------------------------------------------------- #
def test_every_documented_path_is_served(offline) -> None:
    served = set(offline.get("/openapi.json").json()["paths"])
    missing = DOCUMENTED_PATHS - served
    assert not missing, f"docs/api.md describes endpoints that do not exist: {sorted(missing)}"


def test_the_poll_is_documented_even_though_it_is_not_enforced(offline) -> None:
    """The one endpoint whose `response_model` is deliberately left off.

    A model there would re-serialise the largest payload in the project on every poll, and all it would add
    is the power to drop a field the model did not name. So the shape is declared for the OpenAPI document
    and validated by the test below instead.
    """
    schema = offline.get("/openapi.json").json()["paths"]["/api/sessions/{session_id}"]["get"]
    assert "200" in schema["responses"]
    assert schema["responses"]["200"]["content"]["application/json"]["schema"], "the poll documents a body"


def test_health_reports_the_contract_version(offline) -> None:
    body = offline.get("/api/health").json()
    assert body["contract"] == CONTRACT


def test_the_error_body_is_the_declared_shape(offline) -> None:
    """Every failure goes through one body, so one model describes them all."""
    reply = offline.get("/api/sessions/nope")
    ErrorBody.model_validate(reply.json())
    assert reply.json()["status"] == reply.status_code


# --------------------------------------------------------------------------- #
# The answers fit their models
# --------------------------------------------------------------------------- #
def test_a_live_session_validates_against_the_contract(live, open_session) -> None:
    body = open_session(live, sample="crash_target")
    detail = SessionDetail.model_validate(body)
    assert detail.state == "ready"
    assert detail.summary is not None, "a ready session carries the first screen"
    assert detail.summary.session.contract == CONTRACT
    assert detail.summary.threads, "the first screen lists threads"

    # The typed model is not a filter: what the analysis layer put in must still be there afterwards.
    assert detail.summary.threads[0].is_crashed in (True, False)
    assert detail.summary.detail, "the detail section survives validation"


def test_capabilities_answer_the_same_bits_as_the_summary(live, open_session) -> None:
    """§13.6 has one answer in two places, and they must not drift.

    The summary carries the capabilities because the first screen needs them; the endpoint exists so a caller
    can ask the question without holding the whole report. Two answers to one question is exactly the shape
    that drifts quietly, so this asserts they are the same object.
    """
    body = open_session(live, sample="crash_target")
    answer = live.get(f"/api/sessions/{body['id']}/capabilities").json()
    assert answer["capabilities"] == body["summary"]["session"]["capabilities"]
    assert answer["transport"] == body["summary"]["session"]["transport"]
    assert answer["gdb_version"] == body["summary"]["session"]["gdb_version"]
    assert answer["capabilities"]["threads"] is True, "a core that loaded has a thread list, at least"


# --------------------------------------------------------------------------- #
# The two producers of the same JSON agree
# --------------------------------------------------------------------------- #
def _keys(payload: dict) -> set:
    return set(payload)


@pytest.mark.gdb
def test_the_fixture_and_a_live_session_build_the_same_summary(live, open_session) -> None:
    """`dump-fixture.py` and a live session call the same builder — but with different flags.

    The fixture is what the page falls back to with no backend, and it pre-fetches everything the endpoints
    would otherwise serve. That difference is *allowed*; a difference in the keys at the top level, or in the
    session section the frontend reads for its capability switch, is not: it would mean the offline page and
    the live page are reading two different formats. `opt_target` is used because it is 270 KB rather than
    25 MB, and it is the core whose profile (`-O2`) takes the other branch through the builder.
    """
    import analysis.report as report

    live_body = open_session(live, sample="opt_target")
    live_summary = live_body["summary"]
    fixture_summary = report.build_from_paths("opt_target")

    assert _keys(fixture_summary) == _keys(live_summary), (
        f"the two producers disagree about the summary's sections: "
        f"{_keys(fixture_summary) ^ _keys(live_summary)}"
    )
    assert _keys(fixture_summary["session"]) == _keys(live_summary["session"]), (
        "the session section is what the page switches on; a key that exists in only one of the two is a "
        "feature that works online and quietly stops offline"
    )
    assert _keys(fixture_summary["threads"][0]) == _keys(live_summary["threads"][0])
    assert fixture_summary["session"]["contract"] == live_summary["session"]["contract"] == CONTRACT

    # And both are the same *document*, so a consumer can validate either against one model.
    Summary.model_validate(fixture_summary)
    Summary.model_validate(live_summary)


@pytest.mark.gdb
def test_a_generated_fixture_carries_the_contract_version(live, tmp_path: pathlib.Path) -> None:
    """A fixture file on disk says which contract it was built to, so a stale one is visible.

    The `live` fixture is here for its **skip**, not its client: this test builds a summary through
    `build_from_paths`, which needs the practice bundle *and* the cross gdb. It used to assert neither and
    failed with `FileNotFoundError` where every other test that reads a core skips — measured with
    `CDWV_GDB=/nonexistent-gdb`, where it was the only failure in the suite. A fresh clone is supposed to skip,
    not to fail.
    """
    import json

    import analysis.report as report

    data = report.build_from_paths("opt_target")
    path = tmp_path / "data.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["session"]["contract"] == CONTRACT
    Summary.model_validate(written)
