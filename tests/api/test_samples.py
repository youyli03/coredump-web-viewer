"""Every practice core, through the same API, with the awkward fact each one exists to produce.

`docs/api.md` §7 calls this L2, and `practice/README.md` is where each case comes from: the targets were
built to produce the dumps a viewer has to survive, and until now only the *transport* suite read all of them.
Here they are read the way the page reads them — over HTTP — so that "the viewer states what is wrong" is
tested where the viewer actually gets its data.

The list of samples comes from `GET /api/samples`, which is the API's own inventory of the bundle. A test that
hard-coded the six names would keep passing after the bundle changed; this one grows with it.
"""

from __future__ import annotations

import pathlib

import pytest

pytestmark = pytest.mark.gdb

BUNDLE = pathlib.Path(__file__).resolve().parents[2] / "tmp" / "practice"
"""Read from the path rather than from `conftest`: a parametrize list is built before fixtures exist, and this
directory is the same one `src/web/routes.py` discovers samples in."""

SAMPLES = sorted({core.name.split(".")[0] for core in BUNDLE.glob("*.core")}) or ["crash_target"]


def _load(client, open_session, sample: str) -> dict:
    body = open_session(client, sample=sample)
    assert body["state"] == "ready", f"{sample} did not load: {body.get('error')}"
    assert body["summary"], "a ready session carries its first screen"
    return body


def _crashed(summary: dict) -> int:
    crashed = [thread for thread in summary["threads"] if thread["is_crashed"]]
    assert len(crashed) == 1, "exactly one thread crashed, whatever the dump looks like"
    return crashed[0]["num"]


# --------------------------------------------------------------------------- #
# What every sample has to survive, whichever one it is
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("sample", SAMPLES)
def test_every_practice_core_loads_and_states_its_blanks(live, open_session, sample) -> None:
    """No dump is allowed to look like a success it is not, and no frame is allowed to be a blank.

    `architecture.md` §3: "Nothing on a stack is reported as a blank. A missing extent, an unreadable frame
    record and an unverified one are three different answers, so each carries its reason in words" — and a
    `record.why` is present *even when there is no record*. That is the invariant a corrupted stack is here to
    break, and it holds for all six dumps or the viewer is guessing.
    """
    listed = {item["sample"] for item in live.get("/api/samples").json()}
    assert sample in listed, "the API's own inventory disagrees with the bundle on disk"

    body = _load(live, open_session, sample)
    summary = body["summary"]
    thread = _crashed(summary)
    session = body["id"]

    assert summary["detail"][str(thread)]["frames"], "the crashed thread has frames"
    stack = live.get(f"/api/sessions/{session}/stack", params={"thread": thread}).json()
    assert stack["frames"], "and the stack walk answers for it"
    for frame in stack["frames"]:
        record = frame["record"]
        assert record.get("why"), f"{sample} frame {frame['level']} carries no reason at all"
        assert isinstance(record.get("verified"), bool), "verified is a decision, never a blank"
        assert frame["extent_why"] is None or frame["extent_why"], "a missing extent explains itself"

    # The two on-demand views answer for every dump, even the ones gdb cannot symbolise.
    locals_ = live.get(f"/api/sessions/{session}/frames/0", params={"thread": thread})
    assert locals_.status_code == 200, locals_.text
    assert isinstance(locals_.json(), list), "a frame with nothing to name answers an empty list, not an error"
    registers = live.get(f"/api/sessions/{session}/threads/{thread}/registers")
    assert registers.status_code == 200 and registers.json()["registers"]["pc"].startswith("0x")


# --------------------------------------------------------------------------- #
# The fact each sample exists for
# --------------------------------------------------------------------------- #
def test_crash_target_verifies_the_crash_frame(live, open_session) -> None:
    """The intact case, and the baseline the others are compared against: the stack chain is corroborated."""
    body = _load(live, open_session, "crash_target")
    thread = _crashed(body["summary"])
    stack = live.get(f"/api/sessions/{body['id']}/stack", params={"thread": thread}).json()
    first = stack["frames"][0]
    assert first["func"] == "plugin_crash", "the crash is inside the dlopen'ed plugin, on purpose"
    assert first["record"]["verified"] is True
    assert first["record"]["checks"] == {"saved_fp": True, "return_address": True}


def test_smash_fp_keeps_the_frames_but_the_record_contradicts_them(live, open_session) -> None:
    """`practice/src/smash_target.c` fp mode: the frame pointer is a lie and DWARF still walks.

    So the function *is* named and the record does **not** verify — a viewer that trusted the record would draw
    a chain that is not there, and one that only trusted the backtrace would hide the corruption. Both facts
    have to be in the answer, which is why `checks` reports the two halves separately.
    """
    body = _load(live, open_session, "smash_fp")
    thread = _crashed(body["summary"])
    stack = live.get(f"/api/sessions/{body['id']}/stack", params={"thread": thread}).json()
    first = stack["frames"][0]
    assert first["func"] == "crash_here", "DWARF still names the function"
    assert first["record"]["verified"] is False, "and the frame record still disagrees with the next frame"
    assert "disagree" in first["record"]["why"]


def test_smash_ra_leaves_gdb_with_two_unnamed_frames_and_no_warning(live, open_session) -> None:
    """`practice/README.md`: gdb reports two `??` frames and "says nothing else — no corrupt-stack message".

    The viewer is therefore the only thing that can notice, and what it can honestly say is that the frame
    records are not there. An unnamed frame with variables would be an invention.
    """
    body = _load(live, open_session, "smash_ra")
    thread = _crashed(body["summary"])
    session = body["id"]
    stack = live.get(f"/api/sessions/{session}/stack", params={"thread": thread}).json()
    assert all(frame["func"] == "??" for frame in stack["frames"]), "the smasher leaves no name to report"
    assert all(frame["record"]["verified"] is False for frame in stack["frames"])
    assert all(frame["record"]["why"] for frame in stack["frames"]), "and each one says why"

    # Nothing to name means nothing to list — as an empty list, not as a failure.
    locals_ = live.get(f"/api/sessions/{session}/frames/0", params={"thread": thread})
    assert locals_.status_code == 200 and locals_.json() == []


def test_smash_data_leaves_a_verifiably_intact_stack(live, open_session) -> None:
    """The counterpart of `smash_fp`: a pointer was overwritten and the stack is fine.

    Tested next to the other two because the interesting part is the *difference*: the same corruption writer,
    three different answers, and the viewer has to tell them apart rather than report "corrupted stack" for
    all three.
    """
    body = _load(live, open_session, "smash_data")
    thread = _crashed(body["summary"])
    stack = live.get(f"/api/sessions/{body['id']}/stack", params={"thread": thread}).json()
    first = stack["frames"][0]
    assert first["func"] == "data_mode"
    assert first["record"]["verified"] is True, "the stack under the fault is intact, and that is the finding"
    assert first["extent_why"] is None


def test_opt_target_states_a_variable_that_has_no_address(live, open_session) -> None:
    """`-O2`: the argument lives in a register, so it has no bytes in the dump.

    `architecture.md` §3: "a variable only has a slot when gdb puts its address inside this frame. A
    register-resident variable has no bytes in the dump ... both keep their value and get no byte range."
    Which register it is in is a function of the pc, which is why the value and the location come from gdb
    rather than from a table.
    """
    body = _load(live, open_session, "opt_target")
    thread = _crashed(body["summary"])
    session = body["id"]
    stack = live.get(f"/api/sessions/{session}/stack", params={"thread": thread}).json()
    slots = stack["slots"]["0"]
    assert slots, "the crash frame has an argument"
    register_bound = [slot for slot in slots if slot["where"] == "register"]
    assert register_bound, f"this core is -O2 on purpose: {[(s['name'], s['where']) for s in slots]}"
    for slot in register_bound:
        assert slot["slot"] is False, "a variable in a register has no bytes to draw"
        assert slot["address"] in (None, ""), "and no address to jump to"
        assert slot["value"], "but it still has a value — losing that would be the other kind of wrong"

    # The value is still served, through the endpoint the page clicks.
    locals_ = live.get(f"/api/sessions/{session}/frames/0", params={"thread": thread}).json()
    assert any(variable["name"] == "target" for variable in locals_)


def test_snap_target_shows_the_signal_frame(live, open_session) -> None:
    """`snap_target` faults inside a SIGSEGV handler, so the kernel's `sigcontext` is still on the stack.

    gdb shows it as `<signal handler called>`, and a viewer that hides it makes the frames above and below
    look adjacent when they are not.
    """
    body = _load(live, open_session, "snap_target")
    thread = _crashed(body["summary"])
    stack = live.get(f"/api/sessions/{body['id']}/stack", params={"thread": thread}).json()
    names = [frame["func"] for frame in stack["frames"]]
    assert "<signal handler called>" in names, names
    assert names[0] == "on_fault", "the handler is where it faulted"
