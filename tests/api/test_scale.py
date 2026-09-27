"""Scale: a core the size of a small machine's memory, and a stack 30 000 frames deep.

`requirements.md` §5 makes two claims in one line — "cores are GB-scale and a stack can have tens of thousands
of frames" — and the six practice cores that `collect.sh` builds by default cannot test either: they are
kilobytes with 28 frames. `HEAVY=1 bash practice/collect.sh` builds the sample that can, and this is the suite
that holds the viewer to the claim:

    HEAVY=1 bash practice/collect.sh            # in the Linux guest, then copy practice/out/ to tmp/heavy/

Without that bundle these skip, because a gigabyte of core is not something a repository keeps.

Both bugs this file found were **cost** bugs, invisible on a small dump and fatal here:

* a twenty-frame window at offset 20 000 took **52.7 seconds and 45 321 gdb commands**, because the frame
  locations were walked from frame 0 to the window — a scroll that costs O(depth);
* `/frames/20000` answered **404 "thread 1 has no frame 20000"** for a stack that has 30 002 of them: the
  check was made against the 500 frames the first screen pre-fetches, and a paging cap had been mistaken for
  a fact about the dump.
"""

from __future__ import annotations

import pathlib

import pytest

from config import CONFIG
from web.app import create_app

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEAVY = ROOT / "tmp" / "heavy"
"""Where `HEAVY=1 bash practice/collect.sh`'s bundle is copied. `tmp/` is scratch, so a missing one skips."""


def _heavy_core() -> pathlib.Path | None:
    cores = sorted(HEAVY.glob("heavy_target.*.core"))
    return cores[-1] if cores else None


@pytest.fixture
def heavy(tmp_path: pathlib.Path):
    """A session on the heavy core, opened the way a user opens a foreign dump: paths, not a sample name."""
    yield from _heavy_session(tmp_path, command_timeout_s=300)


def _heavy_session(tmp_path: pathlib.Path, *, command_timeout_s: float):
    import dataclasses
    import os

    from fastapi.testclient import TestClient

    core = _heavy_core()
    gdb = pathlib.Path(
        os.environ.get("CDWV_GDB") or ROOT / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
    )
    if core is None or not gdb.exists():
        pytest.skip(f"needs the heavy bundle in {HEAVY} and a cross gdb (see this module's docstring)")

    app = create_app(
        dataclasses.replace(CONFIG, gdb_path=str(gdb), command_timeout_s=command_timeout_s),
        root=ROOT,
        state_path=tmp_path,
        bundle=HEAVY,
    )
    with TestClient(app) as client:
        created = client.post(
            "/api/sessions",
            json={
                "core": str(core),
                "exe": str(HEAVY / "heavy_target"),
                "sysroot": str(HEAVY / "sysroot"),
                "solib_search_path": str(HEAVY),
            },
        ).json()
        loaded = client.get(f"/api/sessions/{created['id']}", params={"wait": 600}).json()
        assert loaded["state"] == "ready", loaded.get("error")
        yield client, loaded


@pytest.mark.gdb
def test_a_gigabyte_core_loads_and_shows_all_of_it(heavy) -> None:
    """The first screen of a 1.13 GB dump: 48 threads, a 30 002-frame stack, and a 1.07 GB mapping.

    `architecture.md` §1 chose a resident gdb so that this happens **once**; what it costs is measured here
    rather than assumed.
    """
    client, loaded = heavy
    summary = loaded["summary"]
    assert len(summary["threads"]) == 48, "the target starts 48 threads in four different states"
    crashed = next(t["num"] for t in summary["threads"] if t["is_crashed"])

    total = summary["detail"][str(crashed)]["total"]
    assert total >= 30000, f"the target recurses 30 000 frames deep, and the dump says {total}"
    assert len(summary["detail"][str(crashed)]["frames"]) <= 500, (
        "the first screen carries a page of them, not all 30 000 — the rest is what `/stack` pages"
    )

    regions = summary["memory_map"]["regions"]
    biggest = max(int(region["size"]) for region in regions)
    assert biggest > 1_000_000_000, f"the 1 GB heap is the biggest mapping in the dump, and it is {biggest}"
    assert any(region.get("path") for region in regions), "and the binaries are still named by NT_FILE"

    stats = client.get(f"/api/sessions/{loaded['id']}/stats").json()
    assert stats["core_loads"] == 1


@pytest.mark.gdb
def test_a_window_far_down_a_deep_stack_costs_a_window(heavy) -> None:
    """**The regression this file exists for.** A window's cost has to be the window, not the offset.

    Measured before the fix, on this core: offset 0 cost 384 commands, offset 5 000 cost 15 321 and offset
    20 000 cost 45 321 — each frame's `sp`/`fp` was fetched by walking from frame 0, so a scroll was O(depth)
    and took 52.7 seconds at the bottom of a 30 000-frame stack.

    The assertion is deliberately about the *count* and not the clock: a command count is a property of the
    code, while seconds are a property of the machine this happens to run on.
    """
    client, loaded = heavy
    session = loaded["id"]
    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])

    def cost(offset: int, limit: int) -> tuple[int, list[int]]:
        reply = client.get(
            f"/api/sessions/{session}/stack", params={"thread": crashed, "offset": offset, "limit": limit}
        )
        assert reply.status_code == 200, reply.text
        body = reply.json()
        assert body["total"] >= 30000
        return int(reply.headers["x-gdb-commands"]), [frame["level"] for frame in body["frames"]]

    near, levels_near = cost(0, 20)
    far, levels_far = cost(20000, 20)

    assert levels_near == list(range(0, 20))
    assert levels_far == list(range(20000, 20020)), "the window is where it was asked for"
    assert far < near * 2, (
        f"a window 20 000 frames down cost {far} commands against {near} at the top: the walk is O(offset) "
        "again, and a scroll of a deep stack is O(depth) per scroll"
    )


@pytest.mark.gdb
def test_a_wide_window_is_a_window_and_not_the_whole_walk(heavy) -> None:
    """**The second regression this file found**: a batch must be *bounded*, or it takes the session with it.

    The `frame apply` that made a window cheap (22 commands against 87) made a wide range fatal when it was sent
    as one command: `/stack` with no `limit` — what the UI asks for when the stack view opens — covered all
    30 002 frames in a single command, the 30 s deadline fired while gdb was still unwinding, and the reply was
    `502 gdb-died`, because a missed deadline kills the debugger rather than answering late. Measured before the
    fix: `502 in 30.0s, 2 commands`.

    That this request *answers* is what is asserted here; the ceiling itself is pinned where it can be pinned
    deterministically — `tests/unit/test_mi_stack.py` asserts the spans of a 600-frame range, and fails if the
    command is one unbounded range again. A deadline assertion here would be a claim about this machine's clock.
    """
    client, loaded = heavy
    session = loaded["id"]
    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])

    reply = client.get(
        f"/api/sessions/{session}/stack", params={"thread": crashed, "offset": 20000, "limit": 1024}
    )
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert [frame["level"] for frame in body["frames"]] == list(range(20000, 21024))
    assert body["truncated"] is True, "19 978 frames above it and ~29 000 below: neither side is the whole stack"
    assert all(frame["record"]["verified"] for frame in body["frames"]), (
        "and every one of the 1 024 has a frame record that agrees with its caller"
    )

    stats = client.get(f"/api/sessions/{session}/stats").json()
    assert stats["timeouts"] == 0, "no command missed its deadline, and gdb is still the one that loaded the core"
    assert stats["gdb_alive"] is True


@pytest.mark.gdb
def test_the_stack_with_no_limit_is_a_page_and_not_the_whole_thing(heavy) -> None:
    """**The third cost bug this file found.** "No `limit` means all of it" is a promise this API cannot keep.

    Measured on this 30 002-frame stack before the page existed: `/stack` with no `limit` took **235.6 s and
    420 146 gdb commands** — and that is the UI's own request when the stack view opens, most of it the
    per-frame variable work. It now answers the page the first screen already carries (500 frames, measured at
    1.2 s / ~7 000 commands) and says where it sits, so the rest is one request away instead of one request too
    many.

    The assertion is about *cost*, like the rest of this file: a command count is a property of the code, and
    seconds are a property of this machine.
    """
    client, loaded = heavy
    session = loaded["id"]
    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])

    reply = client.get(f"/api/sessions/{session}/stack", params={"thread": crashed})
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert len(body["frames"]) == 500, "one page, not 30 002"
    assert body["limit"] == 500 and body["offset"] == 0
    assert body["total"] >= 30000
    assert body["truncated"] is True, "and the reply says so, or a page reads as the whole stack"

    # A page costs a page's worth of work. 7 006 commands measured here; the ceiling is loose on purpose,
    # because the number that matters is the shape, not this machine's speed.
    cost = int(reply.headers["x-gdb-commands"])
    assert cost < 20000, f"one page of 500 frames cost {cost} gdb commands, which is the whole stack again"

    # And the next page is exactly that: one page further in, nothing repeated and nothing skipped.
    second = client.get(f"/api/sessions/{session}/stack", params={"thread": crashed, "offset": 500})
    assert second.status_code == 200, second.text
    following = second.json()
    assert following["frames"][0]["level"] == 500
    assert len(following["frames"]) == 500
    assert int(second.headers["x-gdb-commands"]) < 20000


@pytest.mark.gdb
def test_a_stack_page_can_be_drawn_on_its_own(heavy) -> None:
    """A page of frames is not just addresses: it carries what a flow graph draws.

    This is what makes paging possible for the stack view at all. The summary pre-fetches one page *with*
    arguments, while `stack_frames` answers the memory question and carries no `func`, no source site and no
    arguments — so before this, page two of a deep stack would have arrived as rows with no names, which is
    exactly what a stripped core looks like. Measured: the arguments for a 500-frame page cost **one** command.
    """
    client, loaded = heavy
    session = loaded["id"]
    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])

    before = client.get(f"/api/sessions/{session}/stats").json()["commands_by_op"].get("-stack-list-arguments", 0)
    page = client.get(f"/api/sessions/{session}/stack", params={"thread": crashed, "offset": 1000, "limit": 50})
    assert page.status_code == 200, page.text
    frames = page.json()["frames"]
    assert len(frames) == 50
    for frame in frames:
        assert frame["func"], "every frame of the page has a name"
        assert "args" in frame, "and what the call was given"
        assert frame["level"] >= 1000

    after = client.get(f"/api/sessions/{session}/stats").json()["commands_by_op"].get("-stack-list-arguments", 0)
    assert after - before == 1, "one command for the page's arguments, not one per frame"


@pytest.mark.gdb
def test_a_single_frame_can_be_asked_for_at_any_depth(heavy) -> None:
    """One frame is one click, and the click has to work at 20 000 as well as at 0.

    Measured before the fix: `/frames/20000` and `/frames/30001` both answered `404 "thread 1 has no frame
    20000"` — the check used the 500 frames the first screen pre-fetches, so everything deeper than the
    prefetch was reported as not existing.
    """
    client, loaded = heavy
    session = loaded["id"]
    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])
    total = loaded["summary"]["detail"][str(crashed)]["total"]

    deepest = client.get(f"/api/sessions/{session}/frames/{total - 1}", params={"thread": crashed})
    assert deepest.status_code == 200, deepest.text
    assert deepest.json(), "the deepest frame has the recursion's arguments, and they are its locals"

    # And the boundary is still a boundary: one past the end is not a frame that exists.
    beyond = client.get(f"/api/sessions/{session}/frames/{total}", params={"thread": crashed})
    assert beyond.status_code == 404
    assert str(total) in beyond.json()["detail"], "the refusal says how many frames there really are"


@pytest.mark.gdb
def test_the_deepest_window_says_what_it_left_out(heavy) -> None:
    """`total` and `truncated` are what keep a paged stack from reading like a short one."""
    client, loaded = heavy
    session = loaded["id"]
    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])
    total = loaded["summary"]["detail"][str(crashed)]["total"]

    last = client.get(
        f"/api/sessions/{session}/stack", params={"thread": crashed, "offset": total - 10, "limit": 10}
    ).json()
    assert [frame["level"] for frame in last["frames"]] == list(range(total - 10, total))
    assert last["total"] == total
    assert last["truncated"] is True, "there are 30 000 frames above this window and the answer says so"
    assert last["frames"][0]["level"] == total - 10
    assert last["frames"][-1]["func"] == "main", "the highest level is the outermost frame, where it all began"
