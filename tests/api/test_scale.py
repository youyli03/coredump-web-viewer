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
        dataclasses.replace(CONFIG, gdb_path=str(gdb), command_timeout_s=300),
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
