"""Cores that are not this checkout's practice bundle.

Real cores arrive without ceremony: a dump from a machine you do not have, often without the binary that
produced it, of an architecture your gdb may or may not know. Every one of those is a case the practice bundle
cannot produce, and three of them were broken in ways that only a *foreign* core could show:

* **the summary assumed the core lived in this checkout** — `core.relative_to(ROOT)` answered a core in
  `tmp/cores` with `ValueError: … is not in the subpath of …`, for a session that had loaded perfectly;
* **a missing `sysroot` was silently replaced by this checkout's practice bundle**, so a core-only session
  reported the *practice binaries'* symbols and frames. A fallback that manufactures a plausible answer is the
  one failure this project keeps refusing;
* **the stack pointer was read by the name `sp`**, which is aarch64's name for it. On a real x86-64 core read by
  the matching gdb the answer was "gdb could not read this core's registers" — because gdb calls it `rsp` there
  and `esp` on i386. The transport already knew the portable way (`$sp`, as `_frame_locations` uses); the
  report had gone around it.

The last test needs a core of another architecture, which is not something this repository can commit. It skips
unless one has been fetched, and says how — `AGENTS.local.md` has the command.
"""

from __future__ import annotations

import pathlib
import shutil

import pytest
from fastapi.testclient import TestClient

from config import CONFIG
from web.app import create_app

ROOT = pathlib.Path(__file__).resolve().parents[2]
FOREIGN = ROOT / "tmp" / "cores"
"""Where a fetched core of another architecture is looked for. `tmp/` is scratch: absent, and every test here
that needs one skips."""

X86_64_GDB = pathlib.Path(shutil.which("x86_64-linux-gnu-gdb") or "/opt/homebrew/bin/x86_64-linux-gnu-gdb")


def _portable_gdb() -> pathlib.Path:
    """The cross gdb these tests read the practice core with, resolved the way the other suites resolve it."""
    import os

    return pathlib.Path(
        os.environ.get("CDWV_GDB") or ROOT / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
    )


def _app(**overrides):
    settings = {"gdb_path": str(_portable_gdb()), **overrides}
    import dataclasses

    return create_app(dataclasses.replace(CONFIG, **settings), root=ROOT, state_path=overrides.pop("_state", ROOT))


# --------------------------------------------------------------------------- #
# A core that lives somewhere else
# --------------------------------------------------------------------------- #
def test_a_core_outside_the_checkout_is_named_by_its_real_path(tmp_path: pathlib.Path, core_for, bundle) -> None:
    """The report says where a core is; it does not require the core to be inside the checkout.

    Everything needed is named explicitly — the core, its binary, the sysroot and the search path — which is
    what a user does when the dump came from another machine, and which is exactly the shape that used to fail
    with a `ValueError` from `relative_to`.
    """
    core = core_for("crash_target")
    if core is None or not _portable_gdb().exists():
        pytest.skip("needs the practice bundle and the cross gdb")

    elsewhere = tmp_path / "from-another-machine"
    elsewhere.mkdir()
    moved = elsewhere / core.name
    shutil.copy(core, moved)

    app = create_app(
        __import__("dataclasses").replace(CONFIG, gdb_path=str(_portable_gdb())),
        root=ROOT,
        state_path=tmp_path,
        bundle=bundle,
    )
    with TestClient(app) as client:
        created = client.post(
            "/api/sessions",
            json={
                "core": str(moved),
                "exe": str(bundle / "crash_target"),
                "sysroot": str(bundle / "sysroot"),
                "solib_search_path": str(bundle),
            },
        )
        assert created.status_code == 201, created.text
        loaded = client.get(f"/api/sessions/{created.json()['id']}", params={"wait": 60}).json()

    assert loaded["state"] == "ready", loaded.get("error")
    assert loaded["core"] == str(moved), "the core is reported where it actually is"
    assert pathlib.Path(loaded["summary"]["session"]["core_path"]).is_absolute(), (
        "a core outside the checkout is named by its path; only a core inside it is named relative to it"
    )
    assert pathlib.Path(loaded["summary"]["session"]["exe_path"]) == (bundle / "crash_target").relative_to(ROOT), (
        "the binary *is* inside the checkout, and the report says so the short way"
    )
    # And it really read the dump: the practice core's crash frame, through the binary it was given.
    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])
    assert loaded["summary"]["detail"][str(crashed)]["frames"][0]["func"] == "plugin_crash"


# --------------------------------------------------------------------------- #
# A core without its binary
# --------------------------------------------------------------------------- #
def test_a_core_without_its_binary_borrows_nothing(tmp_path: pathlib.Path, core_for) -> None:
    """The most common real-world shape: you have the dump and not the build, and nothing is substituted.

    Two assertions, because they are two different failures. At the transport level: a caller that named no
    sysroot and no search path gets neither — the practice bundle used to be filled in for both, which is a
    fallback that manufactures a plausible answer. At the API level: a copy of the practice core in a directory
    with no binary beside it answers `??` and `dwarf_types: false`, and *that* is the proof nothing was
    borrowed — had the bundle still been in play, this same session would have come back symbolised.

    (gdb has its own helpfulness here, worth knowing: given only a core, it looks for the matching executable
    beside the core file and loads it if it is there. That is why this test copies the core somewhere lonely
    rather than using the bundle's own copy.)
    """
    from analysis import report

    core = core_for("crash_target")
    if core is None or not _portable_gdb().exists():
        pytest.skip("needs the practice bundle and the cross gdb")

    transport = report.open_transport(core, None, gdb=_portable_gdb())
    try:
        assert transport.sysroot is None, "no sysroot was named, so none may be invented"
        assert transport.solib_search_path is None, "and no search path either"
    finally:
        transport.close()

    lonely = tmp_path / "no-binary-here"
    lonely.mkdir()
    moved = lonely / core.name
    shutil.copy(core, moved)

    app = create_app(
        __import__("dataclasses").replace(CONFIG, gdb_path=str(_portable_gdb())),
        root=ROOT,
        state_path=tmp_path,
        bundle=tmp_path / "no-bundle",
    )
    with TestClient(app) as client:
        created = client.post("/api/sessions", json={"core": str(moved)})
        assert created.status_code == 201, created.text
        loaded = client.get(f"/api/sessions/{created.json()['id']}", params={"wait": 60}).json()

    assert loaded["state"] == "ready", loaded.get("error")
    assert loaded["exe"] is None, "no executable was given, and none is invented"
    assert loaded["summary"]["session"]["exe_path"] is None

    crashed = next(t["num"] for t in loaded["summary"]["threads"] if t["is_crashed"])
    frames = loaded["summary"]["detail"][str(crashed)]["frames"]
    assert frames, "a dump with no symbols still has a stack"
    assert all(frame["func"] in (None, "??") for frame in frames[:3]), (
        f"symbols came from somewhere they were not given: {[f['func'] for f in frames[:3]]}"
    )
    capabilities = loaded["summary"]["session"]["capabilities"]
    assert capabilities["dwarf_types"] is False, "no binary means no DWARF, and the capability has to say so"


# --------------------------------------------------------------------------- #
# A core of another architecture
# --------------------------------------------------------------------------- #
def test_a_core_of_another_architecture_needs_its_own_gdb(tmp_path: pathlib.Path) -> None:
    """Two answers, one dump: the wrong gdb refuses with gdb's words, the right one reads it.

    The core is one of the fixtures `pyelftools` publishes for its own parser tests (x86-64, i386 and a
    big-endian MIPS one are in `test/testfiles_for_unittests/`). Fetch it with:

        mkdir -p tmp/cores && curl -o tmp/cores/core_linux64.elf \\
          https://raw.githubusercontent.com/eliben/pyelftools/main/test/testfiles_for_unittests/core_linux64.elf

    and install the matching gdb with `brew install messense/macos-cross-toolchains/x86_64-unknown-linux-gnu`.
    Without either, this skips — a core of another architecture is not something this repository keeps.
    """
    core = FOREIGN / "core_linux64.elf"
    if not core.is_file():
        pytest.skip(f"no foreign core to read: fetch one into {FOREIGN} (see this test's docstring)")
    if not _portable_gdb().exists() or not X86_64_GDB.exists():
        pytest.skip("needs both the aarch64 and the x86_64 cross gdb")

    def open_with(gdb: pathlib.Path) -> dict:
        app = create_app(
            __import__("dataclasses").replace(CONFIG, gdb_path=str(gdb)),
            root=ROOT,
            state_path=tmp_path,
            bundle=ROOT / "tmp" / "practice",
        )
        with TestClient(app) as client:
            created = client.post("/api/sessions", json={"core": str(core)}).json()
            return client.get(f"/api/sessions/{created['id']}", params={"wait": 60}).json()

    # The wrong gdb: refused, and the account is gdb's own — including the sentence it printed while loading,
    # which is the whole reason startup warnings are collected now.
    wrong = open_with(_portable_gdb())
    assert wrong["state"] == "failed"
    assert "registers" in (wrong["error"] or "")
    assert "general-purpose registers" in (wrong["error"] or ""), wrong["error"]
    assert "architecture's gdb" in (wrong["error"] or ""), "and the answer says what to do about it"

    # The right gdb: threads, a stack, a memory map from the core's own NT_FILE note — and no symbols, because
    # this dump arrived without its binary.
    right = open_with(X86_64_GDB)
    assert right["state"] == "ready", right.get("error")
    assert right["exe"] is None
    summary = right["summary"]
    assert len(summary["threads"]) == 1, "the fixture core has one thread"
    named = [region for region in summary["memory_map"]["regions"] if region.get("path")]
    assert named, "the core's NT_FILE note names the objects it mapped"
    assert any("coredump_self" in (region.get("path") or "") for region in named), named[:3]
    crashed = next(t["num"] for t in summary["threads"] if t["is_crashed"])
    frames = summary["detail"][str(crashed)]["frames"]
    assert frames, "a core with no binary still has frames"
    assert frames[0]["pc"].startswith("0x"), "and the crash pc is a real address"
