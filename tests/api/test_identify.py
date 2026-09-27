"""Identifying an anonymous mapping by its bytes — the one naming path that is an inference.

Two sources can name a region and neither is a guess: the core's `NT_FILE` note (the kernel's record, written
into the dump) and gdb's library list (a reconstruction from the link map). `docs/api.md` §3.1a is about the core
where both come up empty, and `GET …/identify` is what is left: compare the bytes the dump holds against the
files this session was given, and report **which file, at which offset, with how many bytes agreeing** — as an
inference that never becomes a region name.

The core is the practice bundle's `crash_target` with its `NT_FILE` type word patched out, so nothing is named
for free and the answer can only come from the content. It skips unless the bundle and a cross gdb are present,
like every other test that reads a core this repository does not keep in history.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib

import pytest
from fastapi.testclient import TestClient

from config import CONFIG
from web.app import create_app

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tmp" / "practice"
GDB = pathlib.Path(
    os.environ.get("CDWV_GDB") or ROOT / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
)
"""Resolved the way every other suite resolves it (`tests/api/conftest.py` says why): `CDWV_GDB` first, then the
Arm-style name under the download location. Written out here rather than imported from a sibling test module,
because these files are `conftest.py` siblings and importing one from another is the thing that docstring warns
against."""

NT_FILE = (0x46494C45).to_bytes(4, "little")
"""`"FILE"`. Patching that one word is how this shape is built out of the real core, addresses and all — the
offsets the matcher derives are only meaningful against the layout a real dump has."""


@pytest.fixture(scope="module")
def unnamed(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    cores = sorted(BUNDLE.glob("crash_target.*.core"))
    if not cores or not GDB.exists():
        pytest.skip("practice bundle or cross gdb not present")
    raw = cores[-1].read_bytes()
    assert raw.count(NT_FILE) == 1, "the fixture core carries exactly one NT_FILE note"
    out = tmp_path_factory.mktemp("identify") / "crash_target.no-nt-file.core"
    out.write_bytes(raw.replace(NT_FILE, (0xDEADBEEF).to_bytes(4, "little")))
    return out


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory, unnamed: pathlib.Path):
    """A live app on that core, with the bundle named as its sysroot and search path — as a user would."""
    app = create_app(
        dataclasses.replace(
            CONFIG,
            gdb_path=str(GDB),
            sysroot=str(BUNDLE / "sysroot"),
            solib_search_path=str(BUNDLE),
        ),
        root=ROOT,
        state_path=tmp_path_factory.mktemp("identify-state"),
        bundle=BUNDLE,
    )
    with TestClient(app) as test_client:
        created = test_client.post(
            "/api/sessions",
            json={
                "core": str(unnamed),
                "exe": str(BUNDLE / "crash_target"),
                "sysroot": str(BUNDLE / "sysroot"),
                "solib_search_path": str(BUNDLE),
            },
        )
        assert created.status_code == 201, created.text
        session = created.json()["id"]
        loaded = test_client.get(f"/api/sessions/{session}", params={"wait": 60}).json()
        assert loaded["state"] == "ready", loaded.get("error")
        yield test_client, session, loaded["summary"]


def test_a_mapping_is_identified_from_its_bytes(client) -> None:
    """The executable's own first page: the dump names no file for it, and the bytes say which file it is.

    This is the case the whole feature exists for, and the numbers are checkable: the mapping holds the file's
    first page (`offset 0x0`), and a page the loader never rewrote agrees byte for byte.
    """
    test_client, session, summary = client
    regions = summary["memory_map"]["regions"]
    assert regions and not any(region["source"] == "nt_file" for region in regions), (
        "the shape under test is a core whose own note names no mapping"
    )
    # The executable's first mapping, which is where a reader would start: the text of the program that crashed.
    # gdb names some of this dump's regions from the link map (§3.1a); this one it does not, because the file it
    # would place it from is the executable, which the core's link map does not list.
    program = next(region for region in regions if region["perms"] == "r-xp" and not region["path"])

    found = test_client.get(
        f"/api/sessions/{session}/identify", params={"address": program["start"]}
    ).json()
    assert found["inference"], found
    inference = found["inference"]
    assert inference["file"].endswith("/crash_target")
    assert inference["offset"] == 0, "the mapping holds the file's first page"
    assert inference["matched"] == inference["compared"] > 0
    assert inference["ratio"] == 1.0
    # The file is *not* written into the map: it is an inference, and the map goes on saying `anon`.
    assert found["region"]["start"] == program["start"] and "path" not in found["region"]
    # Two honest sentences, and which one arrives depends on the mapping's size: a two-page mapping has no
    # second offset to check against, so it is reported as a single-window match rather than as verified.
    assert "inferred from content" in (found["reason"] or "") or "single-window" in (found["reason"] or ""), (
        found["reason"]
    )


def test_the_answer_carries_what_it_compared_and_what_came_close(client) -> None:
    """A near miss is the useful half of "no match": a page the loader rewrote agrees only partly."""
    test_client, session, summary = client
    regions = summary["memory_map"]["regions"]
    # libc's mappings are anonymous here, and libc *is* one of the files this session was given: gdb found it
    # through the bundle's sysroot. Its RELRO page and its `.data` page are rewritten after loading, so they
    # cannot agree with the file in full — and the reply says so with numbers rather than with silence.
    libc_data = next(
        region
        for region in regions
        if region["path"] is None and region["perms"] == "rw-p" and int(region["size"]) == 8192
    )
    found = test_client.get(
        f"/api/sessions/{session}/identify", params={"address": libc_data["start"]}
    ).json()
    assert found["tried"], found
    assert found["candidates"], "the answer names what it compared against"
    assert any(entry["path"].endswith("libc.so.6") for entry in found["candidates"]), found["candidates"]
    best = max(found["tried"], key=lambda entry: entry["matched"])
    assert best["path"].endswith("libc.so.6"), best
    assert 0 < best["ratio"] < 1, f"a rewritten page agrees partly, not fully: {best}"
    if found["inference"] is None:
        assert str(best["matched"]) in (found["reason"] or ""), found["reason"]


def test_a_mapping_in_no_file_says_that_instead_of_guessing(client) -> None:
    """The heap is in no file, and a viewer that matched it to one would be inventing an answer."""
    test_client, session, summary = client
    heap = next(window for window in summary["memory"]["windows"] if window["name"] == "heap")
    found = test_client.get(
        f"/api/sessions/{session}/identify", params={"address": heap["address"]}
    ).json()
    assert found["inference"] is None
    assert found["reason"], "a refusal with a sentence"
    assert found["tried"], "and the list of what it was refused against"
    assert all(entry["matched"] < entry.get("compared", 1) for entry in found["tried"] if entry["compared"]), (
        found["tried"]
    )


def test_a_mapping_of_zeros_is_not_pretended_to_be_recognisable(client) -> None:
    """The other kind of nothing: bytes are there, but they are fill.

    An unused stack is the ordinary case — the mapping is 132 KB and everything below the live frames is zeros.
    Reporting "no file matched" there would invite a reader to conclude the dump is not from their build, when
    the truth is that these pages carry nothing to compare.
    """
    test_client, session, summary = client
    stack = next(region for region in summary["memory_map"]["regions"] if region["kind"] == "stack")
    found = test_client.get(
        f"/api/sessions/{session}/identify", params={"address": stack["start"]}
    ).json()
    assert found["inference"] is None
    assert "zeros" in (found["reason"] or ""), found["reason"]
    assert found["tried"] == [], "nothing was compared, and the reply does not pretend otherwise"


def test_an_address_outside_every_mapping_is_404_and_names_the_map(client) -> None:
    test_client, session, _ = client
    answer = test_client.get(
        f"/api/sessions/{session}/identify", params={"address": "0xdead0000dead0000"}
    )
    assert answer.status_code == 404, answer.text
    assert "not in any mapping" in answer.json()["detail"]
    assert "0x" in answer.json()["detail"], "the refusal says what the map does cover"


def test_identifying_costs_no_gdb_commands_and_is_cached(client) -> None:
    """It reads files, not the debugger — and the second question about the same address reads nothing."""
    test_client, session, summary = client
    region = next(region for region in summary["memory_map"]["regions"] if region["perms"] == "rw-p")
    first = test_client.get(f"/api/sessions/{session}/identify", params={"address": region["start"]})
    assert first.headers["X-Gdb-Commands"] == "0", first.headers
    again = test_client.get(f"/api/sessions/{session}/identify", params={"address": region["start"]})
    assert again.json() == first.json()
    assert again.headers["X-Gdb-Cached"] == "true", "the answer is remembered, not recomputed"
