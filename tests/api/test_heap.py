"""The heap endpoint: what an anonymous writable mapping is, as the allocator wrote it.

A heap is the one thing in a core dump that names itself with no note, no symbol and no file: glibc puts a chunk
header in front of every block it hands out, and a chain of those covering a whole mapping is not something else
produces. These tests read the real practice core and check both halves of that claim — the heap that *is* one,
and the mappings that are not, including the one a program would call its heap.

The fixtures are `tests/api/conftest.py`'s: `live` is a real app on the real aarch64 core with the real cross
gdb, and every one of these skips without them.
"""

from __future__ import annotations

import pathlib

import pytest

HEAP_ADDRESS = "0xc9bc79ad42a0"
"""The heap node the crashed frame's `head` points at — measured from the practice core, and the address the
typed index answers about too, which is why the two can be checked against each other."""

STACK = "stack"


def _heap(client, session: str, address: str) -> dict:
    answer = client.get(f"/api/sessions/{session}/heap", params={"address": address})
    assert answer.status_code == 200, answer.text
    return answer.json()


def test_a_heap_is_read_from_its_own_chunk_headers(live, open_session) -> None:
    """The 132 KB mapping `head` lives in: 17 chunks, every one of them verified, ending in the wilderness."""
    body = open_session(live, sample="crash_target")
    session = body["id"]
    found = _heap(live, session, HEAP_ADDRESS)

    assert found["heap"] is not None, found
    assert found["heap"]["kind"] == "main arena (brk)"
    assert found["summary"]["chunks"] == 17
    assert found["summary"]["coverage"] == 1.0, "the chain explains the whole mapping"
    assert found["summary"]["top"] > 100_000, "the rest of the mapping is the wilderness"
    assert found["summary"]["in_use"] + found["summary"]["top"] == found["summary"]["covered"]

    # The chunk the address is in, and the arithmetic that says so: a `malloc`ed `struct node *` of 48 bytes sits
    # in a 64-byte chunk, because the header is two words wide.
    chunk = found["heap"]["address_chunk"]
    assert chunk is not None and chunk["in_use"] is True
    assert chunk["size"] == 64 and int(chunk["address"], 16) + 16 == int(HEAP_ADDRESS, 16)
    assert "16-byte aligned" in found["reason"] and "100.0%" in found["reason"], found["reason"]


def test_the_dump_reads_the_heap_and_not_the_debugger(live, open_session) -> None:
    """The walk is arithmetic over the dump: no gdb commands at all, and the arena is asked for once."""
    body = open_session(live, sample="crash_target")
    session = body["id"]
    first = live.get(f"/api/sessions/{session}/heap", params={"address": HEAP_ADDRESS})
    # Four at most, and only for the arena — which this dump's stripped libc refuses (`analysis/heap.py`).
    assert int(first.headers["X-Gdb-Commands"]) <= 4, first.headers
    again = live.get(f"/api/sessions/{session}/heap", params={"address": HEAP_ADDRESS})
    assert again.json() == first.json()
    assert int(again.headers["X-Gdb-Commands"]) == 0, "a repeated question costs nothing"


def test_the_arena_is_reported_even_when_gdb_cannot_answer_it(live, open_session) -> None:
    """glibc's `main_arena` is the confirmation, and a stripped libc refusing it is part of the answer."""
    body = open_session(live, sample="crash_target")
    found = _heap(live, body["id"], HEAP_ADDRESS)
    arena = found["arena"]
    assert arena is not None
    if arena["symbol"] is None:
        assert "main_arena" in arena["why"] and "unable to create variable object" in arena["why"], arena
        assert "read from its own chunk headers" in arena["why"], "and the reply says what was used instead"
    else:  # a dump whose libc has symbols: the arena answers, and the reply carries it
        assert arena["top"] or arena["system_mem"]


def test_a_mapping_that_is_not_a_heap_says_where_it_failed(live, open_session) -> None:
    """The stack is 132 KB of anonymous writable memory too, and nothing about it is a chunk chain."""
    body = open_session(live, sample="crash_target")
    summary = body["summary"]
    stack = next(
        window["address"] for window in summary["memory"]["windows"] if window["name"] == "stack"
    )
    found = _heap(live, body["id"], stack)
    assert found["heap"] is None
    assert found["chunks"] == []
    assert "not an allocator's heap" in found["reason"]
    assert found["region"]["kind"] == STACK


def test_a_named_mapping_is_not_a_heap_either(live, open_session) -> None:
    """A file-backed mapping has a `path` and an ELF header; its bytes are not chunks, and the reply says so."""
    body = open_session(live, sample="crash_target")
    region = next(
        item
        for item in body["summary"]["memory_map"]["regions"]
        if item["path"] and item["path"].endswith("libplugin.so")
    )
    found = _heap(live, body["id"], region["start"])
    assert found["heap"] is None and found["reason"]


def test_an_address_outside_every_mapping_is_404(live, open_session) -> None:
    body = open_session(live, sample="crash_target")
    answer = live.get(f"/api/sessions/{body['id']}/heap", params={"address": "0xdead0000dead0000"})
    assert answer.status_code == 404, answer.text
    assert "not in any mapping" in answer.json()["detail"]


def test_the_mapping_a_program_calls_its_heap_may_hold_no_allocator_metadata(tmp_path: pathlib.Path) -> None:
    """A raw `mmap` is not a heap: no headers, nothing to walk, and the refusal says exactly that.

    The heavy sample's 1 GB — the mapping its own comment calls "1 GB of touched, live, never-freed heap" — is
    `mmap`ed directly rather than `malloc`ed. There is no chunk chain in it and there should not be one, which is
    the difference between a viewer that walks an allocator and one that recognises the *word* heap.
    """
    import dataclasses
    import os

    from fastapi.testclient import TestClient

    from config import CONFIG
    from web.app import create_app

    # Resolved here rather than imported from `conftest.py`: these files are `conftest.py` siblings (see that
    # module's docstring), so what two of them both need is written twice or made a fixture, never imported.
    root = pathlib.Path(__file__).resolve().parents[2]
    gdb = pathlib.Path(
        os.environ.get("CDWV_GDB") or root / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
    )
    heavy = root / "tmp" / "heavy"
    cores = sorted(heavy.glob("heavy_target.*.core"))
    if not cores or not gdb.exists():
        pytest.skip("the heavy bundle is not here (see AGENTS.local.md §5)")
    app = create_app(
        dataclasses.replace(
            CONFIG,
            gdb_path=str(gdb),
            sysroot=str(heavy / "sysroot"),
            solib_search_path=str(heavy),
        ),
        root=root,
        state_path=tmp_path,
        bundle=heavy,
    )
    with TestClient(app) as client:
        created = client.post(
            "/api/sessions",
            json={"core": str(cores[-1]), "exe": str(heavy / "heavy_target"), "sysroot": str(heavy / "sysroot"),
                  "solib_search_path": str(heavy)},
        )
        session = created.json()["id"]
        body = client.get(f"/api/sessions/{session}", params={"wait": 120}).json()
        assert body["state"] == "ready", body.get("error")
        regions = body["summary"]["memory_map"]["regions"]
        biggest = max(regions, key=lambda item: int(item["size"]))
        assert int(biggest["size"]) >= 1 << 30, "the sample's gigabyte mapping"

        found = _heap(client, session, biggest["start"])
        assert found["heap"] is None
        assert "not an allocator's heap" in found["reason"], found["reason"]

        # And the same core *does* have a heap, so the refusal above is about that mapping and not about the
        # walk failing to work at all.
        real = next(
            item
            for item in regions
            if item["perms"] == "rw-p" and int(item["size"]) == 132 * 1024 and item["kind"] == "anon"
        )
        heap = _heap(client, session, real["start"])
        assert heap["heap"] is not None and heap["summary"]["chunks"] > 40, heap["summary"]
