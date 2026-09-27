"""Content matching on its own: no core, no gdb — a `core` that is just a file of bytes.

`analysis/matching.py` is the one place in this viewer that answers a question by comparing content instead of
reading a record, so its arithmetic is pinned here rather than only through a live session: what counts as a
needle, when a file offset is derived, when the second offset has to agree, and what happens when a page was
rewritten by the loader.

The "core" in these tests is a plain file and the "region" is a dictionary pointing into it. That is not a
shortcut around the real thing — `probe_from_core` does `open`/`seek`/`read` and nothing else, and the derived
offsets are the whole point, so they can be built exactly here where a real core's addresses would only obscure
them.
"""

from __future__ import annotations

import pathlib

from analysis import matching

FILL = b"\x00" * 64


def blob(seed: int, length: int) -> bytes:
    """Bytes that are neither fill nor repeating: a needle has to be findable once and only once."""
    out = bytearray()
    value = seed
    while len(out) < length:
        value = (value * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((value >> 16) & 0xFF)
    return bytes(out)


def core_file(tmp_path: pathlib.Path, pages: list[bytes]) -> tuple[pathlib.Path, dict]:
    """A file that stands in for the dump, and the `region` dict that describes page 0 of it."""
    path = tmp_path / "pretend.core"
    path.write_bytes(b"".join(pages))
    region = {
        "start": "0x1000",
        "end": hex(0x1000 + sum(len(page) for page in pages)),
        "size": sum(len(page) for page in pages),
        "dumped": sum(len(page) for page in pages),
        "perms": "r-xp",
        "offset": 0,
        "kind": "anon",
    }
    return path, region


# --- what to search for ----------------------------------------------------------------- #
def test_fill_bytes_are_trimmed_off_both_ends_but_not_out_of_the_middle() -> None:
    middle = b"a needle that is long enough to search for and distinctive" + b"!" * 20
    found = matching.needle_in(FILL + middle + FILL)
    assert found is not None
    at, needle = found
    assert at == 64 and needle == middle, "the trim keeps the needle's position, so an offset stays derivable"


def test_a_mapping_of_zeros_has_nothing_to_search_for() -> None:
    assert matching.needle_in(FILL) is None
    assert matching.needle_in(b"\x00\xff" * 40) is None
    # One byte short of the floor is still nothing: a 63-byte needle is a coincidence waiting to happen.
    assert matching.needle_in(FILL[:10] + b"x" * 63) is None
    assert matching.needle_in(FILL[:10] + b"x" * 64) is not None


def test_the_longest_untouched_runs_come_first() -> None:
    """The fallback needles: a loader-rewritten page still holds runs that are the file's own bytes."""
    probe = b"\x00" * 8 + b"a" * 40 + b"\x00" * 8 + b"b" * 90 + b"\x00" * 8
    runs = matching.runs_in(probe)
    assert [len(run) for _, run in runs][:2] == [90, 40]
    assert all(len(run) >= matching.RUN_MIN for _, run in runs)


# --- finding a probe in a file ----------------------------------------------------------- #
def test_an_exact_window_finds_the_file_offset_it_came_from(tmp_path: pathlib.Path) -> None:
    page = blob(1, 4096)
    library = tmp_path / "libfoo.so"
    library.write_bytes(blob(9, 4096) + page + blob(7, 1024))

    hits = matching.locate(page, 0, page, library)
    assert hits and hits[0]["offset"] == 4096
    assert hits[0]["matched"] == hits[0]["compared"] == 4096
    assert hits[0]["ratio"] == 1.0


def test_a_different_build_is_no_hit_rather_than_a_weak_one(tmp_path: pathlib.Path) -> None:
    """Nothing of this probe is in that file, so nothing is reported — not even a best effort."""
    page = blob(1, 4096)
    library = tmp_path / "libbar.so"
    library.write_bytes(blob(2, 8192))
    assert matching.locate(page, 0, page, library) == []


def test_a_rewritten_page_is_reported_with_its_numbers(tmp_path: pathlib.Path) -> None:
    """The near miss: part of the window was rewritten, and the number is what a reader can act on.

    This is the measured shape of a RELRO page — a relocated pointer every eight bytes over part of it — and the
    untouched part is what finds the file, after which the whole window is scored rather than only that run.
    """
    original = blob(3, 4096)
    library = tmp_path / "libbaz.so"
    library.write_bytes(original)
    rewritten = bytearray(original)
    for index in range(0, 2048, 8):  # the first half: relocated pointers
        rewritten[index : index + 8] = blob(index + 1, 8)

    probe = bytes(rewritten)
    needles = matching._needles(probe)
    assert needles and len(needles[0][1]) == len(probe), "the whole window is tried first"
    assert any(len(needle) < len(probe) for _, needle in needles), "and then the runs, when it is not in the file"

    hits = [hit for at, needle in needles for hit in matching.locate(probe, at, needle, library)]
    assert hits, "the runs that were not rewritten still find the file"
    best = max(hits, key=lambda hit: hit["matched"])
    assert best["offset"] == 0
    assert 0.4 < best["ratio"] < 1.0, "half of it agrees, and the reply says how much"


def test_a_file_that_cannot_be_read_contributes_nothing_instead_of_failing(tmp_path: pathlib.Path) -> None:
    page = blob(4, 4096)
    assert matching.locate(page, 0, page, tmp_path / "not-here.so") == []
    empty = tmp_path / "empty.so"
    empty.write_bytes(b"")
    assert matching.locate(page, 0, page, empty) == []


# --- the inference, end to end over two probes -------------------------------------------- #
MOVED_TO = 0x1000
"""Where in the library the mapping's bytes start, so the derived offset is a page boundary and is not zero."""


def test_two_offsets_have_to_agree_before_a_mapping_is_called_identified(tmp_path: pathlib.Path) -> None:
    library = tmp_path / "libreal.so"
    body = blob(11, 0x5000)
    library.write_bytes(body)
    # The dump holds a contiguous slice of the file — which is what a mapping of it is — and nothing tells the
    # matcher where that slice starts: 0x1000 here, and it has to derive that from the content alone.
    core, region = core_file(tmp_path, [body[MOVED_TO : MOVED_TO + 3 * 4096]])

    answer = matching.identify(core, region, [{"path": str(library), "source": "exe"}])
    assert answer["inference"], answer
    assert answer["inference"]["file"] == str(library)
    assert answer["inference"]["offset"] == MOVED_TO
    assert answer["inference"]["verified"] is True
    assert answer["inference"]["verified_matched"] == answer["inference"]["verified_compared"] == 8192
    assert answer["tried"][0]["page_aligned"] is True
    assert len(answer["probes"]) == 2, "two windows of one mapping, which is what makes the claim checkable"


def test_the_second_probe_landing_somewhere_else_is_not_an_identification(tmp_path: pathlib.Path) -> None:
    """One window can coincide; two cannot. A file that matches the first window and not the second is not it."""
    library = tmp_path / "libhalf.so"
    body = blob(12, 0x5000)
    library.write_bytes(body)
    # The mapping holds the file's bytes at 0x1000, and something else entirely further on: a page the loader
    # rewrote, or a file that is only partly this library.
    core, region = core_file(
        tmp_path, [body[MOVED_TO : MOVED_TO + 4096], blob(77, 4096), body[MOVED_TO + 8192 : MOVED_TO + 12288]]
    )

    answer = matching.identify(core, region, [{"path": str(library), "source": "exe"}])
    assert answer["inference"] is None, answer
    assert answer["tried"][0]["verified"] is False
    assert answer["tried"][0]["second"]["ratio"] < matching.MATCH_FLOOR


def test_a_mapping_that_starts_mid_page_is_not_matched_by_a_file(tmp_path: pathlib.Path) -> None:
    """A mapping starts on a page boundary: an offset that says otherwise is a coincidence of bytes.

    The bytes here *are* in the file, one byte in — so the content check passes and the layout check is what
    refuses. This is the guard that keeps a plausible-looking wrong answer out of the reply.
    """
    library = tmp_path / "libshift.so"
    body = blob(13, 0x5000)
    library.write_bytes(b"\x00" + body)  # everything one byte later than a mapping could ever be
    core, region = core_file(tmp_path, [body[MOVED_TO : MOVED_TO + 3 * 4096]])

    answer = matching.identify(core, region, [{"path": str(library), "source": "exe"}])
    assert answer["tried"][0]["page_aligned"] is False
    assert answer["inference"] is None
    assert "page boundary" in answer["reason"], answer["reason"]


def test_a_mapping_of_zeros_is_refused_before_anything_is_compared(tmp_path: pathlib.Path) -> None:
    library = tmp_path / "libzeros.so"
    library.write_bytes(blob(14, 8192))
    core, region = core_file(tmp_path, [FILL * 64])

    answer = matching.identify(core, region, [{"path": str(library), "source": "exe"}])
    assert answer["inference"] is None
    assert "zeros" in answer["reason"]
    assert answer["tried"] == [], "nothing was compared, so nothing was tried"


def test_a_mapping_the_dump_does_not_hold_says_so(tmp_path: pathlib.Path) -> None:
    core, region = core_file(tmp_path, [b""])
    region["dumped"] = 0
    answer = matching.identify(core, region, [])
    assert answer["reason"] == "the dump holds no bytes for this mapping, so there is nothing to match"


def test_a_session_with_nothing_to_compare_against_is_told_what_to_name(tmp_path: pathlib.Path) -> None:
    core, region = core_file(tmp_path, [blob(15, 4096)])
    answer = matching.identify(core, region, [])
    assert answer["inference"] is None
    assert "exe" in answer["reason"] and "sysroot" in answer["reason"]


# --- which files are candidates ----------------------------------------------------------- #
def test_the_dump_itself_is_never_a_candidate(tmp_path: pathlib.Path) -> None:
    """A core holds the region's bytes, so it matches them perfectly — a true and useless answer."""
    cores = tmp_path / "a.core"
    cores.write_bytes(b"\x7fELF" + b"\x00" * 12 + (4).to_bytes(2, "little") + b"rest of a core")
    program = tmp_path / "program"
    program.write_bytes(b"\x7fELF" + b"\x00" * 12 + (2).to_bytes(2, "little"))

    found = matching.candidate_files(solib_search_path=str(tmp_path), exclude=[str(program)])
    paths = [entry["path"] for entry in found]
    assert str(cores.resolve()) not in paths, "a core is not a file a mapping came from"
    assert str(program.resolve()) not in paths, "and neither is a path the caller excluded"
    assert matching.candidate_files(solib_search_path=str(tmp_path)) == [] or all(
        pathlib.Path(entry["path"]).suffix != ".core" for entry in matching.candidate_files(solib_search_path=str(tmp_path))
    )


def test_candidates_are_deduplicated_resolved_and_bounded(tmp_path: pathlib.Path) -> None:
    libraries = [{"name": "/lib/libc.so.6", "host_name": str(tmp_path / "libc.so.6")}]
    (tmp_path / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 12 + (3).to_bytes(2, "little"))
    (tmp_path / "exe").write_bytes(b"\x7fELF" + b"\x00" * 12 + (2).to_bytes(2, "little"))

    found = matching.candidate_files(
        exe=str(tmp_path / "exe"),
        libraries=libraries,
        sysroot=str(tmp_path),
        solib_search_path=str(tmp_path),
        limit=2,
    )
    assert len(found) == 2, "the list is bounded, and both a sysroot and a search path resolve to one file"
    assert found[0]["source"] == "exe"
    assert all(pathlib.Path(entry["path"]).is_absolute() for entry in found)
    assert len({entry["path"] for entry in found}) == len(found)
