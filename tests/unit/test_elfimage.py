"""ELF images in a dump, and the build-id they carry — a record, not a resemblance.

`analysis/elfimage.py` is the half of identification that does not guess: a mapping whose first bytes are
`\\x7fELF` is an ELF image, and the image says which class, which machine, which kind of object, and — in
`.note.gnu.build-id` — *which build*, in twenty bytes. Everything here runs on synthesized images, so the
arithmetic is pinned without a core: the note's header, the search for it, the bounds on what a dump is allowed
to claim, and which of two layouts a build-id is looked up in.

The measured fact this module rests on is asserted against the real bundle in `tests/gdb/test_libraries.py`'s
neighbour `tests/api/test_identify.py`: the practice core's libc mapping carries
`27027b96e5b8c475fc327aa445bea1c71d37b4e2`, byte for byte the build-id of the libc.so.6 in the sysroot that core
was built against.
"""

from __future__ import annotations

import pathlib

from analysis import elfimage

BUILD_ID_A = "1424e4bd44113cdab5b83ceb70cd6c65a8c1d1e1"
BUILD_ID_B = "27027b96e5b8c475fc327aa445bea1c71d37b4e2"


def core_with(tmp_path: pathlib.Path, content: bytes, *, size: int | None = None) -> tuple[pathlib.Path, dict]:
    """A file standing in for the dump, plus the `region` dict describing its first mapping."""
    core = tmp_path / "pretend.core"
    core.write_bytes(content)
    region = {
        "start": "0x400000",
        "end": hex(0x400000 + (size or len(content))),
        "size": size or len(content),
        "dumped": len(content),
        "perms": "r-xp",
        "offset": 0,
        "kind": "anon",
        "image": None,
    }
    return core, region


# --- the image -------------------------------------------------------------------------- #
def test_an_elf_header_says_what_the_image_is(elf_image) -> None:
    image = elfimage.image_of(elf_image())
    assert image is not None
    assert image["class"] == "ELF64"
    assert image["byte_order"] == "little"
    assert image["type"] == "ET_DYN"
    assert image["machine"] == "aarch64", "the name `analysis/elf.py` uses, not the ELF one"
    assert image["build_id"] == BUILD_ID_A


def test_bytes_that_are_not_an_image_are_not_one(elf_image) -> None:
    assert elfimage.image_of(b"") is None
    assert elfimage.image_of(b"\x7fELF") is None, "an image has a header, not just a magic number"
    assert elfimage.image_of(b"\x7fELF" + b"\x00" * 100) is None, "class 0 and order 0 are not a header"
    assert elfimage.image_of(b"not an elf at all" * 10) is None


def test_anything_that_is_not_the_kernel_or_a_library_is_still_reported_as_it_is(elf_image) -> None:
    """An i386 `ET_EXEC` is not this viewer's business, but the mapping should not be called `ELF64 aarch64`."""
    image = elfimage.image_of(elf_image(None, machine=3, e_type=2))
    assert image is not None
    assert (image["class"], image["machine"], image["type"]) == ("ELF64", "i386", "ET_EXEC")
    assert image["build_id"] is None, "no note in these bytes, and none invented"


def test_an_image_without_a_note_is_still_an_image(elf_image) -> None:
    image = elfimage.image_of(elf_image(None))
    assert image is not None and image["format"] == "ELF"
    assert image["build_id"] is None and image["build_id_at"] is None


def test_a_note_is_found_wherever_it_sits_in_the_probe(elf_image) -> None:
    """The search is over the mapping's own bytes, the way LLDB reads a core: a range has no structure to trust."""
    shifted = b"\xaa" * 777 + elf_image(BUILD_ID_B)
    found = elfimage.build_id_in(shifted)
    assert found is not None
    assert found[1] == BUILD_ID_B
    assert shifted[found[0] : found[0] + 16][:4] == len(b"GNU\x00").to_bytes(4, "little"), "the note's own header"


def test_a_coincidence_of_eight_bytes_is_not_a_note(elf_image) -> None:
    """Without the header check, eight bytes of code would be read as an identifier."""
    coincidence = b"\x00" * 64 + (3).to_bytes(4, "little") + b"GNU\x00" + b"\x99" * 40
    namesz = int.from_bytes(coincidence[56:60], "little")
    assert namesz != 4, "the bytes before the pattern are not a name length"
    assert elfimage.build_id_in(coincidence) is None

    # And a header that claims an identifier longer than any build-id is refused rather than sliced out.
    absurd = b"\x04\x00\x00\x00" + (4096).to_bytes(4, "little") + (3).to_bytes(4, "little") + b"GNU\x00" + b"\x11" * 64
    assert elfimage.build_id_in(absurd) is None


# --- the file's own id ------------------------------------------------------------------ #
def test_a_file_is_parsed_rather_than_searched(elf_image, tmp_path: pathlib.Path) -> None:
    """A file states where its notes are; a memory range cannot, which is why the two paths differ."""
    path = tmp_path / "libx.so"
    path.write_bytes(elf_image(BUILD_ID_B))
    assert elfimage.build_id_of_file(path) == BUILD_ID_B
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"not an elf")
    assert elfimage.build_id_of_file(plain) is None
    assert elfimage.build_id_of_file(tmp_path / "missing") is None


# --- annotating a map ------------------------------------------------------------------- #
def test_only_regions_whose_bytes_are_images_are_marked(elf_image, tmp_path: pathlib.Path) -> None:
    core = tmp_path / "map.core"
    core.write_bytes(elf_image(BUILD_ID_A) + b"\x00" * 2048 + b"heap contents here")
    regions = [
        {"start": "0x1000", "end": "0x1400", "size": 1024, "dumped": 1024, "perms": "r-xp", "offset": 0},
        {"start": "0x2000", "end": "0x2400", "size": 1024, "dumped": 18, "perms": "rw-p", "offset": 2048 + 64},
        {"start": "0x3000", "end": "0x4000", "size": 4096, "dumped": 0, "perms": "---p", "offset": 8192},
    ]
    found = elfimage.annotate(core, regions)
    assert found == 1
    assert regions[0]["image"]["build_id"] == BUILD_ID_A
    assert regions[1]["image"] is None and regions[2]["image"] is None
    assert all("image" in region for region in regions), "every region answers the question, including `no`"


# --- looking a build-id up --------------------------------------------------------------- #
def test_a_debug_tree_is_where_a_build_id_lives(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "debug"
    target = root / BUILD_ID_A[:2] / (BUILD_ID_A[2:] + ".debug")
    target.parent.mkdir(parents=True)
    target.write_bytes(b"debug info")

    answer = elfimage.resolve(BUILD_ID_A, dirs=[str(root)])
    assert answer["found"]["path"] == str(target)
    assert "build-id tree" in answer["found"]["source"]
    assert any(str(root) in path for path in answer["searched"])

    # The same tree without the file: the id is still reported, and where it was looked for.
    missing = elfimage.resolve(BUILD_ID_B, dirs=[str(root)])
    assert missing["found"] is None
    assert BUILD_ID_B in missing["why"], "the id is exact, so the way out names it"
    assert len(missing["searched"]) == 2, "both spellings of the path, with and without `.debug`"


def test_a_debuginfod_cache_is_the_other_layout(tmp_path: pathlib.Path) -> None:
    cache = tmp_path / "cache"
    info = cache / BUILD_ID_B / "debuginfo"
    info.parent.mkdir(parents=True)
    info.write_bytes(b"debug info")

    answer = elfimage.resolve(BUILD_ID_B, caches=[str(cache)])
    assert answer["found"]["path"] == str(info)
    assert "debuginfod cache" in answer["found"]["source"]


def test_a_mapping_with_no_build_id_is_told_so_rather_than_searched_for(elf_image) -> None:
    answer = elfimage.resolve("")
    assert answer["found"] is None and answer["searched"] == []
    assert "no usable build-id" in answer["why"]
    assert elfimage.resolve("not-hex-at-all")["found"] is None
