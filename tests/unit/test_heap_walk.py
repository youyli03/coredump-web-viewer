"""The heap walk's invariants, on synthesized chunks — no core, no gdb.


`analysis/heap.py` reads a mapping the way an allocator wrote it: a two-word header in front of every block, a
size that carries three flag bits, and a next header at `chunk + size`. Everything here pins one of those rules
against a chain built by hand, because each of them was a way to get the answer wrong:

* the flags are part of the size word, so a first version that checked 16-byte alignment on the raw word refused
  the practice core's very first real chunk (`0x291` is a 656-byte chunk with `PREV_INUSE` set);
* a chunk's own status is in its **successor's** header, not its own;
* the last chunk of a chain that reaches the end of the mapping is the wilderness, and one that runs into a scan
  limit is not;
* a free chunk's size has to appear in its successor's `prev_size`, which is what separates a chain of chunks
  from a page of numbers that happen to look like sizes.
"""

from __future__ import annotations

import pathlib

from analysis import heap

SIZE_SZ = 8
HEADER = 2 * SIZE_SZ
ALIGN = 2 * SIZE_SZ
PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA = 1, 2, 4


def glibc_heap(sizes: list[int], *, free: tuple[int, ...] = (), top: int | None = None) -> bytes:
    """A heap laid out the way glibc lays one out, so the walk has something real to read.

    The flag semantics are the whole reason this helper exists: `PREV_INUSE` in a chunk's size word describes the
    chunk **before** it, and a free chunk writes its size into its successor's `prev_size`. A builder that set
    the bit according to a chunk's own status produces chains glibc would never write, and the first version of
    these tests did exactly that — every chain stopped one chunk short of its wilderness and the walk was blamed.
    """
    out = bytearray()
    previous_in_use = True  # glibc sets the first chunk's bit as though the chunk before it were in use
    previous_size = 0
    for index, size in enumerate(sizes):
        flags = PREV_INUSE if previous_in_use else 0
        out += previous_size.to_bytes(SIZE_SZ, "little")
        out += (size | flags).to_bytes(SIZE_SZ, "little")
        out += b"\xaa" * (size - HEADER)
        previous_in_use = index not in free
        previous_size = size if index in free else 0
    if top is not None:
        flags = PREV_INUSE if previous_in_use else 0
        out += previous_size.to_bytes(SIZE_SZ, "little")
        out += (top | flags).to_bytes(SIZE_SZ, "little")
        out += b"\xaa" * (top - HEADER)
    return bytes(out)


def chunk(size: int, *, mmapped: bool = False, arena: bool = False, prev_size: int = 0) -> bytes:
    """One in-use chunk on its own: for the tests that only need a header with flags in it."""
    flags = PREV_INUSE | (IS_MMAPPED if mmapped else 0) | (NON_MAIN_ARENA if arena else 0)
    header = prev_size.to_bytes(SIZE_SZ, "little") + (size | flags).to_bytes(SIZE_SZ, "little")
    return header + b"\xaa" * (size - HEADER)


def region_for(tmp_path: pathlib.Path, content: bytes, *, size: int | None = None) -> tuple[pathlib.Path, dict]:
    core = tmp_path / "heap.core"
    core.write_bytes(content)
    return core, {
        "start": "0x10000",
        "end": hex(0x10000 + (size or len(content))),
        "size": size or len(content),
        "dumped": len(content),
        "perms": "rw-p",
        "offset": 0,
        "kind": "anon",
    }


# --- the size word ------------------------------------------------------------------------ #
def test_the_three_low_bits_are_flags_and_not_part_of_the_size() -> None:
    """The practice core's first real chunk: `0x291` is a 656-byte chunk with `PREV_INUSE` set."""
    assert heap.chunk_size(0x291, size_sz=8) == 0x290
    assert heap.chunk_size(0x291 | IS_MMAPPED, size_sz=8) == 0x290
    assert heap.chunk_size(0x20, size_sz=8) == 0x20


def test_a_chain_of_chunks_walks_and_ends_in_the_wilderness() -> None:
    body = glibc_heap([0x40, 0x30, 0x30], top=0x100)
    result = heap.walk(body, 0x10000, size_sz=8)
    assert [entry["size"] for entry in result["chunks"]] == [0x40, 0x30, 0x30, 0x100]
    assert result["coverage"] == 1.0
    assert result["problem"] is None
    assert result["top"]["size"] == 0x100, "the last chunk runs to the end of the mapping"
    assert result["in_use"] == 0x40 + 0x30 + 0x30
    assert result["free"] == 0, "the wilderness is not a free chunk: it is not in a bin"


def test_a_chunks_status_is_read_from_its_successor() -> None:
    """`PREV_INUSE` in a chunk's own size describes the chunk *before* it, so the walk looks forward."""
    # The third chunk's size says "the chunk before me is free"; the wilderness then says the third is in use.
    body = glibc_heap([0x40, 0x40, 0x40, 0x100], free=(2,))
    result = heap.walk(body, 0, size_sz=8)
    assert [entry["in_use"] for entry in result["chunks"]] == [True, True, False, False], (
        "the wilderness is neither allocated nor free-listed"
    )


def test_a_free_chunk_leaves_its_size_in_the_next_header() -> None:
    """A real heap passes: the free chunk wrote 0x40 into its successor's `prev_size`."""
    result = heap.walk(glibc_heap([0x40, 0x40, 0x200], free=(0,)), 0, size_sz=8)
    assert result["problem"] is None
    assert [entry["size"] for entry in result["chunks"]] == [0x40, 0x40, 0x200]
    assert result["free"] == 0x40, "and the free chunk is tallied as free, not as in use"


def test_a_free_chunk_whose_successor_disagrees_stops_the_walk_where_it_broke() -> None:
    """The invariant that separates chunks from numbers that look like sizes."""
    body = bytearray(glibc_heap([0x40, 0x40, 0x200], free=(0,)))
    body[0x40 : 0x48] = (0x30).to_bytes(8, "little")  # the successor's prev_size no longer agrees
    result = heap.walk(bytes(body), 0, size_sz=8)
    assert result["problem"] is not None
    assert result["problem"]["address"] == "0x0", "the chunk whose successor disagrees is named"
    assert "prev_size" in result["problem"]["why"]
    assert len(result["chunks"]) == 1, "what was verified before the break is kept"


def test_a_size_that_is_not_a_chunk_size_stops_the_walk() -> None:
    body = b"\x00" * 8 + (0x41).to_bytes(8, "little") + b"\xaa" * 0x30
    body += b"\x00" * 8 + (0x11).to_bytes(8, "little")  # 0x11 masks to 0x10: below MINSIZE on a 64-bit target
    result = heap.walk(body, 0x1234, size_sz=8)
    assert result["problem"]["address"] == hex(0x1234 + 0x40)
    assert "below 32 bytes" in result["problem"]["why"]

    misaligned = b"\x00" * 8 + (0x41).to_bytes(8, "little") + b"\xaa" * 0x30
    misaligned += b"\x00" * 8 + (0x48).to_bytes(8, "little")  # 0x48 is not 16-aligned
    assert "not aligned" in heap.walk(misaligned, 0, size_sz=8)["problem"]["why"]


def test_a_32_bit_target_has_its_own_header_size() -> None:
    word = (4).to_bytes(4, "little")
    body = word + (0x21).to_bytes(4, "little") + b"\xaa" * 0x1C  # a 32-byte chunk on a 32-bit target
    result = heap.walk(body, 0, size_sz=4, whole=False)
    assert result["chunks"] and result["chunks"][0]["size"] == 0x20
    assert heap.walk(body, 0, size_sz=8, whole=False)["chunks"] == [], (
        "the same bytes are not a chunk header on a 64-bit target: 0x21 masks to 0x20, below its MINSIZE of 32"
    )


def test_the_end_of_a_scan_is_not_the_wilderness() -> None:
    """A 4 MB slice of a gigabyte heap: the last header is where reading stopped, not the top chunk."""
    body = glibc_heap([0x40, 0x40, 0x40, 0x40])
    cut = heap.walk(body, 0, size_sz=8, whole=False)
    assert cut["top"] is None and cut["chunks"][-1]["truncated"] is True
    whole = heap.walk(body, 0, size_sz=8, whole=True)
    assert whole["top"] is not None and whole["chunks"][-1]["top"] is True


# --- the mapping, not the chain ------------------------------------------------------------- #
def test_a_mapping_that_is_not_a_heap_says_where_it_failed(tmp_path: pathlib.Path) -> None:
    core, region = region_for(tmp_path, b"\x00" * 4096)
    answer = heap.describe(core, region, 0x10000, size_sz=8)
    assert answer["heap"] is None
    assert "0x10000" in answer["reason"] and "not an allocator's heap" in answer["reason"]


def test_a_heap_is_answered_with_the_chunk_at_the_address(tmp_path: pathlib.Path) -> None:
    body = glibc_heap([0x40, 0x40, 0x40, 0x40], top=0x400)
    core, region = region_for(tmp_path, body)
    answer = heap.describe(core, region, 0x10000 + 0x80, size_sz=8)
    assert answer["heap"]["kind"] == "main arena (brk)"
    assert answer["summary"]["chunks"] == 5
    assert answer["summary"]["coverage"] == 1.0
    assert answer["heap"]["address_chunk"]["address"] == hex(0x10000 + 0x80), "the chunk starting there"
    assert answer["heap"]["top"]["size"] == 0x400
    assert "1.00" not in answer["reason"] and "100.0%" in answer["reason"], answer["reason"]


def test_a_chain_too_short_to_mean_anything_is_refused(tmp_path: pathlib.Path) -> None:
    core, region = region_for(tmp_path, glibc_heap([0x40]) + b"\x00" * 8 + b"\x07" * 8 + b"\x00" * 100)
    answer = heap.describe(core, region, 0x10000, size_sz=8)
    assert answer["heap"] is None
    assert "too few" in answer["reason"], answer["reason"]


def test_a_mapping_with_no_bytes_is_refused_before_anything_is_read(tmp_path: pathlib.Path) -> None:
    core, region = region_for(tmp_path, b"", size=4096)
    region["dumped"] = 0
    answer = heap.describe(core, region, 0x10000, size_sz=8)
    assert answer["heap"] is None and "no bytes" in answer["reason"]


def test_one_mmaped_chunk_is_the_whole_mapping(tmp_path: pathlib.Path) -> None:
    """A large `malloc` takes a mapping of its own, header and all: one chunk, no chain, no wilderness."""
    body = chunk(0x1000, mmapped=True)
    core, region = region_for(tmp_path, body)
    answer = heap.describe(core, region, 0x10000, size_sz=8)
    assert answer["heap"]["kind"] == "mmapped-chunk"
    assert answer["summary"]["mmapped"] == 1
    assert "IS_MMAPPED" in answer["reason"]


def test_a_thread_arena_starts_after_its_heap_info(tmp_path: pathlib.Path) -> None:
    """A non-main arena is an `mmap`ed heap whose first bytes are the arena pointer, the previous heap, a size."""
    ar_ptr = 0x20000 + 0x40  # an absolute address, pointing into this very mapping
    info = ar_ptr.to_bytes(8, "little") + (0).to_bytes(8, "little") + (0x2000).to_bytes(8, "little")
    body = info + b"\x00" * (0x40 - len(info)) + glibc_heap([0x40, 0x40, 0x40, 0x40], top=0x1000)
    core, region = region_for(tmp_path, body)
    # The words inside a `heap_info` are addresses, so the mapping has to be where the test says it is.
    region["start"], region["end"] = hex(0x20000), hex(0x20000 + len(body))
    answer = heap.describe(core, region, 0x20000 + 0x40, size_sz=8)
    assert answer["heap"]["kind"] == "thread arena (heap_info)"
    assert answer["heap"]["first_chunk_at"] == hex(0x20000 + 0x40)


def test_a_long_scan_stops_at_its_limit_and_says_so(tmp_path: pathlib.Path) -> None:
    """A gigabyte heap must not be read whole for a question about one address."""
    body = glibc_heap([0x40] * 200, top=0x400)
    core, region = region_for(tmp_path, body, size=len(body) * 4)
    answer = heap.describe(core, region, 0x10000, size_sz=8, scan=0x800)
    assert answer["summary"]["scan_truncated"] is True
    assert answer["summary"]["top"] == 0, "the top chunk was never reached, so none is claimed"
    assert answer["heap"] is not None, "0x800 bytes of consistent headers is already a heap"


# --- is the arena a confirmation at all? ---------------------------------------------------- #
def test_an_arena_from_a_different_build_is_not_a_confirmation(tmp_path: pathlib.Path, elf_image) -> None:
    """gdb will use a library it calls the wrong version — so an arena from it must not be called agreement.

    Measured: handed a core whose libc is build X and a file that is build Y, gdb has loaded the file anyway
    (`wrong library or version mismatch?` is a warning, not a stop) and read values out of it. Those values are
    plausible numbers from the wrong library, which is exactly the answer this project refuses to give.
    """
    dump_libc = elf_image("27027b96e5b8c475fc327aa445bea1c71d37b4e2")  # what the core ran
    other = tmp_path / "libc.so.6"
    other.write_bytes(elf_image("1ca237614d3f804b9f671da20aa60b621c519a20"))  # glibc 2.28 from a toolchain

    regions = [
        {"start": "0xf5000000", "end": "0xf5100000", "image": {"build_id": "27027b96e5b8c475fc327aa445bea1c71d37b4e2"}},
    ]
    libraries = [
        {"name": "/lib/aarch64-linux-gnu/libc.so.6", "host_name": str(other),
         "ranges": [{"start": "0xf5001000", "end": "0xf5002000"}]},
    ]
    check = heap.arena_check(libraries, regions)
    assert check["agrees"] is False
    assert "wrong file" in check["why"] and "1ca23761" in check["why"] and "27027b96" in check["why"]

    # The same file the dump ran: agreement, and the reason names the id both sides hold.
    matching_file = tmp_path / "libc-real.so.6"
    matching_file.write_bytes(dump_libc)
    agreeing = heap.arena_check([{**libraries[0], "host_name": str(matching_file)}], regions)
    assert agreeing["agrees"] is True and "27027b96" in agreeing["why"]


def test_an_arena_with_nothing_to_check_against_says_so() -> None:
    """No host file, no range, no build-id in the mapping: three ways of not knowing, each named."""
    no_host = heap.arena_check([{"name": "/lib/libc.so.6", "host_name": None, "ranges": [{"start": "0x1000", "end": "0x2000"}]}], [])
    assert no_host["agrees"] is None and "found no file" in no_host["why"]
    no_range = heap.arena_check([{"name": "/lib/libc.so.6", "host_name": "/x", "ranges": []}], [])
    assert no_range["agrees"] is None and "placed no range" in no_range["why"]
    assert heap.arena_check([], [])["agrees"] is None


def test_the_reported_chunks_are_a_window_around_the_address_and_always_include_the_top(
    tmp_path: pathlib.Path,
) -> None:
    body = glibc_heap([0x40] * 40, top=0x800)
    core, region = region_for(tmp_path, body)
    answer = heap.describe(core, region, 0x10000 + 0x40 * 20, size_sz=8, report=8)
    reported = [entry["address"] for entry in answer["chunks"]]
    assert len(reported) <= 10
    assert hex(0x10000 + 0x40 * 20) in reported, "the chunk the reader is looking at is in the window"
    assert answer["heap"]["top"]["address"] in reported, "and the wilderness is always shown"
