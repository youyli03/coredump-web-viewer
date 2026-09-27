"""The allocator's own structures: which mapping is a glibc heap, and what is in it.

An anonymous writable mapping is the least informative thing in a core dump, and it is usually the most
interesting: it is where the program's data lives. Nothing in the dump says a mapping is a heap — `NT_FILE`
names only file-backed ones, and this project's measured reality is that the *build* of libc in a dump often
cannot help either: the practice bundle's libc is stripped, so gdb answers every one of `&main_arena`,
`main_arena.top` and `mp_.sbrk_base` with `-var-create: unable to create variable object` (measured, and
reported as such rather than swallowed). With `libc6-dbg` or an unstripped libc those expressions do answer, and
`arena_facts` uses them; they are a **confirmation**, not the foundation.

The foundation is the heap's own layout, which glibc writes into the memory `malloc` hands out:

* a **chunk** is a two-word header — `prev_size`, `size` — followed by the payload. The three low bits of `size`
  are flags (`PREV_INUSE` 1, `IS_MMAPPED` 2, `NON_MAIN_ARENA` 4) and the rest is the chunk's size, so the size
  word is *not* 16-byte aligned — masking the flags first is what makes the first version of this walk fail on
  the practice core's first real chunk (`size 0x291`, a 656-byte chunk whose `PREV_INUSE` is set);
* the next header is at `chunk + size`;
* a chunk is at least `MINSIZE` (32 bytes on a 64-bit target, 16 on a 32-bit one);
* a **free** chunk's size is written into its successor's `prev_size` — the one invariant that distinguishes a
  chain of real chunks from a page of plausible-looking numbers;
* the last chunk is the **top** chunk, and its size reaches the end of what the arena owns;
* a chunk `malloc`ed with `mmap` (large requests) is the *entire* mapping, one header at its start carrying
  `IS_MMAPPED`;
* a thread's arena begins with a `heap_info` (arena pointer, previous heap, size) before its first chunk.

This is the practice pwndbg's `heap` and gef's traversal follow, minus their arena symbols: they read `main_arena`
and walk from `av->top`; this walks the mapping and checks the invariants. Measured on this checkout's cores, it
is not a heuristic that needs luck: the practice core's 132 KB heap walks **17 chunks over 100% of the mapping**
and the heavy core's 132 KB heap walks **51**, while none of the other ~140 anonymous regions of those two cores
(and none in five other practice cores) produces a chain at all — no false positives to explain away.

What it must not do is pretend. A mapping whose first header is not a chunk size gets `heap: null` with the
offset and the number that failed; a chain that starts and then breaks mid-mapping says so *and keeps the chunks
it verified*, because on a crash dump a heap whose metadata stops being valid part-way through is a finding, not
a parse error.
"""

from __future__ import annotations

import pathlib
from typing import Any


FLAG_PREV_INUSE = 1
"""Set in a chunk's `size` when the chunk *before* it is in use — which is why a chunk's own status is read
from its successor's header, not from its own."""

FLAG_IS_MMAPPED = 2
FLAG_NON_MAIN_ARENA = 4
FLAG_MASK = 7

MIN_CHUNKS = 4
"""A chain shorter than this is not called a heap: two valid-looking headers can be a coincidence."""

MIN_COVERAGE = 0.9
"""Of the mapping's dumped bytes, the share a chain has to explain to be called a heap. Real heaps measure
`1.0` here — the top chunk reaches the end of what the arena owns — so this is a floor, not a tuning knob."""

SCAN_BYTES = 4 << 20
"""How much of a mapping is read to walk it. A 1 GB heap would otherwise be read whole for a question about one
address; four megabytes of consistent headers is already overwhelming evidence, and the reply says it stopped."""

REPORT_CHUNKS = 48
"""Chunks reported around the address asked about, plus the top chunk. A heap of thousands of chunks is a table
nobody reads; the summary carries the numbers that matter."""

ARENA_PREFIXES = (0x40, 0x30, 0x50, 0x20, 0x0)
"""Where a thread arena's first chunk can start, after its `heap_info`. Tried in order and confirmed by walking,
because the struct's padding depends on the target's word size."""


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def chunk_size(size_word: int, *, size_sz: int) -> int:
    """The size of a chunk from its `size` word: the low three bits are flags, the rest is the size."""
    return size_word & ~FLAG_MASK


def _plausible_header(blob: bytes, at: int, *, size_sz: int) -> tuple[int, int] | None:
    """`(size_word, chunk_size)` at this offset, or `None` when it is not a chunk header at all."""
    if at + 2 * size_sz > len(blob):
        return None
    size_word = int.from_bytes(blob[at + size_sz : at + 2 * size_sz], "little")
    size = chunk_size(size_word, size_sz=size_sz)
    if size % (2 * size_sz) or size < 4 * size_sz:
        return None
    return size_word, size


def walk(
    blob: bytes, base: int, *, size_sz: int, limit: int = 200_000, whole: bool = True
) -> dict[str, Any]:
    """Walk `blob` as a chain of glibc chunks starting at its first byte.

    Returns what was verified rather than a verdict: the chunks, how far the walk got, what stopped it, and the
    aggregate. A walk that stops at the first byte and one that stops after 40 chunks are different answers, and
    the caller reports both — the second is a heap whose metadata is damaged part-way through.

    `whole` says whether `blob` is the whole mapping or only the part that was read. It decides one thing: the
    last chunk of a chain that runs off the end is the **top** chunk only when the end is the mapping's end. On a
    4 MB slice of a gigabyte heap the last header is simply where reading stopped, and calling that the
    wilderness would put a wrong number in the summary.
    """
    alignment = 2 * size_sz
    chunks: list[dict[str, Any]] = []
    at = 0
    problem: dict[str, Any] | None = None
    top: dict[str, Any] | None = None

    while at + 2 * size_sz <= len(blob) and len(chunks) < limit:
        header = _plausible_header(blob, at, size_sz=size_sz)
        if header is None:
            size_word = (
                int.from_bytes(blob[at + size_sz : at + 2 * size_sz], "little")
                if at + 2 * size_sz <= len(blob)
                else 0
            )
            problem = {
                "at": at,
                "address": hex(base + at),
                "size_word": hex(size_word),
                "why": (
                    "this is not a chunk size: masked to "
                    f"{hex(chunk_size(size_word, size_sz=size_sz))}, which is below {4 * size_sz} bytes or not "
                    f"aligned to {alignment}"
                ),
            }
            break
        size_word, size = header
        entry = {
            "address": hex(base + at),
            "offset": at,
            "size": size,
            "flags": size_word & FLAG_MASK,
            "mmapped": bool(size_word & FLAG_IS_MMAPPED),
            "non_main_arena": bool(size_word & FLAG_NON_MAIN_ARENA),
        }
        nxt = at + size
        if nxt + 2 * size_sz > len(blob):
            # The chain runs out of the bytes we have: either the top chunk (its size reaches the end of what the
            # arena owns) or the end of what was scanned. The caller decides which by looking at the mapping.
            entry["top"] = bool(whole and nxt >= len(blob))
            entry["truncated"] = not entry["top"]
            entry["ends_at"] = hex(base + nxt)
            chunks.append(entry)
            top = entry if entry["top"] else None
            break
        chunks.append(entry)
        nxt_size_word = int.from_bytes(blob[nxt + size_sz : nxt + 2 * size_sz], "little")
        # A free chunk leaves its size in the successor's `prev_size`, and the successor's PREV_INUSE bit is what
        # says whether the chunk just walked is in use — which is why status is read here and not from `size_word`.
        # The check only means something once the successor *is* a header: a garbage size word is reported as
        # garbage at its own address by the next step, and calling it a `prev_size` disagreement would send the
        # reader looking at the wrong chunk. (Measured: a misaligned size at the second header was reported as
        # its predecessor's problem before this guard, which is exactly how one diagnoses the wrong thing.)
        if not nxt_size_word & FLAG_PREV_INUSE and _plausible_header(blob, nxt, size_sz=size_sz) is not None:
            recorded = int.from_bytes(blob[nxt : nxt + size_sz], "little")
            if recorded != size:
                problem = {
                    "at": at,
                    "address": hex(base + at),
                    "size_word": hex(size_word),
                    "why": (
                        f"this chunk is free, so its size {hex(size)} should be in its successor's prev_size, "
                        f"but that says {hex(recorded)}"
                    ),
                }
                break
        at = nxt

    for index, entry in enumerate(chunks):
        if index + 1 < len(chunks):
            successor = chunks[index + 1]
            entry["in_use"] = bool(successor["flags"] & FLAG_PREV_INUSE)
        elif entry.get("top"):
            entry["in_use"] = False  # the wilderness: not free-listed, not allocated
        else:
            entry["in_use"] = bool(entry["flags"] & FLAG_PREV_INUSE)

    reached = at + (chunks[-1]["size"] if chunks and chunks[-1].get("top") else 0)
    covered = sum(entry["size"] for entry in chunks)
    return {
        "chunks": chunks,
        "problem": problem,
        "top": top,
        "scanned": len(blob),
        "reached": reached,
        "covered": covered,
        "coverage": round(covered / len(blob), 4) if blob else 0.0,
        "in_use": sum(entry["size"] for entry in chunks if entry.get("in_use")),
        "free": sum(entry["size"] for entry in chunks if entry.get("in_use") is False and not entry.get("top")),
    }


def describe(
    core: pathlib.Path,
    region: dict[str, Any],
    address: int,
    *,
    size_sz: int,
    scan: int = SCAN_BYTES,
    report: int = REPORT_CHUNKS,
) -> dict[str, Any]:
    """What this mapping is, as an allocator would see it — read from the mapping itself.

    The answer is either a heap (with the chunk containing `address`, its neighbours, and the totals) or a
    refusal that names what failed and where. A mapping with no bytes in the dump, one whose first header is not
    a chunk size, and one whose chain breaks after forty chunks are three different answers.
    """
    facts = {
        "start": region.get("start"),
        "end": region.get("end"),
        "size": region.get("size"),
        "dumped": region.get("dumped"),
        "perms": region.get("perms"),
        "kind": region.get("kind"),
    }
    dumped = int(region.get("dumped") or 0)
    answer: dict[str, Any] = {"region": facts, "heap": None, "chunks": [], "summary": None}
    if dumped <= 0:
        answer["reason"] = "the dump holds no bytes for this mapping, so there is no heap metadata to read"
        return answer
    with core.open("rb") as handle:
        handle.seek(int(region["offset"]))
        blob = handle.read(min(dumped, scan))

    size_word, size = _plausible_header(blob, 0, size_sz=size_sz) or (0, 0)
    prefix = 0
    arena_kind = None
    if size_word & FLAG_IS_MMAPPED and size >= dumped - 2 * size_sz:
        # A chunk `malloc`ed with `mmap` is the whole mapping: one header, no chain.
        answer["heap"] = {
            "kind": "mmapped-chunk",
            "size": size,
            "mmapped": True,
            "arena": None,
        }
        answer["summary"] = {
            "chunks": 1,
            "scanned": len(blob),
            "covered": size,
            "coverage": 1.0,
            "in_use": size,
            "free": 0,
            "top": 0,
            "mmapped": 1,
        }
        answer["reason"] = (
            "this mapping is one `mmap`ed chunk: a large `malloc` takes a mapping of its own, and its header "
            "says so (`IS_MMAPPED`)"
        )
        return answer
    else:
        # A thread's arena starts with a `heap_info`, so its first chunk is not at offset zero — and the check
        # has to run even when offset zero happens to *look* like a header, because a `heap_info`'s first field is
        # a pointer into the mapping: measured, `0x…0040` masks to a 16-byte-aligned size above `MINSIZE`, so the
        # walk would happily start in the middle of the struct and stop one chunk later.
        for candidate in ARENA_PREFIXES:
            if candidate and _looks_like_heap_info(blob, candidate, base=int(region["start"], 16), size_sz=size_sz):
                prefix, arena_kind = candidate, "thread arena (heap_info)"
                break

    walked = walk(
        blob[prefix:],
        int(region["start"], 16) + prefix,
        size_sz=size_sz,
        whole=len(blob) >= dumped,
    )
    chunks = walked["chunks"]
    scanned_whole = len(blob) < dumped
    verdict_reason = _verdict(walked, len(blob), scanned_whole=scanned_whole, prefix=prefix, arena_kind=arena_kind)
    if verdict_reason is not None:
        answer["reason"] = verdict_reason
        return answer

    here = next(
        (
            entry
            for entry in chunks
            if int(entry["address"], 16) <= address < int(entry["address"], 16) + entry["size"]
        ),
        None,
    )
    around = _around(chunks, here, report)
    answer["heap"] = {
        "kind": arena_kind or "main arena (brk)",
        "first_chunk_at": hex(int(region["start"], 16) + prefix),
        "top": walked["top"],
        "chunk_count": len(chunks),
        "address_chunk": here,
    }
    answer["chunks"] = around
    answer["summary"] = {
        "chunks": len(chunks),
        "scanned": len(blob),
        "scan_truncated": scanned_whole,
        "covered": walked["covered"],
        "coverage": walked["coverage"],
        "in_use": walked["in_use"],
        "free": walked["free"],
        "top": walked["top"]["size"] if walked["top"] else 0,
        "mmapped": sum(1 for entry in chunks if entry["mmapped"]),
        "arena_chunks": sum(1 for entry in chunks if entry["non_main_arena"]),
    }
    answer["reason"] = (
        f"{len(chunks)} chunk headers in a row, each 16-byte aligned and at least {4 * size_sz} bytes, and each "
        f"successor's `prev_size` agreeing with what it follows — {walked['coverage'] * 100:.1f}% of this "
        "mapping is a chain of chunks, which is what an allocator's heap looks like and what nothing else does"
    )
    return answer


def _verdict(
    walked: dict[str, Any],
    scanned: int,
    *,
    scanned_whole: bool,
    prefix: int,
    arena_kind: str | None,
) -> str | None:
    """`None` when this really is a heap, otherwise why it is not (or not provably one)."""
    chunks = walked["chunks"]
    problem = walked["problem"]
    if not chunks:
        where = problem["address"] if problem else hex(0)
        return (
            f"this mapping is not an allocator's heap: at {where} the size word is "
            f"{problem['size_word'] if problem else '0x0'}, and {problem['why'] if problem else 'a chunk needs a size'}"
        )
    if len(chunks) < MIN_CHUNKS:
        return (
            f"only {len(chunks)} chunk header{'s' if len(chunks) != 1 else ''} could be read before the layout "
            f"stopped making sense ({problem['why'] if problem else 'the mapping ends'}), which is too few to "
            "call this a heap"
        )
    if problem is not None:
        if walked["coverage"] < MIN_COVERAGE:
            return (
                f"a chain of {len(chunks)} chunks covers {walked['coverage'] * 100:.1f}% of this mapping and then "
                f"stops at {problem['address']}: {problem['why']}. Either this is not a heap or its metadata is "
                "damaged — which, in a crash dump, is worth seeing for itself"
            )
    if walked["coverage"] < MIN_COVERAGE:
        return (
            f"a chain of {len(chunks)} chunks explains only {walked['coverage'] * 100:.1f}% of the "
            f"{scanned} bytes read"
            + (" before the scan limit" if scanned_whole else "")
            + ", which is not what a heap's own metadata looks like"
        )
    return None


def _around(chunks: list[dict[str, Any]], here: dict[str, Any] | None, report: int) -> list[dict[str, Any]]:
    """The chunks worth printing: a window around the one at the address, always including the top chunk."""
    if len(chunks) <= report:
        return chunks
    if here is None:
        return chunks[:report] + ([chunks[-1]] if chunks[-1].get("top") else [])
    index = chunks.index(here)
    half = max(1, report // 2)
    window = chunks[max(0, index - half) : index + half]
    tail = chunks[-1:]
    if tail[0] not in window:
        window = window + tail
    return window


def _looks_like_heap_info(blob: bytes, prefix: int, *, base: int, size_sz: int) -> bool:
    """Does the mapping start with a `heap_info` — the arena pointer, previous heap, and size?

    A thread's arena is an `mmap`ed heap whose first bytes are that struct, and whose first chunk therefore does
    not start at offset zero. The check is deliberately narrow: `ar_ptr` has to point *into this mapping* (it
    points at the arena's `malloc_state`, which lives in the heap), `prev` has to be null or also inside, and the
    size field has to be a page-sized number no larger than the mapping. One of those alone is common; all three
    in a row is not. The addresses are absolute — a core's words hold addresses, not offsets — which is why the
    mapping's own base is an argument.
    """
    if prefix < 4 * size_sz or len(blob) < prefix:
        return False
    low, high = base, base + len(blob)
    ar_ptr = int.from_bytes(blob[0:size_sz], "little")
    prev = int.from_bytes(blob[size_sz : 2 * size_sz], "little")
    size = int.from_bytes(blob[2 * size_sz : 3 * size_sz], "little")
    if not low < ar_ptr < high:
        return False
    if prev and not low < prev < high:
        return False
    if not (0x1000 <= size <= high - low + 0x1000) or size % 0x1000:
        return False
    return _plausible_header(blob, prefix, size_sz=size_sz) is not None


def arena_facts(transport: Any) -> dict[str, Any]:
    """glibc's own arena, when this dump's libc has symbols for it — otherwise why gdb cannot say.

    This is the confirmation, not the foundation: measured on the practice bundle, every one of these
    expressions is refused because that libc is stripped (`-var-create: unable to create variable object`), and
    that refusal is what the caller reports. With `libc6-dbg` present they answer, and then the wilderness chunk
    found by walking can be checked against `main_arena.top` — a record agreeing with an inference.
    """
    facts: dict[str, Any] = {"symbol": None, "top": None, "system_mem": None, "sbrk_base": None, "why": None}
    expressions = {
        "&main_arena": "symbol",
        "main_arena.top": "top",
        "main_arena.system_mem": "system_mem",
        "mp_.sbrk_base": "sbrk_base",
    }
    refusals: list[str] = []
    for expression, key in expressions.items():
        try:
            answer = transport.evaluate(expression)
        except Exception as exc:  # noqa: BLE001 - a refusal is the answer being reported, in gdb's own words
            refusals.append(f"{expression}: {str(exc).splitlines()[0][:120]}")
            continue
        facts[key] = answer.get("value")
    if facts["symbol"] is None:
        facts["why"] = (
            "gdb has no `main_arena` in this dump's libc, so the arena cannot be asked: "
            + ("; ".join(refusals[:2]) if refusals else "the symbol is not there")
            + ". The heap is read from its own chunk headers instead, which needs no symbols"
        )
    else:
        facts["why"] = None
    return facts
