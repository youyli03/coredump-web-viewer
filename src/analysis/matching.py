"""Which file a mapping's bytes came from — an **inference**, and never a name.

A core's `NT_FILE` note and gdb's library list (`analysis/elf.py`) both name regions, and both can come up
empty: a QNX-shaped dump has no note, and gdb names nothing when it cannot reach the file an object lived in.
What is left is the content itself — a mapping that came from a file still holds that file's bytes — and this
module is the one place in the viewer that answers a question by comparing bytes instead of reading a record.

It is deliberately kept apart from the memory map. A mapping identified this way is **not** given a `path` and
**not** given a `kind`: the caller reports it as an inference with its evidence (which file, where in it, how
many bytes matched out of how many compared), and the map goes on saying `anon`. A wrong guess in a viewer whose
whole promise is "nothing invented" would be worse than the honest `[anon]`, so the answer carries its numbers
and the reader can check them.

The arithmetic:

* **probe** — up to `PROBE_BYTES` read from the core file at the region's own file offset. Never through gdb:
  the bytes are in the dump, and a debugger round trip would cost more than the answer is worth. Reading stops
  at `p_filesz` (`regions[].dumped`), because a core holds what was resident and the rest of the mapping is not
  in the file at all.
* **needle** — the longest run inside the probe that is worth searching for: at least `NEEDLE_MIN` bytes and not
  a stretch of zeros or `0xff`, which appear in every file ever built and would match everywhere.
* **hit** — an occurrence of that needle in a candidate file. Where it lands gives the file offset the region's
  *first* byte corresponds to, which is the thing the dump does not record, so it is **derived** here.
* **score** — the probe is then compared with the candidate's bytes at that offset, byte for byte. A living
  process's writable pages have been modified since the file was written (relocations applied, `.got` patched),
  so the comparison is counted rather than required: `matched` out of `compared`, with `MATCH_FLOOR` as the
  line between "this is that file" and "these bytes merely look like it".
* **verification** — the same is done at a second probe, half the region further on, and only the candidates
  that hold at **both** offsets are reported as `verified`. One window can coincide; two offsets inside one
  region cannot, and the runtime that would have to fake it is not one this viewer is trying to impress.
"""

from __future__ import annotations

import mmap
import pathlib
from typing import Any, Iterable

PROBE_BYTES = 8192
"""How much of a region is read at each probe: enough to be sure, small enough that a request stays instant."""

NEEDLE_MIN = 64
"""The shortest run worth searching for. Shorter, and a candidate file matches by coincidence."""

MATCH_FLOOR = 0.75
"""Of the bytes compared, the share that must be equal before an offset is called a match at all."""

NEAR_MISS = 0.5
"""Of the bytes compared, the share below which a candidate is not even worth naming as "the closest".

Measured: without it, a mapping of ld.so's text named another practice binary as its closest candidate on the
strength of a 32-byte run, and "the closest is opt_target" is a sentence that sends a reader somewhere wrong.
Above it, the candidate is one worth looking at — libc's `.data` mapping agrees with libc on 57% of its bytes,
which is the number that tells a reader this dump *is* from that library.
"""

MAX_HITS = 8
"""Occurrences of one needle to score inside one file, so a needle of zeros cannot cost a whole library."""

MAX_NEEDLES = 6
"""Needles tried per probe: the whole window, then its longest runs. Each one costs a pass over each file.

Six rather than three because of a measured failure: on a page whose *first half* was rewritten, the three
longest runs all straddled the rewrite and were in no file, while the untouched half's run was the fourth. A
handful of passes is a few milliseconds; a mapping that goes unidentified because the wrong three runs were
chosen is the answer being wrong rather than slow.
"""

RUN_MIN = 32
"""The shortest run worth a fallback pass. Shorter, and a candidate file matches by coincidence."""

MAX_CANDIDATES = 64
"""Files to try. This is a bounded answer, not a filesystem walk."""

_FILL = (0, 0xFF)

PAGE = 4096
"""What a mapping's start has to look like: the kernel maps a file on a page boundary, so an offset that would
put the region's first byte mid-page is a coincidence of bytes rather than this file's layout."""


def probe_from_core(core: pathlib.Path, region: dict[str, Any], *, at: int = 0) -> bytes:
    """Bytes of one region, read out of the core itself, starting `at` bytes into it.

    `region` is a `analysis/elf.py` mapping: `offset` is where the dump keeps these bytes, `dumped` is how many
    of them it holds (which is `p_filesz`, and is not the region's size — a core writes what was resident).
    """
    length = min(PROBE_BYTES, max(0, int(region.get("dumped", 0)) - at))
    if length <= 0:
        return b""
    with core.open("rb") as handle:
        handle.seek(int(region["offset"]) + at)
        return handle.read(length)


def needle_in(probe: bytes, *, minimum: int = NEEDLE_MIN) -> tuple[int, bytes] | None:
    """The searchable part of a probe: the window with runs of fill bytes trimmed off both ends.

    The first version of this was the longest run of non-zero bytes, and measured on the practice core's own
    executable mapping it found nothing: the first page of a binary begins with an ELF header, whose runs of
    non-zero bytes are two and four bytes long, so a rule that split the probe at every zero byte called a page
    of real code unreadable. Trimming fill bytes off the **ends** instead keeps the window whole — internal
    zeros and `0xff` runs are part of what makes it distinctive, which is the opposite of the problem: an 8 KB
    window that includes them matches a file only if that file holds the same bytes at the same place.

    `None` when too little is left, which is a real answer about a mapping of zeros: there is nothing in it to
    recognise, and the caller says that instead of reporting a match against a file full of zeros.
    """
    start = 0
    end = len(probe)
    while start < end and probe[start] in _FILL:
        start += 1
    while end > start and probe[end - 1] in _FILL:
        end -= 1
    if end - start < minimum:
        return None
    return start, probe[start:end]


def runs_in(probe: bytes, *, minimum: int = RUN_MIN, limit: int = MAX_NEEDLES) -> list[tuple[int, bytes]]:
    """Long stretches of the probe that are not fill bytes, longest first.

    These are the fallback needles, and they exist because of a measured case: a `r--p` mapping is very often
    **RELRO**, live pointers that the loader rewrote after mapping the file, so the window as a whole is no
    longer in it — measured on this core's libc, whose `r--p` page matched no file at all. A run of bytes the
    loader did not touch (a string table, `.eh_frame`, a jump table) still is, and scoring the *whole* probe at
    the offset such a run implies is what turns "not this file" into "this file, 6 144 of 8 192 bytes equal,
    and here is where the rest differs".
    """
    spans: list[tuple[int, bytes]] = []
    start: int | None = None
    for index in range(len(probe) + 1):
        byte = probe[index] if index < len(probe) else None
        if byte is not None and byte not in _FILL:
            if start is None:
                start = index
            continue
        if start is not None:
            run = probe[start:index]
            if len(run) >= minimum:
                spans.append((start, run))
            start = None
    spans.sort(key=lambda span: -len(span[1]))
    return spans[:limit]


def _compare(probe: bytes, file_bytes: mmap.mmap | bytes, at: int) -> tuple[int, int]:
    """`(equal bytes, bytes compared)` between the probe and the file at `at`; 0/0 when `at` is out of range."""
    if at < 0 or at >= len(file_bytes):
        return 0, 0
    window = file_bytes[at : at + len(probe)]
    return sum(1 for left, right in zip(probe, window) if left == right), len(window)


def locate(
    probe: bytes,
    needle_at: int,
    needle: bytes,
    path: pathlib.Path,
    *,
    max_hits: int = MAX_HITS,
) -> list[dict[str, Any]]:
    """Every place in `path` where this probe could have come from, best first.

    One entry per occurrence of the needle, each carrying the file offset the region's **start** would then have
    (`offset`) and how much of the probe agrees with the file there. The floor is **not** applied here: a
    candidate whose bytes agree at only half the window is not a match, but it is exactly what a reader needs to
    hear when nothing matches — "the closest is libc, where 6 200 of 8 192 bytes agree, because the loader
    rewrote that page" — so `identify` applies the floor and keeps the near miss for the account.

    A file that cannot be read — it moved, it is not a regular file, it is empty — contributes nothing rather
    than raising: "could not read it" is one of the answers this viewer has to be able to give.
    """
    try:
        size = path.stat().st_size
        if not size:
            return []
        with path.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buffer:
                hits: list[dict[str, Any]] = []
                search = 0
                while len(hits) < max_hits:
                    found = buffer.find(needle, search)
                    if found < 0:
                        break
                    search = found + 1
                    offset = found - needle_at
                    matched, compared = _compare(probe, buffer, offset)
                    if compared and matched:
                        hits.append(
                            {
                                "offset": offset,
                                "matched": matched,
                                "compared": compared,
                                "ratio": round(matched / compared, 4),
                            }
                        )
                hits.sort(key=lambda hit: (-hit["matched"], hit["offset"]))
                return hits
    except (OSError, ValueError):
        return []


def identify(core: pathlib.Path, region: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """Which of `candidates` this region's bytes came from, with the evidence and the refusals.

    `candidates` is `[{"path": …, "source": …}]` from `candidate_files`. The reply always carries `probes` (how
    much was read and from where, so the answer can be re-derived), `tried` (every candidate with what it
    scored) and either `inference` — the best candidate that held at **both** probe offsets — or `reason`, in the
    dump's own words where the dump has any. An empty `tried` list is not "no match": it means there was nothing
    to try, and `reason` says which of those two it is.
    """
    probes = []
    blank: list[dict[str, Any]] = []
    for at in _probe_offsets(region):
        probe = probe_from_core(core, region, at=at)
        needles = _needles(probe)
        if not needles:
            blank.append({"at": at, "bytes": len(probe), "usable": _usable(probe)})
            continue
        probes.append({"at": at, "bytes": len(probe), "needles": needles, "probe": probe})
    if not probes:
        return {
            "region": _region_facts(region),
            "inference": None,
            "tried": [],
            "probes": blank,
            "reason": (
                "the dump holds no bytes for this mapping, so there is nothing to match"
                if not any(spot["bytes"] for spot in blank)
                else f"of the {max(spot['usable'] for spot in blank)} bytes in these pages that are not zeros "
                f"or fill, none is a run of the {NEEDLE_MIN} needed to recognise a file by — this is not a "
                "mapping that can be matched against one"
            ),
        }

    primary = probes[0]
    scorer = probes[1] if len(probes) > 1 else None
    tried: list[dict[str, Any]] = []
    for candidate in candidates:
        path = pathlib.Path(str(candidate["path"]))
        best: dict[str, Any] | None = None
        used: dict[str, Any] | None = None
        for needle_at, needle in primary["needles"]:
            hits = locate(primary["probe"], needle_at, needle, path)
            # The best hit of any needle: a window the loader rewrote is not in the file, but a run inside it
            # often is, and scoring the whole probe there is the answer a caller can act on.
            if hits and (best is None or hits[0]["matched"] > best["matched"]):
                best, used = hits[0], {"at": needle_at, "length": len(needle), "hits": len(hits)}
                if best["ratio"] == 1.0:
                    break  # a whole window matching byte for byte cannot be improved on
        if best is None or used is None:
            tried.append({"path": str(path), "source": candidate.get("source"), "matched": 0, "compared": 0})
            continue
        reached_floor = best["ratio"] >= MATCH_FLOOR
        # Where the mapping's *first* byte would land. A mapping starts on a page boundary — the kernel maps
        # files that way — so an offset that says otherwise is a coincidence of bytes, not this file's layout.
        entry = {
            "path": str(path),
            "source": candidate.get("source"),
            "offset": best["offset"],
            "page_aligned": best["offset"] % PAGE == 0,
            "matched": best["matched"],
            "compared": best["compared"],
            "ratio": best["ratio"],
            "reached_floor": reached_floor,
            # Which needle found it, so the inference can be re-derived: a match found through a 512-byte run
            # is weaker evidence than one found through the whole window, and the reply says which it was.
            "needle": used,
        }
        second = _verify(core, region, path, best["offset"], scorer) if scorer else None
        entry["second"] = second
        entry["verified"] = bool(reached_floor and second and second["ratio"] >= MATCH_FLOOR)
        tried.append(entry)

    tried.sort(key=lambda entry: (-int(entry["matched"]), str(entry["path"])))
    answer: dict[str, Any] = {
        "region": _region_facts(region),
        "probes": [
            {
                "at": probe["at"],
                "bytes": probe["bytes"],
                "needles": [{"at": at, "length": len(needle)} for at, needle in probe["needles"]],
            }
            for probe in probes
        ],
        "tried": tried,
        "inference": None,
    }
    if scorer is None:
        # One probe is all this mapping holds, so there is no second offset to check against. The best match is
        # still reported, as an inference the caller can see is unchecked — never as a conclusion.
        best = tried[0] if tried and tried[0].get("reached_floor") else None
        if best is None:
            answer["reason"] = _no_match_reason(tried)
            return answer
        answer["inference"] = _as_inference(best, verified=False)
        answer["reason"] = (
            "this mapping is too small to check at a second offset, so this is a single-window match rather "
            "than a verified one"
        )
        return answer

    won = next((entry for entry in tried if entry.get("verified") and entry.get("page_aligned")), None)
    if won is None:
        answer["reason"] = _no_match_reason(tried)
        return answer
    answer["inference"] = _as_inference(won, verified=True)
    answer["reason"] = (
        "inferred from content, not recorded in this dump: the dump names no file for this mapping, and this "
        "session is not putting one into the map — it is saying which file's bytes these are"
    )
    return answer


def _no_match_reason(tried: list[dict[str, Any]]) -> str:
    """Why nothing matched, naming the closest candidate — a near miss is the most useful thing to report.

    Measured on the practice core's libc: its `r--p` mapping is RELRO, so the loader rewrote the pointers in it
    and no window of it is in the file any more, while its other pages are. Saying only "no file matches" would
    hide that the file *is* the one, with one page that cannot be checked against it — and a reader deciding
    whether this dump came from the library they think it did needs exactly that number.
    """
    if not tried:
        return (
            "this session was given no file to compare against: name the executable (exe), a sysroot or a "
            "shared-object search path, and the files gdb can reach become candidates"
        )
    # A candidate whose bytes *are* these bytes but whose derived offset is not a page boundary is not a near
    # miss: it is the coincidence the alignment check exists to refuse, and saying "the closest is X" about it
    # would invite exactly the conclusion the check was written to prevent.
    shifted = next(
        (entry for entry in tried if entry.get("verified") and not entry.get("page_aligned")), None
    )
    if shifted is not None:
        return (
            f"these bytes are in {pathlib.PurePosixPath(str(shifted['path'])).name}, but they would put this "
            f"mapping's first byte at file offset {hex(int(shifted['offset']))}, which is not a page boundary — "
            "a mapping is mapped on one, so the agreement is a coincidence rather than a layout"
        )
    near = tried[0]
    if not near.get("matched") or near["ratio"] < NEAR_MISS:
        return "no file this session was given holds these bytes"
    name = pathlib.PurePosixPath(str(near["path"])).name
    return (
        f"no file this session was given holds these bytes unchanged: the closest is {name}, where "
        f"{near['matched']} of {near['compared']} bytes agree at file offset {hex(int(near['offset']))} — "
        f"{int(MATCH_FLOOR * 100)}% has to agree, because pages the loader rewrote (relocations, `.got`, RELRO) "
        "are no longer the file's bytes"
    )


def _usable(probe: bytes) -> int:
    """How much of a probe is not a fill byte: what a needle could have been made of."""
    return sum(1 for byte in probe if byte not in _FILL)


def _needles(probe: bytes) -> list[tuple[int, bytes]]:
    """What to search a candidate file for: the whole window, then its longest runs.

    Tried in that order per candidate, and the best match across them is the one scored — so a window the loader
    rewrote still gets its untouched pages compared against the file, and the reply says which needle found it.
    """
    out: list[tuple[int, bytes]] = []
    whole = needle_in(probe)
    if whole is not None:
        out.append(whole)
    for span in runs_in(probe):
        if len(out) >= MAX_NEEDLES:
            break
        if whole is not None and span[0] == whole[0] and len(span[1]) == len(whole[1]):
            continue
        out.append(span)
    return out


def _as_inference(entry: dict[str, Any], *, verified: bool) -> dict[str, Any]:
    return {
        "file": entry["path"],
        "source": entry.get("source"),
        # Where in the file the mapping's first byte would be. Derived from the content, because nothing in the
        # dump records it — an NT_FILE note is the only thing that does, and this is the case it does not cover.
        "offset": entry["offset"],
        "matched": entry["matched"],
        "compared": entry["compared"],
        "ratio": entry["ratio"],
        "verified": verified,
        "verified_offset": (entry.get("second") or {}).get("at"),
        "verified_matched": (entry.get("second") or {}).get("matched"),
        "verified_compared": (entry.get("second") or {}).get("compared"),
    }


def _probe_offsets(region: dict[str, Any]) -> list[int]:
    """Where to read: the region's start, and half of it, which is all the verification this needs."""
    dumped = int(region.get("dumped", 0))
    if dumped <= PROBE_BYTES:
        return [0]
    return [0, min(dumped - PROBE_BYTES, dumped // 2)]


def _verify(
    core: pathlib.Path,
    region: dict[str, Any],
    path: pathlib.Path,
    offset: int,
    probe: dict[str, Any],
) -> dict[str, Any] | None:
    """The same comparison at the second probe, placed at the file offset the first one implied."""
    at = int(probe["at"])
    probe_bytes = probe_from_core(core, region, at=at)
    if not probe_bytes:
        return None
    try:
        with path.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buffer:
                matched, compared = _compare(probe_bytes, buffer, offset + at)
    except (OSError, ValueError):
        return None
    if not compared:
        return None
    return {"at": at, "matched": matched, "compared": compared, "ratio": round(matched / compared, 4)}


def _region_facts(region: dict[str, Any]) -> dict[str, Any]:
    return {
        "start": region.get("start"),
        "end": region.get("end"),
        "perms": region.get("perms"),
        "size": region.get("size"),
        "dumped": region.get("dumped"),
        "kind": region.get("kind"),
    }


def _is_elf_core(path: pathlib.Path) -> bool:
    """Is this file itself a core dump? `e_type == ET_CORE`, straight from the ELF header.

    A core must never be a candidate, and the reason is not squeamishness: it *holds* the region's bytes, so it
    matches perfectly at the offset it keeps them at, and the inference would read "this mapping came from
    `something.core`" — a true statement about this file and a useless answer for the reader. Cores sit in the
    same directory as the binaries they came from often enough that leaving the filter out is not theoretical:
    measured on the practice bundle, every region of the crash_target core "matched" the core itself.
    """
    try:
        with path.open("rb") as handle:
            header = handle.read(18)
    except OSError:
        return False
    return header[:4] == b"\x7fELF" and int.from_bytes(header[16:18], "little") == 4


def candidate_files(
    *,
    exe: str | None = None,
    libraries: Iterable[dict[str, Any]] = (),
    sysroot: str | None = None,
    solib_search_path: str | None = None,
    exclude: Iterable[str] = (),
    limit: int = MAX_CANDIDATES,
) -> list[dict[str, Any]]:
    """The files this session can honestly compare a region against, each with why it is on the list.

    Three sources, in the order a reader would trust them: the executable the session was given; the host files
    gdb found for the dump's objects (which is gdb's answer to "where is libc", possibly its own toolchain's
    copy — the comparison decides whether that was right, so a wrong one is harmless and informative); and the
    names resolved under `sysroot` and `solib_search_path`, which is how a user points this at a bundle of
    libraries. Everything is deduplicated by real path, and the dump being analysed is never a candidate:
    `exclude` names it, and a core is refused by its ELF type (`_is_elf_core`) wherever it is found.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    skip = {str(pathlib.Path(path).resolve()) for path in exclude if path}

    def add(path: pathlib.Path | None, source: str) -> None:
        if path is None or len(out) >= limit:
            return
        try:
            if not path.is_file():
                return
            real = str(path.resolve())
        except OSError:
            return
        if real in seen or real in skip or _is_elf_core(pathlib.Path(real)):
            return
        seen.add(real)
        out.append({"path": real, "source": source})

    add(pathlib.Path(exe) if exe else None, "exe")
    roots = [(root, label) for root, label in ((sysroot, "sysroot"), (solib_search_path, "search path")) if root]
    for library in libraries:
        name = str(library.get("name") or "")
        host = library.get("host_name")
        add(pathlib.Path(str(host)) if host else None, "gdb found this file for the dump's object")
        if not name:
            continue
        for root, label in roots:
            # gdb's own two rules, in gdb's own order: a sysroot replaces the leading `/` of the target path,
            # and a search path is tried against the object's base name.
            root_path = pathlib.Path(root)
            add(root_path / name.lstrip("/"), f"{label} + {name}")
            add(root_path / pathlib.PurePosixPath(name).name, f"{label} + {name}")
    for root, label in roots:
        # A bundle of libraries handed over without a link map: every file beside them is a candidate, and the
        # comparison, not the name, decides. Bounded, and only one level deep.
        root_path = pathlib.Path(root)
        try:
            if not root_path.is_dir():
                continue
            for entry in sorted(root_path.iterdir())[:limit]:
                if entry.is_file() and len(out) < limit:
                    add(entry, f"a file in the {label}")
        except OSError:
            continue
    return out
