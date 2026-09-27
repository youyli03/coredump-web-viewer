"""What a mapping's bytes *are* — and which **build** they are, read out of the dump itself.

`analysis/matching.py` answers "which of the files this session was given do these bytes resemble", and a
resemblance is the weakest kind of answer the viewer gives. This module is the opposite: it reads identifiers
that the dump is *carrying*, so the answer is a record rather than a guess. Two of them:

* **ELF magic** — a mapping whose first bytes are `\\x7fELF` is an ELF image, whatever the map calls it: an
  anonymous `r-xp` region holding an image is the ordinary shape of a `dlopen`ed or copied-in library, and it
  is also what an *injected* one looks like. Reading the header says which class, which machine, and whether
  the image is an executable, a shared object or another core. This is what `volatility3`'s `linux.elfs` does
  (`docs`' precedent for the scan, and it goes on to parse the image with a real ELF parser before believing it);
* **the GNU build-id** — the ELF image carries `.note.gnu.build-id`, a note that names *this build* in 20 bytes.
  LLDB does exactly this on an ELF core and for exactly this reason (commit `536abf8`, PR #92078: *"in case of
  post mortem debugging, we don't always have the main executable available… the `.note.gnu.build-id` of the
  main executable should be available in the core file, as those binaries are loaded in memory and dumped in
  the core file"*), and the commit searches each `NT_FILE` range for the note header before reading the id.

**Measured here** (`tmp/practice`, the aarch64 bundle): the core's `libc.so.6` mapping holds its ELF header, and
at `+0x188` its note, whose id is `27027b96e5b8c475fc327aa445bea1c71d37b4e2` — byte for byte the build-id of
`tmp/practice/sysroot/lib/aarch64-linux-gnu/libc.so.6`. So a mapping can be *named by build* without any
candidate file, and a candidate can be *checked* against it: two files that both claim to be libc.so.6 but have
different build-ids are different builds, which is the difference gdb only manages to put as a warning
(*"wrong library or version mismatch?"*, see `MiTransport.libraries()`).

The one thing this does **not** do is follow the id anywhere off this machine: `resolve()` looks in the local
debug trees and in a `debuginfod` cache if one is present, and reports the directories it searched. A viewer
that silently reached for the network would be doing something the user did not ask for, and the id is in the
reply anyway — anyone who wants `debuginfod-find debuginfo <id>` can run it.
"""

from __future__ import annotations

import pathlib
from typing import Any, Iterable

MAGIC = b"\x7fELF"

PROBE_BYTES = 8192
"""How much of a mapping is read to look for an ELF header and its note. The note follows the program headers of
the file's first page, which is inside this; a mapping whose bytes start with ELF magic but whose note is
further in is reported as an image with no build-id rather than probed further."""

NOTE_TYPE = 3  # NT_GNU_BUILD_ID
NOTE_OWNER = b"GNU\x00"
MAX_ID = 64
"""Longest build-id accepted. The note's `descsz` is a number read out of the dump, and a dump is not trusted
input: a huge one would be a slice of arbitrary length presented as an identifier."""

ELF_CLASSES = {1: "ELF32", 2: "ELF64"}
ELF_DATA = {1: "little", 2: "big"}
ELF_TYPES = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}


def build_id_in(blob: bytes) -> tuple[int, str] | None:
    """The GNU build-id in these bytes, as `(offset_of_the_note, hex id)`.

    The note's layout is `namesz descsz type "GNU\\0" id`, and the search is for the `type` field followed by the
    owner name — LLDB's own approach on a core, and here for the same reason: a memory range cannot be parsed
    the way a file can, so the note is *looked for* rather than assumed to be at a particular offset. The
    header that precedes a hit must then make sense (`namesz` 4, a `descsz` that fits), because a coincidence of
    eight bytes inside a page of code is otherwise indistinguishable from a note.
    """
    at = blob.find(NOTE_TYPE.to_bytes(4, "little") + NOTE_OWNER)
    if at < 8:
        return None
    namesz = int.from_bytes(blob[at - 8 : at - 4], "little")
    descsz = int.from_bytes(blob[at - 4 : at], "little")
    if namesz != len(NOTE_OWNER) or not 1 <= descsz <= MAX_ID:
        return None
    ident = blob[at + 8 : at + 8 + descsz]
    if len(ident) != descsz:
        return None
    return at - 8, ident.hex()


def image_of(blob: bytes) -> dict[str, Any] | None:
    """What these bytes are, when they are an ELF image — `None` when they are not.

    Only the header is read: the class, the byte order, the object type and the machine, plus the build-id if a
    note is in reach. Nothing here says the image is *complete*: a mapping holds one page of a file, and whether
    the rest of it is in the dump is a different question (the map's `dumped` answers it).
    """
    if len(blob) < 20 or blob[:4] != MAGIC:
        return None
    klass = ELF_CLASSES.get(blob[4])
    order = ELF_DATA.get(blob[5])
    if klass is None or order is None:
        return None
    endian = "little" if order == "little" else "big"
    e_type = int.from_bytes(blob[16:18], endian)
    e_machine = int.from_bytes(blob[18:20], endian)

    image: dict[str, Any] = {
        "format": "ELF",
        "class": klass,
        "byte_order": order,
        "type": ELF_TYPES.get(e_type, f"e_type={e_type}"),
        "machine": _machine_name(e_machine),
        "build_id": None,
        "build_id_at": None,
    }
    found = build_id_in(blob)
    if found is not None:
        image["build_id"], image["build_id_at"] = found[1], found[0]
    return image


_E_MACHINE_BY_NUMBER: dict[int, str] = {}
"""`e_machine` number → `EM_*` name. pyelftools' enum runs the other way (`'EM_AARCH64': 183`), and the number
is what a header holds, so it is inverted once and kept."""


def _machine_name(e_machine: int) -> str:
    """`e_machine` → the name this viewer uses, through `analysis/elf.py`'s table.

    That table decides, because it is also what decodes frames and window readings (`analysis/gdb/mi.py`,
    `analysis/reading.py`): one architecture has one name here, or a window read as `aarch64` would sit beside a
    frame read as `EM_AARCH64`. An architecture the table does not list keeps the ELF name lowercased rather
    than being mapped to something it is not.
    """
    from analysis import elf as elf_module

    if not _E_MACHINE_BY_NUMBER:
        from elftools.elf.enums import ENUM_E_MACHINE

        # `_Pass` values are pyelftools' placeholders for names it did not resolve to a number; they are not
        # architectures and are skipped rather than crashed on.
        _E_MACHINE_BY_NUMBER.update(
            {int(value): str(name) for name, value in ENUM_E_MACHINE.items() if isinstance(value, int)}
        )
    name = _E_MACHINE_BY_NUMBER.get(e_machine)
    if name is None:
        return f"e_machine={e_machine}"
    return elf_module.MACHINES.get(name, name.lower())


def build_id_of_file(path: pathlib.Path) -> str | None:
    """The build-id of a file on this machine, or `None` when it has none.

    Parsed properly (pyelftools walks the note segments) rather than searched for, because a file *can* be
    parsed: the offset of a note in a file is a fact the file states. The two paths agree by construction —
    `tests/unit/test_elfimage.py` asserts that what is read out of a core range equals what is parsed out of the
    file that range came from — and they exist side by side because a memory range has no such structure to
    trust.
    """
    from elftools.elf.elffile import ELFFile

    try:
        with path.open("rb") as handle:
            elf = ELFFile(handle)
            for segment in elf.iter_segments():
                if segment["p_type"] != "PT_NOTE":
                    continue
                for note in segment.iter_notes():
                    if note["n_type"] not in ("NT_GNU_BUILD_ID", NOTE_TYPE):
                        continue
                    desc = note["n_desc"]
                    if isinstance(desc, bytes):
                        return desc.hex()
                    text = str(desc).strip()
                    # pyelftools renders this note's descriptor as hex text in the version this checkout pins;
                    # a different build hands over bytes, which is why both are handled rather than one assumed.
                    return text.lower() if all(c in "0123456789abcdef" for c in text.lower()) else None
    except Exception:  # noqa: BLE001 - a file that cannot be read is not a file with a build-id
        return None
    return None


def annotate(core: pathlib.Path, regions: Iterable[dict[str, Any]], *, probe: int = PROBE_BYTES) -> int:
    """Mark the regions that are ELF images, in place; returns how many were.

    Cheap on purpose, because it runs for every region of every session: four bytes are read first, and only a
    mapping that starts with ELF magic is read further. Measured on this checkout's heaviest core (113 regions,
    1.13 GB): four of them are images, and the whole pass is a few milliseconds.
    """
    found = 0
    with core.open("rb") as handle:
        for region in regions:
            region["image"] = None
            dumped = int(region.get("dumped") or 0)
            if dumped < 4:
                continue
            handle.seek(int(region["offset"]))
            if handle.read(4) != MAGIC:
                continue
            handle.seek(int(region["offset"]))
            blob = handle.read(min(probe, dumped))
            image = image_of(blob)
            if image is None:
                continue
            region["image"] = image
            found += 1
    return found


def resolve(
    build_id: str,
    *,
    dirs: Iterable[str] = (),
    caches: Iterable[str] = (),
) -> dict[str, Any]:
    """Where this build-id's file (or its separate debug file) is on this machine, and where that was looked for.

    Two layouts, both conventions rather than inventions: a **debug tree** keeps files at
    `<root>/<first two hex digits>/<rest>.debug` (the `debugedit` / `eu-unstrip` layout every distribution
    uses), and a **`debuginfod` cache** keeps them at `<cache>/<id>/debuginfo` and `<cache>/<id>/executable`.
    Nothing is downloaded: `searched` lists what was looked at, so a caller can tell "there is no such file
    here" from "nobody said where to look".
    """
    searched: list[str] = []
    wanted = build_id.strip().lower()
    if len(wanted) < 3 or any(character not in "0123456789abcdef" for character in wanted):
        return {"found": None, "searched": [], "why": "this mapping carries no usable build-id"}
    for cache in caches:
        root = pathlib.Path(cache).expanduser()
        for name in ("debuginfo", "executable"):
            candidate = root / wanted / name
            searched.append(str(candidate))
            if candidate.is_file():
                found = {"path": str(candidate), "source": f"debuginfod cache in {root}"}
                return {"found": found, "searched": searched}
    for directory in dirs:
        root = pathlib.Path(directory).expanduser()
        stem = root / wanted[:2] / wanted[2:]
        for candidate in (stem.with_suffix(".debug"), stem):
            searched.append(str(candidate))
            if candidate.is_file():
                found = {"path": str(candidate), "source": f"build-id tree in {root}"}
                return {"found": found, "searched": searched}
    return {
        "found": None,
        "searched": searched,
        "why": (
            f"no file for build-id {wanted} is in the debug trees this session was configured with; the id is "
            "exact, so `debuginfod-find debuginfo " + wanted + "` fetches the matching one"
        ),
    }
