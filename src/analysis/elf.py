"""The core's own address space: where its segments are, from the file itself.

gdb cannot answer this — `-info-proc-mappings` needs a live process and MI has no equivalent — so the answer
comes from the core, which records both halves: `PT_LOAD` program headers say which ranges exist and with what
permissions, and the `NT_FILE` note says which file each one came from. That is why `memory_map` is not a
`Transport` method: it does not need a debugger, only the dump.

Ported verbatim from the fixture builder, which had been doing this in a script because the analysis layer did
not exist yet. The permissions string is the kernel's own four characters (`r-xp`), because that is what the
mappings table prints and what readers compare against.
"""

from __future__ import annotations

import pathlib
import struct
from typing import Any

NT_FILE = 0x46494C45  # "FILE"


def _perms(flags: int) -> str:
    return ("r" if flags & 4 else "-") + ("w" if flags & 2 else "-") + ("x" if flags & 1 else "-") + "p"


def _nt_file_entries(desc: object) -> list[tuple[int, int, str]]:
    """NT_FILE ranges and their filenames.

    pyelftools parses this note for us (`num_map_entries`, `Elf_Nt_File_Entry`, `filename`), and the filename
    list is parallel to the entry list. The raw-bytes branch is kept for the case a different pyelftools build
    hands the note over unparsed.
    """
    if isinstance(desc, (bytes, bytearray)):
        if len(desc) < 16:
            return []
        count, _page_size = struct.unpack_from("<QQ", desc, 0)
        names = bytes(desc[16 + count * 24 :]).split(b"\x00")
        out = []
        for index in range(count):
            start, end, _offset = struct.unpack_from("<QQQ", desc, 16 + index * 24)
            name = names[index].decode("utf-8", "replace") if index < len(names) else ""
            out.append((start, end, name))
        return entries

    entries = desc.get("Elf_Nt_File_Entry") or []  # type: ignore[union-attr]
    names = desc.get("filename") or []  # type: ignore[union-attr]
    out = []
    for index, entry in enumerate(entries):
        raw_name = names[index] if index < len(names) else b""
        name = raw_name.decode("utf-8", "replace") if isinstance(raw_name, bytes) else str(raw_name)
        # `vm_start`/`vm_end`, not `start`/`end`: these are pyelftools' Container keys, and the names are only
        # knowable by asking the library — a cleaned-up guess at them is how this parser was broken once.
        out.append((int(entry["vm_start"]), int(entry["vm_end"]), name))
    return out


def _named_by_library(start: int, end: int, libraries: list[dict[str, Any]]) -> str | None:
    """The library whose range lands in this region, if gdb could place one there.

    By **overlap**, not containment, and that is a measured choice: the extent gdb reports is the one the
    module's *sections* span, not its mappings. Measured on the practice bundle, libc's range
    (`0xe9def2dc7d00`–`0xe9def2ee43b4`) sits strictly inside its `r-xp` region
    (`0xe9def2da0000`–`0xe9def2f3a000`), so a "region inside range" rule would name nothing at all there. A
    range that stretches over several mappings names each of them, which is the other half of the same
    reasoning. Where two modules overlap one region — which happens when gdb's answer for one is stale — the
    larger overlap wins, and a tie goes to the lower address so the answer does not depend on gdb's order. A
    library gdb marked `mismatch` — it found a file and said it is the wrong one (`MiTransport.libraries()`) —
    is skipped outright: a name from the link map is not a location.
    """
    best: tuple[int, int] | None = None
    winner: str | None = None
    for library in libraries:
        if library.get("mismatch"):
            # gdb placed this one from a file it then called the wrong version: the name is from the core's link
            # map, the address is not, so it names nothing.
            continue
        for span in library.get("ranges") or []:
            low, high = int(span["start"]), int(span["end"])
            overlap = min(end, high) - max(start, low)
            if overlap <= 0:
                continue
            if best is None or (overlap, -low) > best:
                best, winner = (overlap, -low), str(library.get("name") or "") or None
    return winner


def memory_map(
    core: pathlib.Path,
    stack_pointer: int | None = None,
    libraries: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Every mapped range in the dump, in address order.

    `stack_pointer` (when given) marks the one region a thread's stack lives in, because a stack has no name of
    its own in the file — the kernel's `[stack]` is not written to the core as a path.

    `libraries` is gdb's own list of the dump's shared objects (`MiTransport.libraries()`), and it is a second
    naming source, not a decoration: a core that carries **no `NT_FILE` note** — which is what a QNX dump looks
    like — leaves every region anonymous here, and gdb can still name the ones whose files it could read. Each
    region records which source named it, `"nt_file"` or `"gdb"`, because the two are worth different amounts
    of trust: one is the kernel's own record written into the dump, the other is gdb's reconstruction from the
    link map, and a region neither source knows stays `anon`.

    `dumped` is how many bytes of the region the dump actually **holds** (`p_filesz`), which is not `size`
    (`p_memsz`): a core writes what was resident, so a mapping can be mostly holes. Anything reading a region
    out of the core file itself has to stop there, and `analysis/matching.py` does.
    """
    from elftools.elf.elffile import ELFFile

    regions: list[dict[str, Any]] = []
    with core.open("rb") as handle:
        elf = ELFFile(handle)
        files: list[tuple[int, int, str]] = []
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_NOTE":
                for note in segment.iter_notes():
                    if note["n_type"] in (NT_FILE, "NT_FILE"):
                        files = _nt_file_entries(note["n_desc"])
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = int(segment["p_vaddr"])
            size = int(segment["p_memsz"])
            if not size:
                continue
            end = start + size
            path = next((name for low, high, name in files if low <= start < high), None)
            source = "nt_file" if path else None
            if path is None and libraries:
                path = _named_by_library(start, end, libraries)
                source = "gdb" if path else None
            regions.append(
                {
                    "start": hex(start),
                    "end": hex(end),
                    "size": size,
                    "dumped": min(int(segment["p_filesz"]), size),
                    "perms": _perms(int(segment["p_flags"])),
                    "offset": int(segment["p_offset"]),
                    "path": path,
                    "source": source,
                    "kind": None if path else ("stack" if stack_pointer and start <= stack_pointer < end else "anon"),
                }
            )
    regions.sort(key=lambda region: int(region["start"], 16))
    for region in regions:
        if region["kind"] is None:
            region["kind"] = pathlib.PurePosixPath(region["path"]).name
    return regions


MACHINES = {
    "EM_AARCH64": "aarch64",
    "EM_X86_64": "x86_64",
    "EM_386": "i386",
    "EM_ARM": "arm",
    "EM_MIPS": "mips",
    "EM_PPC64": "powerpc64",
    "EM_S390": "s390x",
    "EM_RISCV": "riscv",
    "EM_LOONGARCH": "loongarch64",
}
"""`e_machine` → the name a reader recognises. Ours, not a standard: the ELF file calls it `EM_AARCH64` and
`analysis/gdb/mi.py`'s frame-record table calls it `aarch64`, so one of the two had to give, and the table
that decodes frames is the one every other module already agrees with. An architecture that is not listed keeps
its `EM_*` name lowercased rather than being mapped to something it is not."""


def facts(core: pathlib.Path) -> dict[str, Any]:
    """The core's own shape — architecture, word size, byte order — from its ELF header.

    Three facts, and every one of them is a *decode* parameter rather than interesting on its own: a word read
    in the wrong byte order is a wrong number that looks right, and a word read at the wrong width is a
    different number altogether. So they are read here, from the file that declares them, and never assumed
    from the machine this viewer happens to run on.

    A value that cannot be read comes back `None` with the reason, because the honest consequence is that no
    decode happens at all — see `analysis/reading.py` — and a caller that has to branch needs to know which of
    the three was missing.
    """
    from elftools.elf.elffile import ELFFile

    try:
        with core.open("rb") as handle:
            elf = ELFFile(handle)
            machine = str(elf.header["e_machine"])
            data = str(elf.header["e_ident"]["EI_DATA"])
            word = int(elf.elfclass) // 8
    except Exception as exc:  # noqa: BLE001 — any failure here means the same thing: no decode
        return {"arch": None, "word_size": None, "byte_order": None, "reason": f"the ELF header could not be read: {exc}"}

    if data not in ("ELFDATA2LSB", "ELFDATA2MSB"):
        return {
            "arch": machine.replace("EM_", "").lower(),
            "word_size": word,
            "byte_order": None,
            "reason": f"the ELF header names a byte order this does not know: {data}",
        }
    return {
        "arch": MACHINES.get(machine, machine.replace("EM_", "").lower()),
        "word_size": word,
        "byte_order": "little" if data == "ELFDATA2LSB" else "big",
    }

