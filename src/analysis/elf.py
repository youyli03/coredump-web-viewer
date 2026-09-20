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


def memory_map(core: pathlib.Path, stack_pointer: int | None = None) -> list[dict[str, Any]]:
    """Every mapped range in the dump, in address order.

    `stack_pointer` (when given) marks the one region a thread's stack lives in, because a stack has no name of
    its own in the file — the kernel's `[stack]` is not written to the core as a path.
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
            regions.append(
                {
                    "start": hex(start),
                    "end": hex(end),
                    "size": size,
                    "perms": _perms(int(segment["p_flags"])),
                    "offset": int(segment["p_offset"]),
                    "path": path,
                    "kind": None if path else ("stack" if stack_pointer and start <= stack_pointer < end else "anon"),
                }
            )
    regions.sort(key=lambda region: int(region["start"], 16))
    for region in regions:
        if region["kind"] is None:
            region["kind"] = pathlib.PurePosixPath(region["path"]).name
    return regions
