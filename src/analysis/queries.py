"""On-demand queries: the same answers the summary carries, asked one page or one window at a time.

The summary exists so the first screen has everything in one piece. Everything after that is a question about
one address, and re-answering it by rebuilding the whole report would put the cost of the overview on every
scroll. These functions take the session's **already-open** transport — the core stays loaded, which is the
point of §1.

`code_page` is deliberately narrow: one page, by the honest route (the symbol table names the functions, each
is asked for with the function form, which refuses on data rather than inventing an instruction).
"""

from __future__ import annotations

import pathlib
from typing import Any

from analysis.gdb.mi import MiTransport
from analysis.reading import ascii_of, words_in


def memory_at(
    transport: MiTransport,
    address: int | str,
    length: int,
    *,
    shape: dict | None = None,
    width: int | None = None,
) -> dict:
    """Bytes, exactly as the transport reads them — including its own account of what was unreadable.

    The window is clamped rather than trusted: a request for a megabyte starting inside a 4 KB mapping gets the
    4K that exist, because "the bytes past the end of the mapping" is not a thing the core can answer.

    Then the two readings `requirements.md` C3 asks for beside the hex: the **ASCII column** (one character per
    byte, per chunk, so it lines up with the bytes it describes) and the **word-by-word reading** when no type
    is known. Both need the core's own byte order and word width, so both come from `shape` — the map's
    `arch`/`word_size`/`byte_order`, read once from the ELF header. A core whose shape could not be read gets
    `unread`-honest bytes and **no** decode, with the reason in `refused`: a word decoded in the wrong byte
    order is a wrong number nobody can tell from a right one.
    """
    window = transport.read_memory(address if isinstance(address, str) else hex(address), length)
    for chunk in window.get("chunks") or []:
        chunk["ascii"] = ascii_of(bytes.fromhex(str(chunk.get("bytes") or "")))

    shape = shape or {}
    byte_order = shape.get("byte_order")
    word_size = width or shape.get("word_size")
    window["arch"] = shape.get("arch")
    window["byte_order"] = byte_order
    window["word_size"] = shape.get("word_size")
    window["width"] = word_size
    if byte_order is None or word_size is None:
        window["words"] = []
        window["refused"] = {
            "words": shape.get("reason")
            or "this core's byte order and word size are unknown, so its bytes are shown and not decoded"
        }
        return window
    window["words"] = words_in(window.get("chunks") or [], byte_order=byte_order, width=int(word_size))
    return window


def code_page(
    transport: MiTransport,
    regions: list[dict],
    frames: list[dict],
    address: int,
    *,
    sample: str = "crash_target",
    files: dict | None = None,
    bundle: pathlib.Path | None = None,
    sysroot: pathlib.Path | None = None,
) -> dict:
    """Every function in the page that contains `address`, disassembled one request at a time.

    This is the "扫到才处理" shape: the caller asks about the page it is looking at, and gets that page. The
    page is found in the core's own map, so a data address never reaches gdb here — and if it did, the function
    form would refuse it rather than decode it.
    """
    page = address & ~0xFFF
    owner = next(
        (
            region
            for region in regions
            if "x" in region["perms"] and int(region["start"], 16) <= page < int(region["end"], 16)
        ),
        None,
    )
    if owner is None:
        return {"page": hex(page), "units": [], "reason": "this page is not an executable mapping in this core"}

    import analysis.report as report  # itself: the helpers live here and are private on purpose

    local = report._local_module(owner.get("path"), bundle, sysroot)
    # The core's own map first, and it is *checked* rather than trusted: the base is the candidate that lands
    # the module's sections inside the core's mapped regions. The frame-based base stays as the fallback for a
    # module whose file cannot be read at all.
    module_regions = [r for r in regions if r.get("path") == owner.get("path")]
    base = report._base_from_map(local, owner, module_regions)
    if base is None:
        base = report._module_base(transport, local, frames)
    units: list[dict[str, Any]] = []
    candidates = 0
    touched: dict[str, Any] = {}
    for value, name in report._elf_functions(local, page - base, page - base + 4096):
        candidates += 1
        reply = transport.disassemble(hex(base + value), source=True, opcodes=True, limit=4096)
        if not reply.get("instructions"):
            continue  # refused: not a function, and nothing is invented in its place
        reply["symbol"] = name
        units.append(reply)
        for group in reply.get("lines", []):
            recorded = group.get("fullname") or group.get("file")
            text = report._local_source(recorded)
            if text is None or str(recorded) in touched:
                continue
            # The source travels with the answer: the rail draws it, and the browser must never be handed a
            # path to open for itself.
            touched[str(recorded)] = {
                "local": str(text.relative_to(report.ROOT)),
                "lines": text.read_text(encoding="utf-8", errors="replace").splitlines(),
            }
    if files is not None:
        files.update(touched)
    return {
        "page": hex(page),
        "module": owner.get("path"),
        "base": hex(base),
        "functions": len(units),
        "candidates": candidates,
        "units": units,
        "files": touched,
        # Whether the file carries a full symbol table. A stripped library still exports its dynamic symbols, so
        # "no function starts in this page" and "this file has no symbols at all" are different statements, and
        # the reader is owed the right one.
        "stripped": _stripped(local),
    }


def _stripped(path: pathlib.Path | None) -> bool:
    if path is None:
        return False
    from elftools.elf.elffile import ELFFile

    with path.open("rb") as handle:
        return ELFFile(handle).get_section_by_name(".symtab") is None


def object_at(index: dict[str, dict], address: int) -> dict | None:
    """The typed object the session's index knows at this address — no gdb call.

    A lookup, not a query: the DWARF types were walked once (at load for the fixture, on the first ask for a
    live session), and "what lives here" is answerable from that index. When nothing is indexed at the address,
    the answer is `None` and the caller says so, rather than inventing a type.
    """
    for expression, obj in index.items():
        value = obj.get("value")
        if not value:
            continue
        try:
            start = int(str(value).split()[0], 16)
        except (ValueError, IndexError):
            continue
        size = obj.get("size") or 0
        if start == address or (size and start <= address < start + size):
            return {"expression": expression, **obj}
    return None


def source_file(path_text: str | None, root: pathlib.Path | None = None) -> dict | None:
    """A source file's lines, for the code rail. Read here rather than in the browser: the file lives on this
    machine (or under the substitution root), and the frontend must never be handed a filesystem path to open.
    """
    if not path_text:
        return None
    path = pathlib.Path(path_text)
    if not path.is_file():
        return None
    return {
        "path": str(path),
        "lines": path.read_text(encoding="utf-8", errors="replace").splitlines(),
    }


def objects_in(index: dict[str, dict], address: int, length: int) -> list[dict]:
    """The typed objects overlapping `[address, address + length)`, for the overlay on those bytes.

    A range question, answered from the index the session already holds: the overlay wants every object the
    window touches, not one per address, and asking gdb again for what it has already walked would be the
    expensive way to be slower.
    """
    low, high = address, address + max(0, length)
    found: list[dict] = []
    for expression, obj in index.items():
        value = obj.get("value")
        if not value:
            continue
        try:
            start = int(str(value).split()[0], 16)
        except (ValueError, IndexError):
            continue
        size = obj.get("size") or 0
        if size and start < high and low < start + size:
            found.append({"expression": expression, **obj})
    found.sort(key=lambda item: int(str(item["value"]).split()[0], 16))
    return found
