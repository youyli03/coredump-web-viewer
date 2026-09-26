"""Build the report the frontend eats, from a live transport.

Threads, backtraces, registers, memory windows and the typed walk all come from our own MI transport
reading the real aarch64 core — the demo therefore shows exactly what the product can produce, and not a
byte more. The memory map is read straight from the core with pyelftools (PT_LOAD + NT_FILE), which is
what `analysis/elf.py` is meant to do, so this doubles as a spike for it.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]  # src/analysis/… → the repository root
sys.path.insert(0, str(ROOT / "src"))
# pyelftools is a real dependency of the product (`analysis/elf.py`), but this sandbox cannot install
# into site-packages, so the wheel is unpacked under the disposable `tmp/` and found from here.
_VENDORED = ROOT / "tmp" / "pylibs"
if _VENDORED.is_dir():
    sys.path.insert(0, str(_VENDORED))

from analysis.gdb.base import GdbError  # noqa: E402
from analysis.elf import memory_map  # noqa: E402
from analysis.gdb.mi import MiTransport  # noqa: E402
from schema import CONTRACT  # noqa: E402  (the contract is shared data; analysis/ may import it)

GDB = pathlib.Path(
    os.environ.get("CDWV_GDB") or ROOT / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
)
"""The cross gdb that reads these cores; `CDWV_GDB` overrides it, exactly as the app reads it, and the
default keeps the Arm-style cross name under `tmp/` with no Windows `.exe`. See `tests/gdb` for why a
host-native gdb will not do: it reads the executable and refuses the core."""
BUNDLE = ROOT / "tmp" / "practice"
EXE_NAME = "crash_target"
"""The binary being analysed: its text window is the one the demo needs, and nothing larger."""
# No module-level core: importing this module must not require a dump to exist. The fixture script picks
# one; a session is given one.

NT_FILE = 0x46494C45  # "FILE"

STACK_WINDOW = 512
"""Bytes of stack to show, from the crashed thread's `sp`: the spill of `stray` sits 0x38 into it."""

HEAP_WINDOW = 1024
"""Bytes of heap from `head`: nodes a/b/c, the blob and the 0x5a-filled buffer all fit."""

CODE_WINDOW = 4096
"""The page holding the crash frame's pc — for a crash, the instruction that faulted is the point.

That page is *file-backed*, and a core usually does not carry a copy of a clean file page: gdb reads it
from libplugin.so itself (via `solib-search-path`). So this window is also the proof that "mapped but not
in the core's bytes" is not the same thing as "not in this dump".
"""

WIDE_WINDOW = 1024
"""`struct wide` is 696 bytes and lives in .bss; a round 1024 covers it with room to see the edges."""



ROOTS = ["head", "hops", "stray", "g_wide"]
"""Where the demo's typed tree starts. Everything below is fetched by walking, not listed by hand."""

MAX_DEPTH = 5
MAX_CHILDREN = 16
"""Bounds for the walk. The product expands one level per click; the fixture walks ahead of time so the
demo can show what a session would fetch on demand. `blob[512]` is 512 rows nobody asked for, and a pointer
cycle must not walk forever — so an aggregate wider than `MAX_CHILDREN` is left as one opaque box."""


def typed_objects(transport: MiTransport) -> dict[str, dict]:
    """The expressions the demo can interpret, walked from `ROOTS`."""
    objects: dict[str, dict] = {}

    def behind(child: dict) -> bool:
        """Is there anything behind this field to walk into?

        A pointer is not a promise: gdb happily expands `head->next->peer` (which is `0x0`) and answers
        with the pointee's fields all empty, so following pointers blindly walks the whole *type* graph —
        three levels of `->peer->next->payload` with nothing in them. `0x0`, an empty value (gdb could not
        read it) and a non-address are all "nothing there".
        """
        if not str(child.get("type") or "").strip().endswith("*"):
            return True
        value = str(child.get("value") or "")
        return value not in ("", "0x0") and value.startswith("0x")

    def visit(expression: str, depth: int) -> None:
        if expression in objects or depth > MAX_DEPTH or len(objects) > 80:
            return
        try:
            summary = transport.expand(expression)
        except GdbError as exc:
            # `stray` is the deliberate stray pointer: "not in this dump" is the expected answer, and the
            # demo has to show it, so the refusal is data rather than a crash.
            objects[expression] = {"expression": expression, "refused": str(exc).splitlines()[0][:200]}
            return
        objects[expression] = summary
        for child in summary.get("children") or []:
            if not child.get("num_children") or not child.get("expression"):
                continue
            if child["num_children"] > MAX_CHILDREN or not behind(child):
                continue
            visit(child["expression"], depth + 1)

    for root in ROOTS:
        visit(root, 0)
    return objects


def memory_windows(
    transport: MiTransport,
    regions: list[dict],
    stack_pointer: str,
    head: str | None,
    crash_pc: str | None,
    wide_expression: str | None = "&g_wide",
    stack_region: tuple[int, int] | None = None,
) -> dict:
    """The memory windows the demo offers.

    Every window past the stack belongs to *this* target's data, so each one is named by the caller rather
    than assumed: a sample whose program has no `g_wide` must be able to say so, not fail on it.

    The **stack window is the whole thread stack mapping**, not a sample of it: `sp` sits 8 KB below the top
    of a 132 KB region, and a hex view whose first row is mid-region can never show what is below. The rows
    that are not live frames are the thread's free stack — stale content, which is a fact about a stack worth
    being able to look at rather than an accident to be cropped away.
    """
    if stack_region is not None:
        begin, end = stack_region
        windows = [{"name": "stack", **transport.read_memory(hex(begin), end - begin)}]
    else:
        windows = [{"name": "stack", **transport.read_memory(stack_pointer, STACK_WINDOW)}]
    if head:
        windows.append({"name": "heap", **transport.read_memory(head, HEAP_WINDOW)})
    if crash_pc:
        page = int(crash_pc, 16) & ~0xFFF
        windows.append({"name": _region_name(regions, page), **transport.read_memory(hex(page), CODE_WINDOW)})
    # The analysed program's own text. Without it, a jump to a caller's return address lands on an address the
    # demo carries no bytes for — true, and useless.
    target = _target_text_window(regions)
    if target is not None:
        begin, end = target
        windows.append({"name": _region_name(regions, begin), **transport.read_memory(hex(begin), end - begin)})
    # The awkward struct lives in .bss, which none of the other windows covers.
    refused: dict[str, str] = {}
    if wide_expression:
        try:
            wide = transport.evaluate(wide_expression)["value"]
        except GdbError as exc:
            # A dump with no DWARF has no `g_wide` to evaluate, and a capability being absent is not a failure
            # to load: §13.6 says such a dump is shown with the typed entry points disabled. Measured before
            # this: a fully stripped binary failed the **whole session** here, so a dump that can still answer
            # threads, stack, memory and disassembly showed nothing at all — which is the v1 prototype's
            # mistake in a new place.
            wide = None
            refused["wide"] = str(exc).splitlines()[0][:200]
        if wide:
            windows.append({"name": _region_name(regions, _first_address(wide)), **transport.read_memory(wide, WIDE_WINDOW)})
    return {"windows": windows, "refused": refused}


SOURCE_ROOT = "/home/lyy/cdwv-practice"
"""What the DWARF in the practice binary records as the build directory."""

LOCAL_ROOT = ROOT / "practice"
"""Where that tree actually is in this checkout. Mapping one to the other is configuration, not a guess."""

CODE_FRAMES = 6
"""How many frames' functions to disassemble for the demo — enough to walk, not the whole stack."""


def _local_source(path: str | None) -> pathlib.Path | None:
    """The local file behind a path recorded on the build machine, or None.

    None is a real answer and the UI has to have one: a core can be analysed where the sources are not, and
    "the source is not here" is different from "this address has no source".
    """
    if not path or not path.startswith(SOURCE_ROOT):
        return None
    local = LOCAL_ROOT / path[len(SOURCE_ROOT) :].lstrip("/")
    return local if local.is_file() else None


def _executable(regions: list[dict], address: str) -> bool:
    """Whether the core's own mappings say this address is executable code.

    This is the check `analysis/elf.py` exists to provide, and it is the *only* thing that may authorise the
    range form of `disassemble`: asked for a range, gdb decodes whatever bytes are there — measured, the heap
    address `0x55ac5bf2a0` comes back as `udf #1`, an instruction the program never executed.
    """
    value = int(address, 16)
    return any(
        "x" in region["perms"] and int(region["start"], 16) <= value < int(region["end"], 16)
        for region in regions
    )


def _first_address(value: str) -> int:
    """The address inside whatever gdb printed.

    `&g_wide` comes back as `0x556e0b2018 <g_wide>` — an address wearing a symbol name — and `int(..., 16)` on
    that is a `ValueError`. The transport's own `_address` parses the same shape by taking the first hex token;
    this is that rule, because a second rule for the same question is how the two drift apart.
    """
    match = re.search(r"0x[0-9a-fA-F]+", str(value))
    if match is None:
        raise ValueError(f"no address in {value!r}")
    return int(match.group(0), 16)


def _region_name(regions: list[dict], address: int) -> str:
    """A region's name, in the map's own vocabulary: the file if it has one, otherwise its kind.

    `libplugin.so · r-xp` is a classification a reader can check against the mappings table; `code` was a note
    about what the demo does with it, and two of those notes turned out to mean the same thing.
    """
    for region in regions:
        if int(region["start"], 16) <= address < int(region["end"], 16):
            leaf_name = pathlib.PurePosixPath(region["path"]).name if region.get("path") else None
            return f"{leaf_name or region.get('kind') or 'anon'} · {region['perms']}"
    return "unmapped"


def _exec_pages(regions: list[dict], frames: list[dict], exe_name: str) -> list[int]:
    """The pages worth disassembling: where the crash is, and the analysed program's own text.

    Both are named rather than guessed: the crash page is the one the crash pc is in, and the program's text is
    the executable mapping whose file is the binary being analysed. A library's text is megabytes and nobody
    asked for it.
    """
    pages: list[int] = []
    crash_pc = frames[0].get("pc") if frames else None
    if crash_pc:
        pages.append(int(crash_pc, 16) & ~0xFFF)
    for region in regions:
        if "x" not in region["perms"] or not region.get("path"):
            continue
        if pathlib.PurePosixPath(region["path"]).name != exe_name:
            continue
        start = int(region["start"], 16)
        for offset in range(0, min(int(region["size"]), 64 * 1024), 4096):
            page = start + offset
            if page not in pages:
                pages.append(page)
    return pages


def _target_text_window(regions: list[dict]) -> tuple[int, int] | None:
    """The executable's own executable mapping, as `(start, end)`."""
    for region in regions:
        if "x" not in region["perms"] or not region.get("path"):
            continue
        if pathlib.PurePosixPath(region["path"]).name == EXE_NAME:
            return int(region["start"], 16), int(region["end"], 16)
    return None


def _local_module(
    path: str | None,
    bundle: pathlib.Path | None = None,
    sysroot: pathlib.Path | None = None,
) -> pathlib.Path | None:
    """The local file behind a runtime path recorded in the core.

    Three places, in the order a cross-debug setup uses them: beside the executable by basename (what
    `solib-search-path` is for, and where the practice plugin is), under the sysroot at the recorded path (a
    sysroot mirrors the target's filesystem, so `/lib/aarch64-linux-gnu/libc.so.6` is right there), and under
    the sysroot's usual library directory by basename.

    Assuming only the first is why a `libc.so.6` page listed nothing: the file was in the bundle all along, one
    directory down.
    """
    if not path:
        return None
    name = pathlib.PurePosixPath(path)
    candidates = [(bundle or BUNDLE) / name.name]
    if sysroot:
        candidates.append(sysroot / str(name).lstrip("/"))
        candidates.append(sysroot / "lib" / "aarch64-linux-gnu" / name.name)
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _base_from_map(
    local: pathlib.Path | None,
    region: dict,
    regions: list[dict] | None = None,
    *,
    page: int = 0x1000,
) -> int | None:
    """The load base, deduced from the core's own map and then **checked against the module's sections**.

    The previous version matched the core's `region["offset"]` against the module's `p_offset`. Those are
    different quantities — one is an offset into the *core file*, the other into the module — so the function
    was comparing numbers that mean different things, and returning whatever fell out. It survived because the
    frame-based fallback happened to answer first in every case that was looked at.

    What the base actually has to satisfy, in order of how much it settles:

    * **page congruence**: mappings are page-granular, so `base = region.start - (p_vaddr & ~(page-1))`. The
      kernel's mapping may start on a page boundary while the segment's first byte is mid-page — gdb prints the
      latter, the core records the former;
    * **coverage and permission**: the region must lie inside the segment's page-rounded range, and a writable
      region cannot be the mapping of a read-only segment (the kernel's `GNU_RELRO` split only ever *removes*
      `w` from part of one, so read-only-inside-writable is allowed);
    * and then the **tie-break that actually decides it**: the candidate that puts the most of the module's
      alloc sections inside the core's mapped regions. Measured on the practice core: the true base lands 23 of
      23 (crash_target), 21 of 22 (libplugin), 30 of 32 (libc), while the arithmetic alternatives land 6-19.
      That is what makes this an answer rather than a plausible number.
    """
    if local is None or not region.get("start"):
        return None
    from elftools.elf.elffile import ELFFile

    mine = regions or [region]
    with local.open("rb") as handle:
        elf = ELFFile(handle)
        loads = [(int(s["p_vaddr"]), int(s["p_memsz"]), int(s["p_flags"]))
                 for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        sections = [(int(s["sh_addr"]), int(s["sh_size"]))
                    for s in elf.iter_sections()
                    if (s["sh_flags"] & 0x2) and int(s["sh_addr"])]  # SHF_ALLOC, with an address

    start = int(region["start"], 16)
    candidates: dict[int, int] = {}
    writable = "w" in (region.get("perms") or "")
    for vaddr, memsz, flags in loads:
        if writable and not (flags & 2):
            continue
        base = start - (vaddr & ~(page - 1))
        implied_low = base + (vaddr & ~(page - 1))
        implied_high = (base + vaddr + memsz + page - 1) & ~(page - 1)
        if implied_low <= start and int(region["end"], 16) <= implied_high:
            # How many regions and sections this base explains, which is the whole point of checking.
            explained = sum(
                1 for other in mine
                if any(
                    base + (va & ~(page - 1)) <= int(other["start"], 16)
                    and int(other["end"], 16) <= (base + va + ms + page - 1) & ~(page - 1)
                    for va, ms, _flags in loads
                )
            )
            landed = sum(
                1 for sh_addr, sh_size in sections
                if any(int(other["start"], 16) <= base + sh_addr
                       and base + sh_addr + max(sh_size, 1) <= int(other["end"], 16) for other in mine)
            )
            candidates[base] = explained * 1000 + landed
    if not candidates:
        return None
    base, score = max(candidates.items(), key=lambda item: item[1])
    print(f"  module base {hex(base)} (from the core's map: {score // 1000} region(s) explained, "
          f"{score % 1000} section(s) inside, of {len(candidates)} candidate(s))")
    return base


def _symbol_address(path: pathlib.Path | None, name: str) -> int | None:
    """The **link-time** address the ELF gives a function."""
    if path is None or not name:
        return None
    from elftools.elf.elffile import ELFFile

    with path.open("rb") as handle:
        elf = ELFFile(handle)
        for section in (".symtab", ".dynsym"):
            table = elf.get_section_by_name(section)
            if table is None:
                continue
            for symbol in table.iter_symbols():
                if symbol.name == name and symbol["st_info"]["type"] == "STT_FUNC":
                    return int(symbol["st_value"])
    return None


def _module_base(transport: MiTransport, path: pathlib.Path | None, frames: list[dict]) -> int:
    """Where the module was loaded: measured from a function we can name, not assumed.

    A core holds `0x7fb189078c` where the ELF holds `0x6a4`; gdb also says how far into the function the pc
    sits (`plugin_crash+232`), so one subtraction gives the base. With no frame to anchor on the answer is 0,
    which makes the symbol search find nothing rather than find something wrong.
    """
    # Not just frame 0: its function belongs to whichever module the crash is in, and the module being
    # anchored here may be a different one. Walk the frames until one names a function this ELF knows — that
    # is the pair whose two addresses can be subtracted.
    for frame in frames:
        name, pc = frame.get("func"), frame.get("pc")
        if not name or not pc:
            continue
        link = _symbol_address(path, name)
        if link is None:
            continue
        try:
            reply = transport.disassemble(pc)
        except Exception:
            continue
        offset = (reply.get("function") or {}).get("offset") or 0
        base = int(pc, 16) - link - int(offset)
        print(f"  module base {hex(base)} (from {name}+{offset} at {pc}, in {path.name})")
        return base
    return 0


def _elf_functions(path: pathlib.Path | None, low: int, high: int, *, limit: int = 240) -> list[tuple[int, str]]:
    """`(link-time address, name)` for every function symbol starting inside `[low, high)`.

    The symbol table is the only honest answer to "where does code begin": the range form cannot tell, and
    asked for this very page it decoded the ELF header as `.inst 0x464c457f`.
    """
    if path is None:
        return []
    from elftools.elf.elffile import ELFFile

    found: list[tuple[int, str]] = []
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        for section in (".symtab", ".dynsym"):
            table = elf.get_section_by_name(section)
            if table is None:
                continue
            for symbol in table.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                value = int(symbol["st_value"])
                if value and low <= value < high:
                    found.append((value, symbol.name))
            if found:
                break
    found.sort()
    return found[:limit]


def code_detail(
    transport: MiTransport, thread_num: int, regions: list[dict], *, levels: int = CODE_FRAMES
) -> dict:
    """The crash site in code: per frame, the function's instructions grouped by source line.

    The source *text* is read here, by the backend: MI answers with line numbers and file names, and the
    file itself is nobody's job but ours. `fullname` comes back under the host's separators, which on
    Windows means backslashes — converting is not decoration, it is whether the file can be opened.
    """
    frames = transport.backtrace(thread_num)["frames"]
    entries: dict[str, dict] = {}
    files: dict[str, dict] = {}

    for frame in frames[:levels]:
        if not frame.get("pc"):
            continue
        reply = transport.disassemble(frame["pc"], source=True, opcodes=True)
        reply["level"] = frame["level"]
        reply["frame_func"] = frame.get("func")
        reply["frame_line"] = frame.get("line")
        reply["executable"] = _executable(regions, frame["pc"])
        entries[str(frame["level"])] = reply
        for group in reply["lines"]:
            recorded = group.get("fullname") or group.get("file")
            local = _local_source(recorded)
            if local is None or str(recorded) in files:
                continue
            files[str(recorded)] = {
                "local": str(local.relative_to(ROOT)),
                "lines": local.read_text(encoding="utf-8", errors="replace").splitlines(),
            }

    # The page's real functions: one function-form request each, at the *loaded* address.
    #
    # Not a range over the page — that is the mistake the architecture notes record: the range form has no idea
    # what is code, and this page begins with the ELF header, so 178 of 228 decoded instructions were
    # fabricated. The function form refuses on anything that is not a function, so it cannot do that.
    whole = None
    crash_pc = frames[0].get("pc") if frames else None
    if crash_pc:
        page = int(crash_pc, 16) & ~0xFFF
        owner = next(
            (
                region
                for region in regions
                if "x" in region["perms"] and int(region["start"], 16) <= page < int(region["end"], 16)
            ),
            None,
        )
        units = []
        candidates = 0
        for page in _exec_pages(regions, frames, EXE_NAME):
            owner = next(
                (
                    region
                    for region in regions
                    if "x" in region["perms"] and int(region["start"], 16) <= page < int(region["end"], 16)
                ),
                None,
            )
            local = _local_module(owner.get("path") if owner else None)
            base = _module_base(transport, local, frames)
            found = _elf_functions(local, page - base, page - base + 4096)
            candidates += len(found)
            for value, name in found:
                # The symbol is link-time; gdb wants the loaded address.
                reply = transport.disassemble(hex(base + value), source=True, opcodes=True, limit=4096)
                if not reply.get("instructions"):
                    continue
                reply["symbol"] = name
                units.append(reply)
            for group in reply.get("lines", []):
                recorded = group.get("fullname") or group.get("file")
                source_local = _local_source(recorded)
                if source_local is None or str(recorded) in files:
                    continue
                files[str(recorded)] = {
                    "local": str(source_local.relative_to(ROOT)),
                    "lines": source_local.read_text(encoding="utf-8", errors="replace").splitlines(),
                }
        whole = {
            "units": units,
            "functions": len(units),
            "candidates": candidates,
            "module": owner.get("path") if owner else None,
            "base": hex(base),
        }
        print(f"  code page {hex(page)}: {whole['functions']} of {whole['candidates']} function(s) disassembled"
              f" from {local.name if local else '?'}")

    # The other half of C6: an address with no debug info at all. This is the threaded frame in libc, and
    # both answers are kept — the refusal the transport gives by default, and what the range form produces
    # when the mappings vouch for the address. The UI shows the first and offers the second with its caveat.
    other = next((t["num"] for t in transport.threads() if t["num"] != thread_num), None)
    stripped = None
    if other is not None:
        frame = transport.backtrace(other)["frames"][0]
        stripped = {
            "thread": other,
            "level": frame["level"],
            "address": frame["pc"],
            "func": frame.get("func"),
            "executable": _executable(regions, frame["pc"]),
            "refused": transport.disassemble(frame["pc"]),
            "range": transport.disassemble(frame["pc"], allow_unsymbolized=True, opcodes=True, limit=16),
        }
    return {
        "frames": entries,
        "window": whole,
        "files": files,
        "stripped": stripped,
        "source_root": SOURCE_ROOT,
        "local_root": str(LOCAL_ROOT.relative_to(ROOT)),
    }


def stack_detail(
    transport: MiTransport, thread_num: int, *, offset: int = 0, limit: int | None = None
) -> dict:
    """The stack as memory: what each frame owns, what its record says, and where the variables sit.

    A stack frame is a structure like any other — a range with named fields at offsets — so the same
    overlay that draws `head` can draw `#0 plugin_crash`. That is the whole reason `stack_frames` and
    `frame_slots` exist, and this is the data they produce on the practice core.

    **Every** frame by default. Fetching six and leaving the rest of the live stack blank is a hole the
    reader cannot tell from "the dump has nothing there": the frames exist, so they get fetched.

    `offset` and `limit` page that (requirements §5 asks for `limit`/`offset` on stacks), and the answer says
    the *total* — a response that quietly returned three of twenty-eight frames would be the same hole in a
    different shape.
    """
    every = transport.backtrace(thread_num)
    total = int(every.get("total") or len(every.get("frames") or []))
    first = max(0, offset)
    last = total - 1 if limit is None else min(total - 1, first + max(0, limit) - 1)
    frames = transport.stack_frames(thread_num, low=first, high=last) if last >= first else []
    slots: dict[str, list[dict]] = {}
    for frame in frames:
        try:
            slots[str(frame["level"])] = transport.frame_slots(thread_num, frame["level"])
        except GdbError as exc:
            # A frame with no code context (`??`) has no variables to place, and the refusal is the data.
            slots[str(frame["level"])] = []
            frame["slots_refused"] = str(exc).splitlines()[0][:200]
    return {
        "thread": thread_num,
        "frames": frames,
        "slots": slots,
        "total": total,
        "offset": first,
        "limit": limit,
        "truncated": last < total - 1,
    }


SAMPLES = {
    # `crash_target` is `-O0`: every variable is spilled to the stack, and it is the core with the whole
    # awkward structure (`head`, `g_wide`). `opt_target` is `-O2`: its variables live in registers, which is
    # the case a stack view has to be able to show and which no `-O0` core can demonstrate.
    "crash_target": {"typed": True, "windows": True},
    "opt_target": {"typed": False, "windows": False},
}

# What a core nobody wrote a profile for gets. The profile is about the *demo's* extras — the typed walk over
# `head`/`g_wide`, and the heap and crash-site windows that hang off them — so the honest default is "neither":
# the stack window is derived from the thread's own `sp` and needs nothing from the profile. This table used to be
# indexed directly, so every other target the practice suite gained (`smash_*`, `snap_target`) crashed the load
# with a `KeyError` — a lookup that could only answer for two names.
DEFAULT_PROFILE = {"typed": False, "windows": False}



def open_transport(
    core: pathlib.Path,
    exe: pathlib.Path,
    *,
    gdb: pathlib.Path | None = None,
    sysroot: pathlib.Path | None = None,
    bundle: pathlib.Path | None = None,
    command_timeout_s: float = 60,
    probe_timeout_s: float = 30,
) -> MiTransport:
    """Start a resident gdb on one core, at the paths the caller names.

    Split out of `build_summary` because a session must own this: §1 chose a resident process precisely so the
    core is read once, and a function that opens and closes its own gdb per call cannot keep that promise.
    """
    transport = MiTransport(
        gdb_path=str(gdb or GDB),
        core_path=str(core),
        exe_path=str(exe),
        sysroot=str(sysroot) if sysroot else str(BUNDLE / "sysroot"),
        solib_search_path=str(bundle or BUNDLE),
        command_timeout_s=command_timeout_s,
        probe_timeout_s=probe_timeout_s,
    )
    transport.start()
    return transport


def build_from_paths(
    sample: str = EXE_NAME,
    *,
    core: pathlib.Path | None = None,
    exe: pathlib.Path | None = None,
    gdb: pathlib.Path | None = None,
    sysroot: pathlib.Path | None = None,
    bundle: pathlib.Path | None = None,
) -> dict:
    """Open a transport, build the report, close it — what a one-shot caller (the fixture script) wants."""
    core = core or sorted(BUNDLE.glob(f"{sample}.*.core"))[-1]
    exe = exe or (BUNDLE / sample)
    transport = open_transport(core, exe, gdb=gdb, sysroot=sysroot, bundle=bundle)
    try:
        return build_summary(
            transport,
            sample=sample,
            core=core,
            include_code=True,
            include_bytes=True,
            include_stack=True,
            # The fixture is what the UI falls back to with no backend, and it has no endpoint to ask: every
            # frame's locals, the parsed stack and the typed tree all have to be in the file, so this is the one
            # caller that wants the full walk.
            include_locals=True,
            include_typed=True,
        )
    finally:
        transport.close()


def build_summary(
    transport: MiTransport,
    *,
    sample: str = EXE_NAME,
    core: pathlib.Path | None = None,
    include_code: bool = False,
    include_bytes: bool = False,
    include_stack: bool = False,
    include_locals: bool = False,
    include_typed: bool = False,
) -> dict:
    """The report for one core: what the first screen needs, and — only when asked — the bulk.

    Two samples because one core cannot show both halves of a stack. `include_code` and `include_bytes` are off
    by default because the disassembly and the window bytes are most of the report's size, and both have an
    endpoint that answers them for the window being looked at (§4, "summary vs on demand"). The fixture script
    turns them on: a static file has no backend to ask.
    """
    profile = SAMPLES.get(sample, DEFAULT_PROFILE)
    # Given, not snapshotted: a session is handed a core, and a module that picks the newest practice core
    # while it is being imported cannot serve a second one.
    core = core or sorted(BUNDLE.glob(f"{sample}.*.core"))[-1]
    caps = transport.capabilities()
    threads = transport.threads()

    detail = {}
    for thread in threads:
        # `with_arguments` costs one extra query for the *whole* stack, and a stack view without them is
        # only function names.
        backtrace = transport.backtrace(thread["num"], limit=500, with_arguments=True)
        payload = {"total": backtrace["total"], "frames": backtrace["frames"]}
        if thread["is_crashed"]:
            payload["registers"] = transport.registers(thread["num"])
        detail[str(thread["num"])] = payload
    crashed_num = next(t["num"] for t in threads if t["is_crashed"])
    registers = detail[str(crashed_num)]["registers"]
    # The regions come from the core's own segments and NT_FILE note, not from gdb, so they are known before
    # anything is read — which is what lets the stack window be the whole mapping rather than a guess at how
    # much of it to show.
    regions = memory_map(core, int(registers["sp"], 16))
    stack_region = next(
        (
            (int(region["start"], 16), int(region["end"], 16))
            for region in regions
            if int(region["start"], 16) <= int(registers["sp"], 16) < int(region["end"], 16)
        ),
        None,
    )

    # Frame locals are an *on-demand* query in the product (one frame per click), and the demo pre-fetches them
    # so the static fixture carries every frame. That pre-fetch is what `include_locals` is for: with it on, this
    # walks every frame of every thread — measured at 28 frames here, two evaluations each, **5.5 seconds of a
    # 5.6-second load** — and the live session has no use for the result, because `/frames/{level}` answers the
    # one frame that was clicked. Computing it anyway and shipping it was the most expensive thing the load did.
    if include_locals:
        for thread in threads:
            num = thread["num"]
            locals_by_level = {}
            for frame in detail[str(num)]["frames"]:
                if not frame["file"]:
                    continue
                locals_by_level[str(frame["level"])] = transport.frame_variables(num, frame["level"])
            detail[str(num)]["locals"] = locals_by_level
            print(f"  locals thread {num}: {len(locals_by_level)} frame(s)")

    # `evaluate`/`expand` answer about the *selected frame*, and the locals loop above left each thread on
    # its last frame — so put the crashed thread back on frame 0 before the typed walk.
    transport.registers(crashed_num)
    transport.frame_variables(crashed_num, 0)
    # The typed walk is the fixture's: it expands the whole tree (47 `expand` calls, 2.6s measured) so the
    # static file can draw `head`, `g_wide` and their fields without a backend. The live summary hides the tree
    # as `on_demand` and needs exactly one thing out of it — the heap window's entry point — which is a single
    # `evaluate` instead of 47 expansions.
    typed = typed_objects(transport) if (include_typed and profile["typed"]) else {}
    head = typed.get("head", {}).get("value")
    if head is None and profile["typed"]:
        try:
            head = transport.evaluate("head").get("value")
        except GdbError:
            head = None  # nothing named `head` in this core: the heap window simply has no anchor
    crash_pc = detail[str(crashed_num)]["frames"][0]["pc"]
    memory = memory_windows(
        transport,
        regions,
        registers["sp"],
        head,
        crash_pc if profile["windows"] else None,
        wide_expression="&g_wide" if profile["windows"] else None,
        stack_region=stack_region,
    )
    # `include_stack` used to gate only the *shipping* of the parsed stack: it was computed in full and replaced
    # with `on_demand: true` afterwards. Measured, that computation is `stack_frames` 1.9s plus `frame_slots`
    # **5.5s** — 28 frames at ~197ms each — for a value the very next step threw away, on a path whose stack
    # the UI fetches from `/stack` when it opens the view. Computing it at all was the waste, not sending it.
    stack = (
        stack_detail(transport, crashed_num)
        if include_stack
        else {"frames": [], "slots": {}, "on_demand": True}
    )
    code = (
        code_detail(transport, crashed_num, regions)
        if (include_code and profile["windows"])
        else {"frames": {}, "files": {}}
    )
    try:
        transport.read_memory("0xdead0000dead0000", 16)
    except GdbError as exc:
        memory["missing"] = {"address": "0xdead0000dead0000", "reason": str(exc)}
    warnings = list(transport.warnings)

    data = {
        "session": {
            "id": "demo",
            # The version of the contract this summary was built to. The static fixture is the *other*
            # producer of this same JSON, and a version stamped in both is what lets the page (and a test)
            # notice that the file it was handed is older than the code reading it.
            "contract": CONTRACT,
            "sample": sample,
            "core_path": str(core.relative_to(ROOT)),
            "exe_path": str((BUNDLE / sample).relative_to(ROOT)),
            # What the session actually ran, not the module default: a caller may have named another gdb
            # (`open_transport(gdb=…)`), and a summary that reports the wrong one is worse than none.
            "gdb_path": pathlib.Path(transport.gdb_path).name,
            "transport": transport.name,
            "gdb_version": transport.gdb_version,
            "capabilities": caps.as_dict(),
            "warnings": warnings,
        },
        "threads": threads,
        "detail": detail,
        "memory_map": {"source": "core_pt_load+nt_file", "regions": regions},
        "memory": memory,
        "typed": {"objects": typed},
        "stack": stack,
        "code": code,
    }
    print(f"threads={len(threads)} regions={len(regions)} named={sum(1 for r in regions if r['path'])}")
    for window in memory["windows"]:
        read = sum(chunk["length"] for chunk in window["chunks"])
        print(
            f"  window {window['name']:<6} {window['address']} "
            f"{read}/{window['length']} bytes, holes={window['unread']}"
        )
    for expression, obj in typed.items():
        if "refused" in obj:
            print(f"  typed  {expression:<22} refused: {obj['refused'][:70]}")
        else:
            print(f"  typed  {expression:<22} {obj['type']:<18} {obj['value']}")
    if not include_bytes:
        # Identity without content, and only in what is *returned*: the frontend needs to know each window
        # exists, how big it is and how much of it was unreadable — not the bytes themselves until one of them
        # is on screen. The working copy keeps its chunks, because the report's own progress print reads them.
        for window in data["memory"]["windows"]:
            window.pop("chunks", None)
            window["bytes_on_demand"] = True

    if not include_stack:
        # The parsed stack, not the backtrace: 44 KB of frame records and slots, which the stack view asks for
        # when it opens. `detail` stays — the thread list is the first screen.
        data["stack"] = {"frames": [], "slots": {}, "on_demand": True}

    return data
