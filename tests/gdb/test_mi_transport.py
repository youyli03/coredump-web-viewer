"""Integration tests for the MI transport: a real cross gdb reading a real aarch64 core.

The parser unit tests prove we can read MI. These prove we can read a *dump* — symbols, line numbers,
the crash frame, registers. They need the local bundle described in `AGENTS.local.md` and skip cleanly
without it:

    python -m pytest -q tests -m gdb        # run these
    python -m pytest -q tests -m "not gdb"  # skip these
"""

from __future__ import annotations

import os
import pathlib

import pytest

from analysis.gdb.base import CoreNotLoaded, GdbError, GdbTimeout, Unreadable
from analysis.gdb.mi import MiTransport

ROOT = pathlib.Path(__file__).resolve().parents[2]
GDB = pathlib.Path(
    os.environ.get("CDWV_GDB") or ROOT / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
)
"""The gdb that reads the bundle — and it has to be a *cross* gdb.

The gdb that ships with the host is not enough, and that is measured rather than assumed: a native macOS
gdb reads the core's aarch64 ELF executable and then refuses the core itself with *"Core file format not
supported"*, and `--enable-targets=all` does not change that. So the default is the Arm-style cross name
under the download location `AGENTS.md` sanctions (`tmp/`), and `CDWV_GDB` overrides it — the same variable
the app reads (`src/config.py`), so a machine states *which gdb* once and both agree. `AGENTS.local.md`
names the binary that is on this checkout. There is deliberately no `.exe` suffix: that was the Windows dev
box's Arm toolchain, not the contract.
"""
BUNDLE = ROOT / "tmp" / "practice"

pytestmark = pytest.mark.gdb


def _core_for(program: str) -> pathlib.Path | None:
    """The core that belongs to one executable.

    The kernel names a core after the program that produced it, and the bundle now carries several —
    the main target plus the corrupted-stack samples. Picking "the newest" or "the last by sort" is how a
    test suite quietly starts analysing a different dump (a `smash_*` core sorts after `crash_target`).
    """
    cores = sorted(BUNDLE.glob(f"{program}.*.core"))
    return cores[-1] if cores else None


def _bundle() -> dict[str, pathlib.Path]:
    core = _core_for("crash_target")
    exe = BUNDLE / "crash_target"
    sysroot = BUNDLE / "sysroot"
    missing = [str(p) for p in (GDB, exe, sysroot) if not p.exists()]
    if core is None:
        missing.append(str(BUNDLE / "crash_target.*.core"))
    if missing:
        pytest.skip("practice bundle not present: " + ", ".join(missing))
    return {"gdb": GDB, "core": core, "exe": exe, "sysroot": sysroot, "bundle": BUNDLE}


def _start(**overrides) -> MiTransport:
    """A transport on the practice core. Overrides are constructor arguments — a deadline, say.

    A factory rather than one fixture, because the tests that damage a transport on purpose (a missed
    deadline kills its gdb) must not hand the damage to the next test.
    """
    bundle = _bundle()
    settings = {
        "gdb_path": str(bundle["gdb"]),
        "core_path": str(bundle["core"]),
        "exe_path": str(bundle["exe"]),
        "sysroot": str(bundle["sysroot"]),
        "solib_search_path": str(bundle["bundle"]),
        "command_timeout_s": 60,
        "probe_timeout_s": 30,
        **overrides,
    }
    started = MiTransport(**settings)
    started.start()
    return started


@pytest.fixture(scope="module")
def transport() -> MiTransport:
    started = _start()
    yield started
    started.close()


# --------------------------------------------------------------------------- #
# Handshake
# --------------------------------------------------------------------------- #
def test_handshake_reports_interpreter_and_version(transport: MiTransport) -> None:
    assert transport.interpreter in ("mi3", "mi2", "mi")
    assert transport.gdb_version, "the version is on the console stream, not in a result field"
    assert transport.startup_records, "startup output must be drained, not left in the queue"


# --------------------------------------------------------------------------- #
# Capabilities are measured
# --------------------------------------------------------------------------- #
def test_capabilities_are_measured_not_assumed(transport: MiTransport) -> None:
    caps = transport.capabilities()
    assert caps.transport == "mi"
    assert caps.threads and caps.backtrace and caps.registers
    assert caps.memory_map is False, "the memory map is not a gdb query"
    assert "NT_FILE" in caps.notes["memory_map"], "a missing capability must explain itself"
    assert caps.lock_owner is False


# --------------------------------------------------------------------------- #
# Threads
# --------------------------------------------------------------------------- #
def test_threads_include_the_crashed_one(transport: MiTransport) -> None:
    threads = transport.threads()
    assert len(threads) >= 2, "the practice core has several threads"
    crashed = [t for t in threads if t["is_crashed"]]
    assert len(crashed) == 1, "exactly one thread is the one that faulted"
    assert crashed[0]["func"] == "plugin_crash"
    assert all(t["tid"] for t in threads), "each thread carries a tid parsed from its target-id"


# --------------------------------------------------------------------------- #
# Backtrace: the reason any of this exists
# --------------------------------------------------------------------------- #
def test_backtrace_carries_symbols_and_marks_the_crash_site(transport: MiTransport) -> None:
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    result = transport.backtrace(crashed)

    assert result["total"] >= 20, "the practice target recurses 24 frames deep"
    assert len(result["frames"]) == result["total"]

    crash_frame = result["frames"][0]
    assert crash_frame["level"] == 0
    assert crash_frame["func"] == "plugin_crash"
    assert crash_frame["file"].endswith("libplugin.c")
    assert crash_frame["line"] == 29
    assert crash_frame["is_crash_site"] is True
    # The architecture decides how a word of memory is read, so it travels with the frame.
    assert crash_frame["arch"] == "aarch64"

    # The frame the plugin was called from, and the recursion under it. `stacked_args` sits here on purpose:
    # it is the practice target's many-argument frame (thirteen of them, more than the ABI's eight argument
    # registers), so the frame below the crash is also the one that exercises an argument list longer than a
    # line. Asserting the name keeps the sample and this test honest about each other.
    deeper = result["frames"][1]
    assert deeper["func"] == "stacked_args", "the frame below the crash is the one that called the plugin"
    assert deeper["file"].endswith("crash_target.c")

    # ...and under *that* one, the recursion the sample is built around.
    assert result["frames"][2]["func"] == "descend"

    assert sum(1 for f in result["frames"] if f["is_crash_site"]) == 1


def test_backtrace_pages_without_querying_gdb_again(transport: MiTransport) -> None:
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    everything = transport.backtrace(crashed)
    page = transport.backtrace(crashed, limit=3, offset=2)

    assert page["total"] == everything["total"], "total is the unpaginated count"
    assert page["frames"] == everything["frames"][2:5]


# --------------------------------------------------------------------------- #
# Registers
# --------------------------------------------------------------------------- #
def test_registers_include_the_stray_pointer(transport: MiTransport) -> None:
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    registers = transport.registers(crashed)
    frame = transport.backtrace(crashed)["frames"][0]

    assert registers, "a core has registers"
    assert registers["pc"].lstrip("0x").lower() == frame["pc"].lstrip("0x").lower()
    # x0 holds the argument the practice plugin was handed: the deliberate stray pointer. This asserts
    # the whole chain — core, symbol table, register file — agrees with the program's source.
    assert registers["x0"].lower() == "0xdead0000dead0000"


# --------------------------------------------------------------------------- #
# Memory and typed values: what the hex view and the pointer walk are built on
# --------------------------------------------------------------------------- #
def _crashed_at_the_crash_site(transport: MiTransport) -> str:
    """Select the crashed thread and return its stack pointer — frame 0 is where `head` lives."""
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    return transport.registers(crashed)["sp"]


def test_memory_read_returns_the_bytes_the_dump_has(transport: MiTransport) -> None:
    sp = _crashed_at_the_crash_site(transport)
    reply = transport.read_memory(sp, 64)

    assert reply["address"] == sp
    assert reply["unread"] == []
    assert [chunk["length"] for chunk in reply["chunks"]] == [64]
    # `stray` (0xdead0000dead0000) is spilled in the crash frame, and little-endian puts it right here:
    # the hex view can show the pointer that caused the fault, in the dump, at the stack pointer.
    assert reply["chunks"][0]["bytes"].endswith("0000adde0000adde")


def test_memory_read_past_the_region_reports_a_hole(transport: MiTransport) -> None:
    """gdb truncates instead of failing; the missing tail is the caller's to report, never to pad."""
    sp = _crashed_at_the_crash_site(transport)
    reply = transport.read_memory(sp, 1 << 20)

    assert sum(chunk["length"] for chunk in reply["chunks"]) < 1 << 20
    assert reply["unread"], "bytes that are not in the dump must be reported as missing"
    assert int(reply["unread"][0]["address"], 16) > int(sp, 16)


def test_a_stray_pointer_is_unreadable_not_a_failure_of_the_tool(transport: MiTransport) -> None:
    with pytest.raises(Unreadable):
        transport.read_memory("0xdead0000dead0000", 16)


def test_expand_walks_the_practice_chain(transport: MiTransport) -> None:
    """One query per level, and every level is the program's real data — including the NULL field."""
    _crashed_at_the_crash_site(transport)

    head = transport.evaluate("head")
    assert head["type"] == "struct node *"
    assert head["num_children"] == 5

    node = transport.expand("head")
    fields = {child["field"]: child for child in node["children"]}
    assert sorted(fields) == ["id", "name", "next", "payload", "peer"]
    assert fields["id"]["value"] == "1"
    assert fields["next"]["type"] == "struct node *"
    assert fields["peer"]["value"] == "0x0", "the NULL field is a value with nothing to expand"

    # Two levels down, through a pointer to another struct: len 32 and a buffer filled with 0x5a.
    blob = transport.expand("head->next->payload")
    assert blob["type"] == "struct blob *"
    deep = {child["field"]: child for child in blob["children"]}
    assert deep["len"]["value"] == "32"
    assert "repeats 32 times" in deep["data"]["value"]


# --------------------------------------------------------------------------- #
# Layout: a structure is drawn on the bytes it occupies, so it needs offsets
# --------------------------------------------------------------------------- #
def test_expand_says_where_each_field_is(transport: MiTransport) -> None:
    _crashed_at_the_crash_site(transport)
    node = transport.expand("head")
    by_field = {child["field"]: child for child in node["children"]}

    assert node["size"] == 48, "the size of the struct, not of the pointer to it"
    placed = [(name, by_field[name]["offset"], by_field[name]["size"]) for name in ("id", "name", "next", "peer", "payload")]
    assert placed == [("id", 0, 4), ("name", 4, 16), ("next", 24, 8), ("peer", 32, 8), ("payload", 40, 8)]
    # The compiler's 4-byte hole is visible as the gap the offsets leave: 4 + 16 = 20, and next is at 24.
    assert by_field["name"]["offset"] + by_field["name"]["size"] == 20
    assert by_field["next"]["offset"] == 24


def test_array_elements_are_placed_by_index(transport: MiTransport) -> None:
    _crashed_at_the_crash_site(transport)
    name = transport.expand("head->name")

    assert name["size"] == 16
    assert [child["offset"] for child in name["children"]] == list(range(16))
    assert {child["size"] for child in name["children"]} == {1}


def test_a_pointee_child_has_nowhere_to_be_placed(transport: MiTransport) -> None:
    """`&head` is a `struct node **`; its single child is `*head`, which is not a field with an offset."""
    _crashed_at_the_crash_site(transport)
    pointer = transport.expand("&head")

    assert pointer["type"] == "struct node **"
    assert [child["offset"] for child in pointer["children"]] == [None]


def test_the_temporary_variables_are_deleted(transport: MiTransport) -> None:
    """gdb's variable objects are gdb-side state; leaking one per click would grow without bound."""
    _crashed_at_the_crash_site(transport)
    transport.expand("head")
    assert not [w for w in transport.warnings if "could not be deleted" in w]


# --------------------------------------------------------------------------- #
# Frame arguments and locals: a stack of function names is not worth reading
# --------------------------------------------------------------------------- #
def test_arguments_come_with_the_stack_in_one_query(transport: MiTransport) -> None:
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    stack = transport.backtrace(crashed, with_arguments=True)

    head = stack["frames"][0]["args"]
    assert [argument["name"] for argument in head] == ["head"]
    assert head[0]["is_arg"] is True
    assert head[0]["type"] == "struct node *"
    # Not a hard-coded address: the heap moves with ASLR, which makes a magic number a test that breaks
    # for reasons that have nothing to do with the code. What matters is that the argument and the
    # expression name the same object.
    assert head[0]["value"].startswith("0x")
    assert head[0]["value"] == transport.evaluate("head")["value"]

    # A function pointer argument keeps its symbol, so the stack says *which* function was passed. This frame is
    # the many-argument one, which is why it also carries the six plain integers: an argument list longer than
    # the argument registers is the case being exercised, and it is asserted rather than assumed.
    deeper = stack["frames"][1]["args"]
    crash = next(argument for argument in deeper if argument["name"] == "crash")
    assert crash["value"].startswith("0x") and "plugin_crash" in crash["value"]
    names = [argument["name"] for argument in deeper]
    assert names[:9] == ["n", "crash", "a1", "a2", "a3", "a4", "a5", "a6", "label"]
    assert next(argument for argument in deeper if argument["name"] == "a6")["value"] == "6"

    # `main(void)` has no arguments: an empty list is an answer, not a failure to report.
    assert stack["frames"][-1]["args"] == []


def test_asking_twice_does_not_query_gdb_twice(transport: MiTransport) -> None:
    """The arguments of a whole stack are cached with the frames they belong to."""
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    first = transport.backtrace(crashed, with_arguments=True)
    second = transport.backtrace(crashed, with_arguments=True)
    assert first["frames"] == second["frames"]


def test_the_crash_frames_locals_hold_the_cause(transport: MiTransport) -> None:
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    variables = transport.frame_variables(crashed, 0)
    by_name = {variable["name"]: variable for variable in variables}

    assert by_name["head"]["is_arg"] is True
    assert set(by_name) == {"head", "n", "hops", "stray"}
    assert by_name["hops"]["value"] == "4"
    # The deliberate stray pointer, as a local, exactly as the source wrote it.
    assert by_name["stray"]["value"] == "0xdead0000dead0000"
    assert by_name["stray"]["is_arg"] is False


def test_a_thread_with_no_debug_info_still_answers(transport: MiTransport) -> None:
    """libc frames have no named arguments; the answer is an empty list, not an error and not silence."""
    other = next(t["num"] for t in transport.threads() if not t["is_crashed"])
    arguments = transport.frame_arguments(other)
    assert arguments, "the range form answers for every frame in the range"
    assert any(not level for level in arguments.values()), "libc frames have no arguments to name"


# --------------------------------------------------------------------------- #
# The failure path that matters most
# --------------------------------------------------------------------------- #
def test_a_bogus_core_is_a_failure_not_an_empty_dump(tmp_path: pathlib.Path) -> None:
    """A dump that cannot be read must never look like a dump with nothing in it."""
    bogus = tmp_path / "bogus.core"
    bogus.write_bytes(b"this is not a core dump\n")

    broken = MiTransport(
        gdb_path=str(_bundle()["gdb"]),
        core_path=str(bogus),
        command_timeout_s=30,
        probe_timeout_s=15,
    )
    try:
        with pytest.raises(GdbError) as caught:
            broken.start()
        assert str(caught.value), "the failure must say something the user can act on"
    finally:
        broken.close()


def test_core_not_loaded_is_the_specific_failure() -> None:
    """`CoreNotLoaded` is a `GdbError`, so callers may catch either — but the type must exist."""
    assert issubclass(CoreNotLoaded, GdbError)


# --------------------------------------------------------------------------- #
# The stack as memory, not as a list of function names
# --------------------------------------------------------------------------- #
def test_frames_own_contiguous_stack_memory(transport: MiTransport) -> None:
    """Each frame runs from its own `sp` to its caller's `sp`, so the slice tiles the stack exactly.

    This is the property a memory view needs and a backtrace does not carry. It is also measured rather
    than derived: the two ends are `$sp` of two frames, and nothing here assumes a frame layout.
    """
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    frames = transport.stack_frames(crashed, low=0, high=5)

    assert [frame["level"] for frame in frames] == [0, 1, 2, 3, 4, 5]
    for frame in frames:
        assert frame["sp"] and frame["fp"], "a frame with no sp/fp is not a frame we can draw"
        assert frame["start"] == frame["sp"]
        if frame["end"] is not None:
            assert int(frame["start"], 16) < int(frame["end"], 16), "a frame runs upwards"
    for here, caller in zip(frames, frames[1:]):
        assert here["end"] == caller["start"], "no gap and no overlap between neighbouring frames"


def test_the_frame_record_agrees_with_the_next_frame_gdb_found(transport: MiTransport) -> None:
    """The decoded saved fp / return address must match frame `n+1`.

    This is the whole basis for trusting a hand-decoded frame record, and the reason the ABI table is
    safe to carry across platforms: on a stack where it does not hold — no frame pointers, a signal
    frame, a different ABI — the check fails instead of the chain being drawn anyway.
    """
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    frames = transport.stack_frames(crashed, low=0, high=4)

    verified = [frame for frame in frames[:4] if frame["record"] and frame["record"]["verified"]]
    assert len(verified) == 4, "the practice core is built with frame pointers on aarch64"
    for frame, caller in zip(frames, frames[1:]):
        record = frame["record"]
        assert record["saved_fp"] == caller["fp"], f"frame {frame['level']} points at its caller's frame"
        assert record["return_address"] == caller["pc"], "the return address is where gdb says we came from"


def test_a_frame_record_reads_both_words_from_the_abis_offsets(transport: MiTransport) -> None:
    """`[fp+0]` is the saved frame pointer and `[fp+8]` the return address on aarch64 — read, not assumed."""
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    frame = transport.stack_frames(crashed, low=0, high=0)[0]
    assert frame["record"]["at"] == frame["fp"]
    raw = transport.read_memory(frame["fp"], 16)["chunks"][0]["bytes"]
    saved_fp = int.from_bytes(bytes.fromhex(raw[0:16]), "little")
    return_address = int.from_bytes(bytes.fromhex(raw[16:32]), "little")
    assert frame["record"]["saved_fp"] == f"0x{saved_fp:x}"
    assert frame["record"]["return_address"] == f"0x{return_address:x}"


def test_the_locals_of_the_crashed_frame_lie_inside_its_own_stack_range(transport: MiTransport) -> None:
    """The end-to-end check: gdb's `&variable` and our frame range have to agree.

    Two independent answers about the same bytes — where gdb says a variable lives, and where the frame's
    memory is — and if they disagree the whole "label the spill on the stack" idea is wrong.
    """
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    frame = transport.stack_frames(crashed, low=0, high=0)[0]
    start, end = int(frame["start"], 16), int(frame["end"], 16)

    slots = {slot["name"]: slot for slot in transport.frame_slots(crashed, 0)}
    inside = [slot for slot in slots.values() if slot["slot"]]
    assert inside, "a frame with locals has at least one slot in its own memory"
    for slot in inside:
        address = int(slot["address"], 16)
        assert start <= address < end, f"{slot['name']} is at {slot['address']}, outside {frame['start']}–{frame['end']}"
        assert slot["size"], "a slot without a size cannot be drawn"
        assert address + slot["size"] <= end, f"{slot['name']} runs past the end of its frame"


def test_a_variable_without_a_stack_slot_says_so_instead_of_guessing(transport: MiTransport) -> None:
    """A register-resident variable has no bytes here; `slot` is False and the value is still reported."""
    crashed = next(t["num"] for t in transport.threads() if t["is_crashed"])
    slots = {slot["name"]: slot for slot in transport.frame_slots(crashed, 0)}
    for slot in slots.values():
        if slot["slot"]:
            continue
        assert slot["address"] is None or slot["size"] is None, "no slot means no size to draw with"
        assert "value" in slot, "no slot is not the same as no value"


# --------------------------------------------------------------------------- #
# Corruption: a stack is untrusted input
#
# The samples come from `practice/src/smash_target.c`, one core per way a stack breaks. Each test asserts
# what that sample *measurably* leaves behind — these are the behaviours, not a theory about them.
# --------------------------------------------------------------------------- #
_STARTED: dict[str, MiTransport] = {}


@pytest.fixture(scope="module")
def sample():
    """A transport for one corrupted-stack sample, started on first use and closed with the module."""
    # The same guard the rest of the module uses. Without it this fixture checked only that the *core* was
    # there, so a bundle without a gdb did not skip — it failed with FileNotFoundError, which is the one
    # thing this module promises never to do on a fresh clone.
    bundle = _bundle()

    def open_sample(name: str) -> MiTransport:
        if name not in _STARTED:
            core = _core_for(name)
            if core is None:
                pytest.skip(f"the bundle has no {name} core — run practice/collect.sh")
            transport = MiTransport(
                gdb_path=str(bundle["gdb"]),
                core_path=str(core),
                exe_path=str(BUNDLE / name),
                sysroot=str(BUNDLE / "sysroot"),
                solib_search_path=str(BUNDLE),
                command_timeout_s=60,
                probe_timeout_s=30,
            )
            transport.start()
            _STARTED[name] = transport
        return _STARTED[name]

    yield open_sample
    for transport in _STARTED.values():
        transport.close()
    _STARTED.clear()


def _crashed(transport: MiTransport) -> int:
    return next(t["num"] for t in transport.threads() if t["is_crashed"])


def test_a_smashed_return_address_leaves_gdb_with_nothing_to_follow(sample) -> None:
    """`smash_ra`: the `ret` went to the marker, and gdb announces nothing at all about it.

    The viewer cannot wait to be told: gdb reports two unnamed frames and no warning, so "this stack has
    been overwritten" has to come out of our own checks. This test pins that silence, because a future gdb
    that *does* say something should change this expectation deliberately rather than by accident.
    """
    transport = sample("smash_ra")
    crashed = _crashed(transport)
    frames = transport.stack_frames(crashed, low=0, high=1)

    assert transport.warnings == [], "gdb says nothing about this corruption; we are the ones who notice"
    # gdb's sentinel for "no symbol here" is the literal string `??`, not a missing field — the transport
    # passes it through, and rendering it as a name is the UI's decision to make.
    assert all(frame["func"] in (None, "??") for frame in frames), "no function names: the pc is not in any code"
    assert all(str(frame["pc"]).startswith("0x4141") for frame in frames)
    for frame in frames:
        assert frame["record"]["at"] is None, "the frame pointer is the marker, so there is no record to read"
        assert frame["record"]["verified"] is False
        assert frame["record"]["why"], "an absent record still has to say why it is absent"
    # Both frames report the same `sp`, so the extent is not a range — and it says so rather than guessing.
    assert frames[0]["end"] is None and frames[0]["extent_why"]
    assert transport.frame_slots(crashed, 0) == [], "a frame with no code context has no variables to place"


def test_a_broken_frame_pointer_does_not_take_the_frames_with_it(sample) -> None:
    """`smash_fp`: DWARF CFI still unwinds correctly while the frame pointer chain is a lie.

    This is the case that separates two questions the viewer must not conflate: *what are the frames*
    (gdb answers, and it is right) and *is the frame record trustworthy* (it is not, and we say so).
    """
    transport = sample("smash_fp")
    crashed = _crashed(transport)

    backtrace = transport.backtrace(crashed)
    names = [frame["func"] for frame in backtrace["frames"]]
    assert names[0] == "crash_here" and "main" in names, "CFI unwinding is not the thing that broke"

    frames = transport.stack_frames(crashed, low=0, high=1)
    record = frames[0]["record"]
    assert record["at"] is not None, "the record itself is readable — it is the chain that is broken"
    assert record["verified"] is False, "it disagrees with the next frame, so it is not believed"
    assert record["checks"]["saved_fp"] is False, "and the reason is nameable"
    assert "frame pointer" in record["why"]
    assert frames[1]["fp"] == "0x4141414141414141", "the caller's frame pointer is the marker"
    assert frames[1]["record"]["at"] is None, "so there is nothing to read a record at"


def test_an_overwritten_local_is_located_while_the_stack_still_verifies(sample) -> None:
    """`smash_data`: the stack is fine and the answer is a local's bytes.

    The viewer's job here is the opposite of the two cases above — do not doubt the stack, show *which
    bytes* were overwritten. That only works if the slot really is located inside the frame's own range.
    """
    transport = sample("smash_data")
    crashed = _crashed(transport)
    frame = transport.stack_frames(crashed, low=0, high=0)[0]

    assert frame["record"]["verified"] is True, "a data overwrite leaves the frame record truthful"
    assert frame["func"] == "data_mode"

    slots = {slot["name"]: slot for slot in transport.frame_slots(crashed, 0)}
    local = slots["local"]
    assert local["slot"] is True and local["size"] == 8
    start, end = int(frame["start"], 16), int(frame["end"], 16)
    assert start <= int(local["address"], 16) < end

    # The payoff: the bytes at that slot are the marker, and the fault was a store through that value.
    raw = transport.read_memory(local["address"], local["size"])["chunks"][0]["bytes"]
    assert raw == "41" * 8, "the overwritten local reads as AAAA…, which is what the crash address says too"


def test_an_optimised_frame_says_which_register_holds_what(sample) -> None:
    """`opt_target` (`-O2`): the argument is in a register, and gdb knows which one.

    At `-O0` every variable is spilled and this question never comes up. At `-O2` it is the normal case: the
    variable has no address, so a viewer that only draws what it can place loses it. The location is a
    *function of the pc* — gdb answers with one per range — so the answer has to be the range this frame's
    pc falls in, and the register name comes from gdb rather than from a table of our own.
    """
    transport = sample("opt_target")
    crashed = _crashed(transport)
    frame = transport.stack_frames(crashed, low=0, high=0)[0]
    assert frame["func"] == "crash_now"

    slots = {slot["name"]: slot for slot in transport.frame_slots(crashed, 0)}
    target = slots["target"]
    assert target["value"] == "7", "the fault is a store through an integer, not a pointer"
    assert target["address"] is None and target["slot"] is False
    assert target["where"] == "register", "it is in a register at the fault, not on the stack"
    assert target["register"], "and gdb names it — the name is not ours to invent"
    assert target["location"], "the location expression is kept, so the claim can be checked by hand"


def test_an_optimised_frame_can_hold_both_kinds_at_once(sample) -> None:
    """The same `-O2` build has a variable in memory: a `volatile` local cannot live in a register.

    It is also the case that broke the first version of `frame_slots`: `main`'s extent is unknown (its
    caller is in libc, whose unwind info is not in this dump), and requiring an address to fall inside a
    *known* range threw away a variable gdb had just placed inside the frame.
    """
    transport = sample("opt_target")
    crashed = _crashed(transport)
    slots = {slot["name"]: slot for slot in transport.frame_slots(crashed, 1)}

    pinned = slots["pinned"]
    assert pinned["where"] == "stack" and pinned["slot"] is True
    assert pinned["address"], "a volatile local has a real address"
    assert transport.stack_frames(crashed, low=1, high=1)[0]["end"] is None, "and the frame's end is unknown"
    assert pinned["inside"] is None, "so the extent can corroborate nothing: None, not False"

    # `total` is multi-location; at this pc its location is the same slot `pinned` was written into, which is
    # exactly the kind of thing a reader has to be told rather than shown twice.
    total = slots["total"]
    assert total["where"] == "stack"
    assert total["address"] == pinned["address"], "two names, one slot: the compiler reused it"





# --------------------------------------------------------------------------- #
# Code: the instructions, and the source they came from
#
# The facts this section pins were measured against GDB 13.3 (Arm GNU Toolchain):
#
#   - `-a ADDRESS -c COUNT` is refused (`Unknown option `c'`); only `-a ADDRESS` or `-s/-e` exist;
#   - `-a ADDRESS` disassembles the whole enclosing *function* and refuses when there is none;
#   - `-s/-e` answers for any bytes, *including data*: the heap address below decodes as `udf #1`;
#   - mode 1/3 groups by source line and needs no readable source file to do it.
# --------------------------------------------------------------------------- #
def test_the_crash_site_disassembles_as_the_function_that_contains_it(transport: MiTransport) -> None:
    crashed = _crashed(transport)
    frame = transport.backtrace(crashed)["frames"][0]
    reply = transport.disassemble(frame["pc"])

    assert reply["function"]["name"] == frame["func"]
    assert reply["symbolized"] is True
    assert reply["reason"] is None
    assert len(reply["instructions"]) > 4, "a function is more than a handful of instructions"

    # The instruction *at* the address asked for is the crash site, and gdb offsets it from the function.
    here = next(i for i in reply["instructions"] if i["address"] == reply["address"])
    assert here["offset"] is not None and here["offset"] > 0
    assert here["func"] == frame["func"]
    assert reply["instructions"][0]["offset"] == 0, "the first instruction is the function's entry"
    assert reply["truncated"] is False


def test_source_grouping_agrees_with_the_frame_the_backtrace_reported(transport: MiTransport) -> None:
    """The line the crash is on is the line the frame says it is — the two come from different queries."""
    crashed = _crashed(transport)
    frame = transport.backtrace(crashed)["frames"][0]
    reply = transport.disassemble(frame["pc"], source=True)

    assert reply["lines"], "the practice binary is built -g, so DWARF has the lines"
    assert all(group["file"] for group in reply["lines"])
    assert reply["lines"][0]["fullname"].endswith(pathlib.Path(frame["file"]).name)
    assert str(frame["line"]) in [str(group["line"]) for group in reply["lines"]]
    # Flattened, the same lines are on the instructions — that is what an interleaved view draws.
    assert {str(i["line"]) for i in reply["instructions"] if "line" in i} <= {
        str(group["line"]) for group in reply["lines"]
    }


def test_opcodes_come_back_with_the_bytes_and_give_the_range_an_end(transport: MiTransport) -> None:
    crashed = _crashed(transport)
    pc = transport.backtrace(crashed)["frames"][0]["pc"]
    reply = transport.disassemble(pc, opcodes=True)

    assert all("bytes" in instruction for instruction in reply["instructions"])
    assert all(len(i["bytes"].split()) == 4 for i in reply["instructions"]), "aarch64 instructions are 4 bytes"
    assert reply["range"]["end"] is not None and int(reply["range"]["end"], 16) > int(reply["range"]["last"], 16)


def test_a_stripped_address_is_a_reason_unless_the_caller_says_the_bytes_are_code(transport: MiTransport) -> None:
    """This is the measured hazard: the range form decodes *data* into plausible instructions."""
    crashed = _crashed(transport)
    other = next(t["num"] for t in transport.threads() if t["num"] != crashed)
    pc = transport.backtrace(other)["frames"][0]["pc"]
    assert transport.backtrace(other)["frames"][0]["func"] in (None, "??"), "pick a frame with no symbols"

    refused = transport.disassemble(pc)
    assert refused["instructions"] == []
    assert refused["reason"] and "No function contains" in refused["reason"]
    assert refused["symbolized"] is False

    allowed = transport.disassemble(pc, allow_unsymbolized=True)
    assert allowed["instructions"], "the bytes are reachable, so a caller who vouches for them gets them"
    # `symbolized` reports how the answer was obtained, and this is a window of bytes, not a function: an
    # instruction inside a minimal symbol may still be named (measured here), but nothing says where a
    # function starts, so there is no function and no offset.
    assert allowed["symbolized"] is False
    assert allowed["function"] is None


def test_the_heap_address_that_gdb_happily_decodes_as_code(transport: MiTransport) -> None:
    """`head` is a data address. The range form calls it `udf #1`.

    The test exists to keep the guard honest: without `allow_unsymbolized` the answer is a reason, because
    "this is not code" is not something the transport may decide by asking a disassembler.

    The address is asked of the core rather than written down: the heap moves with ASLR, so a literal here
    would be a test that breaks for reasons that have nothing to do with the guard — which is exactly what
    happened when the practice cores were rebuilt.
    """
    heap = transport.evaluate("head")["value"]
    assert heap.startswith("0x") and " " not in heap, f"head is not a plain address: {heap!r}"

    refused = transport.disassemble(heap)
    assert refused["instructions"] == []
    assert refused["reason"] and "No function contains" in refused["reason"]

    decoded = transport.disassemble(heap, allow_unsymbolized=True)
    assert decoded["instructions"], "and here is what that produces when a caller vouches for it"


def test_an_unmapped_address_says_what_gdb_said(transport: MiTransport) -> None:
    reply = transport.disassemble("0xdead0000dead0000", allow_unsymbolized=True)
    assert reply["instructions"] == []
    assert reply["reason"] and "Cannot access memory" in reply["reason"]


# --------------------------------------------------------------------------- #
# What a repeated question costs
# --------------------------------------------------------------------------- #
def test_a_repeated_query_is_answered_by_the_session_not_gdb(transport: MiTransport) -> None:
    """architecture.md §4: *"asking for the same thread's stack twice must not send a second command to gdb"*.

    It did. Measured 2026-09-26 on the practice core, a second `/stack` cost 64 commands: the backtrace and
    the frame locations were cached, and everything *inside* a frame was not — `-stack-list-variables`,
    `&name`, `info address`, `sizeof`, and the memory read for each frame record all went back to gdb.

    The core cannot change while a session holds it, so the same question has one answer for the life of the
    transport, and re-asking is not freshness — it is the difference between a viewer that clicks instantly
    and one that re-reads a gigabyte of dump per click.
    """
    thread = next(t["num"] for t in transport.threads() if t["is_crashed"])

    first = transport.stack_frames(thread, low=0, high=2)
    asked = transport.commands_sent
    assert asked > 0, "the first answer has to be asked for"
    assert transport.stack_frames(thread, low=0, high=2) == first
    assert transport.commands_sent == asked, "a repeated range still went back to gdb"

    slots = transport.frame_slots(thread, 0)
    asked = transport.commands_sent
    assert slots, "the crash frame has variables"
    assert transport.frame_slots(thread, 0) == slots
    assert transport.commands_sent == asked, "a repeated frame still went back to gdb"

    variables = transport.frame_variables(thread, 1)
    asked = transport.commands_sent
    assert variables, "the frame under the crash has arguments"
    assert transport.frame_variables(thread, 1) == variables
    assert transport.commands_sent == asked, "a repeated variable list still went back to gdb"


def test_a_cached_answer_is_a_copy(transport: MiTransport) -> None:
    """The transport hands out copies, because callers annotate what they are given.

    `report.stack_detail` marks a frame whose slots gdb refused (`slots_refused`), and with a shared list that
    annotation would still be there on the next request — a stale field, which is the kind of wrong answer
    this project refuses everywhere else.
    """
    thread = next(t["num"] for t in transport.threads() if t["is_crashed"])
    first = transport.stack_frames(thread, low=0, high=0)
    first[0]["slots_refused"] = "annotated by the caller"
    assert "slots_refused" not in transport.stack_frames(thread, low=0, high=0)[0]


def test_a_missed_deadline_kills_gdb_instead_of_answering_from_its_stream() -> None:
    """architecture.md §6: *"on deadline, kill the gdb process and fail the session"* — and it had not been.

    The transport stayed alive after a deadline, and the abandoned command's reply was still on its way: the
    **next** command read it as its own answer. Measured before this fix — read the crashed thread's stack
    pointer, shorten the deadline past the point where gdb can answer, then read the same address again:

        before:  01000000616c7068                          (the bytes, correctly)
        after:   422 "… is not in this dump: gdb refused the command: Unable to read memory."

    A wrong answer wearing the clothes of a legitimate refusal is the worst kind of wrong this project can
    produce, and it is exactly what "there is nothing to resynchronise" in §6 is about.
    """
    transport = _start()
    try:
        thread = next(t["num"] for t in transport.threads() if t["is_crashed"])
        sp = transport.registers(thread)["sp"]
        assert transport.read_memory(sp, 8)["chunks"], "the crashed thread's stack is in this dump"

        transport._proc.command_timeout_s = 1e-6
        with pytest.raises(GdbTimeout):
            transport.read_memory(sp, 8)

        assert not transport.alive, "a gdb that missed a deadline must not be trusted with the next command"
        with pytest.raises(GdbError):
            transport.read_memory(sp, 8)
    finally:
        transport.close()
