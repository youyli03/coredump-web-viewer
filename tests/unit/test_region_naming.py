"""Which source named a region — and which one refused to.

`analysis/elf.py` has two naming sources now: the core's own `NT_FILE` note (the kernel's record, written into
the dump) and gdb's library list (`MiTransport.libraries()`, a reconstruction from the link map). The second is
worth less than the first, so each region says which one named it and a region neither knows stays `anon`.

The rule that turns gdb's ranges into names is pure arithmetic, so it is tested here — no gdb, no core. It is
tested at all because it is *not* the obvious rule: gdb reports the extent of a module's **sections**, not its
mappings, so a "the region lies inside the range" test names nothing at all (measured on the practice bundle,
where libc's range sits strictly inside its `r-xp` region). Overlap is what works, and a rule that is chosen
against intuition is a rule that needs pinning.
"""

from __future__ import annotations

from analysis.elf import _named_by_library


def library(name: str, *spans: tuple[int, int], mismatch: bool = False) -> dict:
    return {
        "name": name,
        "ranges": [{"start": low, "end": high} for low, high in spans],
        "mismatch": mismatch,
    }


def test_no_library_places_nothing() -> None:
    assert _named_by_library(0x1000, 0x2000, []) is None
    assert _named_by_library(0x1000, 0x2000, [library("libc.so.6")]) is None


def test_a_range_inside_the_region_names_it() -> None:
    # The measured shape: gdb's extent for libc is narrower than the r-xp mapping it belongs to.
    assert _named_by_library(0x1000, 0x9000, [library("libc.so.6", (0x4000, 0x5000))]) == "libc.so.6"


def test_a_range_over_several_regions_names_each_of_them() -> None:
    spanned = [library("libm.so.6", (0x1800, 0x2800))]
    assert _named_by_library(0x1000, 0x2000, spanned) == "libm.so.6"
    assert _named_by_library(0x2000, 0x3000, spanned) == "libm.so.6"


def test_a_range_that_lands_in_a_hole_names_nothing() -> None:
    # Also measured: the x86-64 fixture's ld.so range falls in a gap between two mappings, so this dump cannot
    # be named from gdb no matter how well gdb knows the object.
    assert _named_by_library(0x1000, 0x2000, [library("ld-linux.so.2", (0x9000, 0xa000))]) is None


def test_the_larger_overlap_wins_and_a_tie_goes_to_the_lower_address() -> None:
    two = [library("b.so", (0x1000, 0x1800)), library("a.so", (0x1800, 0x2000))]
    assert _named_by_library(0x1000, 0x2000, two) == "b.so"
    tied = [library("b.so", (0x1000, 0x1800)), library("a.so", (0x1000, 0x1800))]
    assert _named_by_library(0x1000, 0x2000, tied) == "b.so", "gdb's order decides nothing"


def test_a_file_gdb_rejected_names_nothing() -> None:
    """The name is from the core's link map; the location came from a file gdb called the wrong one."""
    rejected = [library("ld-linux-aarch64.so.1", (0x1000, 0x2000), mismatch=True)]
    assert _named_by_library(0x1000, 0x2000, rejected) is None


def test_a_region_named_by_the_note_keeps_its_own_source() -> None:
    """Read from the practice fixture is the gdb half; this pins the other one against a real ELF header."""
    import pathlib

    from analysis import elf

    core = pathlib.Path(__file__).resolve().parents[2] / "tmp" / "cores" / "core_linux64.elf"
    if not core.is_file():
        import pytest

        pytest.skip("needs the public x86-64 fixture under tmp/cores")
    regions = elf.memory_map(core, None, [library("not-this-one.so", (0x400000, 0x401000))])
    named = [region for region in regions if region["path"]]
    assert named, "the fixture names its files through NT_FILE"
    assert all(region["source"] == "nt_file" for region in named), (
        "the note wins: gdb is asked only about what the note left anonymous"
    )
