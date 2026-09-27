"""gdb's library list: the second naming source, and where it refuses to place anything.

A core's `NT_FILE` note names its regions, and it is a Linux convention; a core without it — the shape a QNX
dump is expected to have — leaves `analysis/elf.py` with ranges and no names at all. gdb still knows the link
map, so it can still name them, and that is what these tests pin. They need the local bundle and a cross gdb,
and skip cleanly without either:

    python -m pytest -q tests/gdb/test_libraries.py

The half worth testing is not that gdb can name a module — it is that a **name and a location are different
answers**, and gdb sometimes has only the first. Measured here: handed *no* sysroot, a cross gdb finds its own
toolchain's ld.so for this core, reports a range for it, and says in the same breath that the file is the wrong
version (`wrong library or version mismatch?`). The name came from the core's link map and is right; the address
did not, so no region may be named from it — the rule lives in `tests/unit/test_region_naming.py` and the
measurement it comes from is the third test below.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from analysis import elf
from analysis.gdb.mi import MiTransport

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tmp" / "practice"
GDB = pathlib.Path(
    os.environ.get("CDWV_GDB") or ROOT / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
)
pytestmark = pytest.mark.gdb

NT_FILE = (0x46494C45).to_bytes(4, "little")
"""`"FILE"`: the type word that makes a note an `NT_FILE`. Patching that one word out of a copy is how these
tests build "a core that names none of its files" out of the real core, addresses and all — a synthesized
layout would not put gdb's own ranges where the real ones land."""


def _core_for(program: str) -> pathlib.Path | None:
    cores = sorted(BUNDLE.glob(f"{program}.*.core"))
    return cores[-1] if cores else None


def _start(core: pathlib.Path, *, sysroot: bool) -> MiTransport:
    started = MiTransport(
        gdb_path=str(GDB),
        core_path=str(core),
        exe_path=None,
        sysroot=str(BUNDLE / "sysroot") if sysroot else None,
        solib_search_path=str(BUNDLE) if sysroot else None,
        command_timeout_s=60,
        probe_timeout_s=30,
    )
    started.start()
    return started


@pytest.fixture(scope="module")
def practice_core() -> pathlib.Path:
    core = _core_for("crash_target")
    if core is None or not GDB.exists():
        pytest.skip("practice bundle or cross gdb not present")
    return core


@pytest.fixture(scope="module")
def unnamed(practice_core: pathlib.Path, tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """The practice core with its `NT_FILE` note disabled, written outside the checkout (`tmp/` is scratch)."""
    raw = practice_core.read_bytes()
    assert raw.count(NT_FILE) == 1, "the fixture core carries exactly one NT_FILE note"
    out = tmp_path_factory.mktemp("unnamed") / "crash_target.no-nt-file.core"
    out.write_bytes(raw.replace(NT_FILE, (0xDEADBEEF).to_bytes(4, "little")))
    return out


def test_the_dump_names_its_objects_and_asking_twice_is_free(practice_core: pathlib.Path) -> None:
    transport = _start(practice_core, sysroot=True)
    try:
        libraries = transport.libraries()
        assert libraries
        # A library gdb could read carries a range and a host file; one it could not carries neither. Two
        # different answers, not one empty one.
        libc = next(library for library in libraries if library["name"].endswith("libc.so.6"))
        assert libc["ranges"] and libc["host_name"] and not libc["mismatch"], libc

        before = transport.commands_sent
        assert transport.libraries() == libraries
        assert transport.commands_sent == before, "a cached answer costs no command"
    finally:
        transport.close()


def test_a_core_that_names_no_files_is_still_named_where_gdb_could_place_the_object(
    unnamed: pathlib.Path,
) -> None:
    without = elf.memory_map(unnamed)
    assert without and not any(region["path"] for region in without), (
        "the shape under test is a core where no mapping names a file"
    )

    transport = _start(unnamed, sysroot=True)
    try:
        regions = elf.memory_map(unnamed, None, transport.libraries())
    finally:
        transport.close()

    named = [region for region in regions if region["path"]]
    assert named, "gdb knows this dump's shared objects even when the core does not name them"
    assert all(region["source"] == "gdb" for region in named)
    assert all(region["kind"] == pathlib.PurePosixPath(region["path"]).name for region in named)
    # What gdb places is a module's *code* region: the extent it reports is its sections', which is narrower than
    # the mapping, which is why the rule is overlap (`tests/unit/test_region_naming.py`).
    assert any(region["perms"].endswith("xp") for region in named), named
    # And everything it cannot place stays anonymous rather than being guessed at from the name.
    assert any(region["kind"] == "anon" for region in regions)


def test_a_name_without_a_usable_location_names_nothing(unnamed: pathlib.Path) -> None:
    transport = _start(unnamed, sysroot=False)
    try:
        libraries = transport.libraries()
        regions = elf.memory_map(unnamed, None, libraries)
    finally:
        transport.close()

    assert libraries, "gdb still knows the names"
    assert not any(region["path"] for region in regions), (
        "a name from the link map is not a location: nothing may be placed from a file gdb rejected"
    )
    rejected = [library for library in libraries if library["mismatch"]]
    if rejected:
        # The measurement this rule exists for: gdb calls the file wrong *and* reports a range from it.
        assert any(library["ranges"] for library in rejected), rejected
    else:
        assert not any(library["ranges"] for library in libraries), (
            "either gdb placed nothing, or it placed from a file it rejected — never the second silently"
        )
