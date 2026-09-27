"""Helpers shared by the unit tests, as fixtures rather than imports.

`tests/api/conftest.py`'s docstring states the rule this file follows: these modules are `conftest.py` siblings
and pytest resolves `from conftest import …` by its import mode rather than by intent, so a helper that two test
modules need is a **fixture**, not an import from a sibling test.

The one helper here builds a *valid* ELF image with a GNU build-id. Valid rather than plausible, because one of
the readers under test is a real parser: `analysis/elfimage.py` searches raw bytes for the note (a memory range
has no structure to trust) and parses the note segments when the input is a file, and a header with no program
headers would make the second path honestly answer `None` — which is how the first version of these tests failed.
"""

from __future__ import annotations

import pytest

BUILD_ID_A = "1424e4bd44113cdab5b83ceb70cd6c65a8c1d1e1"
BUILD_ID_B = "27027b96e5b8c475fc327aa445bea1c71d37b4e2"
"""Two real ids from the practice bundle (`crash_target` and the libc.so.6 in its sysroot), so a synthesized
image and a real one name the same kind of thing."""


def elf_image_bytes(
    build_id: str | None = BUILD_ID_A,
    *,
    machine: int = 183,
    e_type: int = 3,
    body: bytes = b"",
) -> bytes:
    """A minimal but valid ELF64 image: header, one `PT_NOTE` program header, the note, then a body.

    `machine=183` is AArch64 and `e_type=3` is `ET_DYN`, which is what both readers see for a real shared
    object. `build_id=None` writes no note at all (a stripped or pre-build-id binary).
    """
    note = b""
    if build_id is not None:
        raw = bytes.fromhex(build_id)
        note = (
            (4).to_bytes(4, "little")  # namesz
            + len(raw).to_bytes(4, "little")  # descsz
            + (3).to_bytes(4, "little")  # NT_GNU_BUILD_ID
            + b"GNU\x00"
            + raw
            + b"\x00" * ((4 - len(raw) % 4) % 4)  # a note is padded to four bytes
        )

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # ELF64
    header[5] = 1  # little-endian
    header[6] = 1  # version
    header[16:18] = e_type.to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")  # e_phoff: right after the header
    header[54:56] = (56).to_bytes(2, "little")  # e_phentsize
    header[56:58] = (1 if note else 0).to_bytes(2, "little")  # e_phnum

    program = bytearray(56)
    program[0:4] = (4 if note else 0).to_bytes(4, "little")  # PT_NOTE
    program[8:16] = (120).to_bytes(8, "little")  # p_offset
    program[16:24] = (120).to_bytes(8, "little")  # p_vaddr
    program[32:40] = len(note).to_bytes(8, "little")  # p_filesz
    program[40:48] = len(note).to_bytes(8, "little")  # p_memsz
    return bytes(header) + bytes(program) + note + body


@pytest.fixture
def elf_image():
    """`elf_image(build_id="…", body=b"…")` — the builder above, for tests that need one."""
    return elf_image_bytes
