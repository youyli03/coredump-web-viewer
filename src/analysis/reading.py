"""What bytes *say*, once the core's own shape is known: an ASCII column, and words.

`requirements.md` C3 asks the memory view for "raw bytes on the left (address gutter, 16 bytes, ASCII), and what
those bytes *mean* on the right — the DWARF fields when a type is known there, the plain word-by-word reading
when it is not". The DWARF half is `frame_slots` / `expand`; **this module is the other half**, and it is why
it exists at all: a word's *meaning* depends on the target's byte order and word width, and a frontend left to
guess those is a frontend that will one day decode a big-endian dump as if it were little-endian while every
number it prints stays plausible.

So the two facts a decode needs — `byte_order` and `word_size` — are read from the core's ELF header
(`analysis.elf.facts`) and travel with the answer. Nothing here guesses: no header, no decode, and the caller is
told which of the two it is missing.

Pure functions over bytes: no gdb, no file, no session. Everything below is asserted in
`tests/unit/test_reading.py` without a core.
"""

from __future__ import annotations

from typing import Any, Iterable

PRINTABLE = range(0x20, 0x7F)

WIDTHS = (1, 2, 4, 8, 16)
"""The units a caller may ask a window to be read in. Not arbitrary: these are the sizes a reader asks about —
a byte, a halfword, a word, a pointer, a vector register — and gdb's own register widths are drawn from it."""


def ascii_of(raw: bytes) -> str:
    """One character per byte: printable ASCII as itself, everything else as `.`.

    The `.` is the hexdump convention, and it is a *rendering*: the bytes remain the authority, and they are in
    the same reply. That matters here, because `.` stands for both `0x00` and a real full stop — a caller that
    needs the difference reads `chunks[].bytes`, which is what a test of this column is really asserting about.
    """
    return "".join(chr(byte) if byte in PRINTABLE else "." for byte in raw)


def words_in(chunks: Iterable[dict[str, Any]], *, byte_order: str, width: int) -> list[dict[str, Any]]:
    """Every unit of `width` bytes that is **wholly inside one chunk**, decoded in `byte_order`.

    Two rules, both of them about not inventing anything:

    * **alignment is on the address, not on the window.** A unit starts where `address % width == 0`, so the
      same bytes answer the same way whichever window they were asked for — two windows that overlap agree
      about the word they share, which is the property a test can hold this to;
    * **a unit the window does not hold is not decoded at all.** A unit straddling a hole, crossing a chunk
      boundary, or running past the end is *absent* from the answer rather than zero-filled. `unread` says
      where the bytes were not; a zero here would say the dump contains zeroes, which is a different claim.

    `unsigned` and `signed` are decimal **strings**: a 64-bit word does not survive a JSON number in every
    client (JavaScript's numbers stop being exact at 2^53), and a value that comes back changed is worse than
    one that comes back as text.
    """
    if width not in WIDTHS:
        raise ValueError(f"width must be one of {WIDTHS}, not {width}")
    if byte_order not in ("little", "big"):
        raise ValueError(f"byte_order must be 'little' or 'big', not {byte_order!r}")

    out: list[dict[str, Any]] = []
    for chunk in chunks:
        raw = bytes.fromhex(str(chunk.get("bytes") or ""))
        start = _int(chunk.get("address"))
        if start is None or len(raw) < width:
            continue
        # The first aligned unit inside this chunk, then every `width` bytes that still fits.
        offset = (-start) % width
        bits = width * 8
        while offset + width <= len(raw):
            unit = raw[offset : offset + width]
            value = int.from_bytes(unit, byte_order)
            out.append(
                {
                    "address": hex(start + offset),
                    "size": width,
                    "hex": hex(value),
                    "unsigned": str(value),
                    "signed": str(value - (1 << bits) if value >= 1 << (bits - 1) else value),
                }
            )
            offset += width
    return out


def _int(value: Any) -> int | None:
    """An address that arrived as a string, from hex or decimal — `None` if it is neither."""
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None
