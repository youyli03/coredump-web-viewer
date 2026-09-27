"""What bytes say: the ASCII column and the word-by-word reading — no gdb, no core.

`analysis/reading.py` is pure for a reason: the two things a decode needs (byte order, word width) come from the
core's ELF header, and the arithmetic that consumes them is worth testing on its own — a word read in the wrong
order is a wrong number that looks right, which is the one failure mode this viewer is not allowed to have.

`ascii_of` is the column `requirements.md` C3 puts beside the hex; `words_in` is the "plain word-by-word
reading when no type is known" beside it.
"""

from __future__ import annotations

import pytest

from analysis.reading import WIDTHS, ascii_of, words_in


def chunk(address: str, raw: bytes) -> dict:
    return {"address": address, "length": len(raw), "bytes": raw.hex()}


# --- the ASCII column ------------------------------------------------------------------ #
def test_printable_bytes_are_themselves_and_everything_else_is_a_dot() -> None:
    assert ascii_of(b"alpha") == "alpha"
    # `0x20` is a space, which is printable and is *not* a dot: the column would otherwise lie about it.
    assert ascii_of(bytes([0x00, 0x1F, 0x20, 0x7E, 0x7F, 0xFF])) == ".. ~.."


def test_a_dot_stands_for_both_a_zero_byte_and_a_full_stop() -> None:
    """The column is a rendering, and the reply keeps the difference: `.` is a hexdump convention.

    A test that asserted this column without saying so would be pinning a display choice as if it were data.
    The bytes are in `chunks[].bytes`, in the same reply, and they are the authority.
    """
    assert ascii_of(b"\x00.") == ".."
    assert ascii_of(b"\x00.").encode() != b"\x00."


def test_an_empty_window_reads_as_an_empty_column() -> None:
    assert ascii_of(b"") == ""


def test_the_column_is_one_character_per_byte() -> None:
    """Alignment is the whole point of the column: every byte owns exactly one cell, always."""
    raw = bytes(range(256)) * 3
    assert len(ascii_of(raw)) == len(raw)


# --- the word reading ------------------------------------------------------------------ #
def test_a_word_is_decoded_in_the_byte_order_it_was_given() -> None:
    raw = b"alpha\x00\x00\x00"
    little = words_in([chunk("0x1000", raw)], byte_order="little", width=8)
    big = words_in([chunk("0x1000", raw)], byte_order="big", width=8)
    # Little-endian, the first byte is the *low* one: `61 6c 70 68 61 00 00 00` is 0x00000061_68706c61.
    assert little[0]["hex"] == "0x6168706c61"
    assert big[0]["unsigned"] == str(int.from_bytes(raw, "big")), (
        "the same eight bytes are two different numbers, and which one is right is the core's business"
    )
    assert little[0]["address"] == big[0]["address"] == "0x1000"


def test_a_signed_reading_is_the_same_bits_read_as_signed() -> None:
    word = words_in([chunk("0x1000", b"\xff" * 8)], byte_order="little", width=8)[0]
    assert word["unsigned"] == str(2**64 - 1)
    assert word["signed"] == "-1"
    byte = words_in([chunk("0x1000", b"\x80")], byte_order="little", width=1)[0]
    assert byte["unsigned"] == "128" and byte["signed"] == "-128"
    positive = words_in([chunk("0x1000", b"\x7f")], byte_order="little", width=1)[0]
    assert positive["unsigned"] == positive["signed"] == "127"


def test_a_wide_value_is_text_because_a_json_number_would_change_it() -> None:
    """JavaScript's numbers stop being exact at 2^53, and a value that comes back changed is worse than text."""
    word = words_in([chunk("0x1000", (2**64 - 1).to_bytes(8, "little"))], byte_order="little", width=8)[0]
    assert isinstance(word["unsigned"], str)
    assert word["unsigned"] == "18446744073709551615"
    assert int(word["unsigned"]) > 2**53


def test_units_are_aligned_on_the_address_not_on_the_window() -> None:
    """Two windows that overlap must agree about the word they share, or scrolling changes the numbers."""
    raw = bytes(range(32))
    whole = words_in([chunk("0x1000", raw)], byte_order="little", width=8)
    shifted = words_in([chunk("0x1005", raw[5:])], byte_order="little", width=8)
    assert [word["address"] for word in whole] == ["0x1000", "0x1008", "0x1010", "0x1018"]
    assert shifted[0]["address"] == "0x1008", "the first aligned unit inside the window, not the window's start"
    assert shifted[0] == whole[1], "the same eight bytes, whichever window asked for them"


def test_a_unit_the_window_does_not_hold_is_absent_rather_than_zero() -> None:
    """A hole is not a zero: the reply says where the bytes were not, and nothing decodes across the gap."""
    chunks = [chunk("0x1000", bytes(8)), chunk("0x1010", bytes(8))]
    words = words_in(chunks, byte_order="little", width=8)
    assert [word["address"] for word in words] == ["0x1000", "0x1010"], (
        "the word at 0x1008 straddles the hole between the two chunks and is not in the answer at all"
    )


def test_a_trailing_partial_unit_is_dropped() -> None:
    words = words_in([chunk("0x1000", bytes(12))], byte_order="little", width=8)
    assert [word["address"] for word in words] == ["0x1000"]


def test_every_width_a_reader_asks_about_is_supported() -> None:
    raw = bytes(range(16))
    for width in WIDTHS:
        words = words_in([chunk("0x1000", raw)], byte_order="little", width=width)
        assert all(word["size"] == width for word in words)
        assert len(words) == len(raw) // width
        assert words[0]["hex"] == hex(int.from_bytes(raw[:width], "little"))


def test_a_width_or_an_order_this_does_not_know_is_an_error_not_a_guess() -> None:
    raw = [chunk("0x1000", bytes(8))]
    with pytest.raises(ValueError):
        words_in(raw, byte_order="little", width=3)
    with pytest.raises(ValueError):
        words_in(raw, byte_order="middle", width=8)


def test_a_chunk_shorter_than_the_unit_decodes_nothing() -> None:
    """A four-byte chunk holds no eight-byte word, and half a word is not a word."""
    assert words_in([chunk("0x1000", bytes(4))], byte_order="little", width=8) == []
    assert words_in([], byte_order="little", width=8) == []


def test_an_address_that_is_not_one_is_skipped_rather_than_crashing() -> None:
    """The chunks come from a transport reply; a malformed one is a missing answer, not an exception."""
    assert words_in([{"address": "not-an-address", "bytes": "00" * 8}], byte_order="little", width=8) == []
    assert words_in([{"bytes": "00" * 8}], byte_order="little", width=8) == []
    assert words_in([{"address": "0x1000", "bytes": ""}], byte_order="little", width=8) == []
