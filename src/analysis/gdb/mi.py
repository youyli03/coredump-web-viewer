"""The MI transport: gdb's machine interface, parsed record by record.

MI is implemented first because it is the baseline — most `nto*-gdb` builds have no Python, and a gdb
without usable MI is barely usable at all — and because it is the only transport this development
machine can exercise (both local gdbs are `--without-python`).

Nothing here assumes MI exists: the interpreter is downgraded `mi3 → mi2 → mi` until one starts, and the
capabilities are probed **command by command**, since a vendor fork may implement only part of the record
set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from analysis.gdb.base import (
    Capabilities,
    CoreNotLoaded,
    GdbDied,
    GdbError,
    GdbTimeout,
    Transport,
    Unreadable,
    Unsupported,
)
from analysis.gdb.runner import GdbProcess

INTERPRETERS = ("mi3", "mi2", "mi")
"""Downgraded until one starts. The record shapes we parse are stable across all three."""


class MiParseError(GdbError):
    """A record that does not fit the MI grammar. That is our bug, not the user's."""


# --------------------------------------------------------------------------- #
# The MI value grammar: const | tuple | list, and `name=value` results
# --------------------------------------------------------------------------- #
_WHITESPACE = " \t"
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


class _Parser:
    """Recursive-descent reader for the MI value grammar.

    Small on purpose: the grammar is tiny (strings, `{…}` tuples, `[…]` lists, `name=value`), and a
    library for it would be one more dependency for one more parser.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def _skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in _WHITESPACE:
            self.pos += 1

    def peek(self) -> str:
        self._skip_ws()
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def eat(self, expected: str) -> None:
        if self.peek() != expected:
            raise MiParseError(f"expected {expected!r} at offset {self.pos} in {self.text!r}")
        self.pos += 1

    def cstring(self) -> str:
        self.eat('"')
        out: list[str] = []
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch == "\\":
                self.pos += 1
                if self.pos >= len(self.text):
                    break
                out.append(_ESCAPES.get(self.text[self.pos], self.text[self.pos]))
                self.pos += 1
            elif ch == '"':
                self.pos += 1
                return "".join(out)
            else:
                out.append(ch)
                self.pos += 1
        raise MiParseError(f"unterminated string in {self.text!r}")

    def bareword(self) -> str:
        """An unquoted token: a result name, a class name, or a stray constant."""
        self._skip_ws()
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] not in ',=]}\n':
            self.pos += 1
        return self.text[start : self.pos].strip()

    # --- grammar ----------------------------------------------------------------------- #
    def value(self) -> Any:
        ch = self.peek()
        if ch == '"':
            return self.cstring()
        if ch == "{":
            return self.tuple()
        if ch == "[":
            return self.list()
        return self.bareword()

    def tuple(self) -> dict[str, Any]:  # noqa: A003 - "tuple" is the grammar's own name for it
        self.eat("{")
        out: dict[str, Any] = {}
        if self.peek() == "}":
            self.pos += 1
            return out
        while True:
            out.update(self.result())
            ch = self.peek()
            if ch == ",":
                self.pos += 1
                continue
            if ch == "}":
                self.pos += 1
                return out
            raise MiParseError(f"expected ',' or '}}' at offset {self.pos} in {self.text!r}")

    def list(self) -> list[Any]:  # noqa: A003 - same
        self.eat("[")
        items: list[Any] = []
        if self.peek() == "]":
            self.pos += 1
            return items
        while True:
            items.append(self.element())
            ch = self.peek()
            if ch == ",":
                self.pos += 1
                continue
            if ch == "]":
                self.pos += 1
                return items
            raise MiParseError(f"expected ',' or ']' at offset {self.pos} in {self.text!r}")

    def element(self) -> Any:
        """A list element is a bare value, or a `name=value` result."""
        if self.peek() in ('"', "{", "["):
            return self.value()
        return self.result()

    def result(self) -> dict[str, Any]:
        name = self.bareword()
        self.eat("=")
        return {name: self.value()}

    def results(self) -> dict[str, Any]:
        """`name=value` pairs separated by commas, running to the end of the text."""
        out: dict[str, Any] = {}
        while True:
            self._skip_ws()
            if self.pos >= len(self.text):
                return out
            out.update(self.result())
            if self.peek() == ",":
                self.pos += 1


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #
_RECORD = re.compile(r"^(?P<token>\d+)?(?P<kind>[\^*=+~&@])(?P<body>.*)$", re.DOTALL)
_KINDS = {
    "^": "result",
    "*": "exec",
    "=": "notify",
    "+": "status",
    "~": "console",
    "&": "log",
    "@": "target",
}


def parse_record(line: str) -> dict[str, Any]:
    """Parse one MI output line.

    A result record becomes `{"kind": "result", "token": …, "class": "done", "results": {…}}`;
    a stream record becomes `{"kind": "console", "text": "[New LWP 2804926]\\n"}`.
    """
    match = _RECORD.match(line.rstrip("\r\n"))
    if match is None:
        raise MiParseError(f"not an MI record: {line!r}")
    kind = _KINDS[match.group("kind")]
    token = int(match.group("token")) if match.group("token") else None
    body = match.group("body")

    if kind in ("console", "log", "target"):
        parser = _Parser(body)
        text = parser.cstring() if parser.peek() == '"' else body
        return {"kind": kind, "token": token, "text": text}

    parser = _Parser(body)
    out: dict[str, Any] = {"kind": kind, "token": token, "class": parser.bareword(), "results": {}}
    if parser.peek() == ",":
        parser.pos += 1
        out["results"] = parser.results()
    return out


def parse_records(lines: Iterable[str]) -> list[dict[str, Any]]:
    return [parse_record(line) for line in lines]


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_LWP = re.compile(r"\(\s*LWP\s+(\d+)\s*\)")
_TRAILING_INT = re.compile(r"(\d+)\s*\)?\s*$")
_HEX_TAIL = re.compile(r"0x[0-9a-fA-F]+\s*\)?\s*$")
_NO_SUCH_COMMAND = re.compile(r"undefined mi command|no such command|not a mi command|usage:", re.I)


def _tid_from_target_id(target_id: str | None) -> int | None:
    """`LWP 2804926`, `Thread 0x7f89… (LWP 2804927)`, `process 1234` → the thread id.

    The parenthesised form is tried first, and a bare `Thread 0x…` is refused rather than mined for
    digits: reading `80` out of `0x7f895def80` would be a wrong tid that looks like a right one.
    """
    if not target_id:
        return None
    text = target_id.strip()
    match = _LWP.search(text)
    if match:
        return int(match.group(1))
    if _HEX_TAIL.search(text):
        return None
    match = _TRAILING_INT.search(text)
    return int(match.group(1)) if match else None


def _hex_int(value: Any) -> int | None:
    """MI writes addresses as `0x0000007ff029f130` (zero-padded to the target's word size)."""
    if value is None:
        return None
    try:
        return int(str(value), 16)
    except ValueError:
        return None


_HEX_BYTES = re.compile(r"\A[0-9a-fA-F]*\Z")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]+")


def _address(value: Any) -> str | None:
    """The address inside whatever gdb printed.

    gdb dresses addresses up — `(struct wide *) 0x555c932018`, `0x7f87b906a4 <plugin_crash>`, `0x7ff029f130`
    — and those dressed strings are exactly what a caller has in hand, because they are what the UI shows.
    Refusing them would push a string-parsing chore onto every caller. The first hex token is the address.
    """
    match = _ADDRESS.search(str(value or ""))
    return match.group(0) if match else None


_READ_MIN = 64
"""The smallest range a refusal is believed for.

Believability improves as the request shrinks, and that is measured rather than assumed: at one address in the
practice core's partly-resident text mapping, 8 192 bytes, 1 024 and 896 all answer or refuse in ways that
contradict each other, while 128 answers and 3 refuses — the true hole there is three bytes wide. So the
subdivision stops at 64 bytes: "the dump has no bytes in these 64" is a claim gdb was asked about directly, at
a size it does not play games with, and the granularity of that claim is stated here instead of being implied.
"""

_READ_ROUNDS = 64
"""The most `-data-read-memory-bytes` commands one window may cost.

A contiguous window — a heap node, a live stack — needs **one**. The partly-resident text mapping above needs a
few. The ceiling is what keeps a pathologically fragmented window from turning one scroll into a thousand
commands, and whatever it cuts off is reported as `not_read` (a caller can ask again) rather than as `unread`
(the dump has nothing there).
"""


def _merged(ranges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adjacent ranges joined, keeping the order: two refusals side by side are one hole, not two."""
    out: list[dict[str, Any]] = []
    for item in sorted(ranges, key=lambda entry: int(entry["address"], 16)):
        previous = out[-1] if out else None
        if previous is not None:
            previous_end = int(previous["address"], 16) + int(previous["length"])
            if previous_end >= int(item["address"], 16):
                end = max(previous_end, int(item["address"], 16) + int(item["length"]))
                previous["length"] = end - int(previous["address"], 16)
                continue
        out.append(dict(item))
    return out


def _chunk_end(entry: Any) -> int | None:
    """Where one `memory=[…]` entry ends, or `None` if the entry is not one this can measure."""
    if not isinstance(entry, dict):
        return None
    contents = str(entry.get("contents") or "").strip()
    begin = _hex_int(entry.get("begin"))
    if not contents or begin is None or len(contents) % 2:
        return None
    return begin + len(contents) // 2


def _unread_within(addr: str, length: int, chunks: list[dict[str, Any]], not_read: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The window's bytes that were asked for and refused: everything no chunk covers and no round skipped.

    The three states are computed once, here, and they partition the window: `chunks` are the bytes gdb handed
    over, `not_read` are the ranges the round ceiling left unasked, and this is the rest — each byte in exactly
    one of them, which is what lets a caller add them up and get the window back.
    """
    start = _hex_int(addr)
    if start is None:
        raise MiParseError(f"not an address: {addr!r}")
    end = start + length
    unasked = [(_hex_int(item["address"]), _hex_int(item["address"]) + int(item["length"])) for item in not_read]
    unasked = [(low, high) for low, high in unasked if low is not None and high is not None]

    pieces: list[tuple[int, int]] = []
    cursor = start
    for chunk in chunks:  # already disjoint and in address order
        begin = _hex_int(chunk["address"])
        if begin is None:
            continue
        if begin > cursor:
            pieces.append((cursor, min(begin, end)))
        cursor = max(cursor, begin + int(chunk["length"]))
    if cursor < end:
        pieces.append((cursor, end))

    out: list[dict[str, Any]] = []
    for low, high in pieces:
        remaining = [(low, high)]
        for skip_low, skip_high in unasked:
            remaining = [piece for part in remaining for piece in _cut(part, skip_low, skip_high)]
        out.extend({"address": hex(low_), "length": high_ - low_} for low_, high_ in remaining if high_ > low_)
    return _merged(out)


def _cut(piece: tuple[int, int], low: int, high: int) -> list[tuple[int, int]]:
    """`piece` with `[low, high)` taken out of it — the whole piece when they do not overlap."""
    piece_low, piece_high = piece
    if high <= piece_low or low >= piece_high:
        return [piece]
    return [part for part in ((piece_low, min(piece_high, low)), (max(piece_low, high), piece_high)) if part[1] > part[0]]


def _within(entry: Any, start: int, end: int) -> bool:
    """Whether one `memory=[…]` entry says anything about `[start, end)`."""
    return isinstance(entry, dict) and (
        _chunk_end(entry) is not None
        and _hex_int(entry.get("begin")) is not None
        and _hex_int(entry.get("begin")) < end
        and _chunk_end(entry) > start
    )


def _disjoint(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The same bytes once, in address order, with the first reading of an overlap winning.

    A window is assembled from several `-data-read-memory-bytes` answers (see `read_memory`), and a gdb that
    skips forward inside a range can report bytes that another answer already covered. Two chunks over one
    address is not a cosmetic problem: `analysis/reading.py` decodes words per chunk, the frontend draws them,
    and an overlap would show one byte twice with two different neighbours.
    """
    out: list[dict[str, Any]] = []
    covered = 0
    for chunk in sorted(chunks, key=lambda item: int(item["address"], 16)):
        begin = int(chunk["address"], 16)
        stop = begin + chunk["length"]
        if out:
            previous_begin = int(out[-1]["address"], 16)
            covered = max(covered, previous_begin + out[-1]["length"])
        if begin < covered:
            if stop <= covered:
                continue
            cut = covered - begin
            chunk = {"address": hex(covered), "length": stop - covered, "bytes": chunk["bytes"][cut * 2 :]}
            begin = covered
        out.append(chunk)
        covered = max(covered, stop)
    return out


def _memory_reply(entries: Iterable[Any], addr: str, length: int) -> dict[str, Any]:
    """Turn `-data-read-memory-bytes` entries into chunks plus the holes between them.

    gdb answers a range it can only partly read by *truncating* the last chunk (measured: 8192 bytes
    asked for, `end` on the region boundary), so the request's own end is the only thing that says how
    much is missing. Nothing may be padded: a hole has to stay visible as a hole.

    Which is why the caller walks the window (`read_memory`): the entries handed in here are the runs of the
    *whole* request, gathered over as many commands as it took, and every gap between two of them is a hole
    gdb skipped.
    """
    start = _hex_int(addr)
    if start is None:
        raise MiParseError(f"not an address: {addr!r}")
    if length <= 0:
        raise ValueError("a memory read needs a positive length")

    chunks: list[dict[str, Any]] = []
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        contents = str(raw.get("contents") or "").strip()
        begin = _hex_int(raw.get("begin"))
        if not contents or begin is None:
            continue
        if len(contents) % 2 or not _HEX_BYTES.match(contents):
            raise MiParseError(f"contents is not an even run of hex digits: {contents[:64]!r}")
        chunks.append({"address": hex(begin), "length": len(contents) // 2, "bytes": contents.lower()})
    chunks = _disjoint(chunks)

    unread: list[dict[str, str]] = []
    cursor = start
    end = start + length
    for chunk in chunks:
        begin = int(chunk["address"], 16)
        if begin > cursor:
            unread.append({"address": hex(cursor), "length": min(begin, end) - cursor})
        cursor = max(cursor, begin + chunk["length"])
    if cursor < end:
        unread.append({"address": hex(cursor), "length": end - cursor})

    return {"address": hex(start), "length": length, "chunks": chunks, "unread": unread}


_NO_FUNCTION = re.compile(r"no function contains", re.I)

_APPLY_CHUNK = 256
"""How many frames one `frame apply` command may cover.

A range is not free at its far end — reaching frame A is work inside gdb before the range is even run — and
the command is a promise to the caller: it has to answer inside the command deadline, or the transport kills
gdb and the session dies with it. Measured on the 30 000-frame sample, a range costs roughly 0.9 ms per frame
plus the walk to its start: 256 frames took 0.03 s at level 0 and 1.04 s at level 20 000, and 1 024 took 0.20 s
and 4.23 s at the same two starts.

The ceiling was not a tidy-up. Asking for that whole stack in **one** command — which is what `/stack` with no
`limit` does, because the UI asks for all of it — was still unwinding when the 30 s deadline fired, and the
answer was `502 gdb-died`: a reasonable question, a killed debugger, and a session that had to be reopened.
256 frames keeps a whole-stack request to 118 bounded commands and a ~1 s worst case on this machine.
"""


def _instruction(entry: Any, line: int | None) -> dict[str, Any] | None:
    """One `asm_insns` entry, in the one shape the viewer needs.

    `text` is gdb's rendering, kept verbatim (tabs and all): re-spelling a mnemonic is how a disassembler
    starts lying about the instruction. `bytes` is absent unless it was asked for — some targets cannot
    produce opcodes, and an empty field would read as "no bytes" rather than "not requested".
    """
    if not isinstance(entry, dict):
        return None
    address = _hex_int(entry.get("address"))
    text = entry.get("inst")
    if address is None or not isinstance(text, str):
        return None
    instruction: dict[str, Any] = {"address": hex(address), "text": text}
    offset = _as_int(entry.get("offset"))
    if offset is not None:
        instruction["offset"] = offset
    if entry.get("func-name"):
        instruction["func"] = entry["func-name"]
    opcodes = entry.get("opcodes")
    if isinstance(opcodes, str) and opcodes.strip():
        instruction["bytes"] = " ".join(opcodes.split()).lower()
    if line is not None:
        instruction["line"] = line
    return instruction


def _disassembly_reply(
    entries: Iterable[Any],
    target: str,
    *,
    source: bool,
    limit: int,
    symbolized: bool,
    reason: str | None = None,
) -> dict[str, Any]:
    """Normalise `-data-disassemble`'s two answers into one reply.

    The modes answer in two different shapes: 0 and 2 give a flat list of instructions, 1 and 3 give a list
    of *source lines*, each carrying its own instructions. A code view wants both at once — which line the
    crash is on, and what that line compiled to — so the flat list is always built, and `lines` is filled
    in when gdb grouped them.

    `symbolized` says **how the answer was obtained**, not whether some instruction happened to have a
    name: the function form knows the function, its start and each instruction's offset into it; the range
    form is a window of bytes that may still name an instruction from a minimal symbol (measured on a libc
    range) while knowing nothing about where anything begins. `function` is therefore only reported for the
    function form — an `offset` from an unknown base is not an offset.

    `limit` is a bound on the *reply*, not on the request: asked for an address, gdb disassembles the whole
    enclosing function, and a 4000-instruction function is not a screen. Truncation is reported rather than
    silent, because "there is more" and "that is all" are different answers.
    """
    instructions: list[dict[str, Any]] = []
    lines: list[dict[str, Any]] = []
    truncated = False

    def take(entry: Any, line: int | None) -> bool:
        """Append one instruction; False once the limit is reached."""
        nonlocal truncated
        if limit and len(instructions) >= limit:
            truncated = True
            return False
        parsed = _instruction(entry, line)
        if parsed is None:
            return True
        instructions.append(parsed)
        return True

    for entry in entries:
        if truncated:
            break
        if not isinstance(entry, dict):
            continue
        group = entry.get("src_and_asm_line")
        if group is None:
            take(entry, None)
            continue
        line = _as_int(group.get("line"))
        group_instructions: list[dict[str, Any]] = []
        for raw in group.get("line_asm_insn") or []:
            before = len(instructions)
            if not take(raw, line):
                break
            if len(instructions) > before:
                group_instructions.append(instructions[-1])
        # A source line with no instructions is kept: it is a line the crash can be reported on (a
        # declaration, a brace) and dropping it would make the listing disagree with the file.
        lines.append(
            {
                "line": line,
                "file": group.get("file"),
                "fullname": group.get("fullname"),
                "instructions": group_instructions,
            }
        )

    start = _hex_int(target)
    function = instructions[0].get("func") if instructions else None
    # Where the *asked-for* address sits inside the function, when that address is one of the instructions.
    offset = next(
        (instruction["offset"] for instruction in instructions if instruction.get("address") == target and "offset" in instruction),
        None,
    )
    # The byte after the last instruction is only knowable when the opcodes were asked for — without them
    # nothing here says how long an instruction is, and guessing a word size would be an architecture
    # assumption the caller never made.
    end: str | None = None
    if instructions and all("bytes" in instruction for instruction in instructions):
        last = instructions[-1]
        end = hex(int(last["address"], 16) + len(last["bytes"].replace(" ", "")) // 2)
    return {
        "address": target,
        "range": {
            "start": instructions[0]["address"] if instructions else (hex(start) if start is not None else target),
            "last": instructions[-1]["address"] if instructions else None,
            "end": end,
        },
        "function": {"name": function, "offset": offset} if (symbolized and function) else None,
        "instructions": instructions,
        "lines": lines if source else [],
        "symbolized": symbolized,
        "truncated": truncated,
        "reason": reason,
    }


def _mi_quote(text: str) -> str:
    """An MI cstring. Expressions contain spaces and quotes; the grammar escapes both."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mi_unquote(text: str) -> str:
    """The inverse: one quoted MI payload back into the text gdb printed.

    A literal backslash is parked on a NUL while the escapes gdb actually uses are undone, because one pass
    would turn an escaped backslash followed by `n` into a newline.
    """
    body = text
    if body.startswith('"'):
        body = body[1:]
    if body.endswith('"'):
        body = body[:-1]
    body = body.replace("\\\\", "\x00")
    body = body.replace("\\n", "\n").replace('\\"', '"').replace("\\t", "\t")
    return body.replace("\x00", "\\")


def _field_of(variable_name: Any) -> str | None:
    """`var3.next.payload` → `payload`, when gdb sends no `exp` for a child."""
    if not isinstance(variable_name, str):
        return None
    return variable_name.rsplit(".", 1)[-1] or None


_POINTER_TAIL = re.compile(r"[\s*]+$")
_IDENTIFIER = re.compile(r"\A[A-Za-z_]\w*\Z")
_ARRAY_TYPE = re.compile(r"\A(?P<element>.+?)\s*\[\s*\d*\s*\]\Z")


def _int_literal(value: Any) -> int | None:
    """gdb answers `&…` with hex and `sizeof` with decimal; both mean a number."""
    if value is None:
        return None
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text, 10)
    except ValueError:
        return None


def _pointee(type_string: Any) -> str | None:
    """`struct node *` → `struct node`: a pointer's children are the pointee's fields,
    so offsets have to be asked about the pointee, not about the pointer."""
    text = (type_string or "").strip()
    stripped = _POINTER_TAIL.sub("", text)
    return stripped or None


def _array_element(type_string: Any) -> str | None:
    """`char [16]` → `char`: an array's children are elements, and their offsets are their index."""
    match = _ARRAY_TYPE.match((type_string or "").strip())
    return match.group("element").strip() if match else None



# --------------------------------------------------------------------------- #
# The transport
# --------------------------------------------------------------------------- #
class MiTransport(Transport):
    """Talks to one gdb about one dump over MI.

    Construct, then `start()`. Nothing is queried until `start()` has completed its handshake, and the
    handshake is what decides whether this dump is readable at all.
    """

    name = "mi"

    def __init__(
        self,
        *,
        gdb_path: str,
        core_path: str,
        exe_path: str | None = None,
        sysroot: str | None = None,
        solib_search_path: str | None = None,
        command_timeout_s: float = 30.0,
        probe_timeout_s: float = 20.0,
        shutdown_grace_s: float = 5.0,
        interpreter: str | None = None,
    ) -> None:
        self.gdb_path = gdb_path
        self.core_path = core_path
        self.exe_path = exe_path
        self.sysroot = sysroot
        self.solib_search_path = solib_search_path
        self.command_timeout_s = command_timeout_s
        self.probe_timeout_s = probe_timeout_s
        self.shutdown_grace_s = shutdown_grace_s
        self.interpreter = interpreter
        # What this transport has cost, counted where every command passes (docs/api.md §4). Without it the
        # promises of §1 and §4 — the core is loaded once, a repeated query sends nothing — are unobservable
        # from outside, and a promise nobody can observe is a sentence that stops being true.
        self.commands_sent = 0
        self.commands_by_op: dict[str, int] = {}
        self.timeouts = 0
        self.errors = 0

        self.gdb_version: str | None = None
        self.startup_records: list[str] = []
        """What gdb said while starting up (banner, warnings, `=library-loaded`). Kept for diagnostics."""
        self.warnings: list[str] = []
        """Log-stream lines gdb emitted while working, and the ones it emitted while *starting*.

        Only ever shown, never interpreted — but they have to be complete to be worth showing, and the startup
        lines were not: gdb says the important things about a core while it loads it. Measured on a core of
        another architecture handed to the wrong gdb: the whole account was
        *"warning: Couldn't find general-purpose registers in core file."* — printed during loading, kept in
        `startup_records`, and therefore absent from the message that reported the failure.
        """
        self._proc: GdbProcess | None = None
        self._caps: Capabilities | None = None
        self._crashed_thread: int | None = None
        self._register_names: list[str] | None = None
        self._selected_thread: int | None = None
        self._selected_frame: int | None = None
        """Where gdb is, thread *and* frame, so a selection is not repeated. See `_select_frame`."""
        self._stacks: dict[int, list[dict[str, Any]]] = {}
        self._args_loaded: set[int] = set()
        """Threads whose frame arguments are already in the cached frames."""
        self._located: dict[int, dict[int, dict[str, int | None]]] = {}
        # What a session was asked twice. `architecture.md` §4 promises that on-demand results are cached per
        # session — "asking for the same thread's stack twice must not send a second command to gdb" — and
        # measured 2026-09-26 it did: a repeated `/stack` cost 64 commands, because the per-frame queries
        # (`-stack-list-variables`, `&name`, `info address`, `sizeof`, the frame record's memory read) went
        # back to gdb every time even though the backtrace and the frame locations were already cached.
        # Keyed the way the question is asked, and cleared with the rest when the session closes.
        self._registers: dict[int, dict[str, Any]] = {}
        self._variables: dict[tuple[int, int], list[dict[str, Any]]] = {}
        self._arguments: dict[tuple[int, int, int], dict[int, list[dict[str, Any]]]] = {}
        """`(thread, low, high) → the frame arguments of that range`, which is asked for a *page* at a time."""
        self._slots: dict[tuple[int, int], list[dict[str, Any]]] = {}
        self._frame_rows: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
        """`thread → level → {sp, fp}`, asked frame by frame because MI's frame tuple has neither."""
        self._offsets: dict[tuple[str, str], int | None] = {}
        """`(type, field) → byte offset`, asked once per session — a layout does not change."""
        self._sizes: dict[str, int | None] = {}
        """`type → sizeof`, likewise; `None` remembers a type gdb could not spell."""

    # --- command line ------------------------------------------------------------------ #
    def argv_for(self, interpreter: str) -> list[str]:
        """The gdb command line for one interpreter.

        `sysroot` and `solib-search-path` are not optional decoration for a core that came from another
        machine: the core records absolute paths that do not exist here, and without these two settings
        every frame prints `??`.
        """
        argv = [
            self.gdb_path,
            "--nx",
            "-q",
            f"--interpreter={interpreter}",
            "-ex",
            "set pagination off",
            "-ex",
            "set confirm off",
        ]
        if self.sysroot:
            argv += ["-ex", f"set sysroot {self.sysroot}"]
        if self.solib_search_path:
            argv += ["-ex", f"set solib-search-path {self.solib_search_path}"]
        if self.exe_path:
            argv += [self.exe_path, self.core_path]
        else:
            argv += ["--core", self.core_path]
        return argv

    # --- lifecycle --------------------------------------------------------------------- #
    def _collect_startup_warnings(self) -> None:
        """What gdb said about this dump while it loaded it, kept in gdb's own words.

        The records are **not** one message each: gdb breaks its output wherever it likes, and it does. Measured
        on a core of another architecture handed to the wrong gdb, the stream was

            &"\nwarning: "                                              ← the prefix, alone
            &"Couldn't find general-purpose registers in core file.\n"  ← the sentence, next record

        so a payload is unquoted first and the *text* is assembled second; reading record by record collects the
        word `warning:` and throws the sentence away. Async records (`=`/`*`/`+`) are not messages and are
        skipped, and from the console stream only the lines gdb calls a warning are kept — the console also
        carries the banner and `Reading symbols from …`.
        """
        text = ""
        for chunk in self.startup_records:
            raw = str(chunk)
            marker = raw[:1]
            if marker in ("=", "*", "+"):
                continue
            payload = _mi_unquote(raw[1:] if marker in ("~", "&", "@") else raw)
            if marker == "~" and not payload.lstrip().startswith("warning:"):
                continue
            text += payload

        for line in text.splitlines():
            line = line.strip()
            if line and line not in self.warnings and len(self.warnings) < 100:
                self.warnings.append(line)

    @property
    def alive(self) -> bool:
        """Whether the gdb this transport is talking to still exists.

        A session asks this before every query, so that a debugger that died is reported as *gone* rather than
        as an answer about the core. Without it the transport's `GdbDied` reached the HTTP layer correctly but
        the session went on advertising itself as ready — half a fix, which is why this is asked for here.
        """
        return self._proc is not None and self._proc.alive

    @property
    def pid(self) -> int | None:
        """The gdb process, so a caller can say which one it is talking about — and a test can kill it."""
        return self._proc.pid if self._proc is not None else None

    def start(self) -> "MiTransport":
        candidates = [self.interpreter] if self.interpreter else list(INTERPRETERS)
        problems: list[str] = []
        for interpreter in candidates:
            proc = GdbProcess(self.argv_for(interpreter), command_timeout_s=self.command_timeout_s)
            try:
                proc.start()
                self._proc = proc
                # Everything gdb says while starting up (banner, `-ex` results, library notifications)
                # is discarded here, so the handshake's first command cannot read a stale `^done`.
                self.startup_records = proc.drain()
                self._collect_startup_warnings()
                self._handshake(interpreter)
                self.interpreter = interpreter
                return self
            except GdbError as exc:
                problems.append(f"{interpreter}: {exc}")
                proc.close(grace_s=2.0)
                self._proc = None
        raise GdbError("no usable MI interpreter — " + " ;; ".join(problems))

    def _handshake(self, interpreter: str) -> None:
        """`-thread-info` is the whole decision: it proves the interpreter works *and* that the core loaded."""
        results = self._result(self._exec("-thread-info", timeout=self.probe_timeout_s))
        threads = results.get("threads") or []
        if not threads:
            raise CoreNotLoaded(
                f"gdb started ({interpreter}) but reported no threads for {self.core_path!r}; "
                f"stderr: {self._proc.stderr_tail() if self._proc else ''}"
            )
        current = _as_int(results.get("current-thread-id"))
        self._crashed_thread = current
        self.gdb_version = self._version_from(self._exec("-gdb-version", timeout=self.probe_timeout_s))

    @staticmethod
    def _version_from(records: Iterable[dict[str, Any]]) -> str | None:
        """The version arrives either as a `version=` field or as the banner on the console stream."""
        for record in records:
            version = (record.get("results") or {}).get("version")
            if version:
                return str(version)
        for record in records:
            text = str(record.get("text") or "")
            if text.startswith("GNU gdb"):
                return text.strip()
        return None

    # --- plumbing ---------------------------------------------------------------------- #
    def _exec(self, command: str, *, timeout: float | None = None) -> list[dict[str, Any]]:
        if self._proc is None:
            raise GdbError("the transport has not been started")
        # Counted before it is sent, not after it returns: a command that timed out or was refused was still
        # sent, and hiding the ones that failed is how a cost report starts lying.
        op = command.split(" ", 1)[0] or command
        self.commands_sent += 1
        self.commands_by_op[op] = self.commands_by_op.get(op, 0) + 1
        try:
            records = parse_records(self._proc.command(command, timeout=timeout))
        except GdbTimeout:
            self.timeouts += 1
            raise
        except GdbError:
            self.errors += 1
            raise
        for record in records:
            if record.get("kind") == "log":
                # gdb's log stream is advice, not data: it is collected to be shown next to the session
                # (a cross gdb on Windows does warn about its host encoding, for instance) and ignored
                # by everything that reads records.
                text = str(record.get("text") or "").strip()
                if text and text not in self.warnings and len(self.warnings) < 100:
                    self.warnings.append(text)
        return records

    @staticmethod
    def _result(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
        for record in records:
            if record.get("kind") == "result":
                if record.get("class") == "done":
                    return record.get("results") or {}
                raise GdbError(f"gdb refused the command: {_refusal(record)}")
        raise GdbError("gdb sent no result record")

    def _probe_message(self, command: str) -> str | None:
        """`None` when gdb accepted the command, otherwise why it did not.

        The reason is the capability's `notes` entry: a disabled panel has to say what gdb said, not
        just go grey.
        """
        try:
            records = self._exec(command, timeout=self.probe_timeout_s)
        except GdbError as exc:
            return str(exc)
        for record in records:
            if record.get("kind") != "result":
                continue
            if record.get("class") == "done":
                return None
            return f"gdb refused it: {_refusal(record)}"
        return "gdb sent no result record"

    def _probe(self, command: str) -> bool:
        """Does gdb accept this command and answer `^done`? A refusal is a capability, not a failure."""
        return self._probe_message(command) is None

    # --- operations -------------------------------------------------------------------- #
    def capabilities(self) -> Capabilities:
        if self._caps is not None:
            return self._caps

        notes: dict[str, str] = {
            "memory_map": (
                "the memory map is not a gdb query: it comes from the core's own PT_LOAD segments and "
                "NT_FILE note (analysis/elf.py)"
            ),
        }
        # Asked as a question about *this dump*, not about the command. `-symbol-info-types` answers `done`
        # with an empty list when there is no DWARF at all, so probing "does gdb understand this command"
        # reported DWARF as present on a fully stripped practice target — and the viewer then offered a typed
        # tree that cannot exist. §13.6 names exactly this case as the one that must be *stated as absent*.
        dwarf = False
        try:
            answer = self._result(
                self._exec("-symbol-info-types --max-results 1", timeout=self.probe_timeout_s)
            )
            # Measured shape: `symbols={debug=[{filename=…, symbols=[{name="long long"}]}]}`, and on a fully
            # stripped target `symbols={}`. An empty answer is the dump saying it has no types.
            debug = (answer.get("symbols") or {}).get("debug") or []
            dwarf = any(entry.get("symbols") for entry in debug)
            if not dwarf:
                notes["dwarf_types"] = "this dump carries no DWARF types"
        except GdbError as exc:
            notes["dwarf_types"] = str(exc).splitlines()[0][:200]

        def asked(command: str, flag: str) -> bool:
            reason = self._probe_message(command)
            if reason:
                notes[flag] = reason
            return reason is None

        # `$pc` is the address that is certainly there: this dump has a thread with a program counter,
        # so a refusal here is about the command, not about the dump.
        memory_read = asked("-data-read-memory-bytes $pc 8", "memory_read")
        evaluate = asked("-data-evaluate-expression 1", "evaluate")

        expand = True
        try:
            created = self._result(self._exec("-var-create - * $pc", timeout=self.probe_timeout_s))
            self._var_delete(created.get("name"))
        except GdbError as exc:
            expand = False
            notes["expand"] = str(exc)

        # Both halves are probed: arguments for a whole stack, and the selected frame's locals. One
        # capability, because a stack view with arguments but no locals is not half usable — it is
        # misleading, and the note says which half is missing.
        arguments = True
        for command in ("-stack-list-arguments --simple-values 0 0", "-stack-list-variables --simple-values"):
            reason = self._probe_message(command)
            if reason:
                arguments = False
                notes["arguments"] = f"{command.split()[0]}: {reason}"
                break

        names = any(thread.get("name") for thread in self.threads())
        if not names:
            notes["thread_names"] = "no thread in this dump reports a name"

        self._caps = Capabilities(
            transport="mi",
            threads=True,
            backtrace=self._probe("-stack-list-frames 0 1"),
            registers=self._probe("-data-list-register-names"),
            memory_map=False,
            memory_read=memory_read,
            evaluate=evaluate,
            expand=expand,
            arguments=arguments,
            dwarf_types=dwarf,
            thread_names=names,
            core_notes=False,
            lock_owner=False,
            notes=notes,
        )
        return self._caps

    def threads(self) -> list[dict[str, Any]]:
        results = self._result(self._exec("-thread-info"))
        out: list[dict[str, Any]] = []
        for raw in results.get("threads") or []:
            num = _as_int(raw.get("id"))
            frame = raw.get("frame") or {}
            out.append(
                {
                    "num": num,
                    "tid": _tid_from_target_id(raw.get("target-id")),
                    "name": raw.get("name"),
                    "state": raw.get("state"),
                    "is_crashed": num is not None and num == self._crashed_thread,
                    # Not computed here: the frame count costs one query per thread, and the thread
                    # list must stay one query. `backtrace()` fills it in on demand.
                    "frame_count": None,
                    # The top frame comes free with -thread-info, and the thread list is much more
                    # useful with "where is this thread" than without it.
                    "func": frame.get("func"),
                    "pc": frame.get("addr"),
                    "arch": frame.get("arch"),
                }
            )
        return out

    def backtrace(
        self,
        thread_num: int,
        *,
        limit: int = 256,
        offset: int = 0,
        with_arguments: bool = False,
    ) -> dict[str, Any]:
        """The stack, whole and cached, sliced by `limit`/`offset`.

        `with_arguments` costs one extra query for the *entire* stack (not one per frame) and is off by
        default: the frame list is a summary, and the API decides when a caller has earned the detail.
        """
        frames = self._frames(thread_num)
        if with_arguments and thread_num not in self._args_loaded:
            arguments = self.frame_arguments(thread_num, low=0, high=max(0, len(frames) - 1))
            for frame in frames:
                frame["args"] = arguments.get(frame["level"], [])
            self._args_loaded.add(thread_num)

        return {
            "thread_num": thread_num,
            "total": len(frames),
            "frames": frames[offset : offset + limit],
        }

    def _frames(self, thread_num: int) -> list[dict[str, Any]]:
        """Every frame of one thread, fetched once and cached.

        Fetched whole because it gives an exact `total` for paging, and the second page is then free.
        Deep stacks are a known cost, to be revisited only if a real one shows up.
        """
        frames = self._stacks.get(thread_num)
        if frames is None:
            self._select_thread(thread_num)
            results = self._result(self._exec("-stack-list-frames"))
            is_crashed = thread_num == self._crashed_thread
            frames = [
                _frame(_labelled(raw, "frame"), is_crashed=is_crashed)
                for raw in results.get("stack") or []
            ]
            self._stacks[thread_num] = frames
        return frames

    def frame_arguments(self, thread_num: int, *, low: int = 0, high: int | None = None) -> dict[int, list[dict]]:
        """`-stack-list-arguments --simple-values LOW HIGH`.

        The `--simple-values` flag is not optional in gdb 13: without it the command is a usage error.
        An aggregate argument (an array) then comes back with a type and **no value at all** — which is
        different from a value that could not be read, and the caller has to keep them apart.

        Cached per *(thread, range)*, because a page of a stack is asked for again every time it is scrolled
        back to: the core is a snapshot, so the same range has the same arguments, and a repeated `/stack` is
        the promise `docs/api.md` §4 makes — "the same question must not go back to gdb". Measured, that
        promise held at **0** commands before arguments were added to a page, and adding them made a repeat cost
        one command until this cache existed (`tests/api/test_cost.py` is what noticed).
        """
        frames = self._frames(thread_num)
        top = high if high is not None else max(0, len(frames) - 1)
        key = (thread_num, low, top)
        cached = self._arguments.get(key)
        if cached is not None:
            return {level: [dict(argument) for argument in arguments] for level, arguments in cached.items()}
        self._select_thread(thread_num)
        results = self._result(self._exec(f"-stack-list-arguments --simple-values {low} {top}"))

        out: dict[int, list[dict]] = {}
        for raw in results.get("stack-args") or []:
            frame = _labelled(raw, "frame")
            level = _as_int(frame.get("level"))
            if level is None:
                continue
            out[level] = [_variable(argument, is_arg=True) for argument in frame.get("args") or []]
        self._arguments[key] = out
        return {level: [dict(argument) for argument in arguments] for level, arguments in out.items()}

    def frame_variables(self, thread_num: int, level: int = 0) -> list[dict]:
        """`-stack-list-variables --simple-values` on one selected frame: arguments and locals.

        Cached, and a copy is returned: the core does not change under a session, so the same question has the
        same answer, and a caller annotating its own row must not be able to edit what the session keeps.
        """
        key = (thread_num, level)
        cached = self._variables.get(key)
        if cached is not None:
            return [dict(variable) for variable in cached]
        self._select_frame(thread_num, level)
        results = self._result(self._exec("-stack-list-variables --simple-values"))
        variables = [_variable(raw) for raw in results.get("variables") or []]
        self._variables[key] = variables
        return [dict(variable) for variable in variables]

    def stack_frames(self, thread_num: int, *, low: int = 0, high: int | None = None) -> list[dict[str, Any]]:
        """Each frame's stack memory, and the frame record at its frame pointer.

        See `Transport.stack_frames`. The range is the measured one — `sp` of this frame to `sp` of its
        caller — and the record is decoded from memory and then **checked against the next frame**, because
        an ABI table says where the two words *would* be, not that there is a frame record there at all.
        """
        frames = self._frames(thread_num)
        if not frames:
            return []
        first = max(0, low)
        top = len(frames) - 1 if high is None else min(high, len(frames) - 1)
        key = (thread_num, first, top)
        cached = self._frame_rows.get(key)
        if cached is not None:
            return [dict(row) for row in cached]
        # One frame further up than asked for: a frame ends where its caller's stack begins, so the last
        # range in the slice needs the `sp` of the frame after it.
        located = self._frame_locations(thread_num, first, min(top + 1, len(frames) - 1))

        out: list[dict[str, Any]] = []
        for index in range(first, top + 1):
            frame = frames[index]
            caller = frames[index + 1] if index + 1 < len(frames) else None
            here = located.get(frame["level"]) or {}
            sp, fp = here.get("sp"), here.get("fp")
            caller_here = (located.get(caller["level"]) or {}) if caller else {}

            layout = FRAME_RECORDS.get(_arch_key(frame.get("arch")))
            if fp is None:
                record = _no_record("this frame has no frame pointer to read a record at")
            elif layout is None:
                record = _no_record(f"no frame-record layout is known for {frame.get('arch') or 'this architecture'!r}")
            else:
                read = self._read_frame_record(frame, fp)
                record = read if read is not None else _no_record("the frame record is not in this dump")
            if record["at"] is not None:
                record = _verify_record(record, caller_here, caller)

            # The extent is `sp` of this frame to `sp` of its caller. When there is no caller in the dump,
            # or the caller's stack does not begin above this frame's, there is no range to report — and
            # *why* is worth saying, because an empty extent is not the same answer as a broken chain.
            end = caller_here.get("sp")
            extent_why: str | None = None
            if end is None and record["verified"] and layout and fp is not None:
                # Only a *verified* record may stand in for a caller we cannot see: an unverified one is
                # exactly the case where the frame pointer turned out not to be a frame pointer.
                end = fp + layout.size
            if end is None:
                extent_why = "the caller is not in this dump"
            elif sp is not None and end <= sp:
                # Equal counts: a frame that allocated nothing owns no bytes, and a chain that repeats the
                # same `sp` looks identical from here. Saying which one it is is the *record's* job.
                end = None
                extent_why = "the caller's stack pointer is not above this frame's"

            out.append(
                {
                    "level": frame["level"],
                    "func": frame.get("func"),
                    # Every address in this reply is written one way. gdb pads its `addr=` to the target's
                    # word width (`0x000000555c921198`) while a value decoded out of memory is minimal
                    # (`0x555c921198`); leaving both as they come means a caller comparing `pc` with a
                    # record's `return_address` sees "different" for two equal addresses.
                    "pc": _hex(_int_literal(frame.get("pc"))),
                    "sp": _hex(sp),
                    "fp": _hex(fp),
                    "start": _hex(sp),
                    "end": _hex(end),
                    "extent_why": extent_why,
                    "record": record,
                }
            )
        self._frame_rows[key] = out
        return [dict(row) for row in out]

    def frame_slots(self, thread_num: int, level: int = 0) -> list[dict[str, Any]]:
        """Arguments and locals of one frame, each with the stack bytes it occupies.

        The variable list gives values, not positions, so the position is asked for separately — `&name`
        for an address and `info address` for the DWARF location that says *what kind* of place it is.
        Without the second question a variable in a register has no address, gets dropped, and the frame
        silently looks as if it had fewer variables than it has.

        `slot` is True for a variable that is **in this frame's memory**; the rest still carry their value
        and say where they are (`where`, `register`). `inside` is the extent check kept as corroboration:
        True, False, or None when the frame's end is unknown — gdb's own location expression is the
        authority on "is it in this frame", and an address range is a second opinion.
        """
        key = (thread_num, level)
        cached = self._slots.get(key)
        if cached is not None:
            return [dict(slot) for slot in cached]
        frames = self.stack_frames(thread_num, low=level, high=level)
        if not frames:
            raise GdbError(f"thread {thread_num} has no frame {level}")
        # The frame is selected **here**, not left to `frame_variables` below. That call answers from its cache
        # without touching gdb, and everything after it — `&(name)`, `info address` — is evaluated in whatever
        # frame gdb happens to be on. Measured: an `-O2` frame's register-resident variable came back
        # "unavailable" because its location was asked in the frame *above* it, which is the parent's `pc`
        # range and therefore a different answer, or none.
        self._select_frame(thread_num, level)
        start = _int_literal(frames[0]["start"])
        end = _int_literal(frames[0]["end"])
        pc = _int_literal(frames[0]["pc"])

        out: list[dict[str, Any]] = []
        for variable in self.frame_variables(thread_num, level):
            name = variable.get("name")
            expression = str(name) if name is not None else None
            address = _int_literal(_address(self._expression_text(f"&({expression})"))) if expression else None
            location = _variable_location(self._location_text(expression) if expression else None, pc)

            in_memory = location["where"] == "stack"
            inside = (
                (start <= address < end)
                if address is not None and start is not None and end is not None
                else None
            )
            size = self._sizeof(variable.get("type")) if in_memory else None
            out.append(
                {
                    **variable,
                    "expression": expression,
                    "address": _hex(address),
                    "size": size,
                    # The DWARF location decides: a register-resident variable has no bytes to draw, and a
                    # `static`'s address is not this frame's, however close it looks.
                    "slot": bool(in_memory and address is not None and size),
                    "where": location["where"],
                    "register": location["register"],
                    "location": location["location"],
                    "location_reason": location["reason"],
                    # True/False when the frame's extent is known, None when it is not.
                    "inside": inside,
                }
            )
        self._slots[key] = out
        return [dict(slot) for slot in out]

    def _console(self, command: str, *, timeout: float | None = None) -> str:
        """Run one CLI command inside gdb and hand back exactly what it printed.

        The transport's second and last place of this kind (the first is `info address`): some questions have no
        MI command at all — a variable's location, and `frame apply`, which is how a *range* of frames is asked
        about in one go. What comes back is text, and it stays text until a caller parses the one field it
        named; nothing here reshapes gdb's answer into something gdb did not say.

        The command is quoted as an MI cstring, so a format string with quotes in it survives the trip.
        """
        records = self._exec(f"-interpreter-exec console {_mi_quote(command)}", timeout=timeout)
        return "".join(
            str(record.get("text") or "") for record in records if record.get("kind") in ("console", "log")
        )

    def _location_text(self, expression: str) -> str | None:
        """`info address` for one variable, as text.

        There is no MI command for a variable's location: `-symbol-info-variables` returns the symbol, and
        `-stack-list-variables --all-values` returns nothing at all on a core. Hence the CLI, and hence `_console`.
        """
        try:
            return self._console(f"info address {expression}")
        except GdbError:
            return None

    def _read_frame_record(self, frame: dict[str, Any], fp: int) -> dict[str, Any] | None:
        """The frame record at `fp`, or `None` when this dump does not have those bytes.

        A frame record on a page a partial dump does not carry is a normal answer, not a warning per
        frame, so a refusal here is silence rather than a note — but it is *reported* by the caller
        (`why`), because "the record is not here" and "here is a record that disagrees" are different
        answers about the stack.
        """
        layout = FRAME_RECORDS.get(_arch_key(frame.get("arch")))
        if layout is None:
            return None
        try:
            chunk = self.read_memory(_hex(fp), layout.size)
        except GdbError:
            return None
        raw = chunk["chunks"][0]["bytes"] if chunk.get("chunks") else ""
        return _frame_record(frame.get("arch"), fp, bytes.fromhex(raw))

    def _frame_locations(self, thread_num: int, first: int, upto: int) -> dict[int, dict[str, int | None]]:
        """`sp` and `fp` of the frames in `[first, upto]`, in bounded batches and cached per level.

        There is no cheaper way: an MI frame tuple carries `addr` (the pc) and neither `sp` nor `fp`. The
        batches are `frame apply level A-B`, so the cost is a few commands per *window* instead of two per
        frame; whatever a batch cannot answer is asked one frame at a time.

        **It starts at `first`, not at frame 0**, and that is not a micro-optimisation. Measured on a core with
        a 30 000-frame stack: asking for twenty frames at offset 20 000 walked twenty thousand of them first —
        45 321 gdb commands and **52 seconds** for one scroll, where the window itself is twenty frames. A
        stack that deep is the case requirements §5 names, and a viewer whose cost is O(depth) per scroll has
        no answer for it.

        The batches are **chunked** (`_APPLY_CHUNK`), because one command that covers the whole stack is a
        command that cannot answer inside the deadline — and a command that misses the deadline takes the
        session with it. Measured, and it is why the ceiling exists: `/stack` with no `limit` on that same core
        asked for all 30 002 frames in one `frame apply`, the 30 s deadline fired while gdb was still unwinding,
        and the reply was `502 gdb-died` with the debugger killed underneath a perfectly reasonable question.
        """
        cached = self._located.setdefault(thread_num, {})
        frames = self._frames(thread_num)
        levels = [
            frame["level"]
            for frame in frames
            if frame["level"] is not None and first <= frame["level"] <= upto
        ]
        missing = [level for level in levels if level not in cached]
        if not missing:
            return cached

        self._select_thread(thread_num)
        for start in range(0, len(missing), _APPLY_CHUNK):
            chunk = missing[start : start + _APPLY_CHUNK]
            if not self._apply_locations(chunk[0], chunk[-1], cached):
                break

        # Whatever the batches left behind — a gdb older than 8.1 that has no `frame apply` at all, or a chunk
        # it refused — is asked one frame at a time. Not dead code: this transport is meant to work with
        # whatever gdb a machine has (the same rule as the capability probes), and a refusal is a slower answer
        # rather than a failed one.
        for level in missing:
            if level in cached:
                continue
            self._select_frame(thread_num, level)
            cached[level] = {
                "sp": _int_literal(self._expression_text("$sp")),
                "fp": _int_literal(self._expression_text("$fp")),
            }
        return cached

    def _apply_locations(self, first: int, upto: int, cached: dict[int, dict[str, int | None]]) -> bool:
        """`sp` and `fp` for a whole range of frames in **one** command. False if this gdb cannot.

        `frame apply level A-B` runs a command on each frame of a range, inside gdb, in one pass — which is the
        whole point: selecting a frame is O(its depth) *inside gdb* (measured: 5 ms at level 0, 549 ms at level
        20 000, and 536 ms again after any `-thread-select`, which resets gdb's frame cache), so two commands per
        frame made a window of a deep stack cost the depth. Measured on a 30 000-frame stack: 21 frames cost
        92 ms here against 549 ms for the first selection alone the old way.

        The output is parsed by its own markers rather than by counting lines: gdb prints `#<level> …` before
        each frame's output, so a frame whose `$sp` cannot be read — a corrupted stack — leaves a gap that does
        not shift everything after it.
        """
        # A raw string, and not for style: this format belongs to **gdb's** printf, not to Python's. Written as
        # an ordinary literal, `\n` is a newline in Python before gdb ever sees it, and gdb then receives a
        # command broken over two lines — measured, and the only symptom is `Undefined command: ""`, because
        # the second half of the command reads to gdb as an empty command name.
        shape = r"%p %p\n"
        command = f'frame apply level {first}-{upto} printf "{shape}", $sp, $fp'
        try:
            text = self._console(command)
        except GdbError:
            return False

        level: int | None = None
        found = 0
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#"):
                head = line[1:].split(" ", 1)[0]
                level = int(head) if head.isdigit() else None
                continue
            if level is None:
                continue
            parts = line.split()
            if len(parts) != 2:
                continue  # a refusal or a note, not a pair: the next `#level` re-synchronises
            sp, fp = _int_literal(parts[0]), _int_literal(parts[1])
            if sp is None and fp is None:
                continue  # two tokens that are not numbers are still a note
            # Either may be None: gdb prints some registers as decimal (`549405564880`) and a frame whose
            # `$fp` cannot be read still has an `$sp`. `_int_literal` is the one parser for both forms.
            cached[level] = {"sp": sp, "fp": fp}
            found += 1
            level = None
        return found > 0

    def stack_pointer(self, thread_num: int) -> int | None:
        """The stack pointer of this thread's current frame, asked as `$sp`.

        `$sp` and not `registers()["sp"]`: the stack pointer has a different *name* on every architecture —
        `rsp` on x86-64, `esp` on i386, `sp` on aarch64 and MIPS — and the report had that name written into
        it. Measured with three real cores: an x86-64 core read by the *matching* gdb was reported as "gdb could
        not read this core's registers", because the summary went looking for a key called `sp`. gdb's `$sp` is
        the same question on every target it knows, which is why it is asked here instead of adding a table that
        grows with every architecture.

        None means gdb did not give one: an architecture this gdb cannot read, or a core whose registers are
        not in it. That is an answer to report, not an exception to raise from deep inside a parser.
        """
        located = self._frame_locations(thread_num, 0, 0)
        return (located.get(0) or {}).get("sp")

    def registers(self, thread_num: int) -> dict[str, str]:
        """One thread's registers, cached for the session's life.

        A core is a snapshot: a thread's registers cannot change while the session holds it, so this follows
        the same rule as the backtrace and the frame rows — the second question is answered by the session. It
        matters because more than one view asks (the registers endpoint and the stack window both do), and a
        copy is returned rather than the cached dictionary.
        """
        cached = self._registers.get(thread_num)
        if cached is not None:
            return dict(cached)
        if self._register_names is None:
            names = self._result(self._exec("-data-list-register-names")).get("register-names") or []
            self._register_names = [str(name) for name in names]

        # Registers in gdb belong to the *selected frame*, so frame 0 is named rather than assumed: a thread's
        # registers are the innermost frame's, and after a deep query the current frame is not that.
        self._select_frame(thread_num, 0)
        values = self._result(self._exec("-data-list-register-values x")).get("register-values") or []

        out: dict[str, str] = {}
        for entry in values:
            index = _as_int(entry.get("number"))
            value = entry.get("value")
            if index is None or not value:
                continue
            if 0 <= index < len(self._register_names) and self._register_names[index]:
                out[self._register_names[index]] = str(value)
        self._registers[thread_num] = out
        return dict(out)

    def memory_map(self) -> dict:
        raise Unsupported(
            "the memory map is not a gdb query: it comes from the core's own PT_LOAD segments and "
            "NT_FILE note (analysis/elf.py)"
        )

    def read_memory(self, addr: str, length: int) -> dict[str, Any]:
        """`-data-read-memory-bytes`, holes preserved — and **the whole window asked for**, not just its first run.

        One command is not enough, and this is measured rather than assumed. Two facts about gdb, both on the
        practice core's `crash_target` text mapping (8 192 bytes at `0x…610000`, from the executable's file
        offset 12 288), which is only partly resident:

        * **a run ends at the first byte gdb cannot reach.** Asked for 8 192 bytes, gdb stops at `0x…6115d5` and
          says nothing about the rest — so the reader used to call 2 603 bytes "not in this dump" while they
          were sitting right there: asked again from `0x…6115d5`, gdb skips three missing bytes and hands over
          253 more. Reporting present bytes as absent is the same class of lie as reporting absent bytes as
          zero, which is what this walk exists to stop;
        * **whether gdb answers at all depends on how much was asked for.** From `0x…6115d5`, 896 bytes answer
          and 1 024 refuse — with the same data at the same addresses in between. So a refusal is only evidence
          about the bytes it covered *at the size it was asked*, and the walk narrows to `_READ_PROBE` bytes
          before it believes one.

        Every range this reports as `unread` was therefore asked for **exactly**, at a size gdb answers, and
        refused: that is what makes "the dump has no bytes here" a measurement rather than an inference. A skip
        gdb reports inside an answer is checked the same way before it is called a hole. When the round ceiling
        is reached the remainder goes in `not_read` — "not asked about", which a caller can act on — never in
        `unread`.
        """
        target = _address(addr)
        if target is None:
            raise GdbError(f"not an address: {addr!r}")
        start = int(target, 16)
        entries: list[Any] = []
        holes: list[dict[str, Any]] = []
        not_read: list[dict[str, Any]] = []
        refusals: list[str] = []
        not_read: list[dict[str, Any]] = []
        self._cover(start, start + length, entries, not_read, _READ_ROUNDS, refusals)

        if not entries and not not_read:
            # Nothing came back and nothing was left unasked: every byte of the window was asked for and refused.
            # This is the "none of it could be read" case, which the API reports as `422 unreadable` rather than as
            # a window full of holes — and it carries **gdb's own words**, because a refusal that loses its
            # sentence is a refusal nobody can act on.
            why = refusals[0] if refusals else "gdb refused the command"
            raise Unreadable(f"{target} for {length} bytes is not in this dump: {why}")

        reply = _memory_reply(entries, target, length)
        reply["unread"] = _unread_within(target, length, reply["chunks"], not_read)
        if not_read:
            reply["not_read"] = _merged(not_read)
        return reply

    def _cover(
        self,
        start: int,
        end: int,
        entries: list[Any],
        not_read: list[dict[str, Any]],
        budget: int,
        refusals: list[str],
    ) -> int:
        """Ask for `[start, end)` and keep subdividing until every byte has either been answered or been asked.

        Two measurements shape this, both in `read_memory`'s docstring: a run stops at the first byte gdb cannot
        reach, and whether gdb answers *at all* depends on how much was asked for. So neither "it stopped here"
        nor "it refused" is believed about a byte until the range has been cut down to `_READ_MIN` — and an
        answer that begins late sends the range it skipped back through the same process, which is how bytes a
        long request hides (measured: 379 of them behind a skip gdb reported as 383) come back.

        Two things are recorded: the entries that answered, and the ranges that were **never asked about**
        because the budget ran out. What is left — the bytes that were asked for and refused — is the difference,
        worked out from the window in `_unread_within`, so a byte cannot be in two states at once.
        """
        while start < end:
            if budget <= 0:
                not_read.append({"address": hex(start), "length": end - start})
                return 0
            budget -= 1
            answered, refusal = self._read_once(start, end - start)
            asked_end = end
            if answered is None:
                if refusal:
                    refusals.append(refusal)
                if end - start <= _READ_MIN:
                    return budget  # asked for exactly these bytes, refused: they are not in the dump
                middle = start + (end - start) // 2
                budget = self._cover(start, middle, entries, not_read, budget, refusals)
                start = middle
                continue

            # Clamped to the range that was asked about: gdb's answer is evidence about the bytes it was asked
            # for, and nothing beyond them.
            runs = [
                (max(begin, start), min(stop, asked_end))
                for begin, stop in ((_hex_int(entry.get("begin")), _chunk_end(entry)) for entry in answered)
                if begin is not None and stop is not None and min(stop, asked_end) > max(begin, start)
            ]
            if not runs:
                # An answer with nothing in it, at a size that answers: cut it in half if there is room,
                # otherwise say it was not asked about rather than let it look like absent bytes.
                if end - start > _READ_MIN:
                    middle = start + (end - start) // 2
                    budget = self._cover(start, middle, entries, not_read, budget, refusals)
                    start = middle
                    continue
                not_read.append({"address": hex(start), "length": end - start})
                return budget

            first = min(begin for begin, _stop in runs)
            last = max(stop for _begin, stop in runs)
            if first > start:
                # gdb skipped these bytes. It may be right or it may be hiding data, so they go back through the
                # same subdivision rather than being called missing on gdb's say-so.
                budget = self._cover(start, first, entries, not_read, budget, refusals)
            entries.extend(entry for entry in answered if _within(entry, start, asked_end))
            if last >= end:
                return budget
            start = min(last, end)
        return budget

    def _read_once(self, start: int, length: int) -> tuple[list[Any] | None, str]:
        """One `-data-read-memory-bytes`: `(entries, "")`, or `(None, gdb's own words)` when it refuses.

        A refusal here is a statement about the *dump*, so a transport failure never comes back this way: a dead
        or unresponsive gdb raises. Measured the hard way — a killed child made every read of a perfectly mapped
        address answer "not in this dump", with the transport's own failure text appended, and nothing above had
        a chance to notice.
        """
        try:
            results = self._result(self._exec(f"-data-read-memory-bytes {hex(start)} {length}"))
        except (GdbDied, GdbTimeout):
            raise
        except GdbError as exc:
            if _NO_SUCH_COMMAND.search(str(exc)):
                raise Unsupported(f"this gdb has no -data-read-memory-bytes: {exc}") from exc
            return None, str(exc)
        return list(results.get("memory") or []), ""

    def disassemble(
        self,
        address: str,
        *,
        end: str | None = None,
        source: bool = False,
        opcodes: bool = False,
        allow_unsymbolized: bool = False,
        limit: int = 512,
    ) -> dict[str, Any]:
        """`-data-disassemble`, in the two forms it actually accepts.

        Measured on GDB 13.3 (Arm GNU Toolchain): the documented `-a ADDRESS -c COUNT` is **refused**
        outright (`Unknown option 'c'`), and `-n COUNT` exists only for the `-f FILE -l LINE` form. So a
        caller can ask for an address, or for a range, and nothing else.

        * Address form (`-a`): gdb disassembles the whole enclosing **function**, naming it and offsetting
          every instruction from its start. It refuses when no function contains the address — which is the
          correct answer for a stripped or non-executable address, and is returned as `reason`.
        * Range form (`-s`/`-e`): answers for any bytes the dump can reach, **including data**. Measured:
          the heap address `0x55ac5bf2a0` comes back as `udf #1` — a real instruction the program never
          executed. It is therefore only used when the caller has established that the address is code (the
          core's `PT_LOAD` permissions, `analysis/elf.py`) and passes `allow_unsymbolized`.

        An unmapped address refuses in both forms (`Cannot access memory at address …`), and mode 1/3 needs
        no source file to be readable — the line numbers and file names come from DWARF, and the *text* is
        the backend's business (`set substitute-path`, then read the file).
        """
        target = _address(address)
        if target is None:
            raise GdbError(f"not an address: {address!r}")
        # One canonical form per reply. `_address` keeps the token exactly as gdb printed it — usually
        # zero-padded to the word size (`0x0000007fb189078c`) — while every instruction here is written with
        # `hex()`. Comparing the two, or returning both, is how a reply ends up with two spellings of the
        # same address and a caller matching on the string misses.
        start = _hex_int(target)
        if start is None:
            raise GdbError(f"not an address: {address!r}")
        target = hex(start)
        mode = (3 if opcodes else 1) if source else (2 if opcodes else 0)

        # A caller who names an end is asking for *that range*, not for the function around it: falling
        # through to the function form would answer a different question (measured: -a on an address inside
        # a function returns the whole function, however narrow the range asked for).
        if end:
            given = _hex_int(_address(end))
            if given is None:
                raise GdbError(f"not an address: {end!r}")
            results = self._result(
                self._exec(f"-data-disassemble -s {target} -e {hex(given)} -- {mode}")
            )
            return _disassembly_reply(
                results.get("asm_insns") or [], target, source=source, limit=limit, symbolized=False
            )

        # Otherwise the function form first: it is the one that knows what the bytes *are*.
        try:
            results = self._result(self._exec(f"-data-disassemble -a {target} -- {mode}"))
        except GdbError as exc:
            if _NO_SUCH_COMMAND.search(str(exc)):
                raise Unsupported(f"this gdb has no -data-disassemble: {exc}") from exc
            if not _NO_FUNCTION.search(str(exc)):
                # "Cannot access memory", a bad range, anything else: a fact about this dump.
                return _disassembly_reply([], target, source=source, limit=limit, symbolized=False, reason=str(exc))
            if not allow_unsymbolized:
                return _disassembly_reply([], target, source=source, limit=limit, symbolized=False, reason=str(exc))
        else:
            return _disassembly_reply(
                results.get("asm_insns") or [], target, source=source, limit=limit, symbolized=True
            )

        # Range form, for code gdb has no symbol for. Only the caller can say the bytes are code, and it
        # said so; the window is generous because instruction length is not known ahead of the answer.
        given = _hex_int(_address(end)) if end else None
        finish = hex(given) if given is not None else hex(start + max(1, limit) * 8)
        try:
            results = self._result(self._exec(f"-data-disassemble -s {target} -e {finish} -- {mode}"))
        except GdbError as exc:
            return _disassembly_reply([], target, source=source, limit=limit, symbolized=False, reason=str(exc))
        return _disassembly_reply(
            results.get("asm_insns") or [], target, source=source, limit=limit, symbolized=False
        )

    def evaluate(self, expression: str) -> dict[str, Any]:
        """One expression, one value, one DWARF type.
        Built on a floating variable rather than `-data-evaluate-expression` because only the variable
        form answers with a `type=` as well as a `value=`, and the type is what the typed view is for.

        **An expression is evaluated in a scope, and gdb's scope is the frame it is on.** A name from the crash
        frame (`head`, the root of the demo's typed walk) is only in scope there, so this evaluates in the
        innermost frame of the selected thread — which is where `-thread-select` used to leave gdb as a side
        effect, and which is now said out loud (one `-stack-select-frame 0`, skipped when we are already there).
        A name from an *outer* frame needs that frame selected, which is what `frame_variables` does.
        """
        self._expression_scope()
        created = self._var_create(expression)
        try:
            summary = _var_summary(expression, created)
            summary["size"] = self._sizeof(_pointee(created.get("type")))
            summary["address"] = self._object_address(expression, created)
            return summary
        finally:
            self._var_delete(created.get("name"))

    def expand(self, expression: str) -> dict[str, Any]:
        """One level of children — exactly what one click on a pointer should cost.

        Evaluated in the innermost frame of the selected thread, like `evaluate`; see the note there.

        Each child comes back with the expression that expands *it*, so walking a chain is: expand what
        the user clicked, render the children, offer the ones that have children as clicks again.

        Each child also comes back with `offset` and `size` — where the field *is*, in bytes — because a
        structure laid over memory is drawn on the bytes it occupies, and a value without a position
        cannot be drawn. Same command family as `evaluate` (`-data-evaluate-expression`), so it costs
        two extra queries per field, **cached per type**: `&((T *)0)->field` and `sizeof(field type)`.
        A field whose address cannot be taken (a bit-field, or a type gdb cannot spell as C) keeps
        `offset: None` rather than a guess.
        """
        self._expression_scope()
        created = self._var_create(expression)
        name = created.get("name")
        try:
            summary = _var_summary(expression, created)
            parent_type = created.get("type")
            summary["size"] = self._sizeof(_pointee(parent_type))
            summary["address"] = self._object_address(expression, created)
            results = self._result(self._exec(f"-var-list-children --all-values {name}"))
            children = [
                _child(
                    _labelled(raw, "child"),
                    parent=expression,
                    parent_type=parent_type,
                )
                for raw in results.get("children") or []
            ]
            self._with_layout(children, parent_type)
            summary["children"] = children
            return summary
        finally:
            self._var_delete(name)

    # --- helpers ----------------------------------------------------------------------- #
    def _with_layout(self, children: list[dict[str, Any]], parent_type: str | None) -> None:
        """Where each child sits inside its parent, in bytes.

        Offsets are asked of gdb — `&((T *)0)->field` is a constant expression, so no memory is touched
        — and sizes come from the *type*, so both are cached per type across the whole session. A
        pointer parent's children are the pointee's fields, and an array parent's children are elements
        whose offset is their index, which is why this reads the parent type rather than the child's.
        """
        pointee = _pointee(parent_type)
        element = _array_element(parent_type or "")
        element_size = self._sizeof(element) if element else None

        for index, child in enumerate(children):
            field = child.get("field")
            if element is not None:
                child["offset"] = index * element_size if element_size else None
            elif pointee and isinstance(field, str) and _IDENTIFIER.match(field):
                child["offset"] = self._offset_of(pointee, field)
            else:
                # `*head` (a pointer's own pointee) and array indices have no field to take the address
                # of; refusing beats inventing a position.
                child["offset"] = None
            child["size"] = self._sizeof(child.get("type"))

    def _offset_of(self, type_name: str, field: str) -> int | None:
        key = (type_name, field)
        if key not in self._offsets:
            self._offsets[key] = self._expression_int(f"&(({type_name} *)0)->{field}")
        return self._offsets[key]

    def _sizeof(self, type_string: str | None) -> int | None:
        if not type_string:
            return None
        key = type_string.strip()
        if key not in self._sizes:
            self._sizes[key] = self._expression_int(f"sizeof({key})")
        return self._sizes[key]

    def _expression_int(self, expression: str) -> int | None:
        """One constant expression as an integer; `None` when gdb will not have it."""
        return _int_literal(self._expression_text(expression))

    def _expression_text(self, expression: str) -> str | None:
        try:
            results = self._result(self._exec(f"-data-evaluate-expression {_mi_quote(expression)}"))
        except GdbError:
            return None
        value = results.get("value")
        return str(value) if value is not None else None

    def _object_address(self, expression: str, created: dict[str, Any]) -> str | None:
        """Where the object this expression names actually lives.

        A pointer's `value=` **is** its address; anything else (a struct, an array, a local) prints as its
        contents — `{...}`, `[16]`, `4` — and the address has to be asked for with `&`. Without this the
        viewer has a shape with no position, which is a shape it cannot draw.
        """
        if str(created.get("type") or "").strip().endswith("*"):
            return _address(created.get("value"))
        return _address(self._expression_text(f"&({expression})"))

    def _var_create(self, expression: str) -> dict[str, Any]:
        """`-var-create - * "expr"` — `-` means "you choose the name", `*` means "use the current frame"."""
        results = self._result(self._exec(f"-var-create - * {_mi_quote(expression)}"))
        if not results.get("name"):
            raise GdbError(f"gdb created no variable for {expression!r}: {results}")
        return results

    def _var_delete(self, name: Any) -> None:
        """Best-effort cleanup. A variable that outlives its query is clutter, not a reason to fail."""
        if not name:
            return
        try:
            self._exec(f"-var-delete {name}")
        except GdbError as exc:
            self._note(f"gdb variable {name} could not be deleted: {exc}")

    def _note(self, text: str) -> None:
        if text not in self.warnings and len(self.warnings) < 100:
            self.warnings.append(text)

    def _expression_scope(self) -> None:
        """Put gdb back on the innermost frame of the selected thread, for an expression to be evaluated in."""
        if self._selected_thread is not None:
            self._select_frame(self._selected_thread, 0)

    def _select_frame(self, thread_num: int, level: int) -> None:
        """Put gdb on one frame of one thread — the *pair*, because a thread switch resets the frame.

        `-thread-select` has a side effect the rest of this module used to lean on: it selects frame 0. So
        `frame_variables` skipped its `-stack-select-frame` at level 0 and asked "the current frame's variables"
        — correct only as long as every call re-selected the thread. Once the redundant selection was skipped
        (see `_select_thread`), a level-0 query after a deep one answered with the deep frame's variables; the
        practice suite caught it immediately with `KeyError: 'target'` on an `-O2` frame.

        Naming the frame explicitly is also what makes the *cache* of that selection safe: gdb's registers and
        variables are properties of the selected frame, not of the thread.
        """
        if self._selected_thread == thread_num and self._selected_frame == level:
            return
        self._select_thread(thread_num)
        self._result(self._exec(f"-stack-select-frame {level}"))
        self._selected_frame = level

    def _select_thread(self, thread_num: int) -> None:
        """Switching threads is what makes backtrace/registers meaningful; a bad number is a real error.

        **Selecting a thread that is already selected is skipped, and that is a performance fix with a
        measured cause.** `-thread-select` resets gdb's frame cache, so the next `-stack-select-frame N` pays
        the whole unwind again: on a core with 30 000 frames, selecting frame 20 000 costs 5 ms while the
        thread stays put and **536 ms** after a re-selection. Every per-frame query used to re-select, so a
        twenty-frame window at that depth took 11.9 seconds — nearly all of it this one reset, once per frame.
        Nothing else in this transport switches threads, so the remembered number stays true.
        """
        if self._selected_thread == thread_num:
            return
        records = self._exec(f"-thread-select {thread_num}")
        results = self._result(records)
        # gdb 13 answers `^done,new-thread-id="3"`; older ones may say nothing useful. Either way, a
        # refused selection raises above, so nothing has to be interpreted here.
        _ = results
        self._selected_thread = thread_num

    def close(self) -> None:
        self._selected_thread = None
        self._selected_frame = None
        if self._proc is not None:
            self._proc.close(grace_s=self.shutdown_grace_s)
            self._proc = None
        self._caps = None
        self._stacks.clear()
        self._registers.clear()
        self._variables.clear()
        self._slots.clear()
        self._frame_rows.clear()
        self._arguments.clear()
        self._args_loaded.clear()
        self._located.clear()
        self._offsets.clear()
        self._sizes.clear()


def _labelled(entry: Any, label: str) -> Any:
    """MI wraps list elements in a label: `stack=[frame={…},frame={…}]`.

    The parser reads that as `[{"frame": {…}}, …]`, so the label has to come off before the fields are
    read. Any other shape is returned untouched, because guessing would hide a protocol change.
    """
    if isinstance(entry, dict) and set(entry) == {label}:
        return entry[label]
    return entry


def _refusal(record: dict[str, Any]) -> str:
    """gdb's own words for a refusal.

    The payload is usually `{"msg": "Unable to read memory."}`, and a message is what the user needs —
    not a Python dict repr in the middle of a sentence.
    """
    results = record.get("results")
    if isinstance(results, dict) and results.get("msg"):
        return str(results["msg"])
    return str(results)


def _var_summary(expression: str, created: dict[str, Any]) -> dict[str, Any]:
    """The value and type of one expression, without its children."""
    return {
        "expression": expression,
        "type": created.get("type"),
        "value": created.get("value"),
        "num_children": _as_int(created.get("numchild")) or 0,
    }


def _child(raw: Any, *, parent: str | None = None, parent_type: str | None = None) -> dict[str, Any]:
    """One child of an expanded expression.

    `field` is the name *inside* the parent (`next`); `expression` is the full one to expand next, which
    is the whole point of returning children — the caller never composes C by hand. gdb names the child
    `var3.next` and also reports the field name as `exp`; the full name is kept for diagnostics.
    """
    entry = raw if isinstance(raw, dict) else {}
    field = entry.get("exp") or _field_of(entry.get("name"))
    return {
        "field": field,
        "expression": _step(parent, parent_type, field) if parent and field else None,
        "type": entry.get("type"),
        "value": entry.get("value"),
        "num_children": _as_int(entry.get("numchild")) or 0,
        "variable": entry.get("name"),
    }


def _step(parent: str, parent_type: str | None, field: str) -> str:
    """The next query, from the shape of the parent.

    A pointer parent's children are the pointee's fields, so the step is `->`; an array's children are
    indices, so it is `[i]`; anything else is a member access. If this ever produces something gdb
    refuses, the refusal is shown as-is — a wrong jump is worth less than an honest one.
    """
    kind = (parent_type or "").strip()
    if kind.endswith("*"):
        return f"{parent}->{field}"
    if "[" in kind or field.isdigit():
        return f"{parent}[{field}]"
    return f"{parent}.{field}"



@dataclass(frozen=True)
class _FrameRecord:
    """How one architecture's ABI lays out the frame record a frame pointer points at.

    Keyed by **architecture, not operating system**: QNX on aarch64 is AAPCS64 and QNX on x86_64 is SysV,
    so this one table covers Linux and QNX alike. What an OS changes is metadata — thread stacks, guard
    pages, the shape of a core note — and that is gdb's business, not this table's. An architecture that
    is not here gets no frame-record fields rather than a guess.
    """

    word: int
    saved_fp_at: int
    return_address_at: int
    size: int
    """The whole record, so reading it never has to guess how much to read."""


FRAME_RECORDS: dict[str, _FrameRecord] = {
    "aarch64": _FrameRecord(word=8, saved_fp_at=0, return_address_at=8, size=16),
    "x86_64": _FrameRecord(word=8, saved_fp_at=0, return_address_at=8, size=16),
    "arm": _FrameRecord(word=4, saved_fp_at=0, return_address_at=4, size=8),
    "i386": _FrameRecord(word=4, saved_fp_at=0, return_address_at=4, size=8),
}


_LOCATION_RANGE = re.compile(r"Range\s+(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s*:\s*(.*)")
_REGISTER_LOCATION = re.compile(r"a variable in \$(\w+)", re.IGNORECASE)
_BRACKETED_REGISTER = re.compile(r"\[\$(\w+)\]")
_STACK_OPS = ("DW_OP_fbreg", "DW_OP_breg")
"""Frame-relative memory: the frame base or a register base plus an offset. This is what "in this frame"
means, and it is why the extent check is corroboration rather than the entry requirement — a frame whose
caller is not in the dump has no known end, and that must not erase a variable gdb places inside it."""

_STATIC_OPS = ("DW_OP_addr",)
"""A fixed address (a `static`, a global): a real place, but not this frame's, so it is not a slot."""

_COMPUTED_OPS = ("DW_OP_entry_value", "DW_OP_stack_value", "DW_OP_piece", "DW_OP_bit_piece")


def _variable_location(text: Any, pc: int | None) -> dict[str, Any]:
    """Where gdb says one variable lives, from `info address`.

    gdb answers with a DWARF location expression, and for optimised code with *several*, one per range of
    program counters:

        Symbol "total" is multi-location:
          Base address 0x728  Range 0x…728-0x…73c: a variable in $x0
          Range 0x…73c-0x…743: a variable in $x6
          Range 0x…743-0x…760: a complex DWARF expression:
             0: DW_OP_fbreg -4

    **A variable's location is a function of the pc**, so the range containing *this frame's* pc is the
    answer. Taking the first range, or any of them, is how a viewer ends up claiming a variable is in a
    register it left three instructions ago — which is worse than saying nothing, because it looks true.

    Returns `{"where", "register", "location", "reason"}` with `where` one of:

      * `stack`   — in this frame's memory (`DW_OP_fbreg`, `DW_OP_breg`); the caller can address it;
      * `register`— in `$x0`-style storage, either directly (`a variable in $x0`) or as the value it held on
                    entry (`DW_OP_entry_value` + `DW_OP_reg0 [$x0]` — which for an argument *is* the answer
                    to "which register was it passed in");
      * `static`  — at a fixed address (`DW_OP_addr`): real, but not this frame's;
      * `computed`— the expression yields a value, not a place (`DW_OP_stack_value`): there are no bytes and
                    no register to point at;
      * `unavailable`— optimised out, no symbol, or no location described at this pc.
    """
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    if not lines:
        return {"where": "unavailable", "register": None, "location": None, "reason": "gdb said nothing"}

    ranges: list[tuple[int, int, list[str]]] = []
    for index, line in enumerate(lines):
        match = _LOCATION_RANGE.match(line)
        if match:
            ranges.append((int(match.group(1), 16), int(match.group(2), 16), [match.group(3)]))
            continue
        if ranges:
            # An indented DWARF expression belongs to the range above it.
            ranges[-1][2].append(line)

    if ranges:
        chosen = next((entry for entry in ranges if pc is not None and entry[0] <= pc < entry[1]), None)
        if chosen is None:
            return {
                "where": "unavailable",
                "register": None,
                "location": None,
                "reason": "gdb describes no location for this variable at this pc",
            }
        body = " ".join(chosen[2])
    else:
        body = " ".join(lines)

    lowered = body.lower()
    if "optimized out" in lowered or "no symbol" in lowered:
        return {"where": "unavailable", "register": None, "location": body, "reason": "optimised out"}

    direct = _REGISTER_LOCATION.search(body)
    bracketed = _BRACKETED_REGISTER.search(body)
    if direct:
        return {"where": "register", "register": direct.group(1), "location": body, "reason": None}
    if "DW_OP_entry_value" in body and bracketed:
        # Documented as "the value it had on entry": for an argument that is precisely the register it was
        # passed in, which is the fact a reader is looking for.
        return {
            "where": "register",
            "register": bracketed.group(1),
            "location": body,
            "reason": "the value it held on entry",
        }
    if any(op in body for op in _STACK_OPS):
        return {"where": "stack", "register": None, "location": body, "reason": None}
    if any(op in body for op in _STATIC_OPS):
        return {
            "where": "static",
            "register": None,
            "location": body,
            "reason": "a fixed address: not part of this frame",
        }
    if any(op in body for op in _COMPUTED_OPS):
        return {
            "where": "computed",
            "register": None,
            "location": body,
            "reason": "the debug info yields a value here, not a place",
        }
    return {"where": "unavailable", "register": None, "location": body, "reason": None}


def _arch_key(arch: Any) -> str:
    """The table key for a frame's `arch=` field.

    gdb reports variants (`aarch64`, `armv7`, `i386:x86-64`), and the record layout follows the family, so
    the key is the leading token. Matching nothing is a valid outcome: the caller then shows no record.
    """
    text = str(arch or "").strip().lower()
    for key in ("aarch64", "x86_64", "i386", "arm"):
        if text.startswith(key):
            return key
    return text


def _hex(value: int | None) -> str | None:
    """Addresses cross this module as hex strings, as everywhere else in the transport."""
    return f"0x{value:x}" if value is not None else None


def _no_record(why: str) -> dict[str, Any]:
    """The record that could not even be attempted.

    Always a dict, never `None`: a caller reading `record["verified"]` should not have to branch on the
    shape as well as the answer. `at is None` is what "there is no record here" looks like.
    """
    return {
        "at": None,
        "saved_fp": None,
        "return_address": None,
        "checks": {"saved_fp": None, "return_address": None},
        "verified": False,
        "why": why,
    }


def _frame_record(arch: Any, at: int, data: bytes) -> dict[str, Any] | None:
    """Decode the frame record at `at`, given where this architecture keeps its two words.

    This answers *what these bytes say*; whether they are a frame record at all is `_verify_record`'s
    question, because an ABI table can say where a record would be without one being there (a leaf
    function, `-fomit-frame-pointer`, a signal frame).
    """
    layout = FRAME_RECORDS.get(_arch_key(arch))
    if layout is None or at <= 0 or len(data) < layout.size:
        return None

    def word(offset: int) -> int:
        return int.from_bytes(data[offset : offset + layout.word], "little")

    return {
        "at": _hex(at),
        "saved_fp": _hex(word(layout.saved_fp_at)),
        "return_address": _hex(word(layout.return_address_at)),
        "checks": {"saved_fp": None, "return_address": None},
        "verified": False,
        "why": "decoded, but nothing has corroborated it yet",
    }


def _verify_record(record: dict[str, Any], caller_located: dict[str, Any], caller: dict[str, Any] | None) -> dict[str, Any]:
    """Does this frame record agree with the frame gdb says called us?

    The saved frame pointer has to be the caller's `fp`, and the return address has to be the caller's `pc`.
    Both are checked against gdb's own unwinding rather than against our idea of the ABI, which is what
    makes this usable on a target whose frames we have never seen: a build without frame pointers, a signal
    frame, or a wrong table all fail the check instead of drawing a chain that is not there.

    The two checks are reported **separately**, because they fail for different reasons and mean different
    things: a frame pointer that does not point at the next frame is a broken chain, while a return address
    that does not match is the bytes themselves having been overwritten. `None` means "could not be
    checked", which is not the same as passing, and not the same as failing.
    """
    checks: dict[str, bool | None] = {}

    saved_fp = _int_literal(record.get("saved_fp"))
    caller_fp = caller_located.get("fp") if caller is not None else None
    checks["saved_fp"] = saved_fp == caller_fp if saved_fp is not None and caller_fp is not None else None

    return_address = _int_literal(record.get("return_address"))
    caller_pc = _int_literal(caller.get("pc")) if caller is not None else None
    checks["return_address"] = return_address == caller_pc if return_address is not None and caller_pc is not None else None

    available = [result for result in checks.values() if result is not None]
    verified = bool(available) and all(available)
    return {**record, "checks": checks, "verified": verified, "why": _record_verdict(checks, verified)}


def _record_verdict(checks: dict[str, bool | None], verified: bool) -> str:
    """One sentence a UI can print next to the frame. The reason matters more than the boolean."""
    if verified:
        return "agrees with the next frame gdb found"
    failed = [name for name, result in checks.items() if result is False]
    if len(failed) == 2:
        return "the frame pointer and the return address both disagree with the next frame"
    if failed == ["saved_fp"]:
        return "the saved frame pointer does not point at the next frame"
    if failed == ["return_address"]:
        return "the return address is not where gdb says this frame was called from"
    return "decoded, but there was no next frame to check it against"


def _variable(raw: Any, *, is_arg: bool = False) -> dict[str, Any]:
    """One frame variable: a name, a DWARF type, and its value *if gdb printed one*.

    `value` is `None` when gdb sent no `value=` field at all — which is how `--simple-values` answers for
    an aggregate like `volatile int [32]`. That is not the same as `""` (sent, but empty) or as an
    address that cannot be read, and the three must stay distinguishable all the way to the screen.
    """
    entry = raw if isinstance(raw, dict) else {}
    return {
        "name": entry.get("name"),
        "type": entry.get("type"),
        "value": entry.get("value"),
        # `arg="1"` marks an argument; `-stack-list-arguments` answers about arguments only.
        "is_arg": is_arg or entry.get("arg") == "1",
    }


def _frame(raw: dict[str, Any], *, is_crashed: bool) -> dict[str, Any]:
    level = _as_int(raw.get("level"))
    return {
        "level": level,
        "func": raw.get("func"),
        "pc": raw.get("addr"),
        "file": raw.get("file"),
        "line": _as_int(raw.get("line")),
        # The architecture is not decoration: it decides how a word of memory is read (byte order,
        # word size), so a viewer that shows "read as u64" has to know it.
        "arch": raw.get("arch"),
        # Empty until `backtrace(with_arguments=True)` or `frame_arguments()` fills it: the frame list
        # is a summary and the arguments are detail.
        "args": [],
        "is_crash_site": bool(is_crashed and level == 0),
    }
