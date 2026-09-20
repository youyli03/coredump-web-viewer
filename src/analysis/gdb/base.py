"""The transport interface: how we ask gdb about a dump.

Platform is deliberately **not** an axis here. Linux and QNX are just different `gdb` binaries, and what
matters is what a given binary can actually do, so every transport declares **measured** capabilities
and a probe picks between implementations (`probe.py`, added together with the second transport).

Anything a transport cannot do raises `Unsupported` — an honest refusal — rather than returning empty
data, which would be indistinguishable from "the dump really has nothing there".
"""

from __future__ import annotations

import abc
from dataclasses import asdict, dataclass, field
from typing import Any


class GdbError(RuntimeError):
    """Anything that goes wrong between us and gdb."""


class GdbTimeout(GdbError):
    """A command did not answer within its deadline. The process is not trustworthy afterwards."""


class GdbDied(GdbError):
    """The gdb process is gone (EOF on its output)."""


class CoreNotLoaded(GdbError):
    """gdb is running but has no core loaded.

    This is a **failure**, never an empty result: a dump that cannot be read must not look like a dump
    that happens to contain nothing.
    """


class Unsupported(GdbError):
    """This transport cannot serve this operation."""


class Unreadable(GdbError):
    """gdb cannot read that memory.

    For a core dump this is a **normal answer**, not a bug: absent pages are exactly what a partial dump
    is. It is still an error rather than an empty result, because "nothing here" and "not in this dump"
    must never collapse into the same value.
    """


@dataclass(frozen=True)
class Capabilities:
    """What a transport can *actually* do for this dump. Every default is False on purpose."""

    transport: str = "none"
    threads: bool = False
    backtrace: bool = False
    registers: bool = False
    memory_map: bool = False
    memory_read: bool = False
    evaluate: bool = False
    expand: bool = False
    arguments: bool = False
    """Frame arguments and locals, with values — what a stack view needs to be worth reading."""
    dwarf_types: bool = False
    thread_names: bool = False
    core_notes: bool = False
    lock_owner: bool = False
    notes: dict[str, str] = field(default_factory=dict)
    """Why something is False, in the transport's own words — shown instead of an empty panel."""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class Transport(abc.ABC):
    """One way of talking to one gdb about one dump.

    The process, the deadline and the kill are the runner's job; a transport only encodes a request and
    decodes a reply.
    """

    name: str = "abstract"

    @abc.abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abc.abstractmethod
    def threads(self) -> list[dict]: ...

    @abc.abstractmethod
    def backtrace(self, thread_num: int, *, limit: int = 256, offset: int = 0) -> dict: ...

    @abc.abstractmethod
    def registers(self, thread_num: int) -> dict[str, str]: ...

    # --- not every transport can do these; the default is an honest refusal ------------ #
    def memory_map(self) -> dict:
        raise Unsupported("this transport cannot produce a memory map")

    def read_memory(self, addr: str, length: int) -> dict:
        """The bytes at `addr`, as far as this dump actually has them.

        `{"address", "length", "chunks": [{"address", "length", "bytes"}], "unread": [{"address", "length"}]}`

        `bytes` is a lowercase hex string. Nothing is padded and nothing is concatenated across a hole:
        a dump that is missing a page has to *look* like a dump that is missing a page. Raises
        `Unreadable` when gdb can serve none of the range.
        """
        raise Unsupported("this transport cannot read memory")

    def evaluate(self, expression: str) -> dict:
        """One expression → `{"expression", "type", "value", "children"}`.

        This is the typed view: the *expression* is what the user is pointing at (a frame variable, a
        struct field, a dereferenced pointer), and the type comes from DWARF, never from a guess about
        the bytes.
        """
        raise Unsupported("this transport cannot evaluate an expression")

    def frame_arguments(self, thread_num: int, *, low: int = 0, high: int | None = None) -> dict[int, list[dict]]:
        """Arguments of a range of frames, as `{level: [{"name", "type", "value", "is_arg"}]}`.

        A range rather than a frame, because "what was every call given" is one question about one stack
        and should cost one query, not one per frame.
        """
        raise Unsupported("this transport cannot list frame arguments")

    def frame_variables(self, thread_num: int, level: int = 0) -> list[dict]:
        """Arguments **and** locals of one frame.

        A crash's cause is usually a local, not an argument. Note this *selects* that frame: the frame
        selection is explicit state, and every later expression-based query answers about it.
        """
        raise Unsupported("this transport cannot list frame variables")

    def expand(self, expression: str) -> dict:
        """One level of children of `expression`, as `evaluate()` does plus `children`.

        One level per call is the point: a pointer chain costs one query per click, so following a
        multi-level chain (or noticing that it cycles) never needs the whole graph up front.
        """
        raise Unsupported("this transport cannot expand an expression")

    def stack_frames(self, thread_num: int, *, low: int = 0, high: int | None = None) -> list[dict]:
        """Where each frame's stack memory *is*, and what its frame record says.

        `[{"level", "func", "pc", "sp", "fp", "start", "end", "record"}]`, one entry per frame in the
        range. This is the missing half of a stack view: a backtrace says which functions were called,
        and this says which bytes of memory each of them owns, which is what turns 512 anonymous bytes
        into something a memory view can draw.

        `start`/`end` are measured, not derived from an ABI: a frame owns the memory from its own `sp` up
        to its caller's `sp`. `end` is `None` when the caller is not in this dump or the frame pointer is
        not a frame pointer — an honest hole rather than an invented boundary.

        `record` is the frame record at `fp` — the saved frame pointer and the return address, laid out
        as the architecture's ABI lays them out (`FRAME_RECORDS`) — or `None` when the architecture is not
        one this transport knows or the page is not in the dump. `verified` says the decoded pair agrees
        with the *next frame gdb found*, which is the only reason to believe a hand-decoded record.
        """
        raise Unsupported("this transport cannot locate a frame's stack memory")

    def frame_slots(self, thread_num: int, level: int = 0) -> list[dict]:
        """Arguments and locals of one frame, each with the bytes it occupies.

        `[{"name", "type", "value", "is_arg", "expression", "address", "size", "slot"}]`.

        `slot` is True only when gdb gives the variable an address **inside this frame's stack memory**
        and a size: a variable that lives in a register has no bytes in the dump, and a `static`'s address
        is not this frame's. Both of those still keep their value — they just have no byte range to draw.
        """
        raise Unsupported("this transport cannot locate a frame's variables in memory")

    def symbolize(self, addr: str) -> dict:
        raise Unsupported("this transport cannot look up a symbol")

    def disassemble(
        self,
        address: str,
        *,
        end: str | None = None,
        source: bool = False,
        opcodes: bool = False,
        allow_unsymbolized: bool = False,
        limit: int = 512,
    ) -> dict:
        """The instructions at `address`, and optionally the source lines they came from.

        `{"address", "range", "function", "instructions", "lines", "reason", "symbolized", "truncated"}`

        Each instruction is `{"address", "offset", "text", "bytes", "func", "line"}`; `offset` is the byte
        offset into the enclosing function and is absent when there is no symbol to be offset from; `text`
        is gdb's own rendering (`"ldr\\tw0, [x0]"`), never a re-spelling of the bytes. `lines` groups the
        same instructions by source line, which is what an interleaved view draws.

        **`allow_unsymbolized` is load-bearing.** Given only an address, gdb can disassemble the enclosing
        *function* and it refuses when there is none — which is the honest answer for a stripped address.
        Asked for a *range* instead, it will decode whatever bytes are there: measured on the practice core,
        a heap address comes back as `udf #1`, which is a real instruction the program never executed. So a
        range is only used when the caller has established that the address is in executable memory (the
        core's own `PT_LOAD` permissions — `analysis/elf.py`), and says so here.

        A refusal from the dump — no function contains the address, the bytes are not in the dump — is
        returned as an empty `instructions` list with `reason` set, because "this dump cannot tell you" is a
        fact about the dump and the viewer has to print it. `Unsupported` is only for a transport that
        cannot disassemble at all.
        """
        raise Unsupported("this transport cannot disassemble")

    # --- lifecycle --------------------------------------------------------------------- #
    def close(self) -> None:
        """Release the process. Implementations must be idempotent."""

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
