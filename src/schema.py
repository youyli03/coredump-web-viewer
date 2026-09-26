"""The JSON contract: the shapes, the error vocabulary, and the version of the contract itself.

`requirements.md` §8 asks for exactly this module ("the unified data format, the frontend/backend contract"),
and `architecture.md` §4 leans on it twice: the frontend may never branch on a platform, only on
`capabilities` and `null` fields, and a view that seems to need a frontend change is a *missing field*, not a
missing `if`. Neither promise can be held by a contract that exists only as the dictionaries some function
happened to build, which is what `docs/api.md` §3 records and this file implements.

It is pure data and imports nothing else in the project, so both `web/` and `analysis/` may import it — the
dependency rule forbids `analysis/ → web/`, never `analysis/ → schema`.

Two rules keep the models from becoming a second copy of the analysis layer:

* **declare the envelope, not the payload.** A frame, a chunk, a disassembly unit: those belong to
  `analysis/`, are described where they are built, and are pinned by that layer's own tests. Re-declaring
  every nested field here would mean two definitions of one thing, drifting apart quietly;
* **`extra="allow"` on anything wrapping an analysis payload.** A `response_model` *filters* what it does not
  declare, so a model that names a subset would silently drop the rest — a class of bug this project has
  already paid for once (a `dwarf_types` capability bit nobody read, a summary that quietly became a fixture).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

CONTRACT = "1"
"""The version of this contract, reported by `/api/health` and carried by every summary.

It exists because there are **two producers of the same JSON**: a live session, and
`scripts/dump-fixture.py`, which writes the file the page falls back to with no backend. A version stamped in
both places turns "the fixture is stale" from a wrong answer that looks right into a failing test — which is
the only kind of stale this project tolerates.
"""

CODES: dict[int, str] = {
    400: "bad-request",
    404: "not-found",
    409: "not-ready",
    422: "invalid-parameter",
    500: "gdb",
    501: "unsupported",
    502: "gdb-died",
    504: "timeout",
}
"""The default machine code per status; `docs/api.md` §3.1 is the table with the meanings.

`missing-file`, `no-core` and `unreadable` are *also* 404/409/422 and carry their own codes, because a status
cannot carry the difference and the frontend says different things for each.
"""


class Permissive(BaseModel):
    """Base for every model that wraps a payload built elsewhere.

    Declared fields are contract. Anything else survives serialisation, so a field added by `analysis/` shows
    up in the response and in the tests instead of being dropped on the way out.
    """

    model_config = ConfigDict(extra="allow")


class OpenSession(Permissive):
    """How a session is opened — the one request body in the API, so it is part of the contract too.

    Either a `sample` name from the practice bundle — what the demo's chooser sends, and what keeps a fresh
    clone runnable — or explicit paths, which is what the product uses. The paths win when both are given,
    because a caller that named a file meant that file.
    """

    sample: str | None = None
    core: str | None = None
    exe: str | None = None
    gdb: str | None = None
    sysroot: str | None = None
    solib_search_path: str | None = None


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class ErrorBody(Permissive):
    """Every failure, whatever raised it (`docs/api.md` §3.1)."""

    error: str
    detail: str
    status: int


# --------------------------------------------------------------------------- #
# The small, complete surfaces
# --------------------------------------------------------------------------- #
class Health(Permissive):
    ok: bool
    contract: str
    gdb: str
    sessions: list[dict[str, Any]]


class Sample(Permissive):
    """One practice core the backend can open, discovered from the bundle rather than declared."""

    sample: str
    label: str
    core: str
    exe: str
    hasExe: bool


class Defaults(Permissive):
    """What the form offers on *this* machine, each field checked before it is offered."""

    core: str
    exe: str
    gdb: str
    sysroot: str
    solib_search_path: str
    valid: dict[str, bool]
    root: str


class RecentEntry(Permissive):
    """One core this checkout has opened. `valid` is measured when the list is read, never stored."""

    core: str
    openedAt: str | None = None
    exe: str | None = None
    sysroot: str | None = None
    solib_search_path: str | None = None
    gdb: dict[str, Any] | None = None
    valid: dict[str, bool | None]


class CreatedSession(Permissive):
    id: str
    state: str
    elapsed: float


# --------------------------------------------------------------------------- #
# What a session answers
# --------------------------------------------------------------------------- #
class ThreadBrief(Permissive):
    num: int
    tid: str | int | None = None
    name: str | None = None
    state: str | None = None
    is_crashed: bool
    frame_count: int | None = None
    func: str | None = None
    pc: str | None = None
    arch: str | None = None


class SessionInfo(Permissive):
    """The `session` section: what this dump is, and what this transport can do with it."""

    id: str
    sample: str | None = None
    contract: str
    core_path: str | None = None
    exe_path: str | None = None
    gdb_path: str | None = None
    transport: str | None = None
    gdb_version: str | None = None
    capabilities: dict[str, Any] | None = None
    warnings: list[str] | None = None


class Summary(Permissive):
    """The first screen — §13.1's acceptance item, as data.

    Declared **by section**, because those eight keys are what the page and the fixture both promise to
    carry; what is inside each of them belongs to `analysis/`.
    """

    session: SessionInfo
    threads: list[ThreadBrief]
    detail: dict[str, Any]
    memory_map: dict[str, Any]
    memory: dict[str, Any]
    typed: dict[str, Any]
    stack: dict[str, Any]
    code: dict[str, Any]


class SessionDetail(Permissive):
    """What the poll answers: the state, and the summary once it lands.

    Documented rather than enforced — see `web/routes.py`: a `response_model` here would re-serialise the
    largest payload in the project on every poll, and the one thing it would add is the ability to drop a
    field the model forgot. `tests/api/test_contract.py` validates the real answers against this model
    instead, which is where a drift should be caught.
    """

    id: str
    state: str
    elapsed: float
    progress: str | None = None
    error: str | None = None
    core: str
    exe: str
    gdb: str
    summary: Summary | None = None


class MemoryWindow(Permissive):
    """Bytes, and the holes between them. A hole is data, a refusal is `unreadable`."""

    address: str
    length: int
    chunks: list[dict[str, Any]]
    unread: list[dict[str, Any]]


class FrameVariable(Permissive):
    name: str
    type: str | None = None
    value: str | None = None
    is_arg: bool | None = None


class TypedObject(Permissive):
    """A typed object the summary's index knows about, or one `expand` just walked to."""

    expression: str | None = None
    type: str | None = None
    value: str | None = None
    size: int | None = None
    children: list[dict[str, Any]] | None = None


class Stack(Permissive):
    thread: int
    frames: list[dict[str, Any]]
    slots: dict[str, list[dict[str, Any]]] | None = None


class DisassemblyPage(Permissive):
    """One page of code: the functions in it, or the reason it has none (`docs/api.md` §6)."""

    page: str
    units: list[dict[str, Any]]
    reason: str | None = None


class Capabilities(Permissive):
    """§13.6: what this dump can and cannot do, as data the page switches on."""

    transport: str
    gdb_version: str | None = None
    capabilities: dict[str, Any]
    notes: dict[str, str] | None = None


class SessionStats(Permissive):
    """What a session cost, so the promises of §1 and §4 can be asserted instead of assumed (`docs/api.md` §4)."""

    id: str
    state: str
    core_loads: int
    commands_sent: int
    commands_by_op: dict[str, int]
    cache_hits: int
    cache_misses: int
    timeouts: int
    errors: int
    gdb_pid: int | None = None
    gdb_alive: bool | None = None
    idle_s: float


class ProcessStats(Permissive):
    """What this process has done with sessions, so the capacity policy and the shutdown promise are visible."""

    contract: str
    sessions_created: int
    capacity_evictions: int
    sessions_failed: int
    sessions_open: int
