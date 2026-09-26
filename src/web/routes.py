"""The HTTP layer: validate, call the analysis layer, serialise. Nothing else.

The rule from §5 is that this layer may import `analysis/` and `schema`, and `analysis/` may never import
`web/`. Everything here is therefore thin on purpose: a route that computes anything is a route that has put
logic in the wrong layer.
"""

from __future__ import annotations

import pathlib
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response

from analysis.session import Session, SessionManager
from schema import (
    CONTRACT,
    Capabilities,
    CreatedSession,
    Defaults,
    DisassemblyPage,
    FrameVariable,
    Health,
    MemoryWindow,
    OpenSession,
    ProcessStats,
    SessionStats,
    RecentEntry,
    Sample,
    SessionDetail,
    Stack,
    TypedObject,
)
from web.recent import Recent

router = APIRouter(prefix="/api")

WAIT_CEILING_S = 60.0
"""How long `?wait=` may block, whatever the caller asks for.

A request that can block for an unbounded time is a request that can pin a worker; the ceiling is the policy,
and a caller that wants to wait longer polls again — which is what the frontend already does."""


def _manager(request: Request) -> SessionManager:
    return request.app.state.sessions


def _config(request: Request):
    """The configuration this app was built with.

    Not the `CONFIG` singleton: that is filled while `config` is imported, so anything a test wants to change
    has to be decided before the process starts. Everything settable lives on `app.state` instead — see
    `docs/api.md` §5 for why, and `create_app` for the defaults that reproduce the running service.
    """
    return request.app.state.config


def _root(request: Request) -> pathlib.Path:
    return request.app.state.root


def _bundle(request: Request) -> pathlib.Path:
    return request.app.state.bundle


def _recent(request: Request) -> Recent:
    """The local state file. Beside the checkout by default, wherever the app was pointed otherwise."""
    return Recent(request.app.state.state_path)


def _require(request: Request, session_id: str) -> Session:
    session = _manager(request).get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"no session {session_id!r} (it may have been reclaimed)")
    return session


def _ready(request: Request, session_id: str) -> Session:
    """The session, or the refusal that says *which* of requirements §13.7's four it is.

    Everything used to answer 409 `not-ready` with the state as its whole explanation, so a debugger that had
    been killed, a core that never loaded and a session that is simply still loading were one sentence. The
    distinction is the most expensive lesson in this project — the v1 prototype's `{"threads": []}` looked like
    a successful empty answer — so the kind of failure decides the status: 502 for a gdb that died, 504 for one
    that never answered in time, 409 for a session that is not ready *yet*, and the session's own words in
    every case.
    """
    session = _require(request, session_id)
    if session.state == "ready" and session.transport is not None:
        return session
    reason = session.error or ""
    if session.state == "failed":
        if session.failure == "died":
            raise HTTPException(status_code=502, detail=reason or "the debugger exited")
        if session.failure == "timeout":
            raise HTTPException(status_code=504, detail=reason or "the debugger did not answer in time")
    detail = f"session is {session.state}"
    raise HTTPException(status_code=409, detail=f"{detail}: {reason}" if reason else detail)


def _with_summary(session: Session) -> dict:
    """The summary the session is holding, or 409 while there is none.

    A failed session that never loaded has no summary and answers 409 — never an empty report, which is the v1
    lesson. A session whose debugger *died after* loading still has one, and what it holds is still true (the
    core cannot change), so the endpoints that read it go on answering while the ones that need the debugger
    answer 502. That split is the honest one: the death of a process does not unload a dump.
    """
    if session.summary is None:
        raise HTTPException(status_code=409, detail=f"session is {session.state}")
    return session.summary


@router.get("/health", response_model=Health)
def health(request: Request) -> dict:
    return {
        "ok": True,
        "contract": CONTRACT,
        "gdb": _config(request).gdb_path,
        "sessions": [session.describe() | {"summary": None} for session in _manager(request).all()],
    }


@router.post("/sessions", response_model=CreatedSession, status_code=201)
def open_session(body: OpenSession, request: Request) -> CreatedSession:
    bundle = _bundle(request)

    if body.core:
        core = pathlib.Path(body.core)
        if not core.is_file():
            raise HTTPException(status_code=404, detail=f"no such core: {core}")
        exe = pathlib.Path(body.exe) if body.exe else core
        if not exe.is_file():
            raise HTTPException(status_code=404, detail=f"no such executable: {exe}")
        gdb = pathlib.Path(body.gdb) if body.gdb else pathlib.Path(_config(request).gdb_path)
        sysroot = pathlib.Path(body.sysroot) if body.sysroot else None
        search = pathlib.Path(body.solib_search_path) if body.solib_search_path else None
    else:
        # The practice bundle: both the demo's samples and the thing a fresh checkout can actually run.
        sample = body.sample or "crash_target"
        cores = sorted(bundle.glob(f"{sample}.*.core"))
        if not cores:
            raise HTTPException(status_code=404, detail=f"no {sample!r} core in {bundle}")
        core = cores[-1]
        exe = bundle / sample
        gdb = pathlib.Path(_config(request).gdb_path)
        sysroot = bundle / "sysroot" if (bundle / "sysroot").is_dir() else None
        search = bundle

    session = _manager(request).create(core, exe, gdb=gdb, sysroot=sysroot, solib_search_path=search)
    # *Every* core that opened is remembered, sample or path alike: "opened before" is the list of what this
    # checkout has actually looked at, and one core is loaded at a time, so that list is where the rest live. It
    # used to skip the practice samples on the grounds that they were chips in the bar — they are not any more, and
    # excluding them would leave the history describing only half of what was opened. Recorded after the session
    # exists, so an entry means something really opened.
    _recent(request).record(
        core=str(core),
        exe=str(exe) if exe else None,
        gdb=body.gdb if body.core else None,  # a sample uses the configured gdb, which is not the caller's choice
        sysroot=str(sysroot) if sysroot else None,
        solib_search_path=str(search) if search else None,
        opened_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    return CreatedSession(id=session.id, state=session.state, elapsed=session.elapsed)


@router.get("/samples", response_model=list[Sample])
def samples(request: Request) -> list[dict]:
    """The practice cores this backend can open, discovered rather than declared.

    The UI used to carry the list — `crash_target (-O0)` and `opt_target (-O2)` — which meant the frontend knew
    which cores exist in a directory only the backend can see, and had to be edited whenever the practice suite
    gained a target. What is here is what is on disk: one entry per program that has a core in the bundle, newest
    core first, with the label taken from the program's own name. Flags like `-O0` are not invented here; the
    bundle's manifest is where the build is described, and this endpoint does not claim to know more than the
    file names.
    """
    root = _root(request)
    bundle = _bundle(request)
    found: dict[str, pathlib.Path] = {}
    for core in sorted(bundle.glob("*.core")):
        name = core.name.split(".")[0]
        if name and (found.get(name) is None or core.name > found[name].name):
            found[name] = core
    return [
        {"sample": name, "label": name, "core": str(core), "exe": str(bundle / name),
         "hasExe": (bundle / name).is_file()}
        for name, core in sorted(found.items())
    ]


@router.get("/defaults", response_model=Defaults)
def defaults(request: Request) -> dict:
    """Paths that make sense *on the machine running this backend*.

    The form used to carry the board's paths (`/home/lyy/cdwv-practice/…`) as its defaults, which were true only
    while the backend happened to run on that board — the whole point of the local cross-gdb setup is that it
    does not. The same resolution the sample route uses is the honest source: this checkout's practice bundle,
    plus the configured gdb. Each field is checked before it is offered, so a default that is not there is shown
    as missing rather than typed in as if it were real.
    """
    root = _root(request)
    bundle = _bundle(request)
    cores = sorted(bundle.glob("crash_target.*.core"))
    suggestions = {
        "core": str(cores[-1]) if cores else "",
        "exe": str(bundle / "crash_target"),
        "gdb": str(_config(request).gdb_path),
        "sysroot": str(bundle / "sysroot"),
        "solib_search_path": str(bundle),
    }
    return {
        **suggestions,
        # `bool(value)` first, and not as a flourish: `pathlib.Path("").exists()` is *true* — an empty path is
        # `Path(".")`, and the current directory exists — so an empty suggestion used to be reported as a path
        # that is there. The frontend compares `=== false` to decide whether to mark a field missing, so the
        # bug made a form with nothing to offer look complete. Found by a test that fed it an empty bundle.
        "valid": {key: bool(value) and pathlib.Path(value).exists() for key, value in suggestions.items()},
        "root": str(root),
    }


@router.get("/recent", response_model=list[RecentEntry])
def list_recent(request: Request) -> list[dict]:
    """The cores opened before, each with its files checked *now*.

    Validity is measured on read rather than stored: an entry whose core was deleted is a fact about this
    filesystem, and a remembered `true` would be a claim that goes stale in silence.
    """
    return _recent(request).list()


@router.delete("/recent/{index}", status_code=204)
def forget_recent(index: int, request: Request) -> Response:
    _recent(request).forget(index)
    return Response(status_code=204)


@router.get(
    "/sessions/{session_id}",
    responses={200: {"model": SessionDetail, "description": "the poll: state, then the whole summary"}},
)
def read_session(session_id: str, request: Request, wait: float | None = None) -> dict:
    """The poll. `summary` is absent while loading and the whole report once it lands.

    `?wait=<seconds>` blocks until the session stops loading, capped at `WAIT_CEILING_S`. Loading is
    asynchronous and takes seconds to minutes, so without it every caller invents its own sleep — the frontend
    on a timer, a test in a loop. One implementation here replaces both, and nothing changes when `wait` is
    absent.
    """
    session = _require(request, session_id)
    if wait and wait > 0:
        deadline = time.monotonic() + min(float(wait), WAIT_CEILING_S)
        while session.state == "loading" and time.monotonic() < deadline:
            time.sleep(0.05)
            # Re-fetched on every turn: the session may have been reclaimed or closed while we waited, and
            # answering with a stale object would be answering about a session that no longer exists.
            session = _require(request, session_id)
    return session.describe()


@router.delete("/sessions", status_code=204)
def close_all_sessions(request: Request) -> Response:
    """Close every session — the counterpart of the capacity policy, and how a caller cleans up."""
    _manager(request).close_all()
    return Response(status_code=204)


@router.delete("/sessions/{session_id}", status_code=204)
def close_session(session_id: str, request: Request) -> Response:
    if not _manager(request).close(session_id):
        raise HTTPException(status_code=404, detail=f"no session {session_id!r}")
    return Response(status_code=204)


@router.get("/sessions/{session_id}/stats", response_model=SessionStats)
def session_stats(session_id: str, request: Request) -> dict:
    """What this session has cost: gdb commands, cache hits, the pid, the deadline breaches.

    Read-only, and part of the contract rather than a debug back door — a promise that is not in the contract
    is a promise the next refactor is free to delete (`docs/api.md` §4).
    """
    return _require(request, session_id).stats()


@router.get("/stats", response_model=ProcessStats)
def process_stats(request: Request) -> dict:
    """What this process has done with cores: opened, evicted, failed, still open."""
    return _manager(request).stats()


@router.get("/sessions/{session_id}/capabilities", response_model=Capabilities)
def capabilities(session_id: str, request: Request) -> dict:
    """What this dump can and cannot do — §13.6, as data the page switches on instead of guessing.

    It is the same section the summary carries; having it as an endpoint is what lets a caller (or a test)
    ask the question without holding the whole first screen, and what lets the *fixture* be checked against
    the live answer.
    """
    session = _require(request, session_id)
    info = _with_summary(session)["session"]
    return {
        "transport": info.get("transport"),
        "gdb_version": info.get("gdb_version"),
        "capabilities": info.get("capabilities") or {},
        "notes": (info.get("capabilities") or {}).get("notes"),
    }


@router.get("/sessions/{session_id}/memory", response_model=MemoryWindow)
def memory_at(session_id: str, request: Request, address: str, length: int = 256) -> dict:
    """Bytes, on demand — one window per scroll, which is the query-cost row in §5.

    Clamped by `config.max_limit`, because the ceiling is a policy and this is the endpoint a transcript could
    ask for a gigabyte from.
    """
    session = _ready(request, session_id)
    limit = _config(request).max_limit
    if length < 1 or length > limit:
        raise HTTPException(status_code=400, detail=f"length must be 1..{limit}")
    from analysis import queries

    return queries.memory_at(session.transport, address, length)


@router.get("/sessions/{session_id}/disassemble", response_model=DisassemblyPage)
def disassemble_page(session_id: str, request: Request, address: str) -> dict:
    """The code in the page that contains `address`, one function-form request per function.

    On demand by design: the page's functions are what a reader is looking at, and disassembling the address
    space is not something a summary should carry.
    """
    session = _ready(request, session_id)
    summary = _with_summary(session)
    from analysis import queries

    regions = summary["memory_map"]["regions"]
    frames = []
    for payload in summary.get("detail", {}).values():
        frames.extend(payload.get("frames", []))
    files = summary.setdefault("code", {}).setdefault("files", {})
    return queries.code_page(
        session.transport,
        regions,
        frames,
        int(address, 16),
        sample=session.core.name.split(".")[0],
        files=files,
        # Where the modules actually are: the recorded paths point at the machine that built the core.
        bundle=session.solib_search_path,
        sysroot=session.sysroot,
    )


@router.get("/sessions/{session_id}/object", response_model=TypedObject)
def object_at(session_id: str, request: Request, address: str) -> dict:
    """The typed object known at an address — a lookup in the index the summary already carries."""
    session = _require(request, session_id)
    summary = _with_summary(session)
    from analysis import queries

    found = queries.object_at(summary, int(address, 16))
    if found is None:
        raise HTTPException(status_code=404, detail=f"no type is known for {address}")
    return found


@router.get("/sessions/{session_id}/stack", response_model=Stack)
def stack(session_id: str, request: Request, thread: int | None = None, levels: int | None = None) -> dict:
    """The stack walk for one thread — the on-demand form of what the summary pre-fetches for the first screen."""
    session = _ready(request, session_id)
    summary = _with_summary(session)
    from analysis import report

    number = thread if thread is not None else next(
        (t["num"] for t in summary["threads"] if t["is_crashed"]), summary["threads"][0]["num"]
    )
    return report.stack_detail(session.transport, number, levels)


@router.get("/sessions/{session_id}/objects", response_model=list[TypedObject])
def objects_in(session_id: str, request: Request, address: str, length: int = 4096) -> list:
    """The typed objects overlapping a range — what the overlay on those bytes needs."""

    session = _require(request, session_id)
    summary = _with_summary(session)
    limit = _config(request).max_limit
    if length < 1 or length > limit:
        raise HTTPException(status_code=400, detail=f"length must be 1..{limit}")
    from analysis import queries

    return queries.objects_in(summary, int(address, 16), length)


@router.get("/sessions/{session_id}/frames/{level}", response_model=list[FrameVariable])
def frame_locals(session_id: str, level: int, request: Request, thread: int | None = None) -> list:
    """On demand, one frame per click — the same shape the fixture carries for every frame, asked for one.

    This is the first endpoint that is *not* the whole report, and it is the shape the rest will take: the
    summary arrives in one piece because the first screen needs all of it, and everything after that is a
    question about one address.
    """
    session = _ready(request, session_id)
    summary = _with_summary(session)
    frames = summary.get("detail", {})
    number = thread if thread is not None else next((int(key) for key in frames), None)
    detail = frames.get(str(number), {})
    if level < 0 or level >= len(detail.get("frames", [])):
        raise HTTPException(status_code=404, detail=f"thread {number} has no frame {level}")
    # Asked of gdb, not read out of the summary. This endpoint and the UI were both reading
    # `detail["locals"][level]`, which only ever had an answer because the backend walked every frame of every
    # thread up front — measured at 5.5 seconds of a 5.6-second load. The hop the docstring describes was
    # missing on both sides; this is the backend half, and it is what let the eager walk be removed at all.
    return session.transport.frame_variables(number, level)
