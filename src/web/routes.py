"""The HTTP layer: validate, call the analysis layer, serialise. Nothing else.

The rule from §5 is that this layer may import `analysis/` and `schema`, and `analysis/` may never import
`web/`. Everything here is therefore thin on purpose: a route that computes anything is a route that has put
logic in the wrong layer.
"""

from __future__ import annotations

import pathlib
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from analysis.session import Session, SessionManager
from web.recent import Recent

router = APIRouter(prefix="/api")


class OpenSession(BaseModel):
    """How a session is opened.

    Either a `sample` name from the practice bundle — which is what the demo's chooser sends, and keeps a
    fresh clone runnable — or explicit paths, which is what the product uses. The paths win when both are
    given, because a caller that named a file meant that file.
    """

    sample: str | None = None
    core: str | None = None
    exe: str | None = None
    gdb: str | None = None
    sysroot: str | None = None
    solib_search_path: str | None = None


class SessionCreated(BaseModel):
    id: str
    state: str
    elapsed: float = 0.0


def _manager(request: Request) -> SessionManager:
    return request.app.state.sessions


def _recent() -> Recent:
    """The local state file, at the repository root, next to the checkout it describes."""
    return Recent(pathlib.Path(__file__).resolve().parents[2])


def _require(request: Request, session_id: str) -> Session:
    session = _manager(request).get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"no session {session_id!r} (it may have been reclaimed)")
    return session


@router.get("/health")
def health(request: Request) -> dict:
    from config import CONFIG

    return {
        "ok": True,
        "gdb": CONFIG.gdb_path,
        "sessions": [session.describe() | {"summary": None} for session in _manager(request).all()],
    }


@router.post("/sessions", response_model=SessionCreated, status_code=201)
def open_session(body: OpenSession, request: Request) -> SessionCreated:
    from config import CONFIG

    root = pathlib.Path(__file__).resolve().parents[2]
    bundle = root / "tmp" / "practice"

    if body.core:
        core = pathlib.Path(body.core)
        if not core.is_file():
            raise HTTPException(status_code=404, detail=f"no such core: {core}")
        exe = pathlib.Path(body.exe) if body.exe else core
        if not exe.is_file():
            raise HTTPException(status_code=404, detail=f"no such executable: {exe}")
        gdb = pathlib.Path(body.gdb) if body.gdb else pathlib.Path(CONFIG.gdb_path)
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
        gdb = pathlib.Path(CONFIG.gdb_path)
        sysroot = bundle / "sysroot" if (bundle / "sysroot").is_dir() else None
        search = bundle

    session = _manager(request).create(core, exe, gdb=gdb, sysroot=sysroot, solib_search_path=search)
    # *Every* core that opened is remembered, sample or path alike: "opened before" is the list of what this
    # checkout has actually looked at, and one core is loaded at a time, so that list is where the rest live. It
    # used to skip the practice samples on the grounds that they were chips in the bar — they are not any more, and
    # excluding them would leave the history describing only half of what was opened. Recorded after the session
    # exists, so an entry means something really opened.
    _recent().record(
        core=str(core),
        exe=str(exe) if exe else None,
        gdb=body.gdb if body.core else None,  # a sample uses the configured gdb, which is not the caller's choice
        sysroot=str(sysroot) if sysroot else None,
        solib_search_path=str(search) if search else None,
        opened_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    return SessionCreated(id=session.id, state=session.state, elapsed=session.elapsed)


@router.get("/samples")
def samples(request: Request) -> list[dict]:
    """The practice cores this backend can open, discovered rather than declared.

    The UI used to carry the list — `crash_target (-O0)` and `opt_target (-O2)` — which meant the frontend knew
    which cores exist in a directory only the backend can see, and had to be edited whenever the practice suite
    gained a target. What is here is what is on disk: one entry per program that has a core in the bundle, newest
    core first, with the label taken from the program's own name. Flags like `-O0` are not invented here; the
    bundle's manifest is where the build is described, and this endpoint does not claim to know more than the
    file names.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    bundle = root / "tmp" / "practice"
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


@router.get("/defaults")
def defaults(request: Request) -> dict:
    """Paths that make sense *on the machine running this backend*.

    The form used to carry the board's paths (`/home/lyy/cdwv-practice/…`) as its defaults, which were true only
    while the backend happened to run on that board — the whole point of the local cross-gdb setup is that it
    does not. The same resolution the sample route uses is the honest source: this checkout's practice bundle,
    plus the configured gdb. Each field is checked before it is offered, so a default that is not there is shown
    as missing rather than typed in as if it were real.
    """
    from config import CONFIG

    root = pathlib.Path(__file__).resolve().parents[2]
    bundle = root / "tmp" / "practice"
    cores = sorted(bundle.glob("crash_target.*.core"))
    suggestions = {
        "core": str(cores[-1]) if cores else "",
        "exe": str(bundle / "crash_target"),
        "gdb": str(CONFIG.gdb_path),
        "sysroot": str(bundle / "sysroot"),
        "solib_search_path": str(bundle),
    }
    return {
        **suggestions,
        "valid": {key: pathlib.Path(value).exists() for key, value in suggestions.items()},
        "root": str(root),
    }


@router.get("/recent")
def list_recent(request: Request) -> list[dict]:
    """The cores opened before, each with its files checked *now*.

    Validity is measured on read rather than stored: an entry whose core was deleted is a fact about this
    filesystem, and a remembered `true` would be a claim that goes stale in silence.
    """
    return _recent().list()


@router.delete("/recent/{index}", status_code=204)
def forget_recent(index: int, request: Request) -> Response:
    _recent().forget(index)
    return Response(status_code=204)


@router.get("/sessions/{session_id}")
def read_session(session_id: str, request: Request) -> dict:
    """The poll. `summary` is absent while loading and the whole report once it lands."""
    session = _require(request, session_id)
    return session.describe()


@router.delete("/sessions/{session_id}", status_code=204)
def close_session(session_id: str, request: Request) -> Response:
    if not _manager(request).close(session_id):
        raise HTTPException(status_code=404, detail=f"no session {session_id!r}")
    return Response(status_code=204)


@router.get("/sessions/{session_id}/memory")
def memory_at(session_id: str, request: Request, address: str, length: int = 256) -> dict:
    """Bytes, on demand — one window per scroll, which is the query-cost row in §5.

    Clamped by `config.max_limit`, because the ceiling is a policy and this is the endpoint a transcript could
    ask for a gigabyte from.
    """
    from config import CONFIG

    session = _require(request, session_id)
    if session.state != "ready" or session.transport is None:
        raise HTTPException(status_code=409, detail=f"session is {session.state}")
    if length < 1 or length > CONFIG.max_limit:
        raise HTTPException(status_code=400, detail=f"length must be 1..{CONFIG.max_limit}")
    from analysis import queries

    return queries.memory_at(session.transport, address, length)


@router.get("/sessions/{session_id}/disassemble")
def disassemble_page(session_id: str, request: Request, address: str) -> dict:
    """The code in the page that contains `address`, one function-form request per function.

    On demand by design: the page's functions are what a reader is looking at, and disassembling the address
    space is not something a summary should carry.
    """
    session = _require(request, session_id)
    if session.state != "ready" or session.summary is None or session.transport is None:
        raise HTTPException(status_code=409, detail=f"session is {session.state}")
    from analysis import queries

    regions = session.summary["memory_map"]["regions"]
    frames = []
    for payload in session.summary.get("detail", {}).values():
        frames.extend(payload.get("frames", []))
    files = session.summary.setdefault("code", {}).setdefault("files", {})
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


@router.get("/sessions/{session_id}/object")
def object_at(session_id: str, request: Request, address: str) -> dict:
    """The typed object known at an address — a lookup in the index the summary already carries."""
    session = _require(request, session_id)
    if session.summary is None:
        raise HTTPException(status_code=409, detail=f"session is {session.state}")
    from analysis import queries

    found = queries.object_at(session.summary, int(address, 16))
    if found is None:
        raise HTTPException(status_code=404, detail=f"no type is known for {address}")
    return found


@router.get("/sessions/{session_id}/stack")
def stack(session_id: str, request: Request, thread: int | None = None, levels: int | None = None) -> dict:
    """The stack walk for one thread — the on-demand form of what the summary pre-fetches for the first screen."""
    session = _require(request, session_id)
    if session.state != "ready" or session.transport is None:
        raise HTTPException(status_code=409, detail=f"session is {session.state}")
    from analysis import report

    number = thread if thread is not None else next(
        (t["num"] for t in session.summary["threads"] if t["is_crashed"]), session.summary["threads"][0]["num"]
    )
    return report.stack_detail(session.transport, number, levels)


@router.get("/sessions/{session_id}/objects")
def objects_in(session_id: str, request: Request, address: str, length: int = 4096) -> list:
    """The typed objects overlapping a range — what the overlay on those bytes needs."""
    from config import CONFIG

    session = _require(request, session_id)
    if session.summary is None:
        raise HTTPException(status_code=409, detail=f"session is {session.state}")
    if length < 1 or length > CONFIG.max_limit:
        raise HTTPException(status_code=400, detail=f"length must be 1..{CONFIG.max_limit}")
    from analysis import queries

    return queries.objects_in(session.summary, int(address, 16), length)


@router.get("/sessions/{session_id}/frames/{level}")
def frame_locals(session_id: str, level: int, request: Request, thread: int | None = None) -> list:
    """On demand, one frame per click — the same shape the fixture carries for every frame, asked for one.

    This is the first endpoint that is *not* the whole report, and it is the shape the rest will take: the
    summary arrives in one piece because the first screen needs all of it, and everything after that is a
    question about one address.
    """
    session = _require(request, session_id)
    if session.state != "ready" or session.summary is None:
        raise HTTPException(status_code=409, detail=f"session is {session.state}")
    frames = session.summary.get("detail", {})
    number = thread if thread is not None else next((int(key) for key in frames), None)
    detail = frames.get(str(number), {})
    if level < 0 or level >= len(detail.get("frames", [])):
        raise HTTPException(status_code=404, detail=f"thread {number} has no frame {level}")
    # Asked of gdb, not read out of the summary. This endpoint and the UI were both reading
    # `detail["locals"][level]`, which only ever had an answer because the backend walked every frame of every
    # thread up front — measured at 5.5 seconds of a 5.6-second load. The hop the docstring describes was
    # missing on both sides; this is the backend half, and it is what let the eager walk be removed at all.
    return session.transport.frame_variables(number, level)
