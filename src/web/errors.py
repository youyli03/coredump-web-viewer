"""Exceptions → HTTP status and a body the frontend can print.

The mapping is the interesting part, because a refusal is a *result* in this project, not an error to hide:

* a missing file is 404 and says which path;
* an argument that cannot be honoured is 400;
* a capability this transport does not have is **501** — the UI greys the control out rather than pretending
  the answer was empty (§2.3: a stripped binary is stated, never hidden);
* a command that gdb refused, or a session that died, is 500 with gdb's own words in the body.

**One shape, one vocabulary** (`docs/api.md` §3.1): every failure answers
`{"error": <code>, "detail": <message>, "status": <int>}`. Before this, three shapes coexisted — the handlers
below answered `{"error", "detail"}`, an `HTTPException` fell through to FastAPI's `{"detail"}`, and an
unparseable query parameter answered FastAPI's 422 *list*. requirements.md §13.7 asks for a failure that says
clearly which of four it is; three shapes is not that.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from analysis.gdb.base import CoreNotLoaded, GdbDied, GdbError, GdbTimeout, Unreadable, Unsupported

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
"""The default machine code per status. `missing-file`, `no-core` and `unreadable` are *also* 404/409/422 and
carry their own, more specific code — a distinction a machine consumer needs and a status code cannot carry."""


def body(status: int, detail: str, code: str | None = None) -> dict[str, object]:
    """The one error body."""
    return {"error": code or CODES.get(status, "http-error"), "detail": detail, "status": status}


def _validated_message(exc: RequestValidationError) -> str:
    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(piece) for piece in error.get("loc", ()) if piece != "body")
        message = str(error.get("msg") or "invalid")
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts) or "invalid request"


def install(app: FastAPI) -> None:
    @app.exception_handler(Unsupported)
    async def unsupported(_: Request, exc: Unsupported) -> JSONResponse:
        return JSONResponse(status_code=501, content=body(501, str(exc), "unsupported"))

    @app.exception_handler(Unreadable)
    async def unreadable(_: Request, exc: Unreadable) -> JSONResponse:
        return JSONResponse(status_code=422, content=body(422, str(exc), "unreadable"))

    @app.exception_handler(CoreNotLoaded)
    async def no_core(_: Request, exc: CoreNotLoaded) -> JSONResponse:
        return JSONResponse(status_code=409, content=body(409, str(exc), "no-core"))

    @app.exception_handler(GdbTimeout)
    async def timeout(_: Request, exc: GdbTimeout) -> JSONResponse:
        return JSONResponse(status_code=504, content=body(504, str(exc), "timeout"))

    @app.exception_handler(GdbDied)
    async def died(_: Request, exc: GdbDied) -> JSONResponse:
        return JSONResponse(status_code=502, content=body(502, str(exc), "gdb-died"))

    @app.exception_handler(GdbError)
    async def gdb_error(_: Request, exc: GdbError) -> JSONResponse:
        return JSONResponse(status_code=500, content=body(500, str(exc), "gdb"))

    @app.exception_handler(FileNotFoundError)
    async def missing(_: Request, exc: FileNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content=body(404, str(exc), "missing-file"))

    @app.exception_handler(RequestValidationError)
    async def invalid_parameter(_: Request, exc: RequestValidationError) -> JSONResponse:
        """A query string that could not be parsed at all — 422, and the same body as everything else."""
        return JSONResponse(status_code=422, content=body(422, _validated_message(exc), "invalid-parameter"))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Every `HTTPException` the routes raise, including Starlette's own 404/405 for an unknown path.

        The code comes from the status (`CODES`) or from the exception *type* — `CoreNotLoaded` and
        `Unreadable` have their own handlers above precisely because a status cannot carry the difference.
        """
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content=body(exc.status_code, detail),
            headers=getattr(exc, "headers", None),
        )
