"""Exceptions → HTTP status and a body the frontend can print.

The mapping is the interesting part, because a refusal is a *result* in this project, not an error to hide:

* a missing file is 404 and says which path;
* an argument that cannot be honoured is 400;
* a capability this transport does not have is **501** — the UI greys the control out rather than pretending
  the answer was empty (§2.3: a stripped binary is stated, never hidden);
* a command that gdb refused, or a session that died, is 500 with gdb's own words in the body.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from analysis.gdb.base import CoreNotLoaded, GdbDied, GdbError, GdbTimeout, Unreadable, Unsupported


def install(app: FastAPI) -> None:
    @app.exception_handler(Unsupported)
    async def unsupported(_: Request, exc: Unsupported) -> JSONResponse:
        return JSONResponse(status_code=501, content={"error": "unsupported", "detail": str(exc)})

    @app.exception_handler(Unreadable)
    async def unreadable(_: Request, exc: Unreadable) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error": "unreadable", "detail": str(exc)})

    @app.exception_handler(CoreNotLoaded)
    async def no_core(_: Request, exc: CoreNotLoaded) -> JSONResponse:
        return JSONResponse(status_code=409, content={"error": "no-core", "detail": str(exc)})

    @app.exception_handler(GdbTimeout)
    async def timeout(_: Request, exc: GdbTimeout) -> JSONResponse:
        return JSONResponse(status_code=504, content={"error": "timeout", "detail": str(exc)})

    @app.exception_handler(GdbDied)
    async def died(_: Request, exc: GdbDied) -> JSONResponse:
        return JSONResponse(status_code=502, content={"error": "gdb-died", "detail": str(exc)})

    @app.exception_handler(GdbError)
    async def gdb_error(_: Request, exc: GdbError) -> JSONResponse:
        return JSONResponse(status_code=500, content={"error": "gdb", "detail": str(exc)})

    @app.exception_handler(FileNotFoundError)
    async def missing(_: Request, exc: FileNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"error": "missing-file", "detail": str(exc)})
