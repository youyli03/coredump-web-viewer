"""The FastAPI instance: the API, the frontend, and the lifetime hooks.

Static hosting has one trap on Windows, and it is not cosmetic: `mimetypes` reads the registry, where `.js` is
commonly associated with `text/plain`, and a browser refuses to execute an ES module served as `text/plain` —
the page stays blank and the only evidence is a console message. The demo's own server existed because of this
and the lesson moves here: the type is set before the mount is created.
"""

from __future__ import annotations

import contextlib
import mimetypes
import pathlib

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from config import CONFIG, Config
from web import errors
from web.routes import router

mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/javascript", ".mjs")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("application/json", ".json")
mimetypes.add_type("image/svg+xml", ".svg")

ROOT = pathlib.Path(__file__).resolve().parents[2]


def create_app(
    config: Config | None = None,
    *,
    root: pathlib.Path | None = None,
    state_path: pathlib.Path | None = None,
    bundle: pathlib.Path | None = None,
) -> FastAPI:
    """Build the app from what it is *given*, not from where this file happens to live.

    Every path used to be derived from this module's own `__file__` and every tunable read from the `CONFIG`
    singleton, which is filled while it is imported — so a test could not point the "recent" file at a
    temporary directory, could not open a core that lives somewhere else, and could not shorten a deadline to
    exercise the deadline path. `docs/api.md` §5 is the reasoning; the arguments are the whole of it.

    The defaults reproduce the running service exactly: no argument means the repository root, its
    `tmp/practice` bundle, the recent file next to the checkout, and the configuration from the environment.
    """
    from analysis.session import SessionManager

    config = config or CONFIG
    root = pathlib.Path(root) if root is not None else ROOT

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        """Shutdown kills every child gdb (§6), and it is a lifespan handler rather than `@app.on_event`
        because that decorator is deprecated in this FastAPI and this promise is the one thing on the way out
        that must not quietly stop running."""
        yield
        app.state.sessions.shutdown()

    app = FastAPI(title="coredump-web-viewer", version="0.1.0", lifespan=lifespan)
    app.state.config = config
    app.state.root = root
    app.state.bundle = pathlib.Path(bundle) if bundle is not None else root / "tmp" / "practice"
    app.state.state_path = pathlib.Path(state_path) if state_path is not None else root
    app.state.sessions = SessionManager(config)
    app.include_router(router)
    errors.install(app)

    ui = root / config.ui_dir
    if ui.is_dir():
        # The UI is edited while it is being looked at, so it must not be cached. Measured: FastAPI's
        # StaticFiles sends `ETag` and `Last-Modified` but **no** `Cache-Control`, and a browser then applies
        # heuristic freshness — it keeps serving a cached `app.js` without even revalidating. That cost a
        # confusing hour here: the shell had a new element and the cached script still wrote into the old one,
        # so the page failed with "cannot set properties of null" while the file on disk was correct.
        @app.middleware("http")
        async def _no_store_for_the_ui(request, call_next):
            response = await call_next(request)
            if not request.url.path.startswith("/api"):
                response.headers["cache-control"] = "no-store, must-revalidate"
            return response

        # A header cannot evict a copy the browser already stored, which is why this exists as well: the shell
        # asks for its assets under a version taken from their mtimes, so an edited `app.js` is a *different
        # URL* and no cache can answer for it. Derived rather than typed in, because a hand-kept version number
        # is exactly the thing nobody remembers to bump — which is how the page kept running an old script
        # against a new shell in the first place.
        @app.get("/", include_in_schema=False)
        def _shell() -> "HTMLResponse":
            import re

            from fastapi.responses import HTMLResponse

            html = (ui / "index.html").read_text(encoding="utf-8")
            for asset in ("app.js", "styles.css"):
                stamp = int((ui / asset).stat().st_mtime)
                # Any existing `?v=` is replaced, not appended to: the shell already carried a hand-kept
                # `app.js?v=3`, and a number nobody bumps is a cache that silently outlives the code.
                html = re.sub(rf'"{re.escape(asset)}(\?v=[^"]*)?"', f'"{asset}?v={stamp}"', html)
            return HTMLResponse(html)

        # `html=True` so `/` serves index.html; the API lives under /api and is registered first, so a static
        # file can never shadow a route.
        app.mount("/", StaticFiles(directory=str(ui), html=True), name="ui")

    return app


app = create_app()
