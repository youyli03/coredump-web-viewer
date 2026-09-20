"""The only entry point: `python main.py`.

It puts `src/` on `sys.path` — which is what makes `from web.routes import router` and
`from analysis.session import SessionManager` plain module paths — and starts uvicorn. Two files named
`main.py` was the confusion the old layout produced; there is one, here.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
# pyelftools is a real dependency (analysis/elf.py). A checkout that cannot install into site-packages can
# vendor the wheel under the disposable tmp/; nothing else looks there.
_VENDORED = ROOT / "tmp" / "pylibs"
if _VENDORED.is_dir():
    sys.path.insert(0, str(_VENDORED))


def main() -> None:
    # Parse first, import `config` second: `CONFIG` reads the environment while it is being imported, so an
    # override applied *after* that import is ignored — which is how `--gdb` silently kept the default.
    parser = argparse.ArgumentParser(description="coredump-web-viewer")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--gdb", default=None, help="gdb to run (a cross gdb reads other architectures)")
    parser.add_argument("--reload", action="store_true", help="restart on source changes (development)")
    args = parser.parse_args()

    import os

    if args.gdb:
        os.environ["CDWV_GDB"] = args.gdb

    from config import CONFIG

    host = args.host or CONFIG.host
    port = args.port if args.port is not None else CONFIG.port

    import uvicorn

    if args.reload:
        uvicorn.run("web.app:app", host=host, port=port, reload=True, app_dir=str(ROOT / "src"))
    else:
        from web.app import app

        uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
