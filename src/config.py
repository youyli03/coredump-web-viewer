"""Runtime configuration: every tunable number lives here and nowhere else.

Defaults are overridable by environment variables (`CDWV_*`) so a shell can point the backend at a
different gdb, core directory or sysroot without editing code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_str(name: str, default: str | None) -> str | None:
    raw = os.environ.get(name)
    return raw if raw else default


def _env_paths(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """A colon-separated list of directories, in the same spelling `PATH` uses.

    Empty and unset both mean the default, which is the one difference from `PATH`: an empty `CDWV_BUILD_ID_DIRS`
    is not "look nowhere", it is a variable nobody set.
    """
    raw = os.environ.get(name)
    if not raw:
        return default
    parts = tuple(part for part in raw.split(":") if part)
    return parts or default


@dataclass(frozen=True)
class Config:
    """Everything the backend needs to know about its environment."""

    # Where the service listens. Local only, by design.
    host: str = "127.0.0.1"
    port: int = 8000

    # Which gdb to run. A cross gdb reads cores of another architecture (see AGENTS.local.md).
    gdb_path: str = "gdb"

    # Symbol resolution for a core produced on another machine: the core records absolute paths that
    # do not exist here. `sysroot` maps them (the bundle's sysroot/), `solib_search_path` finds the
    # program's own shared objects by basename when they are recorded under their original paths.
    sysroot: str | None = None
    solib_search_path: str | None = None

    # Deadlines. Every gdb interaction has one; a hung gdb is never trusted.
    probe_timeout_s: float = 20.0
    command_timeout_s: float = 30.0
    load_timeout_s: float = 180.0
    shutdown_grace_s: float = 5.0

    # Paging.
    default_limit: int = 256
    max_limit: int = 4096

    # Lifetime. A resident gdb costs memory for as long as it lives, and a local tool has one user looking at
    # one screen — so a session nobody has asked about for half an hour is reclaimed, and capacity is one.
    idle_reclaim_s: float = 30 * 60
    max_sessions: int = 1

    # Where the frontend lives. It is static HTML/JS served by this backend, never imported (which is why it
    # is not under `src/`).
    ui_dir: str = "ui"

    # Where a **build-id** is looked for, when a mapping's bytes carry one (`analysis/elfimage.py`). A core from
    # another machine names its own libraries by paths that do not exist here, and gdb only manages to say
    # *"wrong library or version mismatch?"* about a file that is not the one it wants; a build-id is exact, so
    # the id read out of the dump is worth looking up. Both layouts are conventions, not inventions: a debug
    # tree keeps files at `<root>/<first two hex digits>/<rest>.debug`, and a `debuginfod` client cache keeps
    # them at `<cache>/<id>/debuginfo`. **Nothing is downloaded** — a viewer that silently reached for the
    # network would be doing something the user did not ask for, and the id is in the reply anyway.
    build_id_dirs: tuple[str, ...] = ("/usr/lib/debug/.build-id",)
    debuginfod_cache: str | None = "~/.cache/debuginfod_client"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            host=_env_str("CDWV_HOST", cls.host) or cls.host,
            port=int(_env_float("CDWV_PORT", cls.port)),
            gdb_path=_env_str("CDWV_GDB", cls.gdb_path) or cls.gdb_path,
            sysroot=_env_str("CDWV_SYSROOT", cls.sysroot),
            solib_search_path=_env_str("CDWV_SOLIB_SEARCH_PATH", cls.solib_search_path),
            probe_timeout_s=_env_float("CDWV_PROBE_TIMEOUT_S", cls.probe_timeout_s),
            command_timeout_s=_env_float("CDWV_COMMAND_TIMEOUT_S", cls.command_timeout_s),
            load_timeout_s=_env_float("CDWV_LOAD_TIMEOUT_S", cls.load_timeout_s),
            shutdown_grace_s=_env_float("CDWV_SHUTDOWN_GRACE_S", cls.shutdown_grace_s),
            default_limit=int(_env_float("CDWV_DEFAULT_LIMIT", cls.default_limit)),
            max_limit=int(_env_float("CDWV_MAX_LIMIT", cls.max_limit)),
            idle_reclaim_s=_env_float("CDWV_IDLE_RECLAIM_S", cls.idle_reclaim_s),
            max_sessions=int(_env_float("CDWV_MAX_SESSIONS", cls.max_sessions)),
            ui_dir=_env_str("CDWV_UI", cls.ui_dir) or cls.ui_dir,
            build_id_dirs=_env_paths("CDWV_BUILD_ID_DIRS", cls.build_id_dirs),
            debuginfod_cache=_env_str("CDWV_DEBUGINFOD_CACHE", cls.debuginfod_cache),
        )


CONFIG = Config.from_env()
"""The process's configuration, read once while this module is imported.

One accessor, not one per caller: `main.py` applies its command-line overrides to the environment *before*
importing anything that reads this, so the order is what makes `--gdb` work.
"""
