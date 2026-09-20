"""The cores this checkout has opened, so they do not have to be typed again.

Kept in one dot-file at the repository root (`.coredump-viewer.json`, gitignored), because "recent" here means
*a set of paths that still exist on this machine* — which only the process that owns the filesystem can answer,
and which is why the list is not in the browser's storage.

Two rules the rest of this project already follows apply here:

* **de-duplicated by the core path**, because that is what makes two entries the same opening;
* **validity is measured when the list is read**, not stored. A recent entry whose core was deleted is a fact
  about the filesystem, and a stored `ok: true` would be a claim that goes stale in silence — the same mistake as
  caching a config snapshot's answer.

The gdb is stored as a *descriptor* rather than a path (`{"kind": "local", "path": …}`) so that a remote gdb —
which the runner was deliberately shaped to allow — is a new `kind` and not a file format change.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

FILENAME = ".coredump-viewer.json"
LIMIT = 20
FIELDS = ("core", "exe", "sysroot", "solib_search_path")


def _normalise(path: str | None) -> str:
    """The key two entries are compared by: the same file named two ways is one core."""
    if not path:
        return ""
    try:
        return str(pathlib.Path(path).resolve()).casefold()
    except OSError:
        return path.casefold()


def _gdb_descriptor(value: Any) -> dict[str, str] | None:
    if not value:
        return None
    if isinstance(value, dict):
        kind = str(value.get("kind") or "local")
        path = value.get("path")
        descriptor = {"kind": kind}
        if path:
            descriptor["path"] = str(path)
        for extra in ("host", "port"):
            if value.get(extra):
                descriptor[extra] = str(value[extra])
        return descriptor
    return {"kind": "local", "path": str(value)}


def gdb_argument(descriptor: Any) -> str | None:
    """What the API's `gdb` field takes today: a path, and only for a local gdb.

    A descriptor for anything else is returned as `None`, so the caller falls back to the configured gdb and the
    entry is still listed — an honest "this entry names a remote gdb, which this build cannot use yet".
    """
    if isinstance(descriptor, dict):
        if descriptor.get("kind", "local") != "local":
            return None
        return descriptor.get("path") or None
    return str(descriptor) if descriptor else None


class Recent:
    """The list, read and written on demand. No cache: the file is small and a `stat` per entry is cheap."""

    def __init__(self, root: pathlib.Path) -> None:
        self.path = root / FILENAME

    # --- disk ------------------------------------------------------------------------------------- #
    def _read(self) -> list[dict[str, Any]]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        entries = raw.get("recent") if isinstance(raw, dict) else raw
        return [entry for entry in entries if isinstance(entry, dict) and entry.get("core")] if isinstance(entries, list) else []

    def _write(self, entries: list[dict[str, Any]]) -> None:
        try:
            self.path.write_text(json.dumps({"recent": entries}, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass  # a read-only checkout must not break loading a core

    # --- the three operations ---------------------------------------------------------------------- #
    def record(self, *, core: str, exe: str | None, gdb: Any, sysroot: str | None,
               solib_search_path: str | None, opened_at: str) -> list[dict[str, Any]]:
        entry: dict[str, Any] = {"core": core, "openedAt": opened_at}
        for key, value in (("exe", exe), ("sysroot", sysroot), ("solib_search_path", solib_search_path)):
            if value:
                entry[key] = value
        descriptor = _gdb_descriptor(gdb)
        if descriptor:
            entry["gdb"] = descriptor
        key = _normalise(core)
        entries = [old for old in self._read() if _normalise(old.get("core")) != key]
        entries.insert(0, entry)
        self._write(entries[:LIMIT])
        return self.list()

    def forget(self, index: int) -> list[dict[str, Any]]:
        entries = self._read()
        if 0 <= index < len(entries):
            entries.pop(index)
            self._write(entries)
        return self.list()

    def list(self) -> list[dict[str, Any]]:
        """The entries with their validity measured *now*: each named file, present or not."""
        out: list[dict[str, Any]] = []
        for entry in self._read():
            valid = {}
            for field in FIELDS:
                value = entry.get(field)
                valid[field] = None if not value else pathlib.Path(str(value)).exists()
            gdb = entry.get("gdb")
            if gdb:
                path = gdb_argument(gdb)
                valid["gdb"] = None if gdb.get("kind", "local") != "local" else bool(path and pathlib.Path(path).exists())
            out.append({**entry, "valid": valid})
        return out
