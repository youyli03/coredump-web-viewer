"""One core, loaded once, answering queries until it is closed.

The whole design rests on §1 of the architecture: a resident gdb that loaded the core a single time, behind a
lock, because one gdb drives one inferior and one command stream. Everything the HTTP layer needs from a
session is here, and nothing in this module knows that HTTP exists.

Loading is asynchronous because a core takes seconds to minutes: `create` returns at once with a session in
`loading`, a worker thread builds the report, and the first screen fills in when it lands. The report is the
same JSON the frontend already eats, which is why the switch from static fixtures to a live core is one call
in `ui/app.js` and nothing else.
"""

from __future__ import annotations

import pathlib
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from analysis import report
from config import CONFIG


@dataclass
class Session:
    """A loaded core and the transport that reads it.

    The transport is opened once and kept: that is the resident-process decision (§1) and "the core is loaded
    once per session" (§6). A session that opened a gdb per query would re-read a multi-gigabyte core for every
    scroll, which is the thing the whole architecture was chosen to avoid.
    """

    id: str
    core: pathlib.Path
    exe: pathlib.Path
    gdb: pathlib.Path
    sysroot: pathlib.Path | None = None
    solib_search_path: pathlib.Path | None = None
    state: str = "loading"  # loading | ready | failed | closed
    error: str | None = None
    summary: dict[str, Any] | None = None
    transport: Any = None
    _closed: bool = False
    """Set by `close()`, and read by `load()` — see the race it closes: a session closed while its gdb is still
    being opened must not leave that gdb running."""
    config: Any = None
    """The configuration this session was opened under, handed down by the manager rather than read from the
    module singleton: deadlines and capacity are per-process decisions, and a test that cannot shorten a
    deadline cannot exercise the deadline path (`docs/api.md` §5)."""
    created: float = field(default_factory=time.time)
    touched: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def settings(self) -> Any:
        return self.config or CONFIG

    @property
    def elapsed(self) -> float:
        return round(time.time() - self.created, 1)

    @property
    def progress(self) -> str | None:
        """gdb's own last word about what it is doing.

        `Reading symbols from …` has been in hand since the first version: the transport keeps everything gdb
        says while starting up in `startup_records` — the same records `_version_from` reads the banner out of —
        and the loading screen showed a clock instead. A clock says something is happening; this says what.
        """
        transport = self.transport
        # `startup_records` holds what gdb wrote while the core was loading, *raw*: it is whatever the process
        # drained, and it is not guaranteed to be well-formed line by line. Handing it to the MI parser raised
        # `MiParseError` once, and because this runs inside `describe()` that took the whole API down with it —
        # so the unwrapping is local, deliberately forgiving, and wrapped: progress is a caption, and a caption
        # must never be able to fail a request.
        try:
            lines: list[str] = []
            for chunk in getattr(transport, "startup_records", None) or []:
                for text in str(chunk).splitlines() or [str(chunk)]:
                    body = re.sub(r"^[~&@]", "", text.strip()).strip().strip('"')
                    body = body.replace("\\n", " ").replace('\\"', '"').replace("\\\\", "\\")
                    if body.strip():
                        lines.append(body.strip())
            for record in getattr(transport, "startup_records", None) or []:
                if isinstance(record, dict) and record.get("text"):
                    lines.append(str(record["text"]).strip())
            lines.extend(str(line).strip() for line in (getattr(transport, "warnings", None) or []))
            for line in reversed(lines):
                if "Reading symbols" in line or "Reading in" in line or "Expanding" in line:
                    return line
        except Exception:
            return None
        return None

    def describe(self) -> dict[str, Any]:
        """What the frontend polls: state, how long, and gdb's own line about what it is doing.

        The object index is left out: it is the last bulk in the report, and both questions it answers have an
        endpoint (`/objects` for a range, `/object` for an address). The session keeps it, because the session
        is the thing holding the core.
        """
        self.touched = time.time()
        summary = self.summary
        if summary is not None and summary.get("typed", {}).get("objects"):
            summary = {**summary, "typed": {"on_demand": True}}
        return {
            "id": self.id,
            "state": self.state,
            "elapsed": self.elapsed,
            "progress": self.progress,
            "error": self.error,
            "core": str(self.core),
            "exe": str(self.exe),
            "gdb": self.gdb.name,
            "summary": summary,
        }

    def load(self) -> None:
        """Open the transport and build the report. Runs in a worker thread; failures are recorded, never
        raised into the void. The transport stays open afterwards — every later query uses this one.

        **A session closed while it is loading closes its own gdb.** `create` evicts the previous session and
        `DELETE /api/sessions/{id}` exists, so "closed" and "still loading" really do happen at once: the load
        thread used to assign the fresh transport *after* `close()` had already looked, and the resident gdb
        nobody would ever query again stayed alive — which turned "shutdown kills every child gdb" (§6) into a
        sentence that was only true for the sessions that finished loading first. Found by the HTTP suite
        hammering the lifetime path; `tests/api/test_live.py` pins it.
        """
        try:
            transport = report.open_transport(
                self.core,
                self.exe,
                gdb=self.gdb,
                sysroot=self.sysroot,
                bundle=self.solib_search_path,
                # The deadlines are configuration (§7), not the transport's own defaults: a setting nobody
                # reads is a sentence that is not true.
                command_timeout_s=self.settings().command_timeout_s,
                probe_timeout_s=self.settings().probe_timeout_s,
            )
            self.transport = transport
            if self._closed:
                self._release()
                return
            # No disassembly or window bytes here: both are the bulk of the report and both have an endpoint
            # for the window being looked at. The session keeps the transport, so those requests reuse the core
            # that is already loaded.
            self.summary = report.build_summary(
                self.transport,
                # Which profile the report walks belongs to the core, and this argument was dropped in a
                # refactor: with the default, the -O2 core was asked for the typed tree it does not have, gdb
                # refused, and the viewer quietly showed the static fixture instead. A silent fallback hiding a
                # real failure is the failure mode this project cares about most.
                sample=self.core.name.split(".")[0] or "crash_target",
                core=self.core,
            )
            if self._closed:
                # Closed while the summary was being built. Checked twice because the two checks cover two
                # different windows, and either one of them can be the one that matters.
                self._release()
                return
            self.state = "ready"
        except Exception as exc:  # a refusal is a result: the user must see why
            # Close the transport *first*: `close()` sets the state to "closed", and setting "failed" before it
            # means a failed load reports "closed" with the reason erased — which is exactly what happened. And
            # a session that was closed on purpose keeps saying "closed": its load failing afterwards is not a
            # failure anybody asked about.
            self._release()
            if not self._closed:
                self.state = "failed"
                self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.touched = time.time()

    def _release(self) -> None:
        """Close the transport if there is one. A failure here must not mask the reason the session ended."""
        transport, self.transport = self.transport, None
        if transport is None:
            return
        try:
            transport.close()
        except Exception:
            pass

    def close(self) -> None:
        self._closed = True
        self._release()
        self.state = "closed"


class SessionManager:
    """The session table: capacity one, one lock, idle reclaim, and a shutdown that kills children.

    Capacity is a policy, not a limitation (§6): this is a local tool, and a second core loaded at once costs
    another resident gdb for a screen that is not being looked at. The interface is still id-addressed, so
    raising the cap later is a config change rather than a rewrite.
    """

    def __init__(self, config: Any = None) -> None:
        self.config = config or CONFIG
        """The one place capacity, deadlines and reclaim are read from. `web.app` builds the manager with the
        configuration it was handed, so an injected config reaches every session (docs/api.md §5)."""
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def create(
        self,
        core: pathlib.Path,
        exe: pathlib.Path,
        *,
        gdb: pathlib.Path | None = None,
        sysroot: pathlib.Path | None = None,
        solib_search_path: pathlib.Path | None = None,
    ) -> Session:
        with self._lock:
            # Capacity is a policy (§6), and it defaults to one: opening a second core closes the first,
            # because the frontend's sample chooser is a switch, not a second window. Enforced here rather than
            # assumed, so raising `CDWV_MAX_SESSIONS` is a configuration change and nothing else.
            keep = max(1, self.config.max_sessions)
            for old in list(self._sessions.values()):
                if len(self._sessions) < keep:
                    break
                old.close()
                self._sessions.pop(old.id, None)
            self._counter += 1
            session = Session(
                id=f"s{self._counter}",
                core=core,
                exe=exe,
                gdb=gdb or pathlib.Path(self.config.gdb_path),
                sysroot=sysroot,
                solib_search_path=solib_search_path,
                config=self.config,
            )
            self._sessions[session.id] = session
        threading.Thread(target=session.load, name=f"load-{session.id}", daemon=True).start()
        return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is not None and self._expired(session):
            session.close()
            with self._lock:
                self._sessions.pop(session_id, None)
            return None
        self._notice_death(session)
        return session

    @staticmethod
    def _notice_death(session: Session | None) -> None:
        """A session whose gdb is gone is not ready, whatever it last believed.

        Measured: killing the child left the session answering `ready` while every query failed with the
        transport's `[Errno 22]` wrapped in "not in this dump". A dead debugger is one of the four answers §13.7
        names, so it is recorded as such — here, because every route and every poll goes through `get`.
        """
        if session is None or session.state != "ready" or session.transport is None:
            return
        if getattr(session.transport, "alive", True):
            return
        session._release()
        session.state = "failed"
        session.error = "gdb exited while the session was open — reload to start a new one"

    def all(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    def close(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.close()
        return True

    def _expired(self, session: Session) -> bool:
        return time.time() - session.touched > self.config.idle_reclaim_s

    def close_all(self) -> int:
        """Close every session and answer how many there were.

        The app's shutdown hook and `DELETE /api/sessions` kill the same children for the same reason, so they
        are one operation with two callers rather than two implementations that drift apart.
        """
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()
        return len(sessions)

    def shutdown(self) -> None:
        """Kill every session on the way out. A transport that is still loading is left to its thread, which
        owns its own process and reaps it on failure."""
        self.close_all()
