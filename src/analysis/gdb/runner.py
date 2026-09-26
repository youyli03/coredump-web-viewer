"""A resident gdb process: one command in flight, every command on a deadline.

Why a thread per stream rather than `select`: Python cannot poll pipes on Windows, so a blocking
readline in the command path would be uninterruptible. The reader threads own the blocking reads; the
command path waits on a queue with a deadline, which is what makes a hung gdb survivable.
"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import time
from collections import deque
from typing import Sequence

from analysis.gdb.base import GdbDied, GdbTimeout

_EOF = object()


class GdbProcess:
    """Owns one gdb subprocess.

    Deliberately not safe for concurrent commands: a single gdb drives a single command stream, so the
    only correct concurrency is one command at a time (enforced by the lock below).
    """

    def __init__(
        self,
        argv: Sequence[str],
        *,
        command_timeout_s: float = 30.0,
        stderr_keep: int = 40,
    ) -> None:
        self.argv = list(argv)
        self.command_timeout_s = command_timeout_s
        self.stderr_keep = stderr_keep

        self._proc: subprocess.Popen[str] | None = None
        self._lines: queue.Queue[object] = queue.Queue()
        self._stderr: deque[str] = deque(maxlen=stderr_keep)
        self._readers: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._saw_eof = False

    # --- lifecycle --------------------------------------------------------------------- #
    def start(self) -> None:
        if self._proc is not None:
            raise RuntimeError("this gdb process has already been started")
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
        )
        self._readers = [
            threading.Thread(target=self._pump_stdout, name="gdb-stdout", daemon=True),
            threading.Thread(target=self._pump_stderr, name="gdb-stderr", daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc is not None else None

    def _pump_stdout(self) -> None:
        stream = self._proc.stdout if self._proc is not None else None
        try:
            if stream is not None:
                for line in stream:
                    self._lines.put(line)
        except (OSError, ValueError):
            pass
        finally:
            self._saw_eof = True
            self._lines.put(_EOF)

    def _pump_stderr(self) -> None:
        stream = self._proc.stderr if self._proc is not None else None
        try:
            if stream is not None:
                for line in stream:
                    text = line.rstrip("\r\n")
                    if text:
                        self._stderr.append(text)
        except (OSError, ValueError):
            pass

    def stderr_tail(self, n: int = 6) -> str:
        """The last few lines gdb wrote to stderr — usually the human explanation of a failure."""
        return " | ".join(list(self._stderr)[-n:])

    def drain(self, *, quiet_s: float = 0.5, max_lines: int = 4000) -> list[str]:
        """Read until the stream has been quiet for `quiet_s`, and return what was thrown away.

        Startup is noisy: the `-ex` commands, the banner, `=library-loaded` notifications and one
        `^done` per `-ex` all arrive before we have sent anything ourselves. If they are not drained,
        the first real command reads someone else's result record and the whole session is off by one.
        """
        drained: list[str] = []
        with self._lock:
            deadline = time.monotonic() + quiet_s
            while len(drained) < max_lines:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    item = self._lines.get(timeout=remaining)
                except queue.Empty:
                    break
                if item is _EOF:
                    self._lines.put(_EOF)
                    break
                if not str(item).startswith("(gdb)"):
                    drained.append(str(item).rstrip("\r\n"))
                deadline = time.monotonic() + quiet_s
        return drained

    # --- the one command path ---------------------------------------------------------- #
    def command(self, text: str, *, timeout: float | None = None) -> list[str]:
        """Send one line and read records until the terminating result record (`^…`).

        Returns the records that arrived, with prompts dropped. Raises `GdbTimeout` or `GdbDied`.
        """
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise GdbDied("gdb was never started")
        deadline = time.monotonic() + (self.command_timeout_s if timeout is None else timeout)

        with self._lock:
            self._drop_prompts()
            try:
                proc.stdin.write(text + "\n")
                proc.stdin.flush()
            except (OSError, ValueError) as exc:
                raise GdbDied(f"cannot write to gdb: {exc}; stderr: {self.stderr_tail()}") from exc

            records: list[str] = []
            while True:
                try:
                    line = self._next_line(deadline, text).rstrip("\r\n")
                except GdbTimeout:
                    # §6, and not as a precaution: "on deadline, kill the gdb process and fail the session —
                    # a hung gdb cannot be trusted, and there is nothing to resynchronise". The reply to this
                    # command is still on its way, and the next command would read *that* as its own answer.
                    # Measured before this: after a deadline, reading a heap address that had just answered
                    # bytes came back as "not in this dump" — a wrong answer wearing the clothes of a
                    # legitimate refusal, which is the worst kind of wrong this project can produce.
                    self.abort()
                    raise
                if line.startswith("(gdb)"):
                    continue  # a prompt, not a record
                records.append(line)
                if line.startswith("^"):
                    return records

    def _next_line(self, deadline: float, text: str) -> str:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GdbTimeout(
                    f"no answer to {text!r} before its deadline; stderr: {self.stderr_tail()}"
                )
            try:
                item = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise GdbTimeout(
                    f"no answer to {text!r} before its deadline; stderr: {self.stderr_tail()}"
                ) from None
            if item is _EOF:
                raise GdbDied(f"gdb exited while answering {text!r}; stderr: {self.stderr_tail()}")
            return str(item)

    def _drop_prompts(self) -> None:
        """Discard leftovers from the previous command — normally just its prompt."""
        while True:
            try:
                item = self._lines.get_nowait()
            except queue.Empty:
                return
            if item is _EOF:
                self._lines.put(_EOF)
                return
            if not str(item).startswith("(gdb)"):
                self._lines.put(item)  # never drop something that is not a prompt
                return

    # --- shutdown ---------------------------------------------------------------------- #
    def abort(self) -> None:
        """Kill it now: no grace, no EOF dance, nothing left to resynchronise.

        Only for the case where the stream is already known to be out of step — a missed deadline. The polite
        `close()` (stdin EOF, then terminate, then kill) is for a gdb that is still answering.
        """
        proc = self._proc
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def close(self, *, grace_s: float = 5.0) -> None:
        """Idempotent: closing an already-dead gdb is a no-op, not an error."""
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()  # gdb exits on EOF of its command stream
        except (OSError, ValueError):
            pass
        try:
            proc.wait(timeout=grace_s)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=grace_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=grace_s)
                except subprocess.TimeoutExpired:
                    pass
        for reader in self._readers:
            reader.join(timeout=grace_s)
        self._proc = None
