# coredump-web-viewer

A browser viewer for Linux and QNX coredumps. One crash is shown as four linked views — the threads, the stack
with each frame's locals, the registers, and the memory beside the structures that live in it — so a corrupted
stack or a variable kept in a register can be read instead of guessed at.

The backend opens the core once with gdb and keeps it resident; the page asks for a window's bytes, a code page's
disassembly or a frame's locals when a view needs them. Nothing is invented: a byte that is not in the dump says
so, an address whose field the debug information does not describe highlights one byte rather than pretending to
know more, and a value gdb could not read prints as unreadable instead of as zero.

## What it needs

- **Python 3.11** and the packages in `requirements.txt`.
- **A gdb that can read the core.** A core of another architecture needs a cross gdb — for example
  `aarch64-none-linux-gnu-gdb` — and a gdb built *without* Python is fine: the transport speaks MI.
- Optionally, **a Linux machine** to build the practice cores the demo uses (see `practice/README.md`).

## Running it

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt      # Windows: .venv\Scripts\pip
.venv/bin/python main.py                       # Windows: .venv\Scripts\python
```

The service listens on `http://127.0.0.1:8000` (local only, by design) and serves the page itself. Options:

```sh
python main.py --port 8010 --gdb /path/to/aarch64-none-linux-gnu-gdb
python main.py --reload                        # restart on source changes
```

`--gdb` may also come from `CDWV_GDB`, and the address to listen on from `CDWV_HOST` / `CDWV_PORT`.

## Analysing a core

The form takes the five things a cross-machine core needs:

| field | what it is |
| --- | --- |
| core path | the core itself — referenced by path, never copied or uploaded |
| executable (with symbols) | the program the core came from |
| gdb | the gdb to run, if it is not the one on `PATH` |
| sysroot | a copy of the target's `/lib`, so the core's absolute library paths resolve |
| solib search path | where the program's own shared objects live, recorded under their original names |

The backend also lists the practice cores it finds under `tmp/practice`, and the rail on the empty screen shows
both what can be opened and what has been opened before.

## Practice cores

`practice/` builds and crashes the targets this viewer is developed against — a `-O0` target, a `-O2` one whose
variables live in registers, three deliberately corrupted stacks, and a register snapshot taken inside a signal
handler — and collects each core together with its binaries and a sysroot:

```sh
bash practice/collect.sh          # on the Linux machine; writes practice/out/
```

Copy the resulting bundle into `tmp/practice/` (a scratch directory that is never committed) and the backend will
offer the cores by name. `practice/README.md` has the details, including what to check when no core is written.

## Working with no backend

`scripts/dump-fixture.py` turns a practice core into a JSON fixture the page can load on its own, which is useful
when editing the frontend without running the backend. The fixtures land in `ui/data/` and are not committed.

## Tests

```sh
.venv/bin/python -m pytest        # Windows: .venv\Scripts\python
```

Unit tests run against recorded gdb replies, so most of the suite needs neither a core nor a toolchain.

## Layout

```
main.py       the entry point: puts src/ on the path and starts uvicorn
src/          the backend: config, the gdb transport and the queries over it, the HTTP layer
ui/           the page, served as static files by the backend
practice/     the targets that produce real cores, plus the collector
scripts/      helpers that talk to gdb from outside the app
tests/        pytest suite
docs/         requirements.md (the specification) and architecture.md (the design)
```

## Documentation

- `docs/requirements.md` — what the viewer must show, what it must refuse to invent, what counts as done.
- `docs/architecture.md` — why gdb is resident, why the transport is MI, where the module boundaries are.
- `AGENTS.md` — the index, and the rules this repository holds itself to (commit format, what may be committed).

## Licence

MIT — see `LICENSE`.
