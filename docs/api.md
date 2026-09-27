---
title: HTTP API
date: 2026-09-26
updated: 2026-09-26
status: Active
---

# HTTP API

> What `web/` exposes, and — the point of this document — **which of this project's promises become
> assertable through it**.
>
> `requirements.md` says what to build and what counts as done (§13, the acceptance list);
> `architecture.md` says how the system is put together (§1 one resident gdb, §4 summary vs on demand,
> §5 code layout). This file says what the HTTP layer answers, what shape those answers have, and how a
> test can hold the backend to it without reading its internals.

---

## 1. Why this exists

The API is currently **exactly what the frontend needs and nothing more**: fourteen endpoints, one consumer,
and no tests. That is the honest state, and its consequence is specific:

- the integration suite (`tests/gdb/`) proves the *transport* reads a real core; the unit suite proves the MI
  parsing; **nothing at all** proves the HTTP layer between them — not a status code, not an error body, not
  the session lifecycle;
- several promises the other documents make are **not assertable** from outside today: "the core is loaded
  once" (§1), "on-demand results are cached per session" (§4), "shutdown kills every child gdb process" (§6),
  and the four distinguishable failures of §13.7. A promise that cannot be observed cannot be tested, and an
  untested promise is a sentence that stops being true.

So this document has one design driver, stated once and used everywhere below:

> **A test may only assert what the API makes observable, and it must assert *promises*, not the key set a
> particular dictionary happens to have this week.**

Everything that follows is either (a) the contract that makes an assertion stable, (b) observability that
makes a promise visible, (c) controllability that makes a scenario cheap to build, or (d) an endpoint that
turns one of §13's acceptance items into data.

---

## 2. The surface today

`GET /api/health` · `GET /api/samples` · `GET /api/defaults` · `GET /api/recent` ·
`DELETE /api/recent/{index}` · `POST /api/sessions` · `GET /api/sessions/{id}` · `POST /api/sessions/{id}/reload` · `DELETE /api/sessions/{id}` ·
`GET /api/sessions/{id}/memory` · `…/disassemble` · `…/object` · `…/objects` · `…/stack` · `…/frames/{level}`

Two endpoints in §5 and §6 are now in the tree and are **not** part of that list: `…/sessions/{id}?wait=<n>`
and `DELETE /api/sessions`. §8 records what else has landed.

| endpoint | testability today |
|---|---|
| `health` `samples` `defaults` `recent` | good — pure reads, no core, no gdb: they are the smoke layer |
| `POST /sessions`, `GET /sessions/{id}`, `DELETE` | workable — but loading is asynchronous, so a test can only poll and hope; and every open **writes the checkout's own `.coredump-viewer.json`** |
| `…/memory`, `…/disassemble`, `…/object`, `…/objects`, `…/stack`, `…/frames/{level}` | correct answers, no cost observable — nothing reports how many gdb commands a request sent, or whether it was answered from cache |

### 2.1 What is missing, with the evidence

| # | gap | evidence |
|---|---|---|
| 1 | **there is no contract module** | `requirements.md` §8 and `architecture.md` §5 both name `src/schema.py` ("the unified data format, the frontend/backend contract"); the file does not exist. Every route returns `-> dict`, so `/openapi.json` documents almost nothing, and tests can only pin today's accidental shape |
| 2 | **the architectural promises are unobservable** | `analysis/session.py` and `web/routes.py` contain no command counter and no result cache; only the transport caches backtraces internally (`mi.py`, "the stack, whole and cached"). `core_loads`, cache hits and command counts cannot be read from HTTP, so §1/§4/§6 cannot be asserted |
| 3 | **the error body has two shapes** | `web/errors.py` answers `{"error", "detail"}` for transport exceptions, while `HTTPException` falls through to FastAPI's default `{"detail"}` — and an unparseable query parameter answers a third shape (FastAPI's 422 list). §13.7 asks for failures that are *clearly which of four they are*; three shapes is not that |
| 4 | ~~two §13 acceptance items were unreachable~~ — **closed in P3; the index behind them added later** | §13.2 needed registers for any thread (the summary carried only the crashed one) and §13.5 needed a way to walk a type one level. Both are served now: `GET …/threads/{num}/registers`, and the typed pair `GET …/object` · `GET …/objects` · `POST …/expand`. The last one names the **type** — the "interpret as…" picker of requirements §4 rather than guessed DWARF — and it was for a while the only half that worked on a live session: `build_summary` is called with `include_typed=False`, so the live summary held no typed index, `GET …/object` answered 404 for **every** live session, and the offline page (fed by the fixture, which *does* pre-fetch the index) drew its structure overlay happily. That asymmetry is gone: a session now walks its **own** index — the crashed frame's arguments, one level at a time, bounded at 80 objects / 5 levels / 16 children — on the first ask, and every ask after it is a lookup. Measured on the practice core's `head`: 44 gdb commands, 8 objects, then **0** per request. A dump whose capability says `dwarf_types: false` answers `501` from all three, because an index that *cannot* exist is not an empty one |
| 5 | **the test prerequisites are absent** | `TestClient` needs an HTTP client; it is in neither the venv nor `requirements.txt` (whose only test dependency is `pytest`), and it has to be `httpx2` rather than `httpx` — starlette 1.7 imports `httpx2` and only falls back to `httpx` with a deprecation warning. There was no `tests/api/` and no HTTP test anywhere in the repository |
| 6 | **nothing is controllable** | `CONFIG` is a module singleton read while it is imported (`main.py` already documents that trap for `--gdb`), `create_app()` takes no arguments, and each route resolves the checkout root from its own `__file__`. So a test cannot shorten `command_timeout_s` to exercise the deadline path, cannot shrink `max_limit` to exercise a refusal, and cannot point the "recent" file anywhere but the checkout |

---

## 3. The contract layer (L1)

**One module, `src/schema.py`, and it is the file the spec already asked for.** Pure data plus the contract
version; it may be imported by `web/` *and* by `analysis/` (the dependency rule in requirements §6.1 forbids
`analysis/ → web/`, never `→ schema`), and it imports nothing else in the project.

| decision | why |
|---|---|
| every response is declared with `response_model=` | `/openapi.json` becomes a **machine-readable contract**: a test can assert that the served document matches the models, and a response that drifts is rejected where it is produced instead of in the browser. **One exception, and it is deliberate**: the session poll (`GET /api/sessions/{id}`) declares its shape in the OpenAPI document but is not re-validated at runtime — a model there would re-serialise the largest payload in the project on every poll, and the one thing it would add is the power to drop a field the model did not name, which is the failure mode this contract exists to prevent. `tests/api/test_contract.py` validates the real answers instead, which is where drift belongs |
| `CONTRACT` (a version string) is reported by `GET /api/health` **and** carried by every summary as `session.contract` | the static fixture in `ui/data/` is produced by `scripts/dump-fixture.py`, i.e. by a *second* producer of the same JSON. A version stamped in both places turns "the fixture is stale" from a silent wrong answer into a failing test |
| one error vocabulary, one body shape: `{"error": <code>, "detail": <message>, "status": <int>}` | §13.7's four answers become four codes; `detail` keeps the existing frontend working (`ui/app.js` reads `reply.detail`) |
| `GET /api/sessions/{id}/capabilities` | §13.6 requires an absent capability to be *stated*. As data it can be asserted: a dump with no DWARF answers `typed: false` **and** returns 501 from the typed endpoints, rather than showing a panel that is permanently empty |

### 3.1 The error vocabulary

| status | code | meaning |
|---|---|---|
| 400 | `bad-request` | an argument was checked here and refused (for example a length above `max_limit`) |
| 404 | `not-found` | no such core / executable / session / typed object at that address |
| 404 | `missing-file` | an operation needed a file that is not there (a source file, a module) |
| 409 | `not-ready` | the session is not `ready` — the state is named in `detail` |
| 409 | `no-core` | the transport has no core loaded, which is not the same failure as a session that is loading |
| 422 | `invalid-parameter` | the query string could not be parsed at all (FastAPI's own validation) |
| 422 | `unreadable` | gdb could not read those bytes (a hole in the dump is data, not an error; this is a refusal) |
| 500 | `gdb` | gdb refused the command; **its own words** are in `detail` |
| 501 | `unsupported` | this transport, or this dump, cannot do that — the frontend greys the control out |
| 502 | `gdb-died` | the debugger exited while the session was open |
| 504 | `timeout` | the command deadline passed; the session is failed, never left half-answered |

Anything not in the table answers the fallback code `http-error` with the same body, so a consumer can always
read `error` without a completeness guarantee on our side.

`501` became reachable in P3 and was not before: the typed walk is the first operation whose *capability* can
be absent for a given dump (`POST …/expand` on a target with no DWARF), and a capability that is absent is
stated with the note the capability itself carries — `tests/api/test_views.py` builds a symbol-free copy of the
practice binary and asserts exactly that, next to the assertion that the same session still answers threads,
stack, registers and memory. The three typed endpoints answer it alike, lookups included: `GET …/object` and
`GET …/objects` are 501 rather than 404/`[]` there, because an index over a dump that *cannot* be typed is not
an empty index — `[]` would read as "there is nothing at this address", which is a claim about the dump where
the truth is a statement about the viewer.

**A lookup that finds nothing is 404 and says how to look differently.** `GET …/object` at an address the
session's index does not reach names the index's own extent and the way out:

```text
no type is known for 0xdead0000dead0000: the index holds what the crashed frame's arguments reach (head).
Name the type instead (POST /expand), which is the 'interpret as…' picker of requirements.md §4 rather than
guessed DWARF
```

A C dump has no runtime types, so "what type is at this address" is only answerable from what was walked or
from a type the caller names. A viewer that guessed would be worse than one that asks.

The four answers of §13.7 map onto `501` (no such capability), `409` (not ready yet), `502` (gdb died),
`504` (timeout) — and a test asserts all four, because the v1 prototype's worst failure was answering
`{"threads": []}` for a core that never loaded.

**Two codes on one status is deliberate.** A status is what a browser or a proxy sees; the code is what the
frontend and the tests branch on, and 409-from-a-session and 409-from-a-transport are different sentences in
the UI. The same is true of 422: an unparseable query string is a client mistake, while `unreadable` is the
dump itself refusing, and only one of those should ever put an error in front of a user.

### 3.1a A core that names none of its files

`analysis/elf.py` takes a mapping's **name** from the core's `NT_FILE` note, which is a Linux convention: it is how
a `gcore` says which file each range came from. A core without it has every region anonymous — measured on the
x86-64 fixture with the note's type patched out: **18 regions, 0 named, `kind: anon` for each** — and that is the
shape a QNX core is expected to have (not measured here: this machine has no QNX core and no `nto*-gdb`, so
whether they carry the note is an open question, see `AGENTS.local.md`).

What a session does with such a core, measured end to end:

| | |
|---|---|
| loads | `ready`; the stack is found through `$sp`, not by name, so `stack` still appears as a window |
| `symbolize` | places the address in its mapping (`r-xp`, `path: null`) and states the missing function: *"this address is in code but gdb named no function for it"* |
| `/disassemble` | **`units: []` with a `reason`**: *"this core names no file for this page, and the session was given no executable to read one from, so there is no symbol table to list functions from — the bytes are still here (disassemble with a range, or name the binary and reload)"*. Without the reason an empty list reads as "this page contains no code", which is a claim about the dump where the truth is a statement about this viewer |
| the names that are missing | the region chips (`[anon]` instead of `libc.so.6`), the summary's text window (it is chosen by a named module), and frame `file`/`line` |

Naming the binary (`exe`) — and its module directory (`solib_search_path`) — is what brings the names back, which
is why those are session inputs rather than assumptions. `tests/api/test_foreign.py` builds this shape from the
x86-64 fixture (patching the note's type) so it is pinned without needing a QNX core.

**gdb is the second naming source, and a name is not a location.** The core's note is the kernel's own record;
gdb's library list is a reconstruction from the link map, and it is asked for once per session
(`MiTransport.libraries()`, one `-file-list-shared-libraries` plus the `=library-loaded` notifications from
startup). Every region says which source named it — `regions[].source` is `"nt_file"`, `"gdb"` or `null` — and
`memory_map.libraries` reports what gdb knew, including what it could **not** place:

```json
"memory_map": {
  "source": "core_pt_load+nt_file+gdb",
  "regions": [{"start": "0xe9def2da0000", "perms": "r-xp", "path": "/lib/aarch64-linux-gnu/libc.so.6",
               "source": "gdb", "kind": "libc.so.6"}],
  "libraries": [{"name": "/lib/aarch64-linux-gnu/libc.so.6", "host_name": "…/sysroot/lib/aarch64-linux-gnu/libc.so.6",
                 "symbols_loaded": true, "mismatch": false, "ranges": [{"start": "0xe9def2dc7d00",
                 "end": "0xe9def2ee43b4"}], "sources": ["notification", "list"], "regions": 1}]
}
```

Three measured facts decide this shape, all on the practice bundle's `crash_target` core with its note patched
out (28 regions, 0 named):

| | |
|---|---|
| a range exists only for an object whose **file** gdb could read | with the bundle's `sysroot` and `solib_search_path`: **2 of 28 regions named** (`libc.so.6`'s and `libplugin.so`'s `r-xp` regions, `source: "gdb"`), and libc's entry carries a range and a `host_name`. With no sysroot: **0 named** |
| the extent gdb reports is its **sections'**, not the module's mapping | libc's range `0xe9def2dc7d00`–`0xe9def2ee43b4` sits strictly **inside** its `r-xp` region `0xe9def2da0000`–`0xe9def2f3a000`, so the naming rule is *overlap* — a "region inside range" rule would name nothing here. What gdb places is therefore each module's code region, and the module's other mappings stay `anon` |
| a name may arrive without a usable address | with no sysroot, a cross gdb finds **its own toolchain's** ld.so for this core and says `warning: .dynamic section for "…/sysroot/lib/ld-linux-aarch64.so.1" is not at the expected address (wrong library or version mismatch?)` — while still reporting a range from it. That library is reported with `"mismatch": true` and names no region: the name is from the link map and is right, the location is not |

The same measured on the x86-64 fixture: gdb names `libc.so.6` and `ld-linux-x86-64.so.2` and places **neither**
— ld.so's range (`0x7fa4599760d8`–`0x7fa4599949e8`) falls in a **hole** between two of that dump's mappings, and
the file it found for it is one it rejects. So a caller asking "which region is this object?" must read
`libraries[].regions`, not infer it from a name being present.

What this does **not** do is guess: a library that gdb could not place, or placed from a file it rejected, names
nothing, and the region stays `anon` with gdb's own warning in `session.warnings`. Identifying a region by its
**content** — matching its bytes against the files this session was given — is a separate and explicit
inference, and it is what covers the case gdb cannot: a module whose file gdb never found.

### 3.2 The memory window: what is there, what is not, and what was never asked about

`GET …/memory` answers three states, and they must not be confused — `requirements.md` C3 asks for the bytes
*and* what they mean, and a window that gets either half wrong is a window that lies about a dump:

* **bytes** → `chunks`, each with its own `ascii` column and the words decoded out of it;
* **the dump has no bytes here** → `unread`, `200` with the gaps listed (or `422 unreadable` with gdb's own
  sentence when *nothing* in the window could be read — measured on the practice core's deliberate stray
  pointer: *"0xdead0000dead0000 for 16 bytes is not in this dump: gdb refused the command: Unable to read
  memory."*);
* **this viewer stopped asking** → `not_read`, which only appears when the round ceiling below is reached. It is
  a different thing from `unread` on purpose: a caller can act on it, and calling those bytes missing would be
  the same lie in the other direction.

The three are a **partition** of the window — measured on the practice core's partly resident `crash_target`
text page (4 096 bytes asked for): **2 389 bytes held, 1 137 missing, 570 unasked** = 4 096. That invariant is
asserted over HTTP, because the first version of the walk broke it in the most convincing way: it accounted for
7 666 bytes in a 4 096-byte window, `unread` having been computed twice — once from the chunk gaps and once from
the walk's own refusals.

Getting `unread` right needed two measurements of gdb that are worth writing down, both on that same page:

* **a run ends at the first byte gdb cannot reach.** Asked for 8 192 bytes, gdb stops at `0x…6115d5`, and the
  reply used to call the remaining 2 603 bytes missing — while they were right there: asked again from that
  address, gdb skips three bytes and hands over 253 more. So the window is **walked**: after each run, ask again
  from where it stopped, and what a long request hides comes back (measured: 379 bytes behind a skip gdb itself
  reported as 383 bytes wide);
* **whether gdb answers at all depends on how much was asked for.** From `0x…6115d5`, 896 bytes answer and 1 024
  refuse, with the same data at the same addresses in between. So a refusal is only believed about **the bytes it
  covered, at the size it was asked**: the walk subdivides (`_READ_MIN` = 64 bytes) and asks a skipped range back
  through the same process before any byte is called missing.

The cost is bounded by `_READ_ROUNDS` (64 commands per window) rather than by the dump's fragmentation: a
contiguous window — a heap node, a live stack — costs **1** command, the partly resident page above costs the
full 64 and reports the tail as `not_read`. Measured through the API: heap `1`, fully resident text page `1`,
partly resident text page `64`, a wholly unreadable address `422` in `1`.

The **reading** is in the same reply rather than in the browser, because a word's meaning depends on facts
only the core has: `arch`, `word_size` and `byte_order` come from its ELF header (`analysis/elf.py`), travel
with the window, and are what the decode uses — `words` are units of `width` (the caller's, default the core's
word size; only 1, 2, 4, 8, 16 are accepted, and anything else is `400`). A unit is decoded only when it is
wholly inside one chunk, aligned **on its address** so two overlapping windows agree about the word they share;
a unit straddling a hole is absent rather than zero-filled. `unsigned` and `signed` are decimal strings, because
a 64-bit value does not survive a JSON number in JavaScript. When the header cannot be read there is no decode
at all: `words` is empty and `refused.words` says why, rather than numbers that look plausible.

`requirements.md` §4 calls the unreadable case "a normal result, not an error", and it is — the *summary* carries
it as data (`memory.missing`), and `ui/app.js` turns the refusal into an `unread` hole rather than a failure.
The 422 keeps "the request could not be honoured" visible to anything that is not that one caller. If it is
ever changed to 200, the body should keep `unread` and the same reason text, so the frontend branch that
already exists keeps working.

---

## 4. Observability (L2)

The cheapest way to make a promise testable is to let the response say what it cost.

| affordance | shape | what it unlocks |
|---|---|---|
| per-request cost | response headers on every `/api/sessions/{id}/*`: `X-Gdb-Commands: <n>`, `X-Gdb-Cached: true\|false` | "ask the same thread's stack twice and the second answer costs **zero** gdb commands" (§4) — asserted, not assumed |
| session counters | `GET /api/sessions/{id}/stats` → `{core_loads, commands_sent, commands_by_op, cache_hits, cache_misses, timeouts, errors, gdb_pid, gdb_alive, idle_s}` | "the core is loaded **once**" (§1): `core_loads == 1` after any number of queries; "a dead gdb fails immediately" (§6) alongside a kill test |
| process counters | `GET /api/stats` → `{sessions_created, session_capacity_evictions, sessions_failed, gdb_processes_spawned}` | the capacity policy of §6 and the shutdown promise become assertable |

**Headers, not an envelope.** The summary JSON is *the same object* the static fixture holds and the frontend
falls back to; wrapping it in `{"data": …, "meta": …}` would break that path for no gain. Headers carry cost,
bodies carry data — and rate-of-change stays a property of the request, which is where it belongs.

`/stats` is read-only and side-effect free. It is part of the contract, not a debug back door: a promise that
is not in the contract is a promise the next refactor may delete.

**Landed 2026-09-26, and it paid for itself immediately.** The transport counts every command at its one
choke point (`MiTransport._exec`: `commands_sent`, `commands_by_op`, `timeouts`, `errors`), the HTTP layer
reports the per-request delta in two headers, and the two `/stats` endpoints carry what a session and the
process cost. The first thing the counters measured was that a promise was not kept: *a repeated `/stack` cost
64 commands*, with the frame locations and the backtrace cached but every per-frame question — the variable
list, `&name`, `info address`, `sizeof`, the frame record's memory read — going back to gdb. Cached the way
they are asked, the same request now costs **0**, and `tests/api/test_cost.py` asserts it.

One answer per request, measured after the change:

| request | `X-Gdb-Commands` | `X-Gdb-Cached` |
|---|---|---|
| `/stack` (first) | 84 | false |
| `/stack` (again, same thread) | **0** | true |
| the poll of a ready session | **0** | true |
| `/memory` (64 bytes at a heap address) | 1 | false |

`/memory` is deliberately not cached: one command per window is cheap, an unbounded window cache in a tool
that reads a gigabyte of dump is a leak, and the header says so instead of the reader having to guess.

---

## 5. Controllability (L3)

A test is only as good as the scenario it can build cheaply. Today none of these are buildable.

```python
create_app(config: Config | None = None, *, root: Path | None = None,
           state_path: Path | None = None, bundle: Path | None = None) -> FastAPI
```

- routes read `request.app.state.config` / `.root` / `.bundle` instead of the module singleton and their own
  `__file__`; `SessionManager` is constructed with the same config, so deadlines, capacity and reclaim all
  come from one place. `main.py` and `web.app:app` keep their current behaviour exactly.
- with that seam a test can inject: `command_timeout_s=0.1` (the 504 path), `max_limit=8` (the 400 path),
  `max_sessions=1` (capacity eviction), `idle_reclaim_s=0.2` (idle reclaim), a `gdb_path` that does not exist
  (a session that fails at load, so `409` and `state: failed` are reachable **without** a core or a real
  gdb), `bundle=` pointing at an empty directory, and `state_path=` in `tmp_path` so that **no test writes
  into the checkout**.
- `POST /api/sessions?wait=ready&timeout_s=10` — the existing poll, optionally waiting for a terminal state,
  bounded by a server-side cap and off by default. It replaces sleep-and-hope in tests and gives the UI a
  better option than its own timer.
- `DELETE /api/sessions` — close everything (test cleanup, and a real "close all" for the page).

**No failure-injection switches.** No `?fail=1`, no magic header. Every failure above is produced by a real
input — a path that is not a core, a gdb that is not there, a deadline that is genuinely short. That is this
repository's rule everywhere else, and a test surface that can lie is worse than none.

---

## 6. Endpoints this adds (L4)

All four **landed**, plus the capability endpoint of §3. Measured on the practice core:

| endpoint | what it answers (measured) |
|---|---|
| `GET …/threads/{num}/registers` | any thread's registers, cached for the session (a core is a snapshot); the crashed thread's answer is identical to the one the first screen already carried; an unknown thread is 404 |
| `GET …/stack?thread&offset&limit` | `total=28`, `truncated`, and windowing that returns *the same frames* rather than a second interpretation; every page together is the whole stack once. `truncated` means "this window is **not** the whole stack" — either side counts, because a window at the *end* of a 30 000-frame stack is still truncated by the 30 000 frames above it, and answering "not truncated" there reads as "this is all of it". The retired `levels` parameter is **refused with 400** rather than silently ignored — a dropped parameter answers a different question than the one asked. Measured at scale on the 30 000-frame sample: a 20-frame window costs ~285 commands at offset 0 and at offset 20 000 alike (and **0** for a repeat), and one frame can be asked for at any level — before the fixes, a window cost O(offset) (45 321 commands, 52.7 s at offset 20 000) and everything past the first screen's 500-frame page answered "no such frame". **No `limit` means one page, and the reply says so** (`report.STACK_PAGE` = 500 — the page the first screen
already carries). It used to mean "all of it", which is a promise this API cannot keep: measured on the
30 000-frame sample, `/stack` with no `limit` cost **235.6 s and 420 146 gdb commands** — the UI's own request
when the stack view opens — where one page costs 1.2 s and ~7 000, and every page after it the same. The reply
carries `offset`, `limit`, `total` and `truncated`, so a caller always knows which part of the stack it holds.

**A page can be drawn on its own.** The same fix made that necessary: `stack_frames` answers the memory
question (extent, frame record, where the variables sit) and carries no `func`, no source site and no
arguments, so a page of a deep stack would have arrived as anonymous rows — indistinguishable from a stripped
core. Each frame in a page now carries `func`, `file`, `line`, `arch` and `args`, and the arguments cost
**one** `-stack-list-arguments` command for the whole page (`tests/api/test_scale.py` asserts the delta is
exactly 1). The frame **locations** for a whole window are now asked for in one `frame apply` command: 22 commands against 87 for the same 21 frames, measured against the per-frame path in the same session, with the same wall time because gdb's own unwinding dominates either way. That command is **chunked at 256 frames**, and the ceiling is load-bearing rather than tidy: a range wide enough to be unbounded is a command that cannot answer inside `CDWV_COMMAND_TIMEOUT_S`, and a missed deadline *kills gdb* — measured, `/stack` with no `limit` (what the UI asks for when the stack view opens) covered all 30 002 frames in one command and came back `502 gdb-died` in 30.0 s after two commands, costing the session instead of answering slowly. Chunked, a whole-stack request is 118 bounded commands; measured on the same core, one 256-frame chunk at level 20 000 costs 1.04 s where the same 1 024 frames sent whole cost 4.23 s |
| `POST …/expand {address, type, field?, follow?}` | one level: `*(struct node *)0x…` → five fields, each carrying the expression that expands *it*; `follow` gives the `parent->next` step; a type or field that is not shaped like one is 400, because the API composes the expression and never hands a caller's string to gdb |
| `GET …/symbolize?address` | the mapping, the enclosing function with the offset into it, and — for a stack address — the thread whose stack pointer is inside that mapping. A heap address answers "no function contains this", a stack address answers with the thread, and the deliberate stray pointer answers three absences with three reasons |
| `GET …/capabilities` | §13.6, the same bits the summary carries (asserted equal), including the note that says why something is false |
| `POST …/reload` | reads the **same core again** in a new session: `201` with the new id, the new session is whole (poll it the same way), and the one it replaced is evicted by capacity — measured on the practice core, 0.9 s end to end. The paths are the *session's* own, not the caller's and not the summary's: the summary reports a display path (relative to this checkout when it can be), and re-opening from a string that was only meant to be read is how a viewer ends up analysing a file nobody named. A session that **failed** to load reloads too — that is when a reader most wants another try — so the endpoint needs `404`-able existence, not readiness |

Each of these is *thin by rule* (§5 of architecture: a route that computes anything has put logic in the wrong
layer); all four are transport operations the interface already declares and `tests/gdb/` already pins.

---

## 7. The test matrix this enables

The point of the whole design. Each row names what is asserted, and the affordance it needs.

| layer | cases | needs |
|---|---|---|
| **L0 — offline** | `health`, `samples`, `defaults`, `recent`; a core path that does not exist → `404 not-found`; a text file offered as a core → a **failed session carrying gdb's own words**; the error vocabulary of §3.1 | L1 + L3 only: no gdb, no core, no checkout writes |
| **L1 — one real core** | crashed thread expanded by default; `/stack` frames whose records are `verified`; `/frames/{level}` locals; registers; `/memory` bytes; `/disassemble` and its "no function contains this address" refusal; `object` / `objects` | the practice bundle + a cross gdb |
| **L2 — every practice core** (parametrized from `GET /api/samples`, so the API supplies its own fixtures) | `smash_ra` → two `??` frames and **no warning at all**; `smash_fp` → DWARF CFI and the frame record **contradicting each other**; `smash_data` → a faulting marker with a verifiably intact stack; `opt_target` → a variable **with no address** because it lives in a register; `snap_target` → a fault inside a signal handler; `STRIP=1` → capability absent **and** 501 | L1 + L4 (`capabilities`), plus the `-O2`/corrupted samples the practice suite already builds |
| **L3 — invariants** | core loaded once (`core_loads == 1`); a repeated query costs zero commands and is cached; capacity eviction; idle reclaim; gdb killed → `502 gdb-died` and `state: failed`; a short deadline → `504 timeout`; `DELETE` → no orphan gdb; two sessions on one core answer **identically** (the practice bundle is designed to be reproducible); the core file's hash is unchanged after the whole run (**read-only**) | L2 observability |
| **L4 — contract** | the served OpenAPI matches the models; every response validates; **the static fixture and a live session agree** — same `contract`, same key set; every endpoint `ui/app.js` calls exists and answers | L1, plus one live session for the parity half |

Two of these are worth calling out because they are cheap and catch the failures this project cares about
most: **the fixture parity test** (the fixture is a second producer of the same JSON, and it silently drifts
the moment either side changes), and **the read-only test** (a viewer that edits the evidence is the one
failure nobody forgives).

**Landed 2026-09-26** — L0 in full; the whole of L2 (every practice core through the API, each awkward case
asserted: `smash_ra`'s two `??` frames with reasons and no variables, `smash_fp`'s named frame whose record
contradicts the next, `smash_data`'s verifiably intact stack, `opt_target`'s register-resident variable with no
address, `snap_target`'s `<signal handler called>`, and a stripped target that loads with `dwarf_types` false);
P2's observability (the headers, both `/stats`, and the cached-replay half
of L3, which is what proved the caching promise was not being kept); the contract half of L4 (the served OpenAPI is the documented surface,
the poll's shape is declared and validated, every answer fits its model, and the two producers of the same
JSON agree key for key); and everything in L1/L3 that needs no new endpoint: the first screen and its
registers, the verified stack record, a frame's own locals, the crash site's function, data stated as data,
both memory answers, the ceiling refusal, capacity eviction, closing, the core's hash, determinism, and the
mid-load close race. L2 and the rest of L3 wait on §4's observability.

---

## 8. Order of work

| phase | content | behaviour change |
|---|---|---|
| **P0 — landed** | `httpx2` as a test dependency; `create_app(config, root, state_path, bundle)`; the uniform error body; `?wait=` and `DELETE /api/sessions`; `tests/api/` with the offline half of L0, the contract half of L4, and the parts of L1/L3 above | one: the error body gained `error` and `status` (`detail` is unchanged, so the frontend did not move), and `defaults.valid` now answers `false` for an empty suggestion instead of `true` |
| **P1 — landed** | `src/schema.py` (the module the spec names): the models, the error vocabulary moved out of `web/errors.py`, the request body, `CONTRACT`; `response_model` on every endpoint that has a fixed shape; `GET …/capabilities`; and the parity test that builds the same summary both ways and compares their keys | additive: `/api/health` and every summary gain `contract`, and the fixture gains the same field, so a stale fixture is visible instead of merely wrong |
| **P2 — landed** | the counters at the transport's choke point, the two `X-Gdb-*` headers, both `/stats`, and with them §13.7's four answers made distinguishable: `502 gdb-died` for a debugger that exited, `504 timeout` for one that missed a deadline, `409 not-ready` carrying the session's own words for a session that is not ready yet, and `501 unsupported` still to come in P3 | one behaviour change, and it is a fix: a session whose debugger dies now answers `502` with the reason instead of `409 "session is failed"` — the same sentence a session that is merely loading gets. Endpoints answered from the summary (`/capabilities`, `/object`, `/objects`, `/stats`, the poll) go on answering, because the death of a process does not unload a dump |
| **P3 — landed** | the four endpoints of §6, the L2 matrix in full, and the `xfail` gone: what it described is now either served (`/expand`) or refused with a reason that names the way out (`/object`). Two §13 acceptance items that had no HTTP answer at all — registers for a non-crashed thread, and any typed walk — are reachable, and `501 unsupported` became testable for the first time | additive, except one: a target with no DWARF used to fail its **whole session**, because the summary evaluates a demo root that gdb cannot evaluate without DWARF. That dump now loads and states what it lacks |

P0 and P1 come first because they change no product behaviour while making every later phase
"write the assertion, then change the implementation" — the only order in which the tests stay honest.

**P0 cost one real bug, found rather than looked for.** Running the suite made the whole test process hang for
minutes, intermittently: `Session.load()` assigns the transport *after* `close()` has already looked, so a
session closed — or evicted by the capacity policy — while it was still loading left its resident gdb running
for the rest of the process, and §6's "shutdown kills every child gdb process" was quietly false for exactly
those sessions. `tests/api/test_live.py` now closes a session mid-load and asserts the gdb is gone; with the
fix reverted the test fails, so it is not passing by luck.

---

## 9. Deliberately not here

- **No envelopes.** The summary is shared with the static fixture; wrapping it would break the offline page.
- **No authentication, no CORS, no versioned URL prefix.** The service binds to `127.0.0.1` by design
  (requirements §5) and has one local user; `/api/v1/…` would be a promise to nobody.
- **No test-only endpoints.** Anything added must be something the frontend could legitimately use; where a
  test needs a scenario, it builds it out of real inputs and injected configuration (§5).
- **No mutation of the core, ever.** Including "convenience" endpoints that rewrite a dump to make a test
  easier. A core is evidence.
