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
`DELETE /api/recent/{index}` · `POST /api/sessions` · `GET /api/sessions/{id}` · `DELETE /api/sessions/{id}` ·
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
| 4 | **two §13 acceptance items are unreachable** | §13.2 "clicking a frame shows its registers": the summary carries registers **only for the crashed thread** (`report.py`, `if thread["is_crashed"]`) and no endpoint serves another thread's. §13.5 (multi-level pointer expansion): `Session.describe()` replaces `typed` with `{"on_demand": True}` and there is **no `expand` endpoint**, so the live page can re-root a tree but cannot walk one level down — only the static fixture, which pre-fetches five levels, appears to work. Measured 2026-09-26, and worse than the description: `GET …/object` at a pointer the crash frame prints answers **404 `not-found`, "no type is known for…"**, and `GET …/objects` answers `[]`. The typed entry points are dead in a live session, because `build_summary` is called with `include_typed=False` so there is no index to look anything up in. `tests/api/test_live.py` pins it as a strict `xfail`, so the day it starts working the suite says so |
| 5 | **the test prerequisites are absent** | `TestClient` needs an HTTP client; it is in neither the venv nor `requirements.txt` (whose only test dependency is `pytest`), and it has to be `httpx2` rather than `httpx` — starlette 1.7 imports `httpx2` and only falls back to `httpx` with a deprecation warning. There was no `tests/api/` and no HTTP test anywhere in the repository |
| 6 | **nothing is controllable** | `CONFIG` is a module singleton read while it is imported (`main.py` already documents that trap for `--gdb`), `create_app()` takes no arguments, and each route resolves the checkout root from its own `__file__`. So a test cannot shorten `command_timeout_s` to exercise the deadline path, cannot shrink `max_limit` to exercise a refusal, and cannot point the "recent" file anywhere but the checkout |

---

## 3. The contract layer (L1)

**One module, `src/schema.py`, and it is the file the spec already asked for.** Pure data plus the contract
version; it may be imported by `web/` *and* by `analysis/` (the dependency rule in requirements §6.1 forbids
`analysis/ → web/`, never `→ schema`), and it imports nothing else in the project.

| decision | why |
|---|---|
| every response is declared with `response_model=` | `/openapi.json` becomes a **machine-readable contract**: a test can assert that the served document matches the models, and a response that drifts is rejected where it is produced instead of in the browser |
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

The four answers of §13.7 map onto `501` (no such capability), `409` (not ready yet), `502` (gdb died),
`504` (timeout) — and a test asserts all four, because the v1 prototype's worst failure was answering
`{"threads": []}` for a core that never loaded.

**Two codes on one status is deliberate.** A status is what a browser or a proxy sees; the code is what the
frontend and the tests branch on, and 409-from-a-session and 409-from-a-transport are different sentences in
the UI. The same is true of 422: an unparseable query string is a client mistake, while `unreadable` is the
dump itself refusing, and only one of those should ever put an error in front of a user.

### 3.2 The memory refusal, measured

`GET …/memory` has two honest answers and they must not be confused:

* **part of the window could not be read** → `200`, with the bytes in `chunks` and the gaps in `unread`;
* **none of it could be read** → `422 unreadable`, with a `detail` that names the address and says which of
  the two it is. Measured on the practice core's deliberate stray pointer: *"0xdead0000dead0000 for 16 bytes
  is not in this dump: gdb refused the command: Unable to read memory."*

`requirements.md` §4 calls that second case "a normal result, not an error", and it is — the *summary* carries
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

| new or changed | serves |
|---|---|
| `GET /api/sessions/{id}/threads/{num}/registers` | §13.2 — a frame's registers for *any* thread, not only the crashed one |
| `GET /api/sessions/{id}/stack?thread&limit&offset` and `total` / `truncated` in the answer | requirements §5: `limit`/`offset` for stacks. Today only `levels` exists and the answer never says how many frames were left out |
| `POST /api/sessions/{id}/expand {address, path}` | §13.5 — the typed walk, one level per click, with cycle detection and the depth cap; the fixture has pretended to do this since it pre-fetched everything |
| `GET /api/sessions/{id}/symbolize?address` | C4's one deterministic step: which function, which segment, or which thread's stack contains this address |
| `GET /api/sessions/{id}/capabilities` | §13.6 |

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

**Landed 2026-09-26** — L0 in full, plus everything in L1/L3 that needs no new endpoint: the first screen and
its registers, the verified stack record, a frame's own locals, the crash site's function, data stated as
data, both memory answers, the ceiling refusal, capacity eviction, closing, the core's hash, determinism, and
the mid-load close race. L2 and the rest of L3 wait on §4's observability; the parity half of L4 waits on
§3's contract.

---

## 8. Order of work

| phase | content | behaviour change |
|---|---|---|
| **P0 — landed** | `httpx2` as a test dependency; `create_app(config, root, state_path, bundle)`; the uniform error body; `?wait=` and `DELETE /api/sessions`; `tests/api/` with the offline half of L0, the contract half of L4, and the parts of L1/L3 above | one: the error body gained `error` and `status` (`detail` is unchanged, so the frontend did not move), and `defaults.valid` now answers `false` for an empty suggestion instead of `true` |
| **P1** | `src/schema.py`, `response_model` everywhere, `CONTRACT`, `capabilities`; the fixture-parity test | none — responses gain a `contract` field |
| **P2** | `X-Gdb-*` headers and both `/stats` endpoints; the cached-replay and the rest of L3 | additive |
| **P3** | the four L4 endpoints; the L2 matrix in full; the `xfail` on `/object` becomes a pass | additive, and it is what finally puts §13.2 and §13.5 within reach |

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
