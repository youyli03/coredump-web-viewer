---
title: Specification
date: 2026-09-17
updated: 2026-09-17
status: Active
---

# Specification

> The only specification in this repository: what to build, what not to build, how it is put together,
> and what counts as done.
> Derived from the original design draft, with one change of emphasis: **stack and memory
> visualization are the product**; everything else supports them or waits.

---

## 1. Positioning

`coredump-web-viewer` — turns QNX / Linux coredump analysis from "reading gdb command-line text" into
"looking at diagrams in a browser".

```text
today:   gdb prints a pile of text  →  a human "wires it up" in their head  →  a conclusion
project: data gdb already has  →  unified JSON  →  the browser draws it  →  read the diagram
```

**Why it is worth building**

- In the coredump space the tools are all "GDB frontends" — they show you text, they do not give you an
  *analysis view*;
- kernel-dump tooling has almost no GUI at all;
- existing tools are all "points"; nobody connects them into "lines".

**The core need is stack and memory visualization, plus the jumps between them.** If those are not good,
the tool has no reason to exist:

- **stack** — the call stack as a tree: which thread crashed, how frames nest, where exactly it died;
- **memory** — the address space as a picture: which segments exist, their ranges, permissions, sizes
  and proportions;
- **navigation** — any value jumps to its memory, any address jumps to what it belongs to, any memory can
  be interpreted as a type; and **every jump can be walked back**.

It reuses what gdb already has. It does **not** write its own DWARF parser and does **not** write its own
disassembler (C6 *renders* gdb's disassembly and the source lines DWARF points at; it never decodes machine
code itself).

---

## 2. Scope

### 2.1 What to build

| Item | Description |
|---|---|
| Linux coredump | user space, glibc / musl |
| QNX coredump | `nto*-gdb` |
| Read-only analysis | never write to the target program, never modify the core file |

### 2.2 Not doing now (and do not abstract for it in advance)

vmcore / ramdump / kernel dump · live process debugging · Windows minidump · AI root-causing ·
authentication · multi-tenancy · clustering

The original draft had a medium-term plan to cover QNX / vmcore / ramdump and a long-term ambition to
become a "multi-backend dump analysis platform". **The multi-backend platform is out of scope for now**;
QNX stays in scope as a target platform, the kernel dump formats do not.

### 2.3 Explicit non-goals

- Not writing our own DWARF parser (use `pyelftools`, or just ask gdb)
- **Not writing our own disassembler, and not decompiling** — that is IDA / Ghidra's job. C6 shows *gdb's*
  disassembly next to the source line; it never decodes bytes itself, and it never guesses a listing for an
  address no function contains
- Not a general-purpose debugger: post-mortem analysis only, it never takes over a running process

---

## 3. Usage form

**Single-person local tool.** `python main.py` starts a service that listens on `127.0.0.1` only, and
the browser is the whole UI.

Therefore it explicitly does **not** require (and does not implement) authentication, multi-tenancy,
clustering, public deployment or quotas.

Analyzing a Linux / QNX core needs a gdb **with support for the corresponding architecture**, which is
usually unavailable on Windows — in that case the backend runs inside WSL2 or a container, **but the
service itself is still a local service**.

---

## 4. Functional requirements

### 4.1 The core — this is the product

| # | Feature | Description |
|---|---|---|
| **C1** | Load core (+ executable) | core path + symbolized binary; **reference only, never copy, never upload** |
| **C2** | **Stack visualization** | the call chain as a **flow graph**, IDA-style: one node per call step, the crash node at the end of the flow and highlighted, **consecutive identical frames folded into one node** (`descend ×24`) and unfoldable, and a switch between call order (`main → crash`) and gdb order (`#0` first). Every node shows **what that call was given** (its arguments, clickable), and **clicking a frame reads that frame's locals** — one query for that frame only, because the crash is usually a local, not an argument, and a deep stack's locals are a lot of queries nobody asked for. An empty argument list is one of two different things and they must not look alike: `main(void)` genuinely has none, while a frame with no debug info has none anyone can name. And the stack is shown **as memory**, not only as names: every frame's extent (its `sp` up to its caller's) and the frame record at its frame pointer (saved frame pointer, return address), with each local and argument marked on the bytes it occupies |
| **C3** | **Memory visualization** | a **hex editor**: raw bytes on the left (address gutter, 16 bytes, ASCII), and what those bytes *mean* on the right — the DWARF fields when a type is known there, the plain word-by-word reading when it is not. Bytes the dump does not have are **shown as missing**, never as zeros, and an address that is **mapped but has no bytes** is a third, different answer from "not in this dump" (a clean file-backed page is missing from the core and still readable). The crash site is marked in the bytes when it is on screen. A region strip above gives the address-space overview (segments × range × permissions × size) |
| **C4** | **Cross-reference navigation** | every value is a link: a register / argument / field → the memory it points at; a memory cell → the function, segment or **thread stack** it belongs to (memory → stack); breadcrumb + back/forward |
| **C5** | **Typed interpretation** | interpret memory as a DWARF type and expand it as a structure tree; follow pointer fields **to any depth** (multi-level pointer structs), one click per level, with cycle detection (the same address reached again is reported as a cycle, not followed) and back/forward |
| **C6** | **Code: source and assembly** | the crash site **in its code**: gdb's disassembly of the enclosing function, and — when the binary has DWARF — the source lines it came from, interleaved so a line sits above the instructions it compiled to. The instruction the program died on is marked, as is the line. Source *text* is the backend's own reading of a file (the paths in DWARF point at the build machine, so a substitution root is configuration, not a guess), and a file that cannot be found is stated, never blank. A stripped address is a **reason** ("no function contains this address"), not a listing of whatever bytes were there |

> C2 and C3 are the two **views**. **C4 and C5 are the point** — the jumps between them are what make this
> an analysis tool instead of two static pictures.
> C5 needs DWARF **in the dump**, not in the transport: MI carries typed expansion fine. A stripped binary
> is the case to detect and state, never to hide — do not offer a control that cannot work.
>
> **C6 renders gdb's disassembly; it is not a disassembler.** §2.3 still holds: we do not decode machine
> code ourselves, and this is not a decompiler. What C6 adds is gdb's answer, drawn — the same relationship
> the stack and the typed view already have with gdb. The distinction matters because it is exactly where a
> viewer starts lying: asked for a *range*, gdb disassembles anything, including data (measured: a heap
> address comes back as `udf #1`), so the address form is the default and a range is used only when the
> caller has established from the core's own mappings that the address is executable code.
>
> The stack is where C2 and C3 meet, so two rules hold there. **A frame record is a claim, not a fact**:
> the saved frame pointer and return address decoded out of memory are drawn only when they agree with the
> next frame gdb found, so a build without frame pointers, a signal frame, or a target whose ABI we have
> wrong shows no chain instead of a wrong one. And **the frame layout is keyed by architecture, not by
> operating system** — QNX on aarch64 is AAPCS64 and QNX on x86_64 is SysV, so the same knowledge covers
> both platforms; what an OS changes is thread metadata, and that comes from gdb.


### 4.2 Supporting — needed to make the core usable

| Feature | Description |
|---|---|
| Thread list | which threads exist and which one crashed |
| Registers / crash point | see at a glance where it died |
| Load progress + cancel | loading takes seconds to minutes; the user must see it move and be able to back out |

### 4.3 Later — explicitly not the point, do not build first

| Feature | Description |
|---|---|
| Object relationship graph | who references whom (fd / socket / mutex) |
| Lock dependency graph (deadlock cycle highlighted) | **was** positioned as the differentiator; demoted here — it must not drive the schedule |
| QNX adaptation | the MI path verified against a real `nto*-gdb` and a real core |
| Jump to IDA / Ghidra | click a stack frame → open that function there |
| A stack's popped frames | **verify, never reconstruct** — see the note below |

> **The stack below `sp` is evidence, not history.** A `ret` moves the stack pointer and erases nothing, so
> below `sp` sits what earlier calls left behind. On the practice core that is 16 KB of the 123 KB free
> stack — 79 saved frame pointers and 12 return addresses, which is to say the records of calls that have
> since returned.
>
> Those records may be **verified one at a time** and then stated as facts: a saved frame pointer that lands
> inside this thread's stack and above itself, a return address that lands in an executable mapping. What
> must **not** be built is a *previous call chain*: a reused stack is ambiguous — the same bytes served
> several calls, at different times — so any reconstructed chain is a hypothesis wearing the clothes of an
> answer, which is precisely the failure this project keeps refusing. Report the record and its evidence;
> never the story.

---

## 5. Non-functional requirements

| Item | Requirement |
|---|---|
| **Interaction latency** | the core is loaded **once**; selecting a thread or clicking a frame must be "there the moment you click" — the user clicks dozens of times in a row, and reloading the core each time (seconds to tens of seconds) is unacceptable |
| **Cross-platform** | usable on Windows, with the backend in WSL2 or a container when the right gdb is not available natively |
| **Read-only** | never write to the target program, never modify the core file |
| **Local** | listens on `127.0.0.1` by default; the core holds sensitive memory |
| **Capability transparency** | a capability that cannot be obtained must be **stated as absent**, never shown as a permanently empty panel |
| **Extensible** | adding a platform does not change the frontend — and **the frontend never branches on platform** |
| **Large data volume** | stack frames, memory regions and hexdumps support `limit` / `offset` — cores are GB-scale and a stack can have tens of thousands of frames |
| **Deployment** | one-command start; Docker when gdb itself has to be pinned to a version |

> **The frontend never branches on platform.** Its only switch is `capabilities`, plus `null` fields —
> there is no `if platform == "qnx"` anywhere in `ui/`. If supporting a new platform ever seems to require a
> frontend change, that means the schema is missing a field or a capability bit: **fix the schema, not the
> frontend.** (A genuinely new *kind* of view — a lock graph, an object graph — is a different thing and is
> allowed to be new UI.)

---

## 6. Architecture

### 6.1 Layers

```text
┌──────────────── browser ────────────────┐
│  stack tree · memory map · (later: graphs) │
└──────────────────┬──────────────────────┘
                   │ HTTP / JSON
┌──────────────────▼──────────────────────┐
│ backend (Python + FastAPI)              │
│  · session management (which core)      │
│  · calls the transport layer            │
│  · cache (the core is loaded once)      │
│  · unified JSON schema                  │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│ transport (probed, one per gdb)        │
│  · ① embedded Python / ② MI            │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│ gdb process (resident)                  │
│  · core + symbols already loaded        │
│  · takes queries, returns JSON          │
└─────────────────────────────────────────┘
```

Three ideas carry this design:

1. **one transport interface with two implementations** (embedded Python / MI), selected by probing
   what a given gdb can actually do — so Linux and QNX are not special cases in the code;
2. **a unified JSON schema** so the frontend only ever sees data, never a backend;
3. **a resident gdb process** so the core is not reloaded per request.

### 6.2 Data flow

```text
open the page
   ↓
give the core path (+ the symbolized binary)
   ↓
backend: start (or reuse) gdb, load the core once
   ↓
extract on demand — strictly serial inside that one process:
   · thread list   (info threads)
   · backtrace     (bt / walk the frames)
   · registers     (info registers)
   · memory map    (ELF program headers + the NT_FILE note)
   · symbols/types (DWARF, when this transport has it)
   ↓
unified JSON → cache
   ↓
browser renders: stack tree (crashed thread expanded) · memory map
```

> **Correction to the original draft.** It described the extraction as "concurrent (parallel)".
> That is wrong: **operations inside a single gdb process must be strictly serial** — gdb drives one
> inferior and one command stream. "Concurrency" can only mean *several sessions in parallel*, which is
> a different thing and is not a requirement here.

### 6.3 Engineering constraints

Learned the hard way; they are not style preferences:

- **The core is referenced by path only.** Never copied, never uploaded, never committed — it is
  GB-scale and contains sensitive memory.
- **gdb output must be sentinel-wrapped before it is parsed as JSON.** gdb writes `Reading symbols
  from ...`, warnings and Python tracebacks into the same stdout, so a bare `json.loads(stdout)` is
  always corrupted.
- **One gdb process = one serial command stream.** No exceptions inside a session.
- **Failure is reported as failure.** "Nothing there" and "it broke" must never collapse into the same
  answer, and a failure must never be rendered as an empty result.

---

## 7. Technology choices

| Layer | Choice | Why |
|---|---|---|
| Backend | **Python + FastAPI** | the parsing ecosystem is Python (gdb's embedded interpreter, `pyelftools`); one language, one process |
| gdb transport | **① embedded Python ② MI** — one class each, chosen by probing | see below |
| ELF parsing | `pyelftools` | pure Python, mature |
| DWARF | `pyelftools`, or ask gdb | type and variable information |
| Frontend | plain HTML + JS | lightweight first; no build step |
| Visualization | **ECharts** / D3.js | stack tree, relationship graphs; canvas for dense memory bars |
| Flame graph | `d3-flame-graph` or hand-rolled | a second view of the same stack |
| Process management | `subprocess` + a resident gdb + a command queue | avoids reloading the core |
| Deployment | Docker | pins the gdb version, especially `nto*-gdb` |

**Two transports, plus one documented fallback** — selected at load time by probing, never by guessing:

```text
A. embedded Python   ★ preferred when it exists
   · a payload runs inside the gdb process; direct access to gdb.Value / symbols / frames / memory
   · output: JSON over stdin/stdout
   · precondition: this gdb was built with Python — many nto*-gdb builds are not

B. MI (Machine Interface)
   · gdb --interpreter=mi3 → mi2 → mi, downgrading until one actually starts
   · structured records in a documented format, parsed outside
   · NOT guaranteed to exist: MI is core gdb, but nto*-gdb is a vendor fork — it may be ancient,
     may expose only part of the record set, and record shapes differ between versions
   · therefore MI is probed **command by command**, and each result becomes a capability bit

C. CLI text parsing   ✗ documented, deliberately NOT built
   · gdb --batch -ex "..." with human-readable output, parsed with regexes
   · it would be the "if this fails there is nothing left" path, since every gdb has a CLI
   · but it parses human-formatted text — exactly what this project avoids everywhere else
   · **not implemented, and no empty stub either**: it plugs into the same transport interface if a
     device ever turns up with neither Python nor usable MI. Until then it is a paragraph, not a file.
```

Probe before trusting any of them — never guess:

```bash
<gdb> --batch -ex "python print('OK')" -ex quit    # embedded Python available?
<gdb> --interpreter=mi2 --version                   # does an MI interpreter start at all?
```

Selection is **not** "which one exists" but "which one can actually serve this dump": the candidates are
tried in priority order, and the winner must pass a smoke test on the real core (load it, list its
threads). "The transport exists" and "the transport works on this dump" are different claims.

**Build order: MI first, embedded Python second.** This is an *implementation* order, not a runtime
preference — at runtime embedded Python is still tried first. MI goes first because:

- it is the **baseline**: a gdb without Python is common (most `nto*-gdb`), while a gdb without usable MI
  is barely usable at all;
- it is the **harder** one — record parsing, per-command capability probing, version differences;
- it is the **only one testable on the current Windows dev box** (the downloaded `gdb-multiarch` is built
  `--without-python`), so it keeps the dev loop local;
- and building the **weakest path first keeps the data model honest**: designed against embedded Python,
  the model would quietly absorb Python-only conveniences and MI would break it later.

Most of the MI transport can be built and verified **before any real core exists**: `-gdb-version`,
`-list-features` and the request/reply plumbing need no inferior, and a *bogus* core is enough to exercise
the `core_not_loaded` path — which is this project's most expensive lesson.

**Status.** MI is implemented and green against a real aarch64 core. **The embedded-Python transport is
deferred** because no gdb *on the development machine* can run it — the MinGW gdb, the multiarch gdb and
the Arm cross gdb are all `--without-python`. Note the asymmetry: **the Linux board's `gdb` and
`gdb-multiarch` both do have Python**, so this transport becomes testable there once a remote (ssh-backed)
runner exists — which is exactly the seam the runner keeps open. An implementation that cannot be run
against reality is worse than none, so **no empty `embedded.py` is written**: the `Transport` interface is
the reservation, and adding it later touches one new file plus one line in the probe list.

**Why not a Node backend**: parsing must be Python, so Node could only forward. That adds a language
boundary, a second process and a second failure surface without solving anything. (A Node *dev server*
for the frontend would be a different, later question.)

---

## 8. Modules

| Module | Responsibility | Key point |
|---|---|---|
| `session` | manage "which core is loaded" | session isolation, idle reclaim |
| `transport` | abstract interface over gdb, two implementations (embedded, MI) | `threads()` / `backtrace()` / `frame_arguments()` / `frame_variables()` / `registers()` / `read_memory()` / `evaluate()` / `expand()` / `memory_map()` … |
| `gdb_runner` | start / reuse the gdb process | resident process + command queue (shared by all transports) |
| `embedded_transport` | the payload that runs inside gdb | emits JSON on stdout; needs Python in that gdb build |
| `mi_transport` | MI records | `--interpreter=mi3/mi2/mi`, parsed record by record |
| `cli_transport` | CLI text | **documented but deliberately not built** — no stub class either; it would plug into the same interface |
| `transport_probe` | pick a transport for a given gdb + core | priority order, then a smoke test on the real core |
| `elf_parse` | ELF / DWARF parsing | `pyelftools` |
| `schema` | the unified data format | the frontend/backend contract |
| `api` | FastAPI routes | `/api/session`, `/api/threads`, `/api/bt`, … |
| `viz` | frontend visualization | stack tree, memory map |

---

## 9. Key technical points

**Embedded Python extraction** — the shape of the script that runs inside gdb:

```python
# runs in gdb:  gdb --batch -ex "source extract.py" ./app ./core
import gdb, json

out = {"threads": [], "frames": []}

for t in gdb.selected_inferior().threads():
    out["threads"].append({"num": t.num, "name": t.name()})

f = gdb.newest_frame()
while f:
    sal = f.find_sal()
    out["frames"].append({
        "func": f.name(),
        "pc": hex(int(f.pc())),
        "file": sal.symtab.filename if sal.symtab else None,
        "line": sal.line,
    })
    f = f.older()

print(json.dumps(out))   # in production this must be sentinel-wrapped (§6.3)
```

**Core loading is slow → keep the process resident.** Starting gdb and loading a multi-GB core costs
seconds to tens of seconds; do it once per session, keep a `session_id → gdb process` table, and reclaim
idle sessions.

**MI, for the paths where embedded Python is unavailable:**

```bash
gdb --interpreter=mi ./app ./core
→ ^done,stack=[frame={level="0",addr="0x...",func="main"},...]
```

**Two sources for the memory view:**

```text
① a live process: info proc mappings
② a core file:    ELF program headers (PT_LOAD) → range, size, permissions, file offset
                  plus the NT_FILE note — PT_LOAD alone cannot tell you which .so a range belongs to
```

**Reading bytes and types over MI** — the hex view and the typed walk need exactly three commands:

```text
-data-read-memory-bytes <addr> <len>    → memory=[{begin,end,offset,contents}]    contents is hex
-var-create - * "<expression>"          → type= and value= for one expression
-var-list-children --all-values <var>   → children=[{name,exp,type,value,numchild}]
```

Two measured behaviours that shape the UI: a range running off the end of a region comes back
**truncated** (8192 bytes asked for, 7888 returned, `^done` and no error), while an address in no mapping
at all is `^error,msg="Unable to read memory."`. Both are *answers* — "the dump does not have these bytes"
and "this address is not in this dump" — and neither may be flattened into an empty panel.

---

## 10. Roadmap

| Phase | Content | Output |
|---|---|---|
| **P0** | Get the chain working: core → gdb → JSON → a page that lists threads | you can see threads and the stack |
| **P0** | **Stack flow graph** (the first real view) | the crashed thread's call chain, readable at a glance |
| **P1** | **Memory view**: region strip + hex editor + the typed inspector beside it | the bytes, and what they mean |
| **P1** | Registers and crash-point highlighting | where it died, immediately |
| **P2** | Cross-reference navigation (C4) and the typed walk (C5): value → memory, memory → stack, pointer chains with cycle detection | inspect objects, and walk back |
| **Later** | object relationship graph · lock dependency graph · QNX on real hardware · IDA/Ghidra jump | not scheduled |

**Transport status.** MI already covers everything the two views need — `threads`, `backtrace`,
`frame_arguments` / `frame_variables` (so a frame shows what its call was given, and the crash frame shows
its own locals), `registers`, `read_memory` (holes preserved), `evaluate` / `expand` for the typed walk —
verified against a real aarch64 core. The memory map is *not* gdb's job: it comes from the core's PT_LOAD
segments and NT_FILE note. What is still missing is the layer above: `analysis/session`, `analysis/elf`,
the `/api/*` routes, and `ui/` as the real frontend.


---

## 11. Risks

| Risk | Countermeasure |
|---|---|
| QNX gdb has no Python support | probe first; MI is the normal path there, and capability limits are stated honestly |
| core loading is slow | resident process + result cache |
| symbols stripped / missing | tell the user exactly what is missing and which file; do not pretend a lookup worked |
| frontend scope creep | P0 is a plain page: thread list + stack tree; do not start with a SPA |
| it degenerates into "yet another GDB frontend" | the differentiation is the **analysis view** — stack tree and memory map first, graphs later |
| the lock graph cannot actually be derived | it is demoted (§4.3); it must not block the stack/memory work |

---

## 12. Reference projects

| Project | What to take from it |
|---|---|
| **core-explorer** | browser + its own DWARF parsing (no gdb) |
| **gdbgui** | the interaction design of a browser GDB frontend |
| **Voltron** | multi-pane debugging UI (stack / registers / memory on one screen) |
| **FlameGraph** | the classic shape of stack visualization |
| **heaptrack / massif-visualizer** | memory layout and timeline visualization |
| **IDA / Ghidra** | ⭐ the benchmark for flow-chart experience — "turn relationships into space" |
| **DumpSuite** | a reference for the web-platform form |
| **Trace32_CLI** | the idea of chaining several environments together |

---

## 13. What counts as done

1. Open the browser → fill in the core path → see the thread list, with the **crashed thread expanded
   by default and its stack tree already open**;
2. The stack tree shows the frame hierarchy, the crashed frame is highlighted, and clicking a frame
   shows its registers — clicking around **never reloads the core**;
3. The memory view shows the address space: segments with range, permissions and size, and which file
   each segment came from;
4. **Any value is clickable and jumps**: a register or field jumps to its memory; a memory cell jumps to
   the function, segment or thread stack it belongs to; **every jump can be walked back**;
5. **Memory can be interpreted as a type** and expanded as a structure tree, following pointer fields to
   any depth (**multi-level pointer structs**), with cycle detection and back/forward;
6. Capabilities that are absent (for example a dump with no DWARF, which takes C5 with it) are **stated as
   absent** in the UI, never shown as a permanently empty panel or a dead control;
7. When an error occurs, say clearly which of the four it is: **no such capability / not ready yet /
   gdb died / timeout**.

> Items 6 and 7 may look like nitpicking; they are the most expensive lesson of this project — the v1
> prototype, given a core that failed to load, answered `{"threads": []}` and looked like a success.

---

## Appendix: one-line positioning

> Take the data gdb already has and reorganize it as diagrams.
> Not "yet another GDB frontend" — the **visualization layer of dump analysis**.
