// The frontend for coredump-web-viewer: one file of plain ES modules, no build step.
//
// Everything on screen comes from `data/data.json`, which was dumped from a REAL aarch64 core: threads,
// stacks and registers through our own MI transport, the memory map from the core's PT_LOAD segments
// and NT_FILE note, the raw bytes and the DWARF-typed fields through `read_memory` / `evaluate` /
// `expand`. No invented data — the ugly parts (`??` frames, unreadable fields) are real.
//
// Data comes from the backend (`/api/sessions`) and, with no backend running, from the static fixture
// switches between the screens so the loading/failed/expired states can be judged too.
//
// Two views carry the design:
//   stack  — an IDA-style flow graph down the call chain, with repeated frames folded into one node;
//   memory — a hex editor: raw bytes on the left, what those bytes *mean* on the right.

const state = {
  ui: "ready", // empty | loading | ready | failed | expired
  view: "stack", // stack | memory | registers
  thread: null,
  region: null, // index into memory_map.regions
  address: null, // the selected address in the memory view
  window: 0, // index into memory.windows, the window last looked at
  trail: [], // addresses jumped *to*, so every jump can be walked back
  folded: {}, // stack groups the user opened, keyed by level+pc
  railCollapsed: false, // the thread rail: collapsed to a spine, giving its width back to the view
  locals: {}, // frame locals read so far, keyed by `thread:level`
  selection: null, // the one selection: { address, start, end, objectKey, objectExpression, fieldExpression }
  asciiAligned: false, // ASCII as one cell per byte (aligned) or as compact text (readable)
  stack: null, // stack frames as objects, built once from the transport's own answers
  typed: null, // address → the objects that start there, built once
  expanded: new Set(), // rail tree nodes the user opened, keyed by expression
  railRoot: null,
  railScroll: 0, // the rail's scroll offset, carried across the rebuild like the pane's
  mapPitch: 0, // which minimap pitch: 0 narrow, 1 wide // the rail's own root object, so opening a field does not re-root it
  zoom: null, // the expression whose fields the overlay draws on top of its containers
  revealRow: null, // a field expression to scroll the rail to after the next render
  revealCode: null, // an instruction address to scroll the code rail to after the next render
  live: null, // {id} while a backend session is answering; null when the fixture is the source
  codePages: {}, // page address → the /disassemble reply (null while in flight)
  codeFiles: {}, // source text that arrived with those replies
  windowPending: {}, // window address → true while its bytes are in flight
  pageAsked: {}, // window address → the set of pages already asked for, so scrolling back does not re-fetch
  windowProgress: 0, // percent of the pending window read, so "reading" can be seen to move
  adhoc: {}, // windows read for an address the report did not name, by the address clicked
  adhocAsked: {}, // one request per address, however many renders happen meanwhile
  adhocRefused: {}, // and the reason, when the read was refused
  stackData: null, // the parsed stack, fetched when a stack is on screen
  typedData: {}, // typed objects fetched for what is on screen, by expression
  objectPages: {}, // window ranges whose objects have been asked for
  objectAsked: {}, // addresses whose object has been asked for
  identified: {}, // region start → what content matching made of that mapping (the *only* inferred answer)
  identifyPending: null, // the region start whose request is in flight
  heaps: {}, // region start → what the allocator's own structures say about that mapping
  heapPending: null, // the region start whose heap request is in flight
  stackPending: false, // one request, however many renders happen while it is in flight
  instruction: null, // the selected instruction: the bytes, its chip and its rail line are one thing
  sample: null, // which sample the data on screen came from — the chip that is lit reads this, nothing else
  form: {}, // the five path fields, held across renders so a failure does not erase what was typed
  formError: null, // why the last load by path failed, shown on the form
  recent: null, // cores opened before, from the backend's state file; null = not fetched yet
  defaults: null, // the paths *this server* suggests for the form; null = not fetched yet
  samples: null, // the practice cores this backend reports; null = not fetched yet
  loaded: [], // the cores opened in *this session*, in order — one chip each in the dev bar
  loadedKey: null, // which of them is on screen, so exactly one chip is lit
  codePromise: {}, // code page address → the fetch in flight, so a second ask can *wait* rather than race
  log: [], // events, newest last: loading, ready, a switch, a failure
  status: null, // the live line while something is loading (cleared when it lands)
  insnRange: null, // [start, end) of that instruction, so a byte can ask without a lookup
  paneTop: null, // the row offset a jump wants, computed by hexPane; render is the only thing that applies it
  scrollTop: 0, // the pane's current offset — derived from `topAddress` on every render, never trusted across one
  topAddress: null, // the address at the top of the pane: the durable form of "where the reader is looking"
  animateFrom: null, // the hex pane position a jump started from, for the short move when it lands
  viewportRows: 0, // how many rows fit on screen, measured from the last pane that existed
  rowsSpec: null, // the row entries of the current window, folding included
  foldZeros: true, // collapse runs of zero pages that have nothing named in them
  unfolded: new Set(), // folded runs the reader opened, keyed by the run's first page
  order: "call", // call: main → crash (top → bottom); gdb: #0 first
  mappings: false, // the region table, folded away by default
  loading: { progress: "Reading symbols from /home/lyy/cdwv-practice/out/crash_target...", seconds: 12 },
  failure: { code: "core_not_loaded", message: "gdb started but reported no threads for this core" },
};

// --------------------------------------------------------------------------- //
// tiny helpers
// --------------------------------------------------------------------------- //
function h(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "title") node.title = value;
    else if (key === "disabled") node.disabled = true;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

// The file name out of a path, for either platform: a core analysed here was very likely produced on Linux and
// named as such, but the machine reading it may spell the same path with backslashes — and a `leaf` that only
// knew `/` returned the whole path, which is what the recent list was showing.
const leaf = (path) => {
  if (!path) return null;
  const text = String(path);
  return text.slice(Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\")) + 1);
};
const bytes = (n) =>
  n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`;
const pad64 = (value) => value.toString(16).padStart(16, "0");
const norm = (value) => `0x${BigInt(value).toString(16)}`;

// A transient note with a **kind**, because the stripe on its left is read before the words are: an amber stripe
// on "paths filled in — press Load to open it" says something went wrong when nothing did, and green on "this
// core is not there any more" would say the opposite. `info` is the ordinary outcome of a click; `warn` is a
// caveat the reader should know about; `error` is a refusal.
function toast(message, kind = "info") {
  const node = h("div", { class: `toast ${kind}`, text: message });
  document.body.appendChild(node);
  setTimeout(() => node.remove(), 3200);
}

// The event log, at the bottom right.
//
// It replaced a sentence that described the current data and was overwritten every time anything changed —
// which loses exactly what a reader wants when something goes wrong: what happened *before*. Events are
// recorded here (loading, ready, a switch, a failure, a fallback), the newest is always on the bar, and the
// rest is one click away. The live progress line is deliberately *not* a log entry: it changes every half
// second while loading, and a log that fills with `loading … 3.5s` is a progress bar pretending to be history.
function logEvent(text) {
  const at = new Date();
  const stamp = `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}:${String(at.getSeconds()).padStart(2, "0")}`;
  state.log.push(`${stamp}  ${text}`);
  if (state.log.length > 200) state.log.splice(0, state.log.length - 200);
  paintLog();
}

function paintLog() {
  const line = document.getElementById("logline");
  const panel = document.getElementById("logpanel");
  if (!line) return;
  const newest = state.status ?? state.log[state.log.length - 1] ?? "";
  line.textContent = newest;
  line.classList.toggle("live", Boolean(state.status));
  if (panel && !panel.hidden) {
    panel.textContent = "";
    panel.append(...state.log.slice(-200).map((entry) => h("div", { text: entry })));
    panel.scrollTop = panel.scrollHeight;
  }
}

// One reading of where the app is, in place of five buttons that could force a state by hand. The stages are
// sequential — a core is asked for, read, and then either answers, fails, or is reclaimed for being idle — so
// the bar shows the stage rather than offering all of them at once. The log next to it says what happened.
const STATE_COLOUR = { empty: "var(--dim)", loading: "var(--accent)", ready: "var(--read)", failed: "var(--crash)", expired: "var(--exec)" };

function paintState() {
  const badge = document.getElementById("statebadge");
  if (!badge) return;
  badge.textContent = state.ui;
  badge.dataset.state = state.ui;
  badge.style.color = STATE_COLOUR[state.ui] ?? "var(--fg)";
}

// --------------------------------------------------------------------------- //
// addresses: the one thing everything on screen has in common
// --------------------------------------------------------------------------- //
const HEX = /0x[0-9a-fA-F]+/;

function parseAddr(value) {
  // A BigInt *is* an address already — it is the type the rest of this file passes around (`regionOf`, `windowFor`,
  // `norm`, every window and region start). Refusing it meant that any caller holding one was told "not an address"
  // and went nowhere, and `instructionPieces` hands over exactly that: every branch target in the code rail (`bl
  // 0x… <name> →`) was a dead link, and clicking one did nothing at all — no jump, no scroll, no highlight.
  if (typeof value === "bigint") return value;
  if (typeof value !== "string") return null;
  const match = value.match(HEX);
  if (!match) return null;
  try {
    return BigInt(match[0]);
  } catch {
    return null;
  }
}

function regionOf(target) {
  return (
    state.data.memory_map.regions.find(
      (region) => BigInt(region.start) <= target && target < BigInt(region.end),
    ) ?? null
  );
}

function windowFor(target) {
  return (
    state.data.memory.windows.find((window) => {
      const start = BigInt(window.address);
      return start <= target && target < start + BigInt(window.length);
    }) ?? null
  );
}

// A window's bytes, from whichever of the two places they came from.
//
// The fixture carries them; the backend does not, because they are most of the report's size — so a window on
// screen asks for *the pages it is looking at* (`ensurePages`). Until the answer arrives the map is empty and
// the pane says so: a page of zeroes would be a claim about bytes nobody has read yet.
// `byteAt` and `bytesAt` replace the per-byte map this used to build. That map was one Map entry per byte with a
// decimal address string as its key — measured on the heavy core's 3.8 MB stack window: **1 772 ms** and
// hundreds of megabytes, rebuilt for every window the reader opened. The bytes are already here as hex runs, so
// a lookup is a binary search over a handful of chunks and two characters of a string.
function byteAt(window, address) {
  const chunks = window?.chunks;
  if (!chunks?.length) return undefined;
  let low = 0;
  let high = chunks.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const chunk = chunks[middle];
    const begin = BigInt(chunk.address);
    if (address < begin) {
      high = middle - 1;
      continue;
    }
    const offset = address - begin;
    if (offset >= BigInt(chunk.length)) {
      low = middle + 1;
      continue;
    }
    return parseInt(chunk.bytes.slice(Number(offset) * 2, Number(offset) * 2 + 2), 16);
  }
  return undefined;
}

// `count` bytes from `address`, `undefined` where the window does not hold them. One call per row rather than
// sixteen: the binary search is the cost, not the parse.
function bytesAt(window, address, count) {
  const out = new Array(count);
  let chunk = null;
  let begin = 0n;
  let length = 0n;
  for (let index = 0; index < count; index += 1) {
    const at = address + BigInt(index);
    if (chunk === null || at < begin || at >= begin + length) {
      chunk = chunkOf(window, at);
      if (!chunk) {
        out[index] = undefined;
        continue;
      }
      begin = BigInt(chunk.address);
      length = BigInt(chunk.length);
    }
    const offset = Number(at - begin) * 2;
    out[index] = parseInt(chunk.bytes.slice(offset, offset + 2), 16);
  }
  return out;
}

// The hex run covering `[from, to)`, or null when the window does not hold all of it. One slice, so a caller
// that only wants to know "is anything in here non-zero" does not walk the bytes.
function hexSlice(window, from, to) {
  const chunk = chunkOf(window, from);
  if (!chunk) return null;
  const begin = BigInt(chunk.address);
  if (begin + BigInt(chunk.length) < to) return null;
  const offset = Number(from - begin) * 2;
  return chunk.bytes.slice(offset, offset + Number(to - from) * 2);
}

function chunkOf(window, address) {
  const chunks = window?.chunks;
  if (!chunks?.length) return null;
  let low = 0;
  let high = chunks.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const chunk = chunks[middle];
    const begin = BigInt(chunk.address);
    if (address < begin) high = middle - 1;
    else if (address >= begin + BigInt(chunk.length)) low = middle + 1;
    else return chunk;
  }
  return null;
}

// A whole range present **and** zero: the fold question, asked of a page at a time. A page the dump does not
// carry is not zero — it is missing — and the two must not fold into the same picture, so this looks for one
// chunk that covers the whole range and reads its hex run.
function rangeIsZero(window, from, to) {
  const chunk = chunkOf(window, from);
  if (!chunk) return false;
  const begin = BigInt(chunk.address);
  if (begin + BigInt(chunk.length) < to) return false;
  const offset = Number(from - begin) * 2;
  return !/[^0]/.test(chunk.bytes.slice(offset, offset + Number(to - from) * 2));
}

// What gdb already knows about an address, and the children it handed us for it.
// One address can be described by several expressions — `head` and `head->next->next->next` are the
// same struct — and that is not a nuisance to hide: it is how a cycle shows up.
// A stack frame is a structure like any other: a range, with named fields at offsets inside it. The saved
// frame pointer and the return address sit in the frame record, and every argument and local gdb could
// place sits where it actually *is* — which is the whole reason a stack is worth parsing at all.
//
// Built once, from the transport's own `stack_frames` / `frame_slots`, so nothing here re-derives what gdb
// already answered. A frame whose record could not be corroborated still gets its fields: the bytes are
// there to read, and the sentence explaining why they are not believed goes in the frame's header.
// Whichever source carries the parsed stack: the fixture's snapshot, or the reply to `/stack` when a stack is
// on screen. One accessor, so the two read sites below cannot disagree about where the stack came from.
// Every typed object this viewer has: the snapshot's, plus whatever has been fetched for what is on screen.
function typedObjects() {
  const snapshot = state.data.typed?.objects ?? {};
  return Object.keys(state.typedData).length ? { ...snapshot, ...state.typedData } : snapshot;
}
function stackSource() {
  return state.stackData ?? state.data.stack ?? {};
}

// The parsed stack, on demand: **one page** for the thread whose stack is on screen.
//
// The server answers a page (`limit` defaults to 500, the same page the first screen carries), because asking
// for the whole stack is a promise it cannot keep: measured on a 30 000-frame dump, one unpaged request cost
// 235.6 seconds and 420 146 gdb commands. A page is 1.2 s and ~7 000, and the reply says where it sits
// (`offset`, `limit`, `total`, `truncated`), so the rest is one request away — `loadMoreStack` below.
async function ensureStack(thread) {
  if (!state.live || thread === null || state.stackData || state.data.stack?.frames?.length) return;
  if (state.stackPending) return;
  state.stackPending = true;
  try {
    const response = await fetch(`/api/sessions/${state.live.id}/stack?thread=${thread}`);
    const reply = await response.json();
    if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
    state.stackData = reply;
    state.stack = null; // the derived frames were built from the other source
    state.typed = null; // and the index over those frames is stale the moment they change
  } catch (error) {
    state.stackRefused = String(error.message ?? error);
  }
  state.stackPending = false;
  render();
}

// The next page of the same thread, appended to the one on screen.
//
// Appended rather than re-fetched from zero: a page is a bounded cost, and asking for `offset=0&limit=1000`
// would pay for the frames already read. `slots` merge the same way, so the overlay keeps drawing every frame
// it has bytes for.
async function loadMoreStack() {
  const stack = state.stackData;
  if (!state.live || !stack || state.stackPending || !stack.truncated) return;
  const loaded = (stack.frames ?? []).length + (stack.offset ?? 0);
  if (loaded >= (stack.total ?? 0)) return;
  state.stackPending = true;
  render(); // the button says it is working rather than looking ignored
  try {
    const page = stack.limit ?? 500;
    const response = await fetch(
      `/api/sessions/${state.live.id}/stack?thread=${stack.thread}&offset=${loaded}&limit=${page}`,
    );
    const reply = await response.json();
    if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
    state.stackData = {
      ...reply,
      offset: stack.offset ?? 0,
      frames: [...(stack.frames ?? []), ...(reply.frames ?? [])],
      slots: { ...(stack.slots ?? {}), ...(reply.slots ?? {}) },
    };
    state.stack = null;
    state.typed = null;
  } catch (error) {
    state.stackRefused = String(error.message ?? error);
  }
  state.stackPending = false;
  render();
}

function stackFrames() {
  if (!state.stack) {
    state.stack = (stackSource().frames ?? [])
      .map((frame) => {
        const start = frame.start ? parseAddr(frame.start) : null;
        const end = frame.end ? parseAddr(frame.end) : null;
        const record = frame.record ?? {};
        const name = `#${frame.level} ${frame.func ?? "??"}`;
        const children = [];

        const at = record.at ? parseAddr(record.at) : null;
        if (start !== null && at !== null) {
          children.push({
            field: "saved x29",
            expression: `${name} · saved frame pointer`,
            type: "void *",
            value: record.saved_fp,
            offset: Number(at - start),
            size: 8,
            num_children: 0,
          });
          children.push({
            field: "saved x30",
            expression: `${name} · return address`,
            type: "void *",
            value: record.return_address,
            offset: Number(at - start) + 8,
            size: 8,
            num_children: 0,
          });
        }

        const elsewhere = [];
        for (const slot of stackSource().slots?.[String(frame.level)] ?? []) {
          const address = slot.address ? parseAddr(slot.address) : null;
          if (!slot.slot || address === null || !slot.size || start === null) {
            // No bytes in this frame: it lives in a register, at a fixed address, or the optimiser removed
            // it. It is still a variable *of this frame*, and dropping it is how a frame comes to look as
            // if it had fewer variables than it has.
            elsewhere.push(slot);
            continue;
          }
          children.push({
            field: slot.name,
            expression: `${name} · ${slot.name}`,
            type: slot.type,
            value: slot.value,
            offset: Number(address - start),
            size: slot.size,
            num_children: 0,
            is_arg: slot.is_arg,
          });
        }

        // A frame whose extent is unknown — its caller is not in the dump, so nothing says where it ends —
        // can still be *drawn* as far as the bytes we can actually place: its own record and its variables.
        // Deriving the span from them is the honest version of "these bytes are this frame's"; the frame's
        // header still says the extent itself is unknown.
        let span = end;
        if (span === null) {
          const placed = children.map((child) => start + BigInt(child.offset) + BigInt(child.size ?? 0));
          if (placed.length && start !== null) span = placed.reduce((a, b) => (b > a ? b : a), start);
        }
        const size = start !== null && span !== null ? Number(span - start) : 0;

        return {
          expression: name,
          type: "stack frame",
          address: frame.start ?? null,
          size,
          start,
          end: span,
          frame,
          children,
          elsewhere,
        };
      })
      .filter((object) => object.start !== null && object.size > 0);
  }
  return state.stack;
}

// Everything the overlay and the rail are allowed to interpret: the DWARF objects the session fetched,
// plus the stack frames. One source, because two sources is how the bytes and the tree start disagreeing.
function allObjects() {
    return [...Object.values(typedObjects()), ...stackFrames()];
}

function typedIndex() {
  if (!state.typed) {
    const map = new Map();
    for (const object of allObjects()) {
      const target = objectAddress(object);
      if (!target || target === 0n) continue;
      const key = norm(target);
      map.set(key, [...(map.get(key) ?? []), object]);
    }
    for (const [key, objects] of map) {
      map.set(key, objects.slice().sort((a, b) => a.expression.length - b.expression.length));
    }
    state.typed = map;
  }
  return state.typed;
}

// `char [16]` arrives as 16 single characters; a structure view wants the string.
function charString(expression) {
  const object = typedObjects()[expression];
  if (!object?.children) return null;
  let out = "";
  for (const child of object.children) {
    const match = String(child.value).match(/^-?\d+\s+'(.*)'$/);
    if (!match) return null;
    const char = match[1].replace(/\\000|\\0$/, "");
    if (!char) return out;
    out += char;
  }
  return out;
}

// --------------------------------------------------------------------------- //
// the jump: every address on screen goes through here (C4), and every jump can be walked back
// --------------------------------------------------------------------------- //
// A trail entry is the *place and the mode* it was left in, not just the address. Choosing a mapping moves from
// the map to the bytes, and the map is what the reader was looking at — so walking back has to restore the map
// as well, or the jump would be one-way and the list would have to be found again by hand.
function trailEntry() {
  return { address: state.address, mappings: state.mappings };
}

// "Go to this address": the jump form of `selectAt` — it records a trail entry (so `back` can return) and switches to
// the memory view. Every address link in the application calls this or `selectAt`; nothing else decides what is
// selected, and nothing else scrolls the pane.
async function goTo(address, { keepTrail = false, showMap = false } = {}) {
  const target = typeof address === "bigint" ? address : parseAddr(address);
  if (target === null) {
    toast(`${address} is not an address`, "warn");
    return;
  }
  const window = windowFor(target);
  if (window) state.window = state.data.memory.windows.indexOf(window);
  const region = regionOf(target);
  state.region = region ? state.data.memory_map.regions.indexOf(region) : null;
  return selectAt(target, { trail: !keepTrail, showMap });
}

// A short move of the hex pane from where it was to where the last render put it.
//
// The pane is a real scrolling element the reader owns, so this is a plain tween of `scrollTop` on animation frames
// rather than `scrollTo({behavior: "smooth"})`: the panes are rebuilt on every render, and a smooth scroll asked of an
// element the browser has not laid out yet is simply dropped. Writing `scrollTop` per frame always works.
//
// Both ends are passed in, not read from the pane: the call happens *before* the render applies the destination, so
// reading `pane.scrollTop` there returned the old position — the two ends came out equal and the move was skipped.
//
// It exists because a jump *inside* one window changes nothing else on screen — same rows, same listing, same
// thread — so without it the view appears not to have moved at all. Under a preference for reduced motion there is
// nothing to animate: the render has already left the pane in the right place.
function animateScrollTo(from, to, duration = 180) {
  const pane = document.querySelector(".hexscroll");
  if (!pane || from === null || from === undefined || to === null || to === undefined) return;
  if (Math.abs(to - from) < 4) return; // already there: a move nobody could see is not worth 180ms of motion
  if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;

  const started = performance.now();
  const step = (now) => {
    // The pane may have been rebuilt since: then this tween is stale and the new pane is already in place.
    if (document.querySelector(".hexscroll") !== pane) return;
    const progress = Math.min(1, (now - started) / duration);
    // Ease out: fast at the start, settling at the end, which is what makes a short move read as deliberate.
    const eased = 1 - (1 - progress) ** 3;
    pane.scrollTop = from + (to - from) * eased;
    if (progress < 1) window.requestAnimationFrame(step);
  };
  pane.scrollTop = from; // start where the reader was, so the first frame is a continuation rather than a jump
  window.requestAnimationFrame(step);
}

function goBack() {
  const previous = state.trail.pop();
  if (!previous) {
    toast("nothing to go back to", "warn");
    return;
  }
  // The mode travels with the step: a jump made *from* the mappings list goes back to the list, one made from
  // the bytes goes back to the bytes.
  goTo(previous.address, { keepTrail: true, showMap: Boolean(previous.mappings) });
}

// --------------------------------------------------------------------------- //
// chrome
// --------------------------------------------------------------------------- //
const CAPS = {
  threads: "threads",
  backtrace: "backtrace",
  registers: "registers",
  memory_map: "memory map",
  memory_read: "memory read",
  evaluate: "evaluate",
  expand: "expand",
  arguments: "frame args",
  dwarf_types: "DWARF types",
  thread_names: "thread names",
  core_notes: "core notes",
  lock_owner: "lock owner",
};

function topbar() {
  const session = state.data?.session;
  const caps = session?.capabilities ?? {};
  return h(
    "div",
    { class: "topbar" },
    h("span", { class: "name", text: leaf(session?.core_path) ?? "no session" }),
    h("span", {
      class: "meta",
      text: [session?.transport, session?.gdb_version?.split(" ").slice(0, 4).join(" ")].filter(Boolean).join(" · "),
    }),
    h(
      "div",
      { class: "caps" },
      Object.entries(CAPS).map(([key, label]) =>
        h("span", {
          class: `cap ${caps[key] ? "on" : "off"}`,
          title: caps.notes?.[key] ?? (caps[key] ? "available" : "not available for this dump"),
          text: `${caps[key] ? "✓" : "✗"} ${label}`,
        }),
      ),
    ),
    h("span", { class: "spacer" }),
    h("button", {
      text: state.reloading ? "reloading…" : "reload",
      title: "read this core again with the same paths — for a core that changed under the session",
      disabled: Boolean(state.reloading),
      onclick: () => reloadSession(),
    }),
    h("button", {
      text: "close session",
      onclick: () => {
        state.ui = "empty";
        render();
      },
    }),
  );
}

// The thread rail, collapsed **sideways**.
//
// At 48 threads the rail is a full column of rows for a list the reader mostly reads the top of, and the screen
// it is taking belongs to the stack or the bytes. Collapsing it gives that width back to the view: the column
// becomes a spine you can click to bring it back, and it keeps saying what is behind it — the count and whether
// anything crashed — because a strip that says nothing is a strip nobody dares click.
function threadsPane() {
  const threads = state.data.threads;
  const crashed = threads.find((thread) => thread.is_crashed);
  if (state.railCollapsed) {
    return h(
      "aside",
      { class: "aside collapsed" },
      h("button", {
        class: "rail-toggle",
        title: "show the thread list",
        text: "›",
        onclick: () => toggleRail(),
      }),
      h(
        "div",
        { class: "rail-spine", title: `threads · ${threads.length}${crashed ? ` · #${crashed.num} crashed` : ""}`, onclick: () => toggleRail() },
        crashed ? h("span", { class: "dot", text: "●" }) : null,
        h("span", { text: `threads · ${threads.length}` }),
      ),
    );
  }
  return h(
    "aside",
    { class: "aside" },
    h(
      "div",
      { class: "section-title with-toggle" },
      h("span", { text: `threads · ${threads.length}` }),
      h("button", {
        class: "rail-toggle",
        title: "collapse the rail to the left",
        text: "‹",
        onclick: () => toggleRail(),
      }),
    ),
    threads.map((thread) =>
      h(
        "div",
        {
          class: `thread ${thread.is_crashed ? "crashed" : ""} ${thread.num === state.thread ? "selected" : ""}`,
          onclick: () => {
            state.thread = thread.num;
            render();
          },
        },
        h("span", { class: "dot", text: thread.is_crashed ? "●" : "" }),
        h("span", { class: "num", text: thread.num }),
        h(
          "span",
          { class: "where", title: thread.pc ?? "" },
          thread.func ?? "??",
          h("span", { class: "pc", text: thread.pc ? `  ${thread.pc.slice(-6)}` : "" }),
        ),
        h("span", {
          class: "tid",
          title: `tid ${thread.tid ?? "?"} · ${thread.state ?? ""}`,
          text: thread.tid ?? "",
        }),
      ),
    ),
  );
}

function toggleRail() {
  state.railCollapsed = !state.railCollapsed;
  render();
}

function tabs() {
  const items = [
    ["stack", "stack"],
    ["memory", "memory"],
    ["registers", "registers"],
  ];
  return h(
    "div",
    { class: "tabs" },
    items.map(([key, label]) =>
      h("button", {
        class: `tab ${state.view === key ? "active" : ""}`,
        text: label,
        onclick: () => {
          state.view = key;
          render();
        },
      }),
    ),
  );
}

// --------------------------------------------------------------------------- //
// stack: the call chain as a flow graph
// --------------------------------------------------------------------------- //
const sameSite = (a, b) => a.func === b.func && a.file === b.file && a.line === b.line && a.pc === b.pc;

// Consecutive frames with the same function, source line and pc are one step in the flow, not 24.
function frameGroups(frames) {
  const groups = [];
  for (const frame of frames) {
    const previous = groups[groups.length - 1];
    if (previous && sameSite(previous.frames[0], frame)) {
      previous.frames.push(frame);
      previous.repeat = true;
      continue;
    }
    groups.push({ repeat: false, frames: [frame] });
  }
  return groups;
}

// Frame locals are read on demand, one frame per click — a deep stack's locals are a lot of queries, and
// nobody wants them all. The backend answers one frame at a time (`/frames/{level}`), which is the same
// transport call the fixture already made, so this is the hop that was missing: it used to read
// `detail[thread].locals`, which only exists because the *backend* walked every frame of every thread up front
// (28 frames here, ~60 gdb round trips, several seconds) — computed so that this line could find it, and thrown
// away by every other path. Asking for the one frame that was clicked is both cheaper and what the text above
// always said happened.
async function loadFrameLocals(threadNum, level) {
  const key = `${threadNum}:${level}`;
  state.locals[key] = { state: "loading" };
  render();
  await new Promise((resolve) => setTimeout(resolve, 0));
  let locals = state.data.detail[String(threadNum)]?.locals?.[String(level)];
  if (locals === undefined && state.live?.id) {
    // Live session: the summary no longer carries locals, so ask for this frame. A refusal is a result —
    // `frames` answers `[]` when gdb has nothing to name for the frame, which is not the same as an error.
    try {
      const reply = await fetch(`/api/sessions/${state.live.id}/frames/${level}?thread=${threadNum}`);
      locals = reply.ok ? await reply.json() : [];
    } catch {
      locals = undefined; // the fetch itself failed: say so rather than claiming gdb had nothing
    }
  }
  state.locals[key] = locals === undefined
    ? { state: "failed", message: "gdb could not be asked about this frame's locals" }
    : locals.length
      ? { state: "ready", variables: locals }
      : { state: "failed", message: "gdb had no locals for this frame" };
  render();
}

function toggleFrameLocals(threadNum, level) {
  const key = `${threadNum}:${level}`;
  if (state.locals[key]) {
    delete state.locals[key];
    render();
    return;
  }
  loadFrameLocals(threadNum, level);
}

function localsBlock(entry) {
  if (entry.state === "loading") return h("div", { class: "flocals dim", text: "reading this frame's locals…" });
  if (entry.state === "failed") return h("div", { class: "flocals dim", text: entry.message });
  // Arguments are already on the line above; repeating them here would only add noise.
  const locals = entry.variables.filter((variable) => !variable.is_arg);
  if (!locals.length) return h("div", { class: "flocals dim", text: "no locals in this frame" });
  return h(
    "div",
    { class: "flocals" },
    h("span", { class: "flabel", text: "locals" }),
    locals.map((variable) =>
      h(
        "span",
        { class: "arg is-local", title: `local · ${variable.type ?? "type unknown"}` },
        h("span", { class: "aname", text: variable.name }),
        h("span", { class: "aeq", text: "=" }),
        valueNode(variable.value, variable.type, variable.name),
      ),
    ),
  );
}

function frameNode(frame, threadNum) {
  const entry = state.locals[`${threadNum}:${frame.level}`];
  const open = Boolean(entry);
  return h(
    "div",
    { class: `fnode ${frame.is_crash_site ? "crash" : ""} ${frame.func ? "" : "nosym"}` },
    h("div", { class: "lvl", text: `#${frame.level}` }),
    h(
      "div",
      { class: "fbody" },
      h(
        "div",
        { class: "fhead" },
        h("span", { class: "fn", text: frame.func ?? "??" }),
        h("span", { class: "site", text: frame.file ? `${leaf(frame.file)}:${frame.line ?? "?"}` : "no source" }),
      ),
      frameArguments(frame),
      open ? localsBlock(entry) : null,
    ),
    h(
      "div",
      { class: "fright" },
      frame.is_crash_site && h("span", { class: "tag", text: "crash site" }),
      // Without debug info there is nothing to ask for, and asking anyway would be a wasted round trip.
      frame.file
        ? h("button", {
            class: `twisty ${open ? "active" : ""}`,
            text: open ? "locals ▴" : "locals",
            title: "read this frame's locals — one query, for this frame only",
            onclick: () => toggleFrameLocals(threadNum, frame.level),
          })
        : h("span", { class: "dim", text: "no debug info" }),
      h("button", { class: "pc", text: frame.pc ?? "", title: "jump to this address", onclick: () => goTo(frame.pc) }),
    ),
  );
}

// What the call was given. An empty list is two different things and they are not allowed to look alike:
// `main(void)` really has no arguments, while a frame in stripped libc has arguments nobody can name.
function frameArguments(frame) {
  const items = frame.args ?? [];
  if (items.length) {
    return h(
      "div",
      { class: "fargs" },
      items.map((item) =>
        h(
          "span",
          { class: "arg is-arg", title: `argument · ${item.type ?? "type unknown"}` },
          h("span", { class: "aname", text: item.name }),
          h("span", { class: "aeq", text: "=" }),
          valueNode(item.value, item.type, item.name),
        ),
      ),
    );
  }
  if (!frame.file) {
    return h("div", { class: "fargs dim", text: "no debug info for this frame — its arguments have no names" });
  }
  return null;
}

function groupNode(group, threadNum) {
  const first = group.frames[0];
  const last = group.frames[group.frames.length - 1];
  if (!group.repeat) return frameNode(first, threadNum);

  const key = `${first.level}-${first.pc}`;
  const open = Boolean(state.folded[key]);
  return h(
    "div",
    { class: "fgroup" },
    h(
      "div",
      { class: `fnode repeat ${first.is_crash_site ? "crash" : ""}` },
      h("div", { class: "lvl", text: `#${first.level}–#${last.level}` }),
      h(
        "div",
        { class: "fbody" },
        h(
          "div",
          { class: "fhead" },
          h("span", { class: "fn", text: first.func ?? "??" }),
          h("span", {
            class: "count",
            // `×24 so far`: the run may continue past the end of the page that carries it, and a count that
            // does not say so is a claim about the whole stack made from a page of it.
            text: `×${group.frames.length}${group.more ? " so far" : ""}`,
          }),
          h("span", {
            class: "site",
            text: first.file ? `${leaf(first.file)}:${first.line ?? "?"}` : "no source",
          }),
        ),
        frameArguments(first),
        open
          ? null
          : h("div", { class: "fargs dim", text: "unfold to see every call (its arguments differ per frame)" }),
      ),
      h(
        "div",
        { class: "fright" },
        h("button", {
          class: "twisty",
          text: open ? "fold" : "unfold",
          title: `${group.frames.length} identical frames`,
          onclick: () => {
            state.folded[key] = !open;
            render();
          },
        }),
        h("button", { class: "pc", text: first.pc ?? "", title: "jump to this address", onclick: () => goTo(first.pc) }),
      ),
    ),
    open ? h("div", { class: "funfolded" }, group.frames.map((frame) => frameNode(frame, threadNum))) : null,
  );
}

// The crashed frame's variables are the crash: `stray` is the pointer that was dereferenced.
function stackView(detail) {
  // The stack view is a stack on screen, so this is where it is read.
  ensureStack(state.thread);
  // Which frames are on screen: the pages fetched so far when there are any (they carry everything a flow
  // graph needs — function, source site, arguments — see `report.stack_detail`), else the summary's own page,
  // which is what the static fixture has.
  const live = state.live && (state.stackData?.frames ?? []).length ? state.stackData : null;
  const frames = live ? live.frames : detail.frames ?? [];
  const total = live ? live.total ?? frames.length : detail.total ?? frames.length;
  const more = Boolean(live?.truncated) && frames.length < total;
  const crashed = state.data.threads.find((thread) => thread.num === state.thread)?.is_crashed;
  const groups = frameGroups(frames);
  // A run of identical frames that is cut by the end of a page is *so far*, not all of it: saying `×24` about
  // twenty-four of an unknown number is the same class of claim as calling a truncated stack complete. The
  // count settles the moment the next page arrives.
  if (more && groups.length) groups[groups.length - 1].more = true;
  const ordered = state.order === "gdb" ? groups : groups.slice().reverse();
  const arrow = state.order === "gdb" ? "↑" : "↓";

  const nodes = [];
  ordered.forEach((group, index) => {
    if (index) nodes.push(h("div", { class: "arrow", text: arrow }));
    nodes.push(groupNode(group, state.thread));
  });
  if (more) {
    const sentinel = h("div", { class: "flowmore" },
      h("button", {
        class: "twisty",
        text: state.stackPending
          ? "reading the next page…"
          : `load the next ${Math.min(live.limit ?? 500, total - frames.length)} frames`,
        title: `frames ${frames.length}–${Math.min(frames.length + (live.limit ?? 500), total) - 1} of ${total}`,
        onclick: () => loadMoreStack(),
      }),
      h("span", { class: "dim", text: ` ${frames.length} of ${total} frames on screen` }),
    );
    // And the same thing when the reader simply scrolls to the end: the button is the visible control, the
    // observer is the same action without a click. One request at a time — `loadMoreStack` refuses while one
    // is in flight — so a long scroll cannot stack up pages.
    watchNear(sentinel);
    nodes.push(sentinel);
  }

  const read = Object.keys(state.locals).filter((key) => key.startsWith(`${state.thread}:`)).length;
  return h(
    "div",
    { class: "view" },
    h(
      "div",
      { class: "viewhead" },
      h("span", {
        class: "frames-note",
        text:
          `${total} frames · ${groups.length} flow steps` +
          `${more ? ` · showing ${frames.length}` : ""}` +
          " · arguments for every frame" +
          ` · locals on click${read ? ` (${read} read)` : ""}` +
          `${crashed ? " · level 0 is the crash site" : " · this thread did not fault"}`,
      }),
      h("span", { class: "spacer" }),
      h("button", {
        class: "twisty",
        text: state.order === "gdb" ? "order: #0 first" : "order: caller → crash",
        title: "IDA reads a graph downwards; gdb numbers the innermost frame #0",
        onclick: () => {
          state.order = state.order === "gdb" ? "call" : "gdb";
          render();
        },
      }),
    ),
    h("div", { class: "flow" }, nodes),
  );
}

// --------------------------------------------------------------------------- //
// registers
// --------------------------------------------------------------------------- //
// --------------------------------------------------------------------------- //
// code: the crash site as source and instructions (C6)
//
// Two rules decide this view's shape. **The listing is gdb's, drawn** — we do not decode machine code, and
// the addresses, the mnemonic text and the raw bytes all come out of the disassembly reply verbatim. And
// **what cannot be shown is stated**: a line whose source is not in this checkout says so, a line that
// compiled to nothing says so, and an address no function contains says that instead of listing whatever
// bytes happen to be there.
// --------------------------------------------------------------------------- //
function codeData() {
  const snapshot = state.data.code ?? { frames: {}, files: {} };
  const pages = Object.values(state.codePages).filter(Boolean);
  if (!pages.length) return snapshot; // the fixture carries everything; nothing was fetched
  return {
    frames: snapshot.frames ?? {},
    files: { ...(snapshot.files ?? {}), ...state.codeFiles },
    window: {
      units: [...(snapshot.window?.units ?? []), ...pages.flatMap((page) => page.units ?? [])],
      refusals: pages.filter((page) => page.reason).map((page) => ({ page: page.page, reason: page.reason })),
    },
  };
}

function codeLevels() {
  return Object.keys(codeData().frames ?? {})
    .map(Number)
    .sort((a, b) => a - b);
}

function codeReply(level) {
  return codeData().frames?.[String(level)] ?? null;
}

// The recorded path is DWARF's own — the build machine's `/home/lyy/cdwv-practice/src/libplugin.c` — and it
// is the key into the file table the backend filled by mapping that root onto this checkout.
function sourceText(recorded, line) {
  const file = recorded ? codeData().files?.[recorded] : null;
  if (!file || !line) return null;
  return file.lines[line - 1] ?? null;
}

function codeView() {
  const levels = codeLevels();
  if (!levels.length) {
    return h(
      "div",
      { class: "view" },
      h("div", {
        class: "frames-note",
        text: "this sample carries no code section — the fixture was dumped without one, so there is nothing to show rather than nothing found",
      }),
    );
  }
  const level = levels.includes(state.codeLevel) ? state.codeLevel : levels[0];
  const reply = codeReply(level);
  const stripped = codeData().stripped;

  return h(
    "div",
    { class: "view codeview" },
    h(
      "div",
      { class: "codehead" },
      h(
        "div",
        { class: "codeframes" },
        levels.map((candidate) => {
          const entry = codeReply(candidate);
          const at = entry.frame_func ?? "??";
          return h("button", {
            class: `codeframe ${candidate === level ? "active" : ""}`,
            title: `frame #${candidate} — ${at} at ${entry.address}`,
            text: `#${candidate} ${at}`,
            onclick: () => {
              state.codeLevel = candidate;
              render();
            },
          });
        }),
      ),
      h(
        "div",
        { class: "codesummary" },
        h("span", { class: "cfun", text: reply.function ? `${reply.function.name}+${reply.function.offset}` : "no function" }),
        h("span", { class: "dim", text: ` · ${norm(reply.address)} · ${reply.instructions.length} instructions · ` }),
        h("span", { class: "dim", text: "disassembly from gdb, source lines from DWARF" }),
      ),
    ),
    // The crash instruction is the one the frame's pc points at: the reply says which address was asked for,
    // and that is the address the program died on.
    codeListing(reply),
    stripped && stripped.refused?.reason ? strippedSection(stripped) : null,
  );
}

// --------------------------------------------------------------------------- //
// code: gdb's disassembly of what the hex pane is looking at (C6), and the source
// line each instruction came from
// --------------------------------------------------------------------------- //
function codeListing(reply, anchor) {
  const rows = [];
  for (const group of reply.lines) {
    const recorded = group.fullname || group.file;
    const text = sourceText(recorded, group.line);
    rows.push(
      h(
        "div",
        { class: `codeline ${text === null ? "nosource" : ""}` },
        h("span", { class: "clineno", text: group.line ?? "—" }),
        h("span", {
          class: "ctext",
          title: recorded ?? "",
          text: text ?? "the source for this line is not in this checkout",
        }),
      ),
    );
    if (!group.instructions.length) {
      rows.push(
        h(
          "div",
          { class: "insnrow nocode" },
          h("span", { class: "itext", text: "— this line compiled to no instructions (a declaration, a brace)" }),
        ),
      );
      continue;
    }
    for (const instruction of group.instructions) rows.push(instructionRow(instruction, reply.address, anchor));
  }
  return h("div", { class: "codelisting" }, ...rows);
}

function instructionRow(instruction, crashAddress, anchor = null) {
  const crash = instruction.address === crashAddress;
  // The anchor is the address at the top of the hex viewport: the same address the bytes above are showing.
  // It is a different mark from the crash mark on purpose — "you are here" and "this is where it died" are
  // two different facts, and a listing that merged them would lose one of them.
  const here = anchor !== null && instruction.address === norm(anchor);
  return h(
    "button",
    {
      class: `insnrow ${crash ? "crashsite" : ""} ${here ? "anchor" : ""}`,
      title: `${instruction.address}${crash ? " — the instruction the program died on" : ""} · click to see these bytes`,
      onclick: () => selectInstruction(instruction.address),
    },
    h("span", { class: "iaddr", text: norm(instruction.address) }),
    h("span", { class: "ibytes", text: instruction.bytes ?? "" }),
    h("span", { class: "itext", text: instruction.text }),
    crash ? h("span", { class: "imark", text: "← crash" }) : null,
  );
}

// The address gdb has no function for. Both halves are shown because they are different answers, and the
// difference is the whole point of the transport's `allow_unsymbolized`: the refusal is the default, and the
// range is what a debugger would print for those bytes — legitimate here because the core's mappings say
// this address is executable, but it still knows nothing about where any function begins.
function strippedSection(stripped) {
  const range = stripped.range ?? {};
  return h(
    "div",
    { class: "codesection" },
    h("div", { class: "codesection-head", text: `and one address with no function: ${norm(stripped.address)}` }),
    h("div", { class: "codesection-body" }, h("span", { class: "dim", text: stripped.refused.reason })),
    range.instructions?.length
      ? h(
          "div",
          { class: "codesection-body" },
          h("span", {
            class: "dim",
            text: stripped.executable
              ? "the core's mappings say this address is executable, so these bytes are code — but nothing says where a function starts, so no offsets are claimed:"
              : "these bytes are not in an executable mapping; gdb decodes them anyway, which is why the viewer does not do this on its own:",
          }),
          h("div", { class: "codelisting" }, ...range.instructions.map((i) => instructionRow(i, null))),
        )
      : null,
  );
}

// --------------------------------------------------------------------------- //
// registers
// --------------------------------------------------------------------------- //
// A register is a name and a value, and gdb's natural format is not that value: the SIMD registers arrive as
// nested unions (`v0 = {d = {f = {0x…, 0x…}, u = {0x…, 0x…}}}`), and every sub-view of every vector is also
// offered as its own register — thirty-two vectors times six views, which is how a register page came to look
// like a page of structures.
//
// So: one row per register, the sub-views dropped (they are the same bits, spelled differently), an aggregate
// rendered as the hex words it is made of, and the exact text gdb sent kept in the tooltip. And a value is a
// link only when it is an address — clicking `{d = {…}}` used to call `goTo` on a struct dump, which can only
// ever end in "that is not an address".
// `q0`/`d0`/`s0`/`h0`/`b0` are not more registers: they are the same 128 bits as `v0`, named at four widths
// and one byte. GDB lists all six, which is 32 × 6 = 192 of the 260 rows in the table — a register page that
// looks like a page of structures because most of it is the same register spelled differently. The `v` form is
// the wide one, so it is the one kept; the aliases are named in the note under the table rather than hidden.
const VECTOR_ALIAS = /^[qdshb]\d+$/; // `q0` (128), `d0` (64), `s0` (32), `h0` (16), `b0` (8) — all `v0`

function registerValue(value) {
  if (!/[{}]/.test(value)) return { text: value, aggregate: false };
  const words = value.match(/0x[0-9a-fA-F]+/g) ?? [];
  // The widest view is the honest one-line form: the whole 128 bits as two 64-bit words, or as the bytes gdb
  // listed when it gave no wide view at all.
  return { text: words.join(" "), aggregate: true };
}

function registersView(detail) {
  const registers = detail.registers;
  if (!registers) {
    return h(
      "div",
      { class: "view" },
      h("div", { class: "frames-note", text: "registers are fetched on demand — switch to the crashed thread" }),
    );
  }
  const hot = new Set(["pc", "sp", "x29", "lr", "x0"]);
  const shown = Object.entries(registers).filter(([name]) => !VECTOR_ALIAS.test(name));
  const hidden = Object.keys(registers).length - shown.length;
  return h(
    "div",
    { class: "view" },
    h(
      "table",
      { class: "regs" },
      shown.map(([name, value]) => {
        const { text, aggregate } = registerValue(value);
        const address = aggregate ? null : parseAddr(value);
        const jumpable = address !== null && regionOf(address) !== null;
        return h(
          "tr",
          { class: hot.has(name) ? "hot" : "" },
          h("td", { class: "name", text: name }),
          h("td", {
            class: `value ${aggregate ? "aggregate" : ""} ${jumpable ? "jump" : ""}`,
            title: aggregate
              ? `gdb's own text for ${name}: ${value}`
              : jumpable
                ? `jump to ${value} and interpret it`
                : value,
            text,
            onclick: jumpable ? () => goTo(value) : null,
          }),
        );
      }),
    ),
    hidden
      ? h("div", {
          class: "frames-note",
          text: `${hidden} further registers are the same SIMD values at other widths — q0 (128 bits), d0 (64), s0 (32), h0 (16), b0 (8) beside v0, for each of the 32 vectors. The widest form is listed; the others are not repeated`,
        })
      : null,
  );
}

// --------------------------------------------------------------------------- //
// memory: hex editor on the left, meaning on the right
// --------------------------------------------------------------------------- //
// What a mapping *is*, which is the question the strip answers at a glance: code you can execute, read-only
// data, writable data, the stack, the heap, anonymous pages that are none of those — and, before any of them,
// whether the range can be read at all.
//
// The last point was a bug for a long time: `---p` has no `w`, so it fell into "read-only data" — and on the
// practice core that band was 64.2 MB out of 88 MB of anonymous memory, all of it a PROT_NONE reservation with
// no bytes in the core at all, labelled as if it were data anyone could read. "Not readable" is not "read-only":
// one has contents and the other has none.
function regionKind(region) {
  if (!region.perms.includes("r")) return "reserved";
  if (region.perms.includes("x")) return "code";
  if (region.kind === "stack") return "stack";
  if (region.kind === "heap") return "heap";
  if (!region.perms.includes("w")) return "read-only";
  if (region.path) return "data";
  return "anonymous";
}

const REGION_KINDS = {
  reserved: { label: "reserved · no access", color: "#4c5566" },
  code: { label: "code", color: "var(--exec)" },
  "read-only": { label: "read-only data", color: "var(--read)" },
  data: { label: "writable data", color: "var(--data)" },
  heap: { label: "heap", color: "var(--heap)" },
  stack: { label: "stack", color: "var(--stack)" },
  anonymous: { label: "anonymous", color: "var(--anon)" },
};

function colorOf(region) {
  return REGION_KINDS[regionKind(region)].color;
}
// The one call for "the reader picked this address". Every entry point goes through it — a byte in the hex pane, a
// field box beside it, a row or a value in the struct rail, a branch target in the listing, a frame's pc, a register
// value, a mapping row, the first address of a session — so the three surfaces always describe the same thing.
//
// What it owns: the trail (only for a jump), where the pane starts from (for the move), the address, the resolved
// selection (which object and which field the address falls in), the rail's root and row, and the request that the
// render applies by scrolling. What it does *not* own: the highlight of any surface. Each of those reads
// `state.selection` and draws itself, which is what keeps them in step.
async function selectAt(address, { trail = false, keepView = false, showMap = false } = {}) {
  const target = typeof address === "bigint" ? address : parseAddr(address);
  if (target === null) {
    toast(`${address} is not an address`, "warn");
    return;
  }
  if (trail && state.address) state.trail.push(trailEntry());
  state.animateFrom = {
    top: document.querySelector(".hexscroll")?.scrollTop ?? null,
    window: state.window,
  };
  // A jump to another window invalidates both halves of the pane's position: the offset and the address at the top
  // belong to the rows that are being replaced. Dropping them means the new window cannot inherit a position that
  // meant something in the old one (which is how a cross-window jump could land at the end of the new window).
  const previousWindow = state.rowsSpec?.window ?? null;
  const nextWindow = windowFor(target);
  if (previousWindow && nextWindow && previousWindow !== nextWindow) {
    state.scrollTop = 0;
    state.topAddress = null;
  }
  if (!keepView) state.view = "memory";
  state.address = norm(target);
  const found = resolveSelection(target);
  state.selection =
    found ??
    {
      address: target,
      start: target,
      end: target + 1n,
      objectKey: null,
      objectExpression: null,
      fieldExpression: null,
    };
  // The rail is re-rooted on what lives at the target, and the selection is what the rail marks: an object when the
  // address is the object, a field when it is inside one. There is no second copy of this: `state.selection` is the
  // only place a selection lives, and the bytes, the overlay boxes and the rail all read it.
  state.railRoot = null;
  state.zoom = state.selection.objectExpression;
  state.revealRow = state.selection.fieldExpression;
  state.instruction = null;
  state.insnRange = null;
  state.mappings = showMap;
  state.reveal = true;
  render();

  const window = windowFor(target);
  const region = regionOf(target);
  if (state.live && window) await ensurePages(window, target);
  if (region && isCode(region)) await selectInstruction(target);
  render();
}

function selectAddress(address) {
  return selectAt(address, { keepView: true });
}

// --------------------------------------------------------------------------- //
// the structure overlay: fields drawn on the bytes they occupy
// --------------------------------------------------------------------------- //
// The hex column and the overlay are both 16 byte-cells per row, with the same 9px group gap after the
// eighth, so a field's width *is* its byte count and its position *is* its offset. Cell `i` of a row is
// grid column `lineOf(i)`, and columns 1..18 are the grid lines around the 17 columns (16 cells + gap).
// The hex and ASCII columns group their digits in eights, with a wider gap after the eighth byte: eight
// hex digits is how a word is read, and the gap is what makes `0x0…0x7 | 0x8…0xf` two halves instead of
// sixteen equals.
//
// The overlay column has no such gap, and that is not an inconsistency: the gap is a reading aid for
// *digits*, and between two fields that are adjacent in memory it would cut the structure in half exactly
// where nothing is there. Two different questions, two grids.
function lineOf(index) {
  return index < 8 ? index + 1 : index + 2;
}

function overlayLine(index) {
  return index + 1;
}

// A `char [N]` is a string, not a structure: its elements are one byte each, so drawing them would put N
// one-byte boxes on bytes the hex pane is already showing, and expanding it in the tree would replace
// `"wide-struct"` with twelve `119 'w'` rows. The characters are still fetched — `charString` needs them to
// build the string — they are just not a thing to lay out.
const CHAR_ARRAY = /^\s*(unsigned\s+)?char\s*\[/;

function isCharArray(object) {
  return CHAR_ARRAY.test(String(object?.type ?? ""));
}

// Is `inner`'s byte range inside `outer`'s? This is what makes "the deepest structure wins a byte" work:
// a piece is dropped when a *contained* object's piece covers part of it.
function contains(outer, inner) {
  const outerStart = objectAddress(outer);
  const innerStart = objectAddress(inner);
  if (outerStart === null || innerStart === null || !outer.size || !inner.size) return false;
  if (outer === inner) return false;
  return innerStart >= outerStart && innerStart + BigInt(inner.size) <= outerStart + BigInt(outer.size);
}

// Which objects to draw on this window's bytes.
//
// Every object that can be drawn, **biggest first**: a nested structure's fields are the ones worth reading
// (`nodes[0].id` says more than `nodes=[3]` covering 144 bytes), and `rowPieces` already drops a piece
// wherever a smaller object covers it — so the deepest structure wins each byte and no two labels land on
// the same cells. An earlier version drew only the outermost objects and left the inside of an array of
// structs blank, which is exactly the "there are sub-structures in there, why is nothing rendered" case.
//
// Only objects covering the *same* range are deduplicated: `head` and `head->next->next->next` are one
// struct under two names, but an array and its first element share a start and are different levels.
function overlayObjects(window) {
  const start = BigInt(window.address);
  const end = start + BigInt(window.length);
  const byRange = new Map();
  for (const object of allObjects()) {
    const objectStart = objectAddress(object);
    // Only what can actually be drawn: a known size, a real field layout, and **any** bytes in this window.
    //
    // Any, not all: a frame that straddles the window's end is still mostly on screen, and the drawing is
    // clipped per row anyway (`rowPieces` cuts every piece to the row it is on). Requiring the whole object
    // inside the window left the last rows of a stack blank — the tail of the next frame, which is exactly
    // the bytes a reader is looking at when they ask "and what about here?".
    if (objectStart === null || !object.size || !object.children?.length) continue;
    if (isCharArray(object)) continue;
    if (objectStart >= end || objectStart + BigInt(object.size) <= start) continue;
    if (!object.children.some((child) => typeof child.offset === "number" && typeof child.size === "number")) {
      continue;
    }
    const key = `${norm(objectStart)}:${object.size}`;
    const known = byRange.get(key);
    // Two expressions can name one range: when the user has pointed at one of them by name, that is the one;
    // otherwise the shortest expression is the readable one.
    const better =
      !known ||
      object.expression === state.zoom ||
      (known.expression !== state.zoom && object.expression.length < known.expression.length);
    if (better) byRange.set(key, object);
  }

  return [...byRange.values()]
    .map((object) => {
      const objectStart = objectAddress(object);
      return { ...object, start: objectStart, end: objectStart + BigInt(object.size) };
    })
    .sort((a, b) => Number(b.size) - Number(a.size));
}

// The object's bytes, split into fields and the holes the compiler left between them.
// `index` is the piece's position within the object — not within the row — so a field that spans two rows
// keeps one colour on both halves instead of changing half way through itself.
// The object's own extent is computed here rather than read off it, because this is called both with the
// decorated objects the window built and with the raw ones the panel holds.
function layoutPieces(object) {
  const objectStart = object.start ?? objectAddress(object);
  const objectEnd = objectStart + BigInt(object.size);
  const placed = object.children
    .filter((child) => typeof child.offset === "number" && typeof child.size === "number")
    // A field cannot live before the object it belongs to. When it does, the offset came from subtracting two
    // addresses that are not on the same footing — a stack frame's `record.at` sitting below the frame's own
    // `start`, which is what `#1 stacked_args` does in this practice core: every one of its fields gets offset
    // -64, and drawing them puts their boxes in the *previous* frame's row, on top of that frame's own fields.
    //
    // Such a field is not placed wrongly by a little: it is not in this object at all, so there is nothing truthful
    // to draw or to link to. It is dropped here, and the bytes keep whichever object really owns them.
    .filter((child) => child.offset >= 0 && BigInt(child.offset) < BigInt(object.size))
    .slice()
    .sort((a, b) => a.offset - b.offset);

  // Fields that share an offset are *alternatives*: union members, and bit-fields sharing one storage unit.
  // There is one set of bytes there and several names for it, and drawing all of them on the same cells
  // means the last one drawn wins and the others silently vanish.
  const groups = [];
  for (const child of placed) {
    const last = groups[groups.length - 1];
    if (last && last.offset === child.offset) last.children.push(child);
    else groups.push({ offset: child.offset, children: [child] });
  }

  const pieces = [];
  let cursor = 0;
  groups.forEach((group, groupIndex) => {
    const next = groupIndex + 1 < groups.length ? groups[groupIndex + 1].offset : object.size;
    // A field never owns bytes past where the next field begins. gdb reports a bit-field's *declared type*
    // (`unsigned int bits : 3` → 4 bytes), and taking that literally makes the bit-field swallow the field
    // that really starts in the next byte.
    const wanted = Math.max(...group.children.map((child) => child.size));
    const extent = Math.max(1, Math.min(wanted, next - group.offset));

    if (group.offset > cursor) {
      pieces.push({
        kind: "hole",
        index: pieces.length,
        object,
        objectStart,
        objectEnd,
        size: group.offset - cursor,
        start: objectStart + BigInt(cursor),
        end: objectStart + BigInt(group.offset),
      });
    }

    group.children.forEach((child, position) => {
      pieces.push({
        kind: "field",
        index: pieces.length,
        object,
        objectStart,
        objectEnd,
        child,
        // `size` is the extent this group actually owns (what gets drawn); `declared` is what gdb said,
        // which stays in the panel because it is gdb's answer and not ours to rewrite.
        size: extent,
        declared: child.size,
        alternatives: group.children.length,
        position,
        start: objectStart + BigInt(group.offset),
        end: objectStart + BigInt(group.offset + extent),
      });
    });
    cursor = group.offset + extent;
  });

  if (cursor < object.size) {
    pieces.push({
      kind: "hole",
      index: pieces.length,
      object,
      objectStart,
      objectEnd,
      size: object.size - cursor,
      start: objectStart + BigInt(cursor),
      end: objectEnd,
    });
  }
  return pieces;
}

// Colour cycles per field, the way bracket colourisation cycles per nesting level: the colour is the
// *identity* of the field, and identity is what ties a label to the bytes it describes.
const HUES = 5;

// Where an object lives: a pointer's value is its address, anything else carries an explicit `address`
// (the transport asks gdb `&expr` for it), because a struct prints as `{...}` and has no address of its own
// in its value.
function objectAddress(object) {
  return (object.address ? parseAddr(object.address) : null) ?? parseAddr(object.value);
}

// Stable ids. The address alone is not enough: an array and its first element start at the same byte, so
// `nodes[0]` and `nodes` would share every id — hovering one would light the other's row, and "locate this
// field" would land on the wrong one. The expression is what actually names an object.
function objectKey(object) {
  const start = objectAddress(object);
  return start === null ? `a?${object.expression}` : `a${start.toString(16)}:${object.expression}`;
}

function fieldKey(object, index) {
  return `${objectKey(object)}f${index}`;
}

// The selection for a field the caller already knows, by expression: the object it lives in, the field itself, and
// the bytes it covers. The counterpart of `resolveSelection`, which is given an address and has to work out which
// field that address falls in. Both produce the same record, so a click on a rail row, a click on an overlay box and
// a jump to an address all leave the application in exactly one state — which is what keeps the three surfaces that
// draw a selection (the bytes, the overlay boxes, the rail) from disagreeing.
function selectionForField(objectExpression, fieldExpression, address = null) {
  const object = allObjects().find((item) => item.expression === objectExpression) ?? null;
  const objectStart = object ? objectAddress(object) : null;
  const child =
    object && fieldExpression
      ? (object.children ?? []).find((item) => item.expression === fieldExpression) ?? null
      : null;
  const hasRange = child && typeof child.offset === "number" && objectStart !== null;
  const start = hasRange ? objectStart + BigInt(child.offset) : objectStart;
  const end = hasRange ? start + BigInt(child.size ?? 0) : start === null ? null : start + 1n;
  return {
    address: address ?? start,
    start: start ?? address,
    end: end ?? (address === null ? null : address + 1n),
    objectKey: object ? objectKey(object) : null,
    objectExpression: objectExpression ?? null,
    fieldExpression: child ? fieldExpression : null,
  };
}

// What the reader's address lands in, resolved once from the same typed-object table the rail and the overlay are
// built from. Keyed by *expression*: an expression is what names a variable (`#0 head->next`, `#1 n`), and the rail,
// the overlay boxes and the byte owners all carry it. Indices do not survive between those tables — the rail counts
// layout pieces, the object counts children — which is how a selection used to end up matching no row at all.
//
// The narrowest covering object wins, and inside it the narrowest field that holds the address. An address that no
// object describes (code, or bytes no type covers) has no selection: null, rather than a guess.
function resolveSelection(address) {
  const start = typeof address === "bigint" ? address : parseAddr(address);
  if (start === null) return null;
  let best = null;
  for (const object of allObjects()) {
    const objectStart = objectAddress(object);
    const size = BigInt(object.size ?? 0n);
    if (objectStart === null || size <= 0n) continue;
    if (start < objectStart || start >= objectStart + size) continue;
    if (best && size >= best.size) continue;
    let field = null;
    for (const child of object.children ?? []) {
      if (typeof child.offset !== "number" || typeof child.size !== "number") continue;
      const childStart = objectStart + BigInt(child.offset);
      if (start < childStart || start >= childStart + BigInt(child.size)) continue;
      if (!field || child.size < field.size) field = child;
    }
    // The range says what the reader picked. A field is a run of bytes, so the whole field is marked; an address
    // that is inside an object but not inside any *named* field is not a run of anything — it is one byte, and
    // marking the whole container (all 64 bytes of a stack frame, four rows of `00`) answered a question nobody
    // asked. The object is still the selection (the rail marks its row, the overlay marks its box); only the byte
    // range is one byte.
    const fieldStart = field ? objectStart + BigInt(field.offset) : start;
    const fieldEnd = field ? fieldStart + BigInt(field.size) : start + 1n;
    best = {
      size,
      objectKey: objectKey(object),
      objectExpression: object.expression,
      fieldExpression: field?.expression ?? null,
      start: fieldStart,
      end: fieldEnd,
    };
  }
  return best ? { address: start, ...best } : null;
}

// Every piece of every object that touches this row, clipped to the row. One function, so the bytes and
// the labels cannot disagree about who owns what.
//
// Nesting needs one more rule here: where a smaller object covers the same bytes, the bigger one's piece is
// **dropped**, not drawn underneath. Two labels placed on the same cells is not "deeper detail", it is
// `{0d{s=[3]}▸×3` — the text of both printed on top of each other.
// What is the same for every row, computed **once per window** instead of once per row.
//
// `layoutPieces` walks an object's fields and the "shaded" question compares an object against every smaller
// object it contains — both are about objects, not about the sixteen bytes of one row, and both used to be
// redone for each of the rows on screen. Measured on the heavy core's stack window, where a deep stack brings
// ~5 000 objects into the overlay: 5 000 piece layouts and a 5 000² nested scan per row. Hoisting it is the
// difference between a pane that opens and a pane that hangs.
function pieceLayout(objects) {
  const laid = objects.map((object) => ({ object, pieces: layoutPieces(object) }));
  // For each object, every *smaller contained* object's pieces — the ranges that drop its own pieces. Built
  // once, per object, from the containment relation that does not depend on the row either.
  const covering = new Map();
  const contained = new Set();
  
  // A smaller object that a piece of ours is dropped for has to *start inside us* — so the candidates for an
  // object are the objects beginning in its own range, found by binary search over the starts, not every object
  // in the window. That is what keeps this out of the O(objects²) class the per-row version lived in.
  const byStart = laid
    .map((entry) => ({ entry, start: entry.object.start ?? objectAddress(entry.object) }))
    .filter((item) => item.start !== null)
    .sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  for (const { entry, start } of byStart) {
    const end = start + BigInt(entry.object.size ?? 0);
    const size = Number(entry.object.size ?? 0);
    const ranges = [];
    // The first index whose start is >= ours, then everything that starts before our end.
    let low = 0;
    let high = byStart.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (byStart[middle].start < start) low = middle + 1;
      else high = middle;
    }
    for (let index = low; index < byStart.length && byStart[index].start < end; index += 1) {
      const other = byStart[index];
      if (other.entry.object === entry.object) continue;
      if (!(Number(other.entry.object.size ?? 0) < size)) continue;
      if (!contains(entry.object, other.entry.object)) continue;
      contained.add(other.entry.object);
      for (const piece of other.entry.pieces) ranges.push([piece.start, piece.end]);
    }
    covering.set(entry.object, ranges);
  }
  const order = laid.slice().sort((a, b) => {
    const sizeA = Number(a.object.size ?? 0);
    const sizeB = Number(b.object.size ?? 0);
    if (sizeA !== sizeB) return sizeA - sizeB; // smaller object = more specific = wins
    const startA = a.object.start ?? objectAddress(a.object) ?? 0n;
    const startB = b.object.start ?? objectAddress(b.object) ?? 0n;
    return startA < startB ? -1 : startA > startB ? 1 : 0;
  });
  // Every piece of every object, in address order, so a row can ask for the pieces that overlap it instead of
  // walking all of them. The row loop used to visit each of the ~4 500 objects' pieces per row — 45 000 tests
  // for a row that has room for about ten — and there are 74 rows on screen and a render per scroll.
  const pieces = [];
  const rank = new Map();
  order.forEach((entry, index) => rank.set(entry.object, index));
  for (const entry of laid) {
    for (const piece of entry.pieces) pieces.push({ entry, piece, start: piece.start, end: piece.end });
  }
  pieces.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  const maxEnd = new Array(pieces.length);
  let furthest = 0n;
  for (let index = 0; index < pieces.length; index += 1) {
    if (pieces[index].end > furthest) furthest = pieces[index].end;
    maxEnd[index] = furthest;
  }
  // The named ranges belong here too: they are a pure function of the same objects, they are ~40 000 ranges for
  // a 500-frame overlay, and both the row layout and the minimap asked for them — building and sorting that list
  // **twice per render** was measured at seconds on the heavy core's window.
  // "Outermost" is the same containment relation, so it is answered here rather than with a nested scan per
  // row: `objects.filter(o => !objects.some(other => contains(other, o)))` is 20 million contains() calls for a
  // 500-frame overlay, and the hex pane asked it **once per row**.
  const outer = laid.filter((entry) => !contained.has(entry.object)).map((entry) => entry.object);
  return { laid, covering, contained, outer, order, rank, pieces, maxEnd, named: coverage(objects) };
}

// The pieces that can touch `[from, to)`: binary search to the first piece that starts before the row ends,
// then walk while the piece starts before it ends. Sorted by the layer's own rank afterwards, because which
// piece claims an overlapping byte is decided by that order and not by the address.
function piecesForRow(layer, from, to) {
  const { pieces, maxEnd } = layer;
  let low = 0;
  let high = pieces.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (pieces[middle].start < to) low = middle + 1;
    else high = middle;
  }
  // Walking back has to stop somewhere, and "the piece before this one ends before the row" is the wrong test:
  // an *enclosing* object starts far behind the row and reaches into it, so a piece that ends early says nothing
  // about the ones before it. `maxEnd[i]` — the furthest end among pieces `0..i` — is the bound that works: once
  // no earlier piece can reach the row, the scan is over. Without it this loop ran the whole list from wherever
  // the bisect landed, per row, which measured at **10.4 s** for one screen of rows on the heavy core's window.
  const found = [];
  for (let index = low - 1; index >= 0 && maxEnd[index] > from; index -= 1) {
    if (pieces[index].end > from) found.push(pieces[index]);
  }
  found.sort((a, b) => (layer.rank.get(a.entry.object) ?? 0) - (layer.rank.get(b.entry.object) ?? 0));
  return found;
}

// One cache per *window build*: the objects array is built once per render and handed to every row of that
// render, so a WeakMap keyed on it is a cache for exactly as long as the layout it describes is valid.
const pieceLayouts = new WeakMap();

function layerFor(objects) {
  let layer = pieceLayouts.get(objects);
  if (!layer) {
    layer = pieceLayout(objects);
    pieceLayouts.set(objects, layer);
  }
  return layer;
}

function rowPieces(objects, row) {
  const rowStart = row;
  const rowEnd = row + 16n;
  const layer = layerFor(objects);
  const { laid, covering, order } = layer;
  const shaded = (entry, from, to) =>
    (covering.get(entry.object) ?? []).some(([start, end]) => start < to && from < end);

  // Two objects can describe the same bytes of this row — a struct and a union member, or (as in a frame whose field
  // offsets came out negative, see `layoutPieces`) one that was placed wrongly. Overlapping cells share a grid track
  // and their labels print on top of each other, which is what "saved x290x7fc1" was. So the row's pieces are
  // arbitrated: the more specific object claims first (`order`, computed with the rest of the layer), and whatever
  // it does not cover stays with the other.
  const taken = [];
  const claim = (from, to) => {
    let spans = [[from, to]];
    for (const [a, b] of taken) {
      const next = [];
      for (const [s, e] of spans) {
        if (b <= s || e <= a) next.push([s, e]);
        else {
          if (s < a) next.push([s, a]);
          if (b < e) next.push([b, e]);
        }
      }
      spans = next;
    }
    for (const [s, e] of spans) taken.push([s, e]);
    return spans;
  };

  const out = [];
  for (const { entry, piece } of piecesForRow(layer, rowStart, rowEnd)) {
    const { object } = entry;
    // The overlap of a group is drawn once, by its first field.
    if (piece.kind === "field" && piece.position) continue;
    const from = piece.start > rowStart ? piece.start : rowStart;
    const to = piece.end < rowEnd ? piece.end : rowEnd;
    if (from >= to) continue;
    if (shaded(entry, from, to)) continue;
    const kind = piece.kind === "field" ? fieldKind(piece.child) : null;
    // Whatever of this piece is still unclaimed; a partial overlap leaves the remainder visible rather than
    // throwing the whole field away.
    for (const [spanFrom, spanTo] of claim(from, to)) {
        out.push({
          ...piece,
          // `pieceKind` keeps "field" or "hole" (the structural question); `kind` is what the field *is*
          // (pointer, scalar, …). Overwriting one with the other is how a hole ends up dereferenced.
          pieceKind: piece.kind,
          object,
          objectId: objectKey(object),
          fieldId: fieldKey(object, piece.index),
          first: spanFrom === piece.start,
          last: spanTo === piece.end,
          from: spanFrom,
          to: spanTo,
          kind,
          tone: kind ? FIELD_TONES[kind] : null,
          // The field's own expression: an array and its first element share an address, so "which object did
          // the user point at" has to be answered by name, not by address.
          expression: piece.child?.expression ?? null,
          // Two strengths of the same tone, alternating field by field: that, and not a border, is what
          // keeps two neighbouring grey fields from reading as one.
          shade: piece.index % 2,
        });
    }
  }  return out;
}

// Which field owns each byte of this row — the answer the *bytes* need, not the labels.
function byteOwners(pieces, row) {
  const owners = new Map();
  for (const piece of pieces) {
    // Only the lead field of a group paints the bytes: the alternatives are the same bytes under other
    // names, and they are listed in the panel where alternatives belong.
    if (piece.pieceKind !== "field" || piece.position) continue;
    for (let address = piece.from; address < piece.to; address += 1n) {
      owners.set(address.toString(), {
        fieldId: piece.fieldId,
        objectId: piece.objectId,
        expression: piece.expression,
        tone: piece.tone,
        start: address === piece.start,
      });
    }
  }
  return owners;
}

// Hovering a field in any of the three views lights up the other two: moving the mouse is how you ask
// "which bytes is this?".
function lightUpField(fieldId, on) {
  for (const node of document.querySelectorAll(`[data-field="${fieldId}"]`)) {
    node.classList.toggle("hot", on);
  }
}

// 010 Editor's "struct outlining": the field under the cursor also puts a frame around the structure it
// lives in, so a field never has to be located in the object by counting.
function lightUpObject(objectId, on) {
  for (const node of document.querySelectorAll(`[data-object="${objectId}"]`)) {
    node.classList.toggle("objhot", on);
  }
}

function hoverFor(fieldId, objectId) {
  const enter = () => {
    lightUpField(fieldId, true);
    lightUpObject(objectId, true);
  };
  const leave = () => {
    lightUpField(fieldId, false);
    lightUpObject(objectId, false);
  };
  return { onmouseenter: enter, onmouseleave: leave };
}

// Clicking a byte or a rail row selects the *field* it belongs to (Wireshark does this the other way round), so the
// bytes, the overlay box, the rail row and the instruction all end up pointing at the same thing.
//
// There is exactly one selection and it lives in `state.selection`. Everything else — an overlay box being outlined, a
// rail row being tinted, a run of bytes being marked — is a *rendering* of that one record, computed at draw time
// from the same expressions. Fields are named by expression (`#1 stacked_args · a1`), because that is what the rail,
// the overlay cells and the byte owners all carry; the older key-based pair (`state.field`/`state.object`) is gone,
// and with it the failure mode where one surface matched by key and another by expression and two different fields
// lit up at once.
function selectField(
  { fieldExpression = null, objectExpression = null, address = null, fromRail = false } = {},
) {
  const target = address === null || address === undefined ? null : BigInt(address);
  const found = target === null ? null : resolveSelection(target);
  // What the caller knows wins (it clicked a named field); otherwise take what the address resolves to.
  const field = fieldExpression ?? found?.fieldExpression ?? null;
  const object = objectExpression ?? found?.objectExpression ?? null;
  state.selection = selectionForField(object, field, target);
  // A field with no address has no bytes to show: it lives in a register, or gdb could not place it in the frame. The
  // selection is still the field — the rail row and the tree highlight — but the hex pane stays where it is, because
  // there is no place to reveal. Clicking such a row used to crash on `BigInt(null)`.
  if (target !== null && state.selection.start !== null) {
    state.address = norm(target);
    state.reveal = true;
  }
  if (!fromRail) state.railRoot = null;
  if (object !== null) state.zoom = object;
  render();
}

// What a value looks like when gdb sent none.
//
// `--simple-values` does not read an aggregate, so an array or a struct arrives with no value at all. That
// is not "unknown" and must not print as `?`: the *type* still says what the thing is, and `[32]` or `{…}`
// is a statement about the type rather than a claim about bytes nobody read. Only a type that says nothing
// falls back to saying nothing.
function shapeOf(type) {
  const text = String(type ?? "");
  const array = text.match(/\[(\d+)\]/);
  if (array) return `[${array[1]}]`;
  if (/^(struct|union|class)\b/.test(text.trim())) return "{…}";
  return "(not read)";
}

function fieldText(child) {
  const missing = child.value === null || child.value === undefined;
  const value = missing ? shapeOf(child.type) : String(child.value);
  const string = String(child.type ?? "").startsWith("char [") && child.expression ? charString(child.expression) : null;
  return `${child.field}=${string !== null ? JSON.stringify(string) : value}`;
}

// What a field *is* decides whether clicking it does anything, and that is worth seeing before trying.
// Three tones, not five hues: a colour that means nothing is decoration, and five of them on one screen is
// noise. Blue = clickable pointer, grey = a value, red = a pointer with nothing behind it.
const FIELD_KINDS = {
  pointer: { label: "pointer — click to follow it", mark: " →" },
  scalar: { label: "a value, not an address", mark: "" },
  null: { label: "NULL — nothing to follow", mark: "" },
  outside: { label: "points outside this dump", mark: " ✗" },
  unreadable: { label: "gdb could not read this field", mark: "" },
};

const FIELD_TONES = { pointer: "leads", scalar: "value", null: "value", outside: "warn", unreadable: "warn" };

function fieldKind(child) {
  if (child.value === "") return "unreadable";
  const target = parseAddr(child.value);
  if (target === null) return "scalar";
  if (target === 0n) return "null";
  if (!regionOf(target)) return "outside";
  return "pointer";
}

// How much of a label fits in a cell, and how much of it the rows above have already shown. Both come from
// the same pixel measure — the cell is `--byte-cell` wide, `2ch + 2px` ≈ 2.3ch, and spends ~8px on its own
// padding and margin — because a mismatch between the two either eats a character at a row's end or repeats
// one at the next row's start. Measured, not guessed: at 2.3 a four-byte cell fits `name="wid`, which is
// what the rows show; at 2.55 it clips.
const CELL_CH = 2.28;
const CELL_PAD_CH = 1.2;

function charsFit(bytes) {
  return Math.max(1, Math.floor(bytes * CELL_CH - CELL_PAD_CH));
}

function charsShown(shownBytes, fieldStart) {
  let shown = 0;
  let address = fieldStart;
  let remaining = shownBytes;
  while (remaining > 0) {
    const inRow = Math.min(16 - Number(address % 16n), remaining);
    shown += charsFit(inRow);
    address += BigInt(inRow);
    remaining -= inRow;
  }
  return shown;
}

// A gap label (`4 B hole`) is a phrase, not a value to be sliced, so it is either shown whole or left to
// the tooltip. It has its own capacity because its font is smaller: measured, a four-byte gap cell is 59px
// wide and `4 B hole` is 47px at 10.5px — where `charsFit` (derived from the 12px cells) says it does not
// fit and would silently hide every padding label on screen.
const HOLE_CHARS_PER_BYTE = 2.6;
const HOLE_PAD_CH = 1.0;

function holePhraseFits(bytes, phrase) {
  return Math.max(1, Math.floor(bytes * HOLE_CHARS_PER_BYTE - HOLE_PAD_CH)) >= phrase.length;
}

// One row's worth of the overlay: the labels, placed on the cells of the bytes they describe.
// The object's own bytes as one continuous strip, drawn *behind* the fields.
//
// Without it the structure is broken up by things that are not fields: the 9px gap after the eighth byte
// splits it, and a hole between two fields is an empty box — so a struct reads as a few islands with the
// row background showing through. The bytes of a structure are contiguous, and it should look contiguous;
// the hole's own label still sits on top of the strip.
//
// Per byte the *deepest* object decides the strip. Stacking one strip per containing object makes a nested
// structure glow brighter than its parent for no reason — and brighter than a continuation block, which then
// disappears into it.
function bandCells(objects, row) {
  const rowStart = row;
  const rowEnd = row + 16n;
  const bands = [];
  let run = null;
  for (let address = rowStart; address < rowEnd; address += 1n) {
    const covering = objects
      .filter((object) => object.start <= address && address < object.end)
      .sort((a, b) => Number(a.size) - Number(b.size))[0];
    const objectId = covering ? objectKey(covering) : null;
    if (run && run.objectId === objectId) {
      run.to = address + 1n;
      continue;
    }
    if (run) bands.push(run);
    run = objectId ? { objectId, object: covering, from: address, to: address + 1n } : null;
  }
  if (run) bands.push(run);

  return bands.map((band) => ({
    column: `${overlayLine(Number(band.from - rowStart))} / ${overlayLine(Number(band.to - rowStart - 1n)) + 1}`,
    objectId: band.objectId,
    title:
      `${band.object.expression} · ${band.object.type} · ${band.object.size} bytes from ${band.object.start.toString(16)}` +
      // The strip is what says "these bytes are this frame's", because the frame's gaps deliberately have no
      // cells of their own: unlabelled stack is not junk and not a missing symbol, it is just unnamed.
      (band.object.type === "stack frame" ? " · the cells on it are the variables that have a name here" : ""),
  }));
}

function overlayCells(pieces, row) {
  const rowStart = row;
  const cells = [];
  for (const piece of pieces) {
    const column = `${overlayLine(Number(piece.from - rowStart))} / ${overlayLine(Number(piece.to - rowStart - 1n)) + 1}`;

    if (piece.pieceKind === "hole") {
      // A gap inside a *struct* is a fact about the layout — the compiler put it there to align the next
      // field — and it gets a label.
      //
      // A gap inside a *stack frame* is not: it is stack that no variable occupies at this pc. It needs no
      // word, and the two words it could have are both wrong: `unnamed` reads as a broken symbol table, and
      // an empty box reads as junk data. So a frame's gaps are not drawn at all — the strip behind the
      // fields already says these bytes are this frame's memory, and the cells are for what has a name.
      if (piece.object?.type === "stack frame") continue;
      const label = `${piece.size} B hole`;
      cells.push({
        column,
        class: "hole",
        text: holePhraseFits(Number(piece.to - piece.from), label) ? label : "",
        title: `${piece.size} bytes of padding — the compiler put them here to align the next field`,
      });
      continue;
    }

    const child = piece.child;
    const full = fieldText(child);
    const kind = piece.kind;
    const jump = kind === "pointer" ? String(child.value) : null;
    // The field's name belongs to the row it starts in; a continuation says "still this field" and lets
    // the cells of the fields that really live there keep their own labels. A box that runs past the row
    // is marked by its dashed right edge, not by a trailing character: `text-overflow` would eat a
    // character exactly when the text is long enough to need it.
    const open = piece.first && piece.start === piece.objectStart;
    const close = piece.last && piece.end === piece.objectEnd;
    // An aggregate box hides its insides, so it says so: an array gets its count, a struct or union a
    // marker. Only an aggregate *value* gets one — a pointer's `→` already says something is behind it, a
    // NULL has nothing behind it, an unreadable field has nothing to show, and a `char [N]` needs no count
    // because the string is its own length.
    const type_text = String(child.type ?? "");
    const badge =
      kind !== "scalar" || !child.num_children || type_text.startsWith("char [")
        ? ""
        : type_text.includes("[")
          ? ` ×${child.num_children}`
          : " ▸";
    // Alternatives: one set of bytes, several names. The first is drawn; the count says the rest exist.
    const alternatives = piece.alternatives > 1 ? ` +${piece.alternatives - 1}` : "";
    // The label **wraps**: a field that spans several rows carries its text on across them, one slice per
    // row, so `name="wide01"` is read in full instead of ending at `name="w…`.
    const label = `${open ? "{" : ""}${full}${badge}${alternatives}${FIELD_KINDS[kind].mark}`;
    const closing = close ? "}" : "";
    const shown = charsShown(Number(piece.from - piece.start), piece.start);
    // One character is held back on the row that carries the closing brace, so the brace is never the
    // character `text-overflow` removes.
    const capacity = Math.max(1, charsFit(Number(piece.to - piece.from)) - closing.length);
    const text = label.slice(shown, shown + capacity);
    // A continuation row of a long field often has nothing left to say: `pad` is 128 bytes and its whole
    // label fits on the first row. That cell is then **not drawn at all** — an empty box under a named field
    // reads as junk data or as a value nobody read, while the strip behind it already says those bytes
    // belong to this field.
    if (!piece.first && !text && !closing) continue;
    cells.push({
      column,
      jump,
      kind,
      fieldId: piece.fieldId,
      objectId: piece.objectId,
      objectExpression: piece.object.expression,
      expression: piece.expression,
      class: `field tone-${piece.tone} s${piece.shade} ${jump ? "leads" : "plain"} ${piece.first ? "" : "continued"} ${piece.last ? "" : "continues"}`,
      text: text + closing,
      title:
        `${child.field} · ${child.type} · offset +${child.offset} (${child.size} bytes)` +
        `${piece.first ? ` · ${full}` : ` · ${full} (continued here)`}` +
        ` · ${FIELD_KINDS[kind].label}` +
        `${open ? ` · start of ${piece.object.expression} (${piece.object.type}, ${piece.object.size} bytes)` : ""}` +
        `${close ? ` · end of ${piece.object.expression}` : ""}`,
    });
  }
  return cells;
}

function overlayLegend() {
  return h(
    "div",
    { class: "overlay-legend" },
    h("span", { class: "legend-item" }, h("span", { class: "legend-swatch tone-leads" }), "pointer — click to follow it"),
    h("span", { class: "legend-item" }, h("span", { class: "legend-swatch tone-value" }), "a value, not an address"),
    h("span", { class: "legend-item" }, h("span", { class: "legend-swatch tone-warn" }), "nothing behind it"),
    h("span", { class: "legend-item dim", text: "hover a field: its bytes light up (and the other way round)" }),
    h("span", { class: "legend-item dim", text: "grey italic = compiler padding" }),
  );
}

// The frame around a structure, drawn in its own narrow column: one glyph per row, so a struct that spans
// three rows is visibly one thing. It carries the object's id, which is how hovering a field lights it up.
//
// **Outermost objects only.** A nested structure has its own extent, but this column is 3 characters wide:
// drawing a frame per level puts five sets of `╭│╰` on one row and the column stops meaning anything. The
// inner levels are already visible where they belong — as labels on the bytes and as `{ }` around their
// fields.
function objectFrames(objects, row) {
  const rowEnd = row + 16n;
  const outer = layerFor(objects).outer;
  const frames = [];
  for (const object of outer) {
    if (object.start >= rowEnd || object.end <= row) continue;
    const startsHere = object.start >= row && object.start < rowEnd;
    const endsHere = object.end > row && object.end <= rowEnd;
    frames.push({
      glyph: startsHere ? "╭" : endsHere ? "╰" : "│",
      objectId: objectKey(object),
      title: `${object.expression} · ${object.type} · ${object.start.toString(16)}–${object.end.toString(16)} (${object.size} bytes)`,
    });
  }
  return frames;
}

// A ruler over the columns, on the same grid as the rows: "which column is byte 9" should never be a
// judgement call, and the group gap after the eighth has to be visible in the ruler too.
// It emits the same number of cells as a data row — including the empty frame column — because a subgrid
// maps children to tracks by position, and one missing cell shifts every column after it.
function hexRuler(hasAsciiAligned, hasFrames) {
  const digits = (className, line) =>
    h(
      "span",
      { class: className },
      [...Array(16).keys()].map((i) => h("span", { class: "rcell", style: `grid-column:${line(i)}`, text: i.toString(16) })),
    );
  return h(
    "div",
    { class: "hexrow ruler" },
    // Five cells always: the column widths are positional, so a missing cell would shift the rest.
    h("span", { class: "sframes" }),
    h("span", { class: "haddr", text: "byte" }),
    digits("hbytes", lineOf),
    hasAsciiAligned ? digits("hascii aligned", lineOf) : h("span", { class: "hascii", text: "(compact ascii)" }),
    hasFrames ? digits("soverlay", overlayLine) : h("span", { class: "soverlay" }),
  );
}

// One screen of rows, not the whole window.
//
// A window is a *region* — the thread's stack is 132 KB, and a heap window can be gigabytes — so the pane
// cannot hold one element per row: 8192 rows of ~40 elements is a third of a million nodes, and a real
// region is millions. Only the rows near the scroll position are built; the rest of the height is one empty
// spacer above and one below, which keeps the scrollbar honest without building anything.
//
// Nothing else changes: a row is still built by the same code from the same pieces, so the labels, the
// strip and the byte ownership cannot drift between the rows that happen to be built and the rows that are
// not.
const ROW_HEIGHT = 19;
const ROW_MARGIN = 24;
const PAGE = 4096n;

// The rows a window actually has, in order: ordinary sixteen-byte rows, and **folded runs of zero pages**.
//
// A stack window is 132 KB and the live frames are 5 KB of it; the rest is free stack that reads as zeros,
// and no amount of scrolling is a good way to get past it. So a run of whole pages that are present, zero,
// and have nothing named in them collapses into one row.
//
// The unit is the **page**, not "a run of zeros wherever they start": a page is what the address space is
// managed in and what a reader recognises, and page-aligned folding cannot produce a fold whose edges mean
// nothing. And the rule about *named* bytes is what keeps this honest — a zero page that a frame or a field
// covers is not folded, because the zeros there are a fact about that structure, not padding to skip.
// The layout is **runs, not rows**: a fold contributes one entry, and every other entry is a sixteen-byte row,
// so a run of ordinary rows is arithmetic. The version this replaces built one object per row for the whole
// window — measured at **240 384** entries for the heavy core's 3.8 MB stack window, on every render — and
// needed a prefix-sum array beside it to find a scroll position. Rows are uniform (see `entryHeight`), so the
// entry at an offset is a division and the offset of an entry is a multiplication. What is left to compute is
// where the folds are, which is a question about *pages* (940 of them for that window, not 240 384 rows).
function rowLayout(window, objects) {
  const start = BigInt(window.address);
  const first = start - (start % 16n);
  const end = start + BigInt(window.length);
  const named = layerFor(objects).named;
  const runs = [];

  // "Is any of this page named" is a **cursor**, not a scan: the pages are walked in address order and
  // `coverage` is sorted by address, so one pointer answers every page in a single pass. It used to be
  // `named.some(...)` per page — measured on the heavy core's stack window, 940 pages against the ~4 500 ranges
  // a 500-frame overlay brings is 4.2 million comparisons *per render*, and that is what made opening that
  // window take tens of seconds while the practice core's two-page window was instant.
  let namedAt = 0;
  const namedIn = (from, to) => {
    while (namedAt < named.length && named[namedAt][1] <= from) namedAt += 1;
    const range = named[namedAt];
    return Boolean(range && range[0] < to && from < range[1]);
  };
  const blank = (from, to) => !namedIn(from, to) && rangeIsZero(window, from, to);
  const rows = (from, to) => {
    const last = runs[runs.length - 1];
    if (last?.kind === "rows" && last.to === from) last.to = to;
    else runs.push({ kind: "rows", from, to });
  };

  for (let row = first; row < end; ) {
    const pageStart = row - (row % PAGE);
    if (state.foldZeros && pageStart === row && pageStart + PAGE <= end && blank(pageStart, pageStart + PAGE)) {
      let runEnd = pageStart + PAGE;
      while (runEnd + PAGE <= end && blank(runEnd, runEnd + PAGE)) runEnd += PAGE;
      if (!state.unfolded.has(pageStart.toString())) {
        runs.push({ kind: "fold", from: pageStart, to: runEnd });
        row = runEnd;
        continue;
      }
    }
    // Ordinary rows, up to the next page boundary the loop above may fold at (or the end of the window).
    const stop = pageStart + PAGE > end ? end : pageStart + PAGE;
    rows(row, stop);
    row = stop;
  }

  // Entry index of each run, so a scroll position and an address can both be mapped without walking anything.
  let index = 0;
  for (const run of runs) {
    run.entry = index;
    run.rows = run.kind === "fold" ? 1 : Number((run.to - run.from) / 16n);
    index += run.rows;
  }
  return { runs, total: index, first, end };
}

// The entry at an index: a fold, or the address of a sixteen-byte row.
function entryForIndex(spec, index) {
  const runs = spec.runs;
  let low = 0;
  let high = runs.length - 1;
  while (low < high) {
    const middle = (low + high + 1) >> 1;
    if (runs[middle].entry <= index) low = middle;
    else high = middle - 1;
  }
  const run = runs[low];
  if (!run) return null;
  if (run.kind === "fold") return run;
  return { kind: "row", row: run.from + BigInt(index - run.entry) * 16n };
}

// The entry an address is on. Folding is why a row *number* and an address are no longer in step, which is the
// question this answers: binary search by address, then arithmetic inside the run.
function indexForAddress(spec, address) {
  const runs = spec.runs;
  let low = 0;
  let high = runs.length - 1;
  while (low < high) {
    const middle = (low + high + 1) >> 1;
    if (runs[middle].from <= address) low = middle;
    else high = middle - 1;
  }
  const run = runs[low];
  if (!run) return 0;
  if (run.kind === "fold") return run.entry;
  const offset = address < run.from ? 0n : (address - run.from) / 16n;
  return run.entry + Number(offset);
}

// The byte ranges something is named in: the objects themselves, deepened by their fields. This is the same
// question `rowPieces` answers per row, asked once for the whole window.
function coverage(objects) {
  const ranges = [];
  for (const object of objects) {
    const start = objectAddress(object);
    if (start === null || !object.size) continue;
    ranges.push([start, start + BigInt(object.size)]);
    for (const child of object.children ?? []) {
      if (typeof child.offset === "number" && child.size) {
        const from = start + BigInt(child.offset);
        ranges.push([from, from + BigInt(child.size)]);
      }
    }
  }
  return ranges.sort((a, b) => (a[0] < b[0] ? -1 : 1));
}

// A page folds when it is present, zero, and unnamed — the three questions `rangeIsZero` and `coverage` answer.

// The lines that belong beside one sixteen-byte row, when this window is code: the source line where it
// changes, and every instruction that lives in those bytes.
//
// Built once per window into `spec.codeRows`, because a scroll must not walk the listing to find out how
// tall a row is — a hex scroll renders at animation-frame rates and the row heights are needed *before* the
// rows exist.
function codeRowsFor(spec) {
  const table = new Map(); // row address (as a string) → [{kind: "source" | "insn", …}]
  if (!spec.code) return table;
  const seen = new Set(); // a source line is printed once, in the row where its first instruction is
  // The window's own reply first, then the frames' — the page is what the hex rows are painting, and the
  // frames' functions are a subset of it that also carry a frame's context.
  const replies = [
    ...(codeData().window?.units ?? []),
    ...Object.values(codeData().frames ?? {}),
  ];
  // One row's worth is added in one place, so the grouped and flat shapes cannot drift apart.
  const add = (instruction, group, recorded) => {
    const row = (BigInt(instruction.address) & ~15n).toString();
    const lines = table.get(row) ?? [];
    if (group && !seen.has(group.line)) {
      seen.add(group.line);
      lines.push({ kind: "source", line: group.line, text: sourceText(recorded, group.line), recorded });
    }
    lines.push({ kind: "insn", instruction });
    table.set(row, lines);
  };

  for (const reply of replies) {
    for (const group of reply.lines ?? []) {
      const recorded = group.fullname || group.file;
      for (const instruction of group.instructions ?? []) add(instruction, group, recorded);
    }
    // A flat reply: instructions and no line numbers. Measured on the code page, which spans several
    // functions, so gdb has no single line to group them under. The instructions are still the answer.
    if (!(reply.lines ?? []).length) {
      for (const instruction of reply.instructions ?? []) add(instruction, null, null);
    }
  }
  return table;
}

// A row is as tall as its listing, never shorter than one line. This is what "the disassembly and the hex on
// one line" costs: sixteen bytes is up to four aarch64 instructions, and stacking them beside the bytes is
// the only way to keep all four *and* keep the byte on the same line as the instruction that touched it.
function entryHeight(entry, spec) {
  // Every row is one line: an instruction stack beside a row of bytes no longer grows it, so the layout is
  // uniform and the scroll arithmetic is a plain multiple again. `spec` is kept because the sixteen-byte
  // path may want it again, and because the signature is what the caller already passes.
  return ROW_HEIGHT;
}
// The content height, which is now a multiplication: every entry is one row tall (`entryHeight`), so a
// 240 384-entry window is `240384 * 19` pixels and needs no array to say so.
function layoutTops(spec) {
  spec.totalHeight = spec.total * ROW_HEIGHT;
  state.contentHeight = spec.totalHeight; // the minimap's viewport rectangle and its drag both need the real height
}

// The entry a pixel offset falls in — a division, because the rows are uniform.
function entryAt(_spec, y) {
  return Math.max(0, Math.floor(y / ROW_HEIGHT));
}

// Which address is at the top of the viewport, and where that address is now.
//
// These two exist because a pixel offset is not a durable fact: folding a run of zero pages, or unfolding one, changes
// the height of everything below it, and the same number then points somewhere else — which is why the pane could
// jump to the end of a window on its own (the stored offset exceeded the new, shorter content and the browser clamped
// it). Storing the *address* instead means every render can put the reader back on the row they were looking at,
// whatever the rows around it now measure.
function topAddressAt(spec, offset) {
  if (!spec?.runs?.length || offset === null || offset === undefined) return null;
  const entry = entryForIndex(spec, entryAt(spec, offset));
  if (!entry) return null;
  return entry.kind === "fold" ? entry.from : entry.row;
}

function offsetOfTopAddress(spec, address) {
  if (!spec?.runs?.length || address === null || address === undefined) return null;
  const start = typeof address === "bigint" ? address : parseAddr(address);
  if (start === null) return null;
  const index = indexForAddress(spec, start);
  const entry = entryForIndex(spec, index);
  const found =
    entry &&
    (entry.kind === "fold"
      ? entry.from <= start && start < entry.to
      : entry.row <= start && start < entry.row + 16n);
  return found ? Math.max(0, index * ROW_HEIGHT) : null;
}

function hexRows(spec) {
  layoutTops(spec);
  const total = spec.total;
  // Scroll position and viewport height come from `state`, not from the DOM: `render()` empties the app
  // before it builds anything, so at this moment there is no pane to ask — and asking the DOM here silently
  // pinned every pane to row zero while the scrollbar itself moved.
  const viewport = state.viewportRows * ROW_HEIGHT || 760;
  const scrolled = state.scrollTop || 0;
  const from = Math.max(0, entryAt(spec, scrolled) - ROW_MARGIN);
  const to = Math.min(total, entryAt(spec, scrolled + viewport) + ROW_MARGIN + 1);

  const rows = [];
  if (from > 0) rows.push(h("div", { class: "rowgap", style: `height:${from * ROW_HEIGHT}px` }));
  for (let index = from; index < to; index += 1) {
    const entry = entryForIndex(spec, index);
    if (!entry) continue;
    rows.push(
      entry.kind === "fold" ? foldRow(entry) : hexRow(spec.objects, spec.target, spec.crashPc, spec.window, entry.row, spec),
    );
  }
  if (to < total) {
    const below = (total - to) * ROW_HEIGHT;
    rows.push(h("div", { class: "rowgap", style: `height:${Math.max(0, below)}px` }));
  }
  return rows;
}
function foldRow(entry) {
  const pages = Number((entry.to - entry.from) / PAGE);
  return h(
    "div",
    {
      class: "hexrow fold",
      title: `${bytes(Number(entry.to - entry.from))} of zeros in ${pages} pages · nothing named in them · click to show the bytes`,
      onclick: () => {
        // Every page of the run, not just its first: the state is keyed by page, and unfolding one page of a
        // run makes the rest of it a *new* run starting at the next page — so remembering only the first
        // would expand one page and fold the other twenty-six straight back up.
        for (let page = entry.from; page < entry.to; page += PAGE) state.unfolded.add(page.toString());
        render();
      },
    },
    h("span", {
      class: "foldtext",
      text: `⋯  ${norm(entry.from)} – ${norm(entry.to)}   ${pages} ${pages === 1 ? "page" : "pages"} of zeros (${bytes(
        Number(entry.to - entry.from),
      )}) — click to show`,
    }),
  );
}

// The entry a given address is on. A jump has to land on the entry, not on a row index, because folding
// means the two are no longer the same number.


// The bytes a selection should cover at an address: the *field* the debug information places there, and nothing
// else. Null means the mark stays the single byte, which is the honest answer for an address the debug info does not
// describe as a field — including one that merely falls inside a larger object it does describe.
//
// There is deliberately no fallback to the containing object. A stack frame is an object too, so falling back to it
// turned "this saved register" into all 64 bytes of the frame whenever the address landed in its padding — a wall of
// tint that says nothing. Fields are recorded as the object's `children` (the same relationship the overlay draws),
// so the search is: narrowest containing object, then the child inside it that holds the address.
function objectCovering(objects, address) {
  let best = null;
  for (const object of objects ?? []) {
    const start = objectAddress(object);
    const size = BigInt(object.size ?? 0n);
    if (start === null || size <= 0n) continue;
    if (address < start || address >= start + size) continue;

    for (const child of object.children ?? []) {
      if (typeof child.offset !== "number" || typeof child.size !== "number") continue;
      const childStart = start + BigInt(child.offset);
      const childEnd = childStart + BigInt(child.size);
      if (address < childStart || address >= childEnd) continue;
      // The smallest covering field wins: objects nest, and two of them can describe the same bytes.
      if (!best || childEnd - childStart < best.end - best.start) {
        best = { start: childStart, end: childEnd };
      }
    }
  }
  return best;
}

function hexRow(objects, target, crashPc, window, row, spec = null) {
  // The row's sixteen bytes, read once: `bytesAt` walks the window's chunks, and asking it sixteen times for
  // the same row would repeat the same search sixteen times.
  const sixteen = bytesAt(window, row, 16);
  const pieces = rowPieces(objects, row);
  const owners = byteOwners(pieces, row);
  const cells = [];
  const ascii = [];
  const codeLines = spec?.code ? spec.codeRows.get(row.toString()) ?? [] : [];
  // What the *selection* covers in this row: the whole field when the address falls inside one the debug info
  // describes, and otherwise nothing but the single byte at that address. That is the difference between "this byte"
  // and "this field" — the same distinction the overlay draws for the fields it knows, applied to where the reader
  // asked to be. A row-wide tint said neither: it marked sixteen bytes as if all sixteen were the answer.
  // The selection, read from the one place that holds it — not recomputed here. This used to look up "which object
  // covers this address" on its own, so the byte range beside the hex and the row the struct rail marked were two
  // independent computations over two independent tables, and they disagreed whenever the address was an object's
  // own base rather than a field inside it.
  const selection = state.selection;
  for (let i = 0; i < 16; i += 1) {
      const address = row + BigInt(i);
      const byte = sixteen[i];
      const selected = target !== null && address === target;
      const isCrash = crashPc !== null && address === crashPc;
      // The bytes carry the colour of the field they belong to: that, and not a label column to be
      // matched up by eye, is what says "these bytes are that field".
      const owner = owners.get(address.toString());
      const inInstruction =
        state.insnRange !== null && state.insnRange[0] <= address && address < state.insnRange[1];
      cells.push(
        h("span", {
          // `chosen` marks the bytes of the selected field — a strong tint with dark text, so the field reads as one
          // run. There used to be a second, wash-like tint drawn from the selection's byte range on top of this one,
          // at a strength the eye cannot tell from ordinary ownership colouring; it made a whole selected field look
          // like a single selected byte, and it is gone. The extent is said twice now, and both are readable: this
          // run, and the accent outline of the field's own box in the overlay.
          class: `byte ${byte === undefined ? "hole" : ""} ${selected ? "sel" : ""} ${inInstruction ? "insnsel" : ""} ${isCrash ? "crashsite" : ""} ${
            owner ? `owned tone-${owner.tone} ${owner.start ? "starts" : ""} ${selection && selection.fieldExpression === owner.expression ? "chosen" : ""}` : ""
          }`,
          style: `grid-column:${lineOf(i)}`,
          text: byte === undefined ? "--" : byte.toString(16).padStart(2, "0"),
          title: `${norm(address)}${isCrash ? " — the crash site: execution stopped here" : byte === undefined ? " — not in this dump" : ""}`,
          onclick: () => {
            // The byte first: it is what was pointed at. Then, if the dump lists an instruction over it, that
            // instruction is selected too — the three-way link, from this end.
            if (instructionAt(address)) {
              selectInstruction(address);
              return;
            }
            // A field is named by its expression everywhere else, so it is named by its expression here: the byte's
            // owner carries one, and the selection is built from it.
            if (owner) selectField({ fieldExpression: owner.expression, address });
            else selectAddress(address);
          },
          ...(owner
            ? { "data-field": owner.fieldId, "data-object": owner.objectId, ...hoverFor(owner.fieldId, owner.objectId) }
            : {}),
        }),
      );
      // A non-printable byte is shown as a middle dot, not a period: a period sits on the baseline, so a
      // row of them reads as sitting lower than the hex digits beside it, and the column stops looking
      // like it lines up. `·` sits at the height of the digits, which is what the eye is comparing.
      ascii.push(byte === undefined ? " " : byte >= 32 && byte < 127 ? String.fromCharCode(byte) : "·");
    }

    const overlay = overlayCells(pieces, row);
    const frames = objects.length ? objectFrames(objects, row) : [];
    return h(
      "div",
      // One line, always. The listing beside these sixteen bytes runs *along* the row rather than down it, so
      // nothing here makes the row taller — which is also what keeps the layout's arithmetic and the browser's
      // rendering the same number. A row that grew by any other amount would put every spacer below it out by that
      // difference, and the scrollbar would lie a little more on each one.
      { class: "hexrow" },
      // Five cells, always, in the order of the column template. An empty frame or overlay column is a
      // zero-width track, but the cell has to be there or every column after it shifts.
      objects.length
        ? h(
              "span",
              { class: "sframes" },
              frames.map((frame) =>
                h("span", {
                  // The frame box of the selected object is marked too: the overlay is the third place that shows what
                  // is at an address, and it used to draw every object as if none of them were the one being looked at.
                  class: `sframe ${state.selection && state.selection.objectKey === frame.objectId ? "chosen" : ""}`,
                  "data-object": frame.objectId,
                  title: frame.title,
                  text: frame.glyph,
                  ...hoverFor(`${frame.objectId}f0`, frame.objectId),
                }),
              ),
            )
          : h("span", { class: "sframes" }),
        h("span", { class: "haddr", text: pad64(row) }),
        h("span", { class: "hbytes" }, cells),
        // Two honest ways to show the same sixteen characters, and they trade off against each other:
        //   compact      — 6.6px per character, so `alpha` is readable as a word;
        //   byte-aligned — one cell per byte, so character 9 sits where byte 9 does and the group gap
        //                  runs through both columns, at the cost of spreading the text out.
        // Which one looks "aligned" depends on what the eye is doing, so it is a switch rather than a
        // decision made on the user's behalf.
        state.asciiAligned
          ? h(
              "span",
              { class: "hascii aligned" },
              ascii.map((char, i) => h("span", { class: "achar", style: `grid-column:${lineOf(i)}`, text: char })),
            )
          : h("span", { class: "hascii", text: ascii.join("") }),
        // No objects in this window means no overlay column at all: an empty ruled column is just noise,
        // and it costs width that the bytes can use. A code window has no types to overlay either, so the
        // same column carries the other thing that belongs beside these bytes: what the instructions say.
        codeLines.length
          ? h("span", { class: "scode" }, codeColumn(codeLines))
          : objects.length
          ? h(
              "span",
              { class: "soverlay" },
              // The strip first, then the fields on top of it.
              bandCells(objects, row).map((band) =>
                h("span", {
                  class: "sband",
                  style: `grid-column:${band.column}`,
                  title: band.title,
                  "data-object": band.objectId,
                  ...hoverFor(`${band.objectId}f0`, band.objectId),
                }),
              ),
              overlay.map((cell) => {
                // A gap is a box, not a control: it names no field, so there is nothing to locate. Only a
                // cell that carries a field id is a way into the tree.
                if (!cell.fieldId) {
                  return h("span", {
                    class: `scell ${cell.class}`,
                    style: `grid-column:${cell.column}`,
                    title: cell.title,
                    text: cell.text,
                  });
                }
                const props = {
                  // The one selection, by expression — the only identity a field has in this application. There used to
                  // be a second test here against a key-based copy of the selection, and because a key and an expression
                  // never match the same field, a click could outline two different boxes at once.
                  class: `scell ${cell.class} ${
                    state.selection?.fieldExpression === cell.expression ? "chosen" : ""
                  }`,
                  style: `grid-column:${cell.column}`,
                  title: `${cell.title} · click to locate it in the field tree`,
                  text: cell.text,
                  "data-field": cell.fieldId,
                  "data-object": cell.objectId,
                  ...hoverFor(cell.fieldId, cell.objectId),
                };
                // Every field block is a way into the tree on the right: one click and the row for this
                // field is open, visible and selected. Following a pointer is the rail value's job (`→`
                // marks it), because both actions on one click would make the click mean two things.
                return h("button", {
                  ...props,
                  onclick: () => locateInRail(cell.objectExpression, cell.expression),
                });
              }),
            )
          : h("span", { class: "soverlay" }),
    );
}

// One line of the code beside a hex row: a source line, or an instruction. Both are one `ROW_HEIGHT` tall,
// which is what keeps the bytes and the instructions on the same lines down the page.
function codeCell(line) {
  if (line.kind === "source") {
    return h(
      "div",
      { class: `ccl ${line.text === null ? "nosource" : ""}` },
      h("span", { class: "clineno", text: line.line ?? "—" }),
      h("span", {
        class: "ctext",
        title: line.recorded ?? "",
        text: line.text ?? "the source for this line is not in this checkout",
      }),
    );
  }
  const instruction = line.instruction;
  const crash = conditionCrash(instruction);
  return h(
    "button",
    {
      class: `ccl insnrow ${crash ? "crashsite" : ""}`,
      title: `${instruction.address}${crash ? " — the instruction the program died on" : ""} · click to see these bytes`,
      onclick: () => goTo(instruction.address),
    },
    h("span", { class: "iaddr", text: norm(instruction.address) }),
    h("span", { class: "itext", text: instruction.text }),
    crash ? h("span", { class: "imark", text: "← crash" }) : null,
  );
}

function conditionCrash(instruction) {
  return state.rowsSpec?.crashPc !== null && state.rowsSpec?.crashPc === BigInt(instruction.address);
}

// The listing that belongs beside one row of bytes: the instructions in boxes, and the source they came from
// to the right of them.
//
// Two things are deliberately absent. **The address**: the hex row on the left *is* an address, printed once
// in its own gutter, and repeating it before every mnemonic is noise that pushes the interesting part off the
// edge. **A line of its own for the source**: the source is a column, not a heading, so a group of
// instructions sits beside the single line they compiled from — which is the pairing this view exists for.
// The listing beside one row of bytes, on a single line: the source line it came from, then every
// instruction those sixteen bytes hold, side by side.
//
// Vertical stacking was the earlier shape and it is what made the page lurch — a row of sixteen bytes is one
// to four instructions, so a row's height followed its listing and the rhythm broke. Laid out in a line, all
// four stay visible, the row stays one line tall, and anything too wide runs off the edge into the hex
// pane's own horizontal scroll, which is what a wide byte row already does.
function codeColumn(lines) {
  const chips = [];
  // The source line is remembered, not drawn: it belongs to the instructions that follow it, and it travels
  // with them as a tooltip. A sixteen-byte row has room for about four chips before it runs off the edge, and
  // a wrapped line of C spends all of them.
  let source = null;
  for (const entry of lines) {
    if (entry.kind === "source") {
      source = entry;
      continue;
    }
    chips.push(instructionBox(entry.instruction, source));
    source = null;
  }
  return h("span", { class: "ccolumn" }, chips);
}
function instructionBox(instruction, source = null) {
  const crash = conditionCrash(instruction);
  const from = source
    ? `\n${source.line ?? "?"}  ${source.text ?? "the source for this line is not in this checkout"}`
    : "";
  return h(
    "button",
    {
      class: `cbox ${crash ? "crashsite" : ""} ${state.instruction === norm(instruction.address) ? "selected" : ""}`,
      title: `${instruction.address}${crash ? " — the instruction the program died on" : ""}${from} · click to link the bytes to it`,
      onclick: () => selectInstruction(instruction.address),
    },
    // gdb separates the mnemonic from its operands with a tab, which does not line up in a fixed-width cell:
    // two spaces read the same and stop ldr from looking indented differently from stp.
    h("span", { class: "mnemonic", text: instruction.text.replace(/\t/g, "  ") }),
    crash ? h("span", { class: "imark", text: "← crash" }) : null,
  );
}

// Which part of a deep stack the overlay on this window actually covers, when it is not all of it.
function stackOverlayNote(window) {
  const stack = stackSource();
  if (window.name !== "stack" || !stack.truncated) return null;
  const shown = (stack.frames ?? []).length + (stack.offset ?? 0);
  return ` · overlaid for ${shown} of ${stack.total} frames — the rest are pages away (stack view)`;
}

// The objects a window overlays, cached against the **state they are built from** — `overlayObjects` returns a
// fresh array every render, so keying on the array's identity (which is what the piece layer's WeakMap does) can
// never hit, and the layer was rebuilt per render. Rebuilt when the typed index or the stack's frames change,
// which is what the window actually depends on.
const overlayCache = new WeakMap();

function overlayFor(window) {
  const key = `${Object.keys(state.typedData ?? {}).length}:${(state.stackData?.frames ?? []).length}:${
    (state.data.stack?.frames ?? []).length
  }:${state.zoom ?? ""}`;
  const cached = overlayCache.get(window);
  if (cached?.key === key) return cached.objects;
  const objects = overlayFor(window);
  overlayCache.set(window, { key, objects });
  return objects;
}

function hexPane(window, target) {

  const start = BigInt(window.address);
  // The window is a whole region, so it starts where the region starts, not where the address of interest
  // happens to be: a hex view whose first row is mid-region cannot show you what is below.
  const first = start - (start % 16n);
  const objects = overlayObjects(window);
  // The address the program died at, if it is in the bytes on screen: for a crash, that byte is the
  // answer, and it should not have to be hunted for.
  const crashPc = parseAddr(state.data.detail[String(state.thread)]?.frames?.[0]?.pc);
  // The rows this window has, folding included. A jump needs it *before* the rows are built, because the row
  // to scroll to is an entry index now — folding means "row number" and "address" are no longer in step.
  const region = regionOf(start);
  const layout = rowLayout(window, objects);
  const spec = { window, objects, target, crashPc, start, first, end: layout.end, runs: layout.runs, total: layout.total };
  // Code rows are built here, before anything measures a row: a row's height *is* its listing, so the layout
  // cannot be computed without knowing what belongs beside those sixteen bytes. `spec.code` is what tells the
  // builder whether this window is code at all — a heap window gets the DWARF overlay instead.
  spec.code = isCode(region);
  spec.codeRows = codeRowsFor(spec);
  // What a pending "take me to this address" request would scroll to, in this spec's own row tops. Computed here
  // because only the layout knows; *applied* in `render`, which is the single place that writes the pane's position.
  //
  // Null means "not a row of this spec (yet)": `entryOf` answers 0 for "not found", and 0 is also a perfectly good
  // row, so an address whose page has not arrived used to silently become "scroll to the top of the window" — which
  // is why a jump inside one window sometimes did nothing and sometimes teleported to the start. The request stands
  // until the row exists, and the render that follows the page arriving satisfies it.
  state.paneTop = null;
  if (state.reveal && target !== null) {
    layoutTops(spec);
    const index = indexForAddress(spec, target);
    const entry = entryForIndex(spec, index);
    const found =
      entry &&
      (entry.kind === "fold"
        ? entry.from <= target && target < entry.to
        : entry.row <= target && target < entry.row + 16n);
    if (found) state.paneTop = Math.max(0, index * ROW_HEIGHT - 100);
  }
  state.rowsSpec = spec;
  // The pages this pane is looking at: the viewport's own range, and the target of a jump, which is where the
  // pane is about to scroll to. `hexRows` below draws only the visible rows, so this is exactly "visible range
  // plus a margin" and nothing else — a window is a whole region, and fetching all of it was the difference
  // between a viewer and a growing heap of bytes nobody is looking at.
  for (const anchor of [viewportAddress(spec), target]) {
    if (anchor !== null && anchor !== undefined) ensurePages(window, anchor);
  }
  const rows = hexRows(spec);


  const holes = window.unread.reduce((total, hole) => total + hole.length, 0);
  return h(
    "div",
    { class: `hexpane ${objects.length ? "" : "no-objects"} ${state.asciiAligned ? "ascii-aligned" : ""} ${spec.code ? "is-code" : ""}` },
    h(
      "div",
      { class: "hexhead" },
      h("span", { text: `${window.name} · ${window.address} · ${bytes(window.length)}` }),
      h("span", {
        class: "dim",
        text:
          (holes ? ` · ${bytes(holes)} missing from this dump` : " · fully present") +
          (region?.perms.includes("x") ? " · executable" : "") +
          // The stack window's frames are a page of them when the thread is deep, and an overlay that stopped
          // at frame 500 without saying so would read as "nothing lives below this" — a claim about the dump
          // made from the size of one answer.
          (stackOverlayNote(window) ?? ""),
      }),
    ),
    objects.length ? overlayLegend() : null,
    // The header and the legend are the pane's own chrome, not content: they sit outside the scroller, so
    // a sticky ruler can never slide over them. Only the ruler and the rows scroll.
    h(
      "div",
      { class: "hexbody" },
      h(
        "div",
        { class: "hexscroll" },
        hexRuler(state.asciiAligned, Boolean(objects.length)),
        h("div", { class: "rows" }, ...rows),
      ),
      // Code goes *beside the bytes*, in the same place the DWARF overlay takes on a stack or heap window:
      // the right of the hex, before the minimap. The listing is what the hex is looking at, so it belongs
      // against the bytes rather than across a strip that summarises them.
      //
      // It is a column, not a per-row cell, and that is forced by arithmetic rather than taste: a hex row is
      // 16 bytes and an aarch64 instruction is 4, so one row carries up to four instructions and a single
      // 19px cell cannot hold them without dropping three. The column scrolls with the bytes instead, which
      // keeps every instruction and still lines the two up by address.
      minimap(),
    ),
  );
}

// --------------------------------------------------------------------------- //
// code: gdb's disassembly of what the hex pane is looking at, and the source it
// came from. A panel of the memory view, not a page (C6).
//
// Two rules decide its behaviour. **The listing follows the bytes**: the frame of reference is the address
// at the top of the hex viewport, so scrolling bytes scrolls code, and the pairing never drifts. And **what
// cannot be shown is stated** — a function nobody dumped says so, an address no function contains keeps
// gdb's reason, and a source line that is not in this checkout says that rather than going blank.
// --------------------------------------------------------------------------- //
function isCode(region) {
  return Boolean(region?.perms?.includes("x"));
}

function disassemblyAt(address) {
  if (address === null) return null;
  const frames = Object.values(codeData().frames ?? {});
  return (
    frames.find((reply) => {
      const first = reply.instructions?.[0]?.address;
      const last = reply.range?.end ?? reply.range?.last;
      return first && last && BigInt(first) <= address && address < BigInt(last);
    }) ?? null
  );
}

// The recorded path is DWARF's own — the build machine's `/home/lyy/cdwv-practice/src/libplugin.c` — and it
// is the key into the file table the backend filled by mapping that root onto this checkout.
function codePanel(spec, region) {
  const stripped = codeData().stripped;
  return h(
    "div",
    { class: "codepanel" },
    h("div", { class: "codepanel-head", text: "code · follows the hex pane" }),
    h("div", { class: "codepanel-body" }, codeBody(spec, stripped)),
  );
}

// The listing the panel shows: the function the viewport is *inside*, or — when the viewport starts before
// it, which is what the code page does, since a page starts at a 4 KB boundary and a function rarely does —
// the next function in this window. "Nothing here" would be true about one address and useless about a view
// that has a function on screen a few rows down.
function disassemblyFor(spec) {
  const anchor = viewportAddress(spec);
  if (anchor === null) return { reply: null, address: null };
  const inside = disassemblyAt(anchor);
  if (inside) return { reply: inside, address: anchor };
  const ahead = Object.values(codeData().frames ?? {})
    .filter((reply) => {
      const first = reply.instructions?.[0]?.address;
      return first && BigInt(first) > anchor && BigInt(first) < spec.end;
    })
    .sort((a, b) => (BigInt(a.instructions[0].address) < BigInt(b.instructions[0].address) ? -1 : 1))[0];
  return ahead ? { reply: ahead, address: BigInt(ahead.instructions[0].address) } : { reply: null, address: anchor };
}

function codeBody(spec, stripped) {
  const { reply, address } = disassemblyFor(spec);
  if (reply) return codeListing(reply, address);

  // Nothing was dumped for this address. Two different things can be behind that, and they must not read
  // alike: an address gdb has no function for at all, and a function this fixture did not disassemble.
  if (stripped && BigInt(stripped.address) === address) return strippedSection(stripped);
  return h("div", {
    class: "codesection-body",
    text: `no disassembly for ${norm(address)} in this dump — the fixture disassembled ${
      Object.keys(codeData().frames ?? {}).length
    } frame(s), and none of them is in this part of the window`,
  });
}

// The listing follows the bytes.
//
// Rebuilt only when the address moves into a *different function* — a different listing is a different
// document — and merely scrolled when it lands inside the same one: a scroll must cost a `scrollTop`, not
// seventy DOM nodes, because a hex scroll renders at animation-frame rates.
function followCode() {
  const panel = document.querySelector(".codepanel-body");
  const spec = state.rowsSpec;
  if (!panel || !spec) return;
  const { reply, address } = disassemblyFor(spec);
  const stripped = codeData().stripped;
  const key = reply
    ? `${reply.instructions?.[0]?.address ?? "?"}`
    : stripped && address !== null && BigInt(stripped.address) === address
      ? "stripped"
      : "none";

  if (panel.dataset.key !== key) {
    panel.dataset.key = key;
    panel.textContent = "";
    panel.append(codeBody(spec, stripped));
  }

  // The "you are here" mark is moved, not rebuilt: inside one function it is the only thing that changes.
  // The viewport top almost never lands exactly on an instruction — it is a byte address and instructions
  // have length — so the mark goes on the instruction that *contains* it: the greatest address at or below
  // the anchor. That is the instruction that would touch the byte on screen.
  const wanted = address === null ? null : BigInt(address);
  const rows = [...panel.querySelectorAll(".insnrow")]
    .map((row) => ({ row, at: parseAddr(row.querySelector(".iaddr")?.textContent) }))
    .filter((entry) => entry.at !== null);
  const target =
    wanted === null
      ? null
      : (rows.filter((entry) => entry.at <= wanted).pop() ?? rows[0])?.row ?? null;
  const marked = panel.querySelector(".insnrow.anchor");
  if (marked && marked !== target) marked.classList.remove("anchor");
  if (target) target.classList.add("anchor");

  // Put the anchor at the top of the panel: the byte on screen and the instruction that touched it are then
  // on the same line of sight, which is the entire reason the two are side by side.
  if (target) panel.scrollTop = Math.max(0, target.offsetTop - panel.offsetTop - 4);
}

// The address at the top of the hex viewport — the anchor the listing follows. It comes from the *row
// layout*, not from the scroll position divided by a row height: with runs of pages folded, a pixel is not
// a fixed number of bytes, and a listing that assumed it would point somewhere nobody is looking.
function viewportAddress(spec) {
  const index = Math.min(spec.total - 1, Math.max(0, Math.round((state.scrollTop || 0) / ROW_HEIGHT)));
  const entry = entryForIndex(spec, index);
  if (!entry) return null;
  return entry.kind === "fold" ? entry.from : entry.row;
}

// A whole window in one strip, the way an editor shows a file's minimap. At 132 KB the hex pane is one
// screen of eight thousand rows, and "where is anything in here" deserves an answer that is not scrolling.
//
// One line per screen pixel, coloured by what the bytes *are* — the same three answers the fold uses:
// something named, some content, or nothing but zeros. The classification is cached per window, because it
// costs a walk over the whole region and a scroll must not pay for it again; the viewport rectangle is
// drawn fresh every time, on top.
// The minimap's mark geometry: one pixel per hex digit, so a byte is two marks and a gap, and the strip is
// exactly one hex row wide — sixteen bytes across, the same width as the row it summarises.
const MINIMAP_MAX_STRETCH = 4; // canvas lines one entry may occupy at most
const MINIMAP_PITCH = [3, 5]; // per byte column, by `state.mapPitch`: narrow and wide
const MINIMAP_MARK = 2;
const MINIMAP_FALLBACK_HEIGHT = 600;

function minimapWidth() {
  return 16 * (MINIMAP_PITCH[state.mapPitch] ?? MINIMAP_PITCH[0]) + 4;
}

function minimapHeight() {
  const pane = document.querySelector(".hexscroll");
  const measured = pane?.clientHeight || state.viewportRows * ROW_HEIGHT || MINIMAP_FALLBACK_HEIGHT;
  // `NaN` is falsy but not caught by `||`, and a canvas of `NaN` measures as zero — which is how a height
  // arithmetic slip becomes a drawing error three functions later.
  return Number.isFinite(measured) && measured > 0 ? Math.round(measured) : MINIMAP_FALLBACK_HEIGHT;
}

function minimap() {
  return h("canvas", {
    class: "minimap",
    width: minimapWidth(),
    height: minimapHeight(),
    title:
      "the whole window · each mark is a byte (its two hex digits) · nothing is drawn where the bytes are zero · blue: something is named here · click or drag to move",
  });
}

// A line covers a dozen hex rows at this height, so a mark cannot be a byte — it is the *column*: a byte
// position marked when **any** of the rows behind that line has a non-zero byte there. That is what makes
// the strip a miniature of the content rather than a highlight of one chosen row per line: a frame's
// pointer columns stay continuous down the picture, and a page with anything in it reads as a page with
// something in it.
function minimapImage(spec, height) {
  // The key includes how many bytes the map actually holds. Without that, the image computed *before* the
  // window's bytes arrived — every row empty, because there was nothing to read — was cached under a key that
  // never changes afterwards, so the strip stayed blank for the life of the window. The same "the source
  // changed and the cache did not" that the typed index and the rail both had.
  const key = `${spec.window.address}:${spec.window.length}:${spec.total}:${height}:${(spec.window.chunks ?? []).length}`;
  if (state.minimapKey === key) return state.minimapImage;

  const named = layerFor(spec.objects).named;
  // The rows are walked in address order and so is `named`, so "is this row named" is a *cursor*, not a search.
  // It was `named.some(...)` inside the per-row loop: measured on the heavy core's stack window, 240 384 rows
  // against ~5 000 named ranges is 1.2 *billion* comparisons, and it is what made opening that window hang the
  // browser for minutes. A cursor makes the whole pass O(rows + ranges).
  let namedAt = 0;
  const isNamedRow = (row) => {
    while (namedAt < named.length && named[namedAt][1] <= row) namedAt += 1;
    const range = named[namedAt];
    return Boolean(range && range[0] < row + 16n && row < range[1]);
  };
  const rows = new Array(height).fill(null); // the 16 column values this line shows, or "fold"
  const tint = new Uint8Array(height);
  const entries = spec.total || 1;
  // The content extent, not the canvas: a window with sixteen rows in a six-hundred-line strip would draw one
  // mark every forty pixels, which is a picture of nothing. Left over is blank on purpose.
  const lines = Math.min(entries * MINIMAP_MAX_STRETCH, height);
  state.minimapLines = lines; // the click and the viewport rectangle measure along this same axis

  for (let y = 0; y < lines; y += 1) {
    const from = Math.floor((y / lines) * entries);
    const to = Math.max(from + 1, Math.floor(((y + 1) / lines) * entries));
    // What this line covers, in addresses. A line holds a *range* of rows, and the range's bytes are one
    // slice of a chunk — so the question "is there anything on this line" is a scan of a hex string, and the
    // per-byte work happens only on the lines that have something on them. The version this replaces asked
    // `bytesAt` for all sixteen bytes of **every** row: 240 384 rows × 16 parses on the heavy core's stack
    // window, on every render, which is where the rest of the browser's stall was.
    const first = entryForIndex(spec, from);
    const last = entryForIndex(spec, Math.min(to, spec.total) - 1);
    if (!first || !last) continue;
    const low = first.kind === "fold" ? first.to : first.row;
    const high = last.kind === "fold" ? last.from : last.row + 16n;
    const lineIsFoldedOnly = first.kind === "fold" && last.kind === "fold";
    const slice = hexSlice(spec.window, low, high);
    if (slice === null) {
      if (lineIsFoldedOnly) rows[y] = "fold";
      continue;
    }
    if (!/[^0]/.test(slice)) {
      // Every byte present and zero: nothing to draw. A *fold* is the same picture for a different reason.
      if (lineIsFoldedOnly) rows[y] = "fold";
      continue;
    }

    const columns = new Uint8Array(16);
    let any = false;
    let isNamed = false;
    for (let index = from; index < to && index < spec.total; index += 1) {
      const entry = entryForIndex(spec, index);
      if (!entry || entry.kind === "fold") continue;
      const row = entry.row;
      if (isNamedRow(row)) isNamed = true;
      const sixteen = bytesAt(spec.window, row, 16);
      for (let i = 0; i < 16; i += 1) {
        const byte = sixteen[i];
        if (!byte) continue;
        // The greatest byte seen in this column: the mark is as bright as the strongest thing behind it.
        if (byte > columns[i]) columns[i] = byte;
        any = true;
      }
    }

    if (!any) {
      if (lineIsFoldedOnly) rows[y] = "fold";
      continue;
    }
    rows[y] = columns;
    tint[y] = isNamed ? 1 : 0;
  }

  state.minimapKey = key;
  state.minimapImage = { rows, tint };
  return state.minimapImage;
}

// The content picture is cached on an offscreen canvas: a scroll must not redraw 600 lines of characters,
// only move the viewport rectangle over them.
function paintMinimap(canvas = document.querySelector(".minimap")) {
  const spec = state.rowsSpec;
  if (!canvas || !spec) return;
  // Keep the bitmap equal to the element's own box, and put the element where the miniature belongs: starting
  // under the ruler, exactly as tall as the rows below it. The strip is a picture of the scrollable part, so it
  // has to begin where that part begins — one line of the strip beside the ruler line meant the whole picture was
  // offset by the header's height, and marked nothing where it pointed.
  const pane = document.querySelector(".hexscroll");
  const ruler = pane?.querySelector(".ruler");
  const offset = ruler ? Math.round(ruler.getBoundingClientRect().height) : 0;
  if (canvas.style.marginTop !== `${offset}px`) canvas.style.marginTop = `${offset}px`;
  const wanted = Math.round(Math.max(1, (pane?.clientHeight || 0) - offset));
  if (pane && canvas.height !== wanted) {
    canvas.height = wanted;
    window.requestAnimationFrame(() => paintMinimap(canvas));
  }
  // The backing store *is* the element's height: one line per screen pixel, so a mark is a pixel
  // and not a stretched shape. A canvas with no height means the pane has not been measured yet (`clientHeight`
  // is 0 before mount), and drawing it is an `InvalidStateError` — so the paint waits for the next render
  // instead of throwing. "Not measured" and "empty" are different states, here as everywhere else.
  const height = Math.round(canvas.height);
  const width0 = Math.round(canvas.width);
  if (!(height > 0) || !(width0 > 0)) return;
  const image = minimapImage(spec, height);

  if (state.minimapPainted !== state.minimapKey || !state.minimapBacking) {
    const width = minimapWidth();
    const backing = state.minimapBacking ?? document.createElement("canvas");
    backing.width = width;
    backing.height = height;
    const off = backing.getContext("2d");
    off.fillStyle = "#0b0e14";
    off.fillRect(0, 0, width, height);
    const pitch = MINIMAP_PITCH[state.mapPitch] ?? MINIMAP_PITCH[0];
    const mark = pitch - 1;

    for (let y = 0; y < height; y += 1) {
      const entry = image.rows[y];
      if (entry === "fold") {
        // Folded pages: a dashed rule, so it reads as "skipped" rather than as a row of data.
        off.fillStyle = "#2b3a52";
        for (let x = 0; x < width; x += 4) off.fillRect(x, y, 2, 1);
        continue;
      }
      if (!entry) continue;
      const blue = image.tint[y] === 1;
      for (let i = 0; i < 16; i += 1) {
        const byte = entry[i];
        if (!byte) continue; // `00` says nothing, and drawing it would turn a page of zeros into a page of text
        const level = 70 + byte;
        off.fillStyle = blue
          ? `rgb(${Math.round(level * 0.5)},${Math.round(level * 0.7)},${level})`
          : `rgb(${Math.round(level * 0.8)},${Math.round(level * 0.85)},${level})`;
        // One mark per byte column, `mark` pixels wide — the two hex digits, one pixel each. The x step is
        // `pitch`, the value chosen above: multiplying by the *array* `MINIMAP_PITCH` gives `NaN`, and
        // `fillRect(NaN, …)` is a silent no-op, which is a blank strip with no error anywhere.
        off.fillRect(i * pitch, y, mark, 1);
      }
    }
    state.minimapBacking = backing;
    state.minimapPainted = state.minimapKey;
  }

  const line = canvas.getContext("2d");
  line.clearRect(0, 0, canvas.width, canvas.height);
  line.drawImage(state.minimapBacking, 0, 0);

  // The viewport: which part of the window the pane is showing. Its geometry comes from the *scroller*, not
  // from a byte count — folding changes how tall the content is, and a rectangle drawn from the unfolded
  // height would sit in the wrong place (and a click computed from it would clamp straight to the bottom).
  const scrollHeight = Math.max(1, pane?.scrollHeight ?? 1);
  const clientHeight = pane?.clientHeight ?? 1;
  // Measured along the *content* extent, not the canvas: a small window is drawn in the top `lines` and the
  // rest of the strip is blank, so a rectangle computed against the canvas height washes the whole strip white
  // — claiming the pane shows a window it is showing a tenth of.
  // The viewport: which part of the window the pane is showing. A plain rectangle, the width of the strip and
  // nothing else — the way an editor's overview ruler does it. No stroke and no rounding: a stroke lands on the
  // bitmap boundary (where it is half-clipped and reads as running off the edge), and rounding was invented here
  // rather than taken from anywhere. Both axes are clamped to the bitmap: `lines` is the content's extent, which
  // is shorter than the canvas for a small window.
  const lines = state.minimapLines || height;
  const viewTop = Math.min(lines, ((state.scrollTop || 0) / scrollHeight) * lines);
  const viewHeight = Math.min(
    lines - viewTop,
    Math.max(6, (clientHeight / scrollHeight) * lines),
  );
  const top = Math.max(0, Math.min(Math.max(0, height - 6), Math.round(viewTop)));
  const tall = Math.max(6, Math.min(height - top, Math.round(viewHeight)));
  line.fillStyle = "rgba(255,255,255,.30)";
  line.fillRect(0, top, width0, tall);
  // The address on screen comes from the *row layout*, not from the scroll ratio: folding means a pixel is
  // no longer a fixed number of bytes, and a ratio that ignores that reports an address nobody is looking
  // at (it claimed the region's start while the pane showed `sp`).
  const entry = entryForIndex(spec, Math.min(spec.total - 1, Math.max(0, Math.round((state.scrollTop || 0) / ROW_HEIGHT))));
  const at = entry ? (entry.kind === "fold" ? entry.from : entry.row) : spec.first;
  canvas.title = `${bytes(Number(spec.end - spec.first))} in this window · at ${norm(at)}`;
}

// Click or drag anywhere on the strip and the pane follows, the way an editor's minimap does — this is a
// scrollbar with the content printed on it, so it has to behave like one.
function bindMinimap(canvas) {
  if (!canvas || canvas.dataset.bound === "1") return;
  canvas.dataset.bound = "1";
  let dragging = false;

  const move = (event) => {
    const pane = document.querySelector(".hexscroll");
    if (!pane) return;
    const rect = canvas.getBoundingClientRect();
    // Where the pointer is, in canvas lines — then as a fraction of the *content* extent, which is shorter
    // than the canvas when the window is small. Clicking the empty part below simply means "the end".
    const canvasLine = ((event.clientY - rect.top) / rect.height) * canvas.height;
    const ratio = Math.min(1, Math.max(0, canvasLine / (state.minimapLines || canvas.height)));
    // How far this can scroll is the *scroller's* answer, not a byte count: with runs of pages folded, the
    // content is a fraction of its unfolded height, and arithmetic on the byte count aims far past the end
    // — which the browser then clamps to the bottom, so every click looked like "jump to the end".
    const max = Math.max(0, pane.scrollHeight - pane.clientHeight);
    // Centre the viewport on where the pointer is: dragging should not snake away from the cursor.
    state.scrollTop = Math.max(0, Math.min(max, ratio * pane.scrollHeight - pane.clientHeight / 2));
    pane.scrollTop = state.scrollTop;
    // The drag is a scroll like any other: what it means is the address now at the top.
    state.topAddress = topAddressAt(state.rowsSpec, state.scrollTop);
    paintRows(pane);
    paintMinimap(canvas);
  };

  canvas.addEventListener("mousedown", (event) => {
    dragging = true;
    move(event);
    event.preventDefault();
  });
  canvas.addEventListener("mousemove", (event) => dragging && move(event));
  window.addEventListener("mouseup", () => {
    dragging = false;
  });
}

// One value on screen, and the three ways it can refuse to be a link. The distinctions matter:
//   null  — gdb sent no value at all (an aggregate `--simple-values` did not read)
//   ""    — gdb sent a value it could not read (the address is not in this dump)
//   0x0   — a real, readable, deliberately empty pointer
// `markCycle` is only for the fields of a structure the user is walking: there the jump history *is* the
// pointer path. An argument on a stack frame is not on that path, and marking it would be a lie.
function valueNode(value, type, expression, markCycle = false) {
  if (value === null || value === undefined) {
    // An aggregate gdb did not read: say what the *type* says it is, not "unknown".
    return h("span", {
      class: "fval muted",
      title: "gdb sent no value for this one — an aggregate is not read unless it is asked for",
      text: shapeOf(type),
    });
  }
  if (value === "") {
    return h("span", {
      class: "fval muted",
      title: "gdb could not read this field — the address is not in this dump",
      text: "(unreadable)",
    });
  }
  const target = parseAddr(value);
  if (target === 0n) return h("span", { class: "fval muted", text: "NULL" });
  const string = String(type ?? "").startsWith("char [") && expression ? charString(expression) : null;
  if (string !== null) {
    return h("span", { class: "fval string", title: value, text: JSON.stringify(string) });
  }
  if (target !== null) {
    if (!regionOf(target)) {
      return h("span", {
        class: "fval bad",
        title: "not in this dump — no mapping in this core covers it",
        text: `${value} ✗`,
      });
    }
    // Two different facts, and the words matter: `↺` means the *data* returns here (a pointer cycle, which the
    // rail's own `↺ a cycle:` chip detects); `↩` means *the reader* has been here before. The old tooltip said
    // "this is a cycle" about the second one — a claim about the dump, made from a browsing history.
    const visited = markCycle && trailAddresses().has(norm(target));
    return h("button", {
      class: `fval jump ${visited ? "visited" : ""}`,
      title: visited
        ? "you have been here on this trail — back returns to where you were"
        : `jump to ${value} and interpret it`,
      text: `${value}${visited ? " ↩" : " →"}`,
      // The value's own link and the row's "select this field" are two different actions, and the row is the
      // outer one: without this the click ran `goTo` and then the row's `selectField`, so the jump was
      // overwritten before it could be seen. Following a pointer belongs to the value; the row belongs to the
      // field.
      //
      // And an address is the address logic wherever it is written — a stack frame's saved register, a struct's
      // pointer, a target in the listing. `goTo` now carries the whole act: move the view, fetch the bytes and the
      // code page, and select the instruction at the target. This handler used to do the last part by hand and
      // record `pendingInstruction` for the case where the page was still in flight — the same intent, written
      // twice, and the other copy (the one in the listing) forgot to record it at all.
      onclick: (event) => {
        event.stopPropagation();
        goTo(value);
      },
    });
  }
  return h("span", { class: "fval", text: value });
}

function fieldValue(child) {
  return valueNode(child.value, child.type, child.expression, true);
}

// The object at an address — or *containing* it, because clicking a byte lands in the middle of a field,
// and "which structure am I inside" is the question that byte was asking.
function objectsAt(target) {
  // The rail asks what lives at an address; with the index on demand, a miss is a question, not an answer.
  if (target !== null && target !== undefined && !typedIndex().has(norm(target)) && !state.typedData[""]) {
    ensureObject(target);
  }
  // No address, no objects. The question is legitimate — a rail with nothing selected still renders — and the
  // answer is "none"; `norm(null)` threw here, reached from the rail on a render where no address was set yet.
  if (target === null || target === undefined) return [];
  const exact = typedIndex().get(norm(target));
  if (exact) return exact;
  for (const objects of typedIndex().values()) {
    const start = objectAddress(objects[0]);
    if (start !== null && objects[0].size && start <= target && target < start + BigInt(objects[0].size)) {
      return objects;
    }
  }
  return [];
}

// The field rail: the object at the current address as a tree, in the notation the Lauterbach debugger
// (`{}` blocks) uses — an aggregate opens a `{ … }` block whose closing brace lines up with the field name,
// and clicking a field opens or closes it. The overlay draws the same layout on the bytes; this is the form
// in which a value like `next=0x5590b662e0` fits, and where the tree can be walked without leaving the view.
const RAIL_STEP = 12;

function railIndent(depth) {
  return `padding-left:${10 + depth * RAIL_STEP}px`;
}

// Can this field's value be opened as a block? Only if this source actually has that object's layout *and*
// gdb gave it an address — a refused object (`stray`) has no position, and a shape with no position is not
// something that can be drawn or walked.
function openable(object) {
  return Boolean(
    object &&
      !object.refused &&
      !isCharArray(object) && // a string is a leaf: its value is the string, not twelve characters
      object.size &&
      objectAddress(object) !== null &&
      object.children?.length,
  );
}

function railFieldRow(object, piece, depth, ancestors, rootAddress) {
  const child = piece.child;
  const fieldId = fieldKey(object, piece.index);
  const target = parseAddr(child.value);
  const nested = typedObjects()[child.expression];
  const cyclic = target !== null && ancestors.has(norm(target));
  const canOpen = openable(nested) && !cyclic;
  const open = canOpen && state.expanded.has(child.expression);
  // Selected means "this is the field the one selection names", by expression. The old fallback — comparing a
  // key-derived copy of the selection — could mark a second row whenever the two disagreed, which they always did.
  const selected = state.selection?.fieldExpression === child.expression;
  // Array elements arrive as `0`, `1`, … — the index is the name, and `[1]` is how anyone reads it.
  const raw = String(child.field ?? "");
  const label = piece.position ? `⌥ ${raw}` : /^\d+$/.test(raw) ? `[${raw}]` : raw;

  return h(
    "div",
    {
      class: `rail-row ${selected ? "selected" : ""}`,
      style: railIndent(depth),
      "data-field": fieldId,
      "data-object": objectKey(object),
      "data-expression": child.expression,
      // One line per field, the way the Lauterbach debugger shows a variable — the type, the offset and the
      // size live here rather than on a second line, which doubled every row's height.
      title: `${label} = ${child.value} — ${child.type} · offset +${child.offset}, ${child.size} bytes${
        piece.position ? " · ⌥ shares the bytes above" : ""
      }${canOpen ? " · click to open" : cyclic ? " · ↺ already on this path" : ""}`,
      ...hoverFor(fieldId, objectKey(object)),
      onclick: () => {
        // The rail stays rooted where the user put it: selecting a field inside the tree must not turn the
        // tree into that field's own object. Only a click in the bytes re-roots it.
        state.railRoot = rootAddress;
        // The field is named by its expression, which is the same name the selection, the overlay cells and the byte
        // owners use — no key is computed and thrown away on the way in.
        selectField({
          fieldExpression: child.expression,
          objectExpression: object.expression,
          address: piece.start,
          fromRail: true,
        });
        if (canOpen) toggleExpanded(child.expression);
      },
    },
    h("span", { class: "twisty", text: canOpen ? (open ? "▾" : "▸") : cyclic ? "↺" : "" }),
    h("span", { class: `swatch tone-${piece.tone}` }),
    h("span", { class: "name", text: label }),
    h("span", { class: "value" }, h("span", { class: "eq", text: "= " }), valueNode(child.value, child.type, child.expression, true)),
  );
}

function railRows(object, depth, ancestors, rootKey) {
  const rows = [];
  const here = objectAddress(object);
  // A refused object has no address and no layout: it is a leaf whatever its type says.
  if (here === null || !object.size || !object.children?.length) return rows;
  const inner = new Set([...ancestors, norm(here)]);
  // The rail lists what a frame *holds*. Gap rows are for structures, where the compiler's alignment is
  // part of the layout worth reading; a stack frame's unnamed bytes are not, and a row with no name reads
  // as a missing symbol rather than as ordinary unused stack.
  const isFrame = object.type === "stack frame";
  for (const piece of layoutPieces(object)) {
    if (piece.kind === "hole") {
      if (isFrame) continue;
      rows.push(
        h(
          "div",
          {
            class: "rail-row hole",
            style: railIndent(depth),
            title: `compiler alignment · +${piece.start - piece.objectStart} · ${piece.size} bytes`,
          },
          h("span", { class: "twisty" }),
          h("span", { class: "swatch" }),
          h("span", { class: "name", text: "(padding)" }),
          h("span", { class: "value" }, h("span", { class: "eq", text: "= " }), `${piece.size} B`),
        ),
      );
      continue;
    }
    rows.push(railFieldRow(object, piece, depth, ancestors, rootKey));

    const child = piece.child;
    const nested = typedObjects()[child.expression];
    const target = parseAddr(child.value);
    const cyclic = target !== null && ancestors.has(norm(target));
    if (!openable(nested) || cyclic || !state.expanded.has(child.expression)) continue;

    rows.push(h("div", { class: "brace", style: railIndent(depth) }, h("span", { text: "{" })));
    rows.push(...railRows(nested, depth + 1, inner, rootKey));
    rows.push(h("div", { class: "brace", style: railIndent(depth) }, h("span", { text: "}" })));
  }
  return rows;
}

function toggleExpanded(expression) {
  if (state.expanded.has(expression)) state.expanded.delete(expression);
  else state.expanded.add(expression);
  render();
}

// The rail remembers its root as an *address*, because that is what the rest of the app looks objects up by.
// (Storing the `a5590b66320` id here instead is how a click on a nested field ended up with `parseAddr`
// receiving a key and returning null.)
function railRootAddress(object) {
  const address = objectAddress(object);
  return address === null ? null : norm(address);
}

// The rail half of a jump: make whatever the debug information places at this address the selection, so the struct
// rail marks the row and scrolls to it. `locateInRail` does that work; this only decides *what* to select — the
// narrowest object covering the address, and inside it the field that holds the address when there is one.
//
// Nothing known at that address is a legitimate outcome (code, or bytes no type describes) and it leaves the rail
// alone rather than pretending: an empty rail beside a jump into a function is honest.
//
// The rail's own idea of "show me this field": open the path to it, root the rail at the outermost ancestor, mark the
// field and scroll the rail to its row. `selectAt` does the equivalent for an address by resolving which field the
// address falls in; this is the version used when the caller already knows the field — a click on the rail itself, or
// on one of the overlay's field boxes.
function parentExpression(expression) {
  for (const object of allObjects()) {
    if ((object.children ?? []).some((child) => child.expression === expression)) return object.expression;
  }
  return null;
}

function locateInRail(objectExpression, fieldExpression) {
  const path = [];
  let current = objectExpression;
  while (current) {
    path.push(current);
    current = parentExpression(current);
  }
  for (const ancestor of path.slice(0, -1)) state.expanded.add(ancestor); // all but the outermost, which is always open
  const root = path[path.length - 1];
  const rootObject = allObjects().find((object) => object.expression === root);
  if (rootObject) state.railRoot = railRootAddress(rootObject);

  // The selection is set here too, from the expressions this function was handed. It used to write a key-based copy
  // of the selection and leave the real one stale, so the box that was clicked and the row that was meant to mark it
  // ended up describing different fields.
  state.selection = selectionForField(objectExpression, fieldExpression, state.address ? parseAddr(state.address) : null);
  if (state.selection.start !== null) state.address = norm(state.selection.start);
  // ...and the overlay keeps drawing the object the click was *inside*, so clicking a block of a nested
  // structure's fields does not throw that zoom away while the tree opens the path to it.
  state.zoom = objectExpression;
  state.revealRow = fieldExpression;
  render();
}

// The rail remembers its root as an *address*, because that is what the rest of the app looks objects up
// by. (Storing the `a5590b66320` id here instead is how a click on a nested field turned the whole rail
// into that field's object — and how `parseAddr` got handed a key and returned null.)
function fieldRail(target, region) {
  // The rail's own root, so opening a field does not re-root the tree under the pointer the user just
  // clicked. Clicking bytes in the hex pane clears it, and the rail follows the address again.
  const objects = state.railRoot ? objectsAt(parseAddr(state.railRoot)) : objectsAt(target);
  const object = objects[0];
  if (!object) {
    return h(
      "aside",
      { class: "srail" },
      h("div", { class: "rail-empty dim", text: "no type is known for this address — the bytes are all this dump has to say about it" }),
      // Which is exactly where the plain word-by-word reading earns its place: `requirements.md` C3 asks for
      // the DWARF fields when a type is known there and *this* when it is not.
      rawSection(target),
      ownerSection(region, target),
    );
  }
  if (object.refused) {
    return h(
      "aside",
      { class: "srail" },
      h("div", { class: "rail-head" }, h("span", { class: "expr", text: object.expression })),
      h("div", { class: "code", text: object.refused }),
    );
  }

  // An alias that walks out of this object and lands back on it is a cycle, and saying so is the
  // difference between a viewer that follows a ring forever and one that shows you the ring.
  const loops = objects.slice(1).filter((alias) => alias.expression.startsWith(`${object.expression}->`));

  return h(
    "aside",
    { class: "srail" },
    h(
      "div",
      // The object's own row. It is marked when the selection is *this object* and no field inside it — which is what
      // a jump to a frame's base or a struct's start produces, and what used to leave the struct rail looking
      // untouched: there is no field row for such an address, so nothing else here could carry the highlight.
      { class: `rail-head ${state.selection?.objectKey === objectKey(object) && !state.selection?.fieldExpression ? "selected" : ""}` },
      h("span", { class: "expr", text: object.expression }),
      h("span", { class: "ftype", text: object.type }),
      h("span", { class: "dim", text: `${object.size ?? "?"} B` }),
    ),
    loops.length
      ? h(
          "div",
          { class: "aliases" },
          h("span", { class: "dim", text: "↺ a cycle: " }),
          loops.map((alias) =>
            h("span", {
              class: "chip cycle",
              title: "following the pointer chain from here arrives back at this same struct",
              text: alias.expression,
            }),
          ),
        )
      : null,
    h(
      "div",
      { class: "rail-rows" },
      h("div", { class: "brace", style: railIndent(0) }, h("span", { text: "{" })),
      ...railRows(object, 1, new Set(), railRootAddress(object)),
      h("div", { class: "brace", style: railIndent(0) }, h("span", { text: "}" })),
    ),
    rawSection(target),
    ownerSection(region, target),
    elsewhereSection(object.elsewhere),
  );
}

// The variables of a frame that are *not* in its memory.
//
// An optimised build keeps arguments and locals in registers, and some variables are gone entirely; none of
// them have bytes to draw on, and all of them are still part of the frame. The place comes from gdb's own
// DWARF location — a register name it reported, not a table of ours — because "which register was this
// passed in" is exactly the question a reader has when the value is not in the dump.
function placeOf(slot) {
  if (slot.where === "register") return slot.register ? `in $${slot.register}` : "in a register";
  if (slot.where === "static") return "at a fixed address";
  if (slot.where === "computed") return "a computed value";
  return slot.location_reason || "no location at this pc";
}

function elsewhereSection(away) {
  if (!away?.length) return null;
  return h(
    "div",
    { class: "section" },
    h("h4", { text: "not in this frame's memory" }),
    away.map((slot) =>
      h(
        "div",
        {
          class: "away",
          title: `${slot.name} · ${slot.type} · ${slot.where}${slot.location ? ` · ${slot.location}` : ""}`,
        },
        h("span", { class: "name", text: slot.name }),
        h("span", { class: "value" }, valueNode(slot.value, slot.type, slot.expression, true)),
        h("span", { class: "place", text: placeOf(slot) }),
      ),
    ),
  );
}

// The window's own shape, from the core's ELF header through the API (`/memory` carries it). Absolute rather
// than guessed: a word read in the wrong byte order is a wrong number that looks exactly like a right one, and
// this page has no business knowing what it is running on — the core may be neither little-endian nor 64-bit.
function windowOrder(window) {
  return window?.byte_order ?? state.data.memory_map?.byte_order ?? null;
}

function windowArch(window) {
  return window?.arch ?? state.data.memory_map?.arch ?? null;
}

// `size` bytes at `target`, in `order`, or null when any of them is not in the window at all.
//
// BigInt, not Number: a 64-bit word does not survive a JavaScript number, and an address that comes back
// rounded is worse than one that comes back as `—`. The byte order decides which end the first byte is.
function readWord(bytes, size, order) {
  let value = 0n;
  for (let index = 0; index < size; index += 1) {
    const byte = bytes[index];
    if (byte === undefined) return null;
    const shift = order === "big" ? size - 1 - index : index;
    value |= BigInt(byte) << BigInt(8 * shift);
  }
  return value;
}

// Neither window nor byte order: the reading is not shown rather than shown with a guess in it.
function rawSection(target) {
  const window = windowFor(target);
  const order = windowOrder(window);
  if (!window || !window.chunks || !order) return null;
  const eight = bytesAt(window, target, 8);
  const rows = [
    ["u8", 1, false],
    ["i8", 1, true],
    ["u16", 2, false],
    ["i16", 2, true],
    ["u32", 4, false],
    ["i32", 4, true],
    ["u64", 8, false],
    ["i64", 8, true],
    ["ptr", 8, false],
  ].map(([label, size, signed]) => {
    const value = readWord(eight, size, order);
    let text = "—";
    if (value !== null) {
      if (signed) {
        const bits = BigInt(size * 8);
        const signedValue = value >= 1n << (bits - 1n) ? value - (1n << bits) : value;
        text = signedValue.toString();
      } else if (label === "ptr") {
        text = `0x${pad64(value)}`;
      } else {
        text = `0x${value.toString(16)}`;
      }
    }
    const clickable = label === "ptr" && value !== null && regionOf(value);
    return h(
      "div",
      { class: "readrow" },
      h("span", { class: "rname", text: label }),
      // The `=` every other row in this rail has. Without it `u64` and its value read as one token — `u640x…`
      // — which is exactly how the panel came to look like a list of mangled names rather than a key.
      h("span", { class: "eq", text: "=" }),
      clickable
        ? h("button", { class: "fval jump", text, onclick: () => goTo(text) })
        : h("span", { class: "fval", text }),
    );
  });

  const ascii = eight.map((byte) =>
    byte === undefined ? " " : byte >= 32 && byte < 127 ? String.fromCharCode(byte) : "·",
  );
  rows.push(
    h(
      "div",
      { class: "readrow" },
      h("span", { class: "rname", text: "as chars" }),
      h("span", { class: "eq", text: "=" }),
      h("span", { class: "fval", text: JSON.stringify(ascii.join("")) }),
    ),
  );

  return h(
    "div",
    { class: "section" },
    h(
      "h4",
      {},
      "read as",
      // Both facts come from the core (`/memory` carries its ELF header's answers), so this line is a statement
      // about the dump rather than about the machine the page happens to be open on.
      h("span", { class: "dim", text: ` ${windowArch(window) ?? "unknown arch"}, ${order}-endian` }),
    ),
    rows,
  );
}

// memory → stack (C4): which thread does this address belong to?
function ownerSection(region, target) {
  if (!region || region.kind !== "stack") return null;
  const owners = state.data.threads.filter((thread) => {
    const registers = state.data.detail[String(thread.num)]?.registers;
    const sp = registers?.sp ? parseAddr(registers.sp) : null;
    return sp !== null && BigInt(region.start) <= sp && sp < BigInt(region.end);
  });
  if (!owners.length) return null;
  return h(
    "div",
    { class: "section" },
    h("h4", { text: "belongs to" }),
    owners.map((thread) =>
      h("button", {
        class: "chip",
        text: `thread ${thread.num}${thread.is_crashed ? " (crashed)" : ""} stack`,
        title: "show this thread's stack",
        onclick: () => {
          state.thread = thread.num;
          state.view = "stack";
          render();
        },
      }),
    ),
  );
}

function trailAddresses() {
  const all = state.trail.map((entry) => entry.address);
  if (state.address) all.push(state.address);
  const set = new Set();
  for (const address of all) {
    const value = parseAddr(address);
    if (value !== null) set.add(norm(value));
  }
  return set;
}

// There are three different answers, and collapsing them is how a viewer starts lying:
//   bytes here   — show them;
//   mapped, but its window has not been read — say exactly that, and name the object it belongs to;
//   in no mapping at all — "not in this dump", which is a result, not an error.
function noBytesPane(target, region) {
  const where = region ? leaf(region.path) ?? `[${region.kind}]` : "unmapped";
  return h(
    "div",
    { class: "hexpane" },
    h(
      "div",
      { class: "hexhead" },
      h("span", { text: `${state.address} · ${where}` }),
      h("span", { class: "dim", text: region ? ` · ${region.perms} · ${bytes(region.size)}` : "" }),
    ),
    h(
      "div",
      { class: "hexempty" },
      h("h3", { text: "This address is mapped, but no memory window covers it" }),
      h("p", {
        text:
          `It is inside ${where} (${region.perms}), which is a real part of this core's address space. ` +
          "Windows are read on demand, one at a time, so the bytes are one request away — this view simply " +
          "has not asked for this address yet. Nothing here is missing from the dump.",
      }),
      h("p", {
        class: "dim",
        text:
          "A file-backed page like this one is readable even when the core does not carry its bytes: gdb takes " +
          "them from libplugin.so itself. That is why the value is still a link, and why this screen is not " +
          '"not in this dump".',
      }),
    ),
  );
}
// --------------------------------------------------------------------------- #
// the code rail: the window's source and assembly, on the right
// --------------------------------------------------------------------------- #
const C_WORDS = new Set([
  "if", "else", "while", "for", "return", "struct", "union", "enum", "static", "const", "int", "char", "void",
  "unsigned", "signed", "long", "short", "sizeof", "switch", "case", "default", "break", "continue", "do",
  "goto", "typedef", "extern", "float", "double", "volatile", "constexpr", "NULL", "true", "false",
]);

// A line of C, split into pieces that can be coloured. Deliberately tiny: comments, strings, numbers and
// keywords are what make a listing readable, and a real parser is neither available nor wanted here.
function highlightC(text) {
  const pieces = [];
  const pattern = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b\d+\b|\b[A-Za-z_]\w*\b)/g;
  let last = 0;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) pieces.push({ text: text.slice(last, match.index), cls: "" });
    const token = match[0];
    const cls = token.startsWith("//") || token.startsWith("/*")
      ? "cm"
      : token.startsWith('"') || token.startsWith("'")
        ? "st"
        : /^\d/.test(token)
          ? "nu"
          : C_WORDS.has(token)
            ? "kw"
            : "";
    pieces.push({ text: token, cls });
    last = match.index + token.length;
  }
  if (last < text.length) pieces.push({ text: text.slice(last), cls: "" });
  return pieces;
}

function sourcePieces(group) {
  const recorded = group.fullname || group.file;
  const text = sourceText(recorded, group.line);
  return text === null ? null : highlightC(text);
}

// The functions the window on screen actually contains.
//
// Every page fetched stays cached — going back to a page should not re-ask gdb — but the rail lists only what
// is beside these bytes. Filtering by instruction rather than by function start keeps a function that begins
// below the window and continues into it.
function codeUnitsFor(window) {
  const pages = Object.values(state.codePages).filter(Boolean);
  const all = [...(state.data.code?.window?.units ?? []), ...pages.flatMap((page) => page.units ?? [])];
  if (!window) return all;
  const low = BigInt(window.address);
  const high = low + BigInt(window.length);
  return all.filter((unit) =>
    (unit.instructions ?? []).some((instruction) => {
      const at = BigInt(instruction.address);
      return low <= at && at < high;
    }),
  );
}

function codeRail(window) {
  const units = codeUnitsFor(window);
  if (!units.length) {
    // Three states, three sentences: an answer that has not arrived, an answer that was refused, and an answer
    // that arrived and names nothing here. Saying "reading…" for the third promises something never coming.
    const page = window ? state.codePages[`0x${(BigInt(window.address) & ~0xfffn).toString(16)}`] : null;
    const said = state.live
      ? page && page.reason
        ? `this page could not be read: ${page.reason}`
        : page
          ? page.stripped
            ? "no function symbol starts in this page, and this module is stripped — only its exported symbols are known"
            : "no function symbol starts in this page"
          : "reading this page's code…"
      : "no disassembly is carried for this window";
    return h(
      "aside",
      { class: "srail coderail" },
      h("div", { class: "rail-empty dim", text: said }),
    );
  }
  return h(
    "aside",
    { class: "srail coderail" },
    h(
      "div",
      { class: "rail-head" },
      h("span", { class: "expr", text: `code · ${units.length} function(s)` }),
      h("span", { class: "dim", text: " · from the symbol table, one request each" }),
    ),
    ...units.map(codeUnit),
  );
}

function codeUnit(unit) {
  const rows = [
    h(
      "div",
      { class: "cunit-head" },
      h("span", { class: "cfun", text: unit.symbol ?? "?" }),
      h("span", {
        class: "dim",
        text: ` · ${norm(unit.address)} · ${(unit.instructions ?? []).length} instructions`,
      }),
    ),
  ];
  const groups = unit.lines ?? [];
  if (groups.length) {
    for (const group of groups) {
      rows.push(
        h(
          "div",
          { class: "csrc" },
          h("span", { class: "cln", text: group.line ?? "—" }),
          h(
            "span",
            { class: "ct" },
            ...(sourcePieces(group) ?? [h("span", { class: "nosource", text: "the source for this line is not in this checkout" })]).map(
              (piece) => h("span", { class: piece.cls, text: piece.text }),
            ),
          ),
        ),
      );
      for (const instruction of group.instructions ?? []) rows.push(codeRailRow(instruction));
    }
  } else {
    // A flat reply has no line numbers (the page spans several functions), so the instructions stand alone.
    for (const instruction of unit.instructions ?? []) rows.push(codeRailRow(instruction));
  }
  return h("div", { class: "cunit" }, ...rows);
}

// Where the instructions in the listing point, as pieces that can be drawn and clicked.
//
// Deliberately literal: only an address written in the text is a target. `adrp` + `add` compute one over two
// instructions and `[x0, #4056]` needs a register, so they stay text — a viewer that guessed at those would be
// inventing an address, which is the one thing this file is not allowed to do.
function instructionPieces(text) {
  const pieces = [];
  let last = 0;
  for (const match of text.matchAll(/0x[0-9a-fA-F]+/g)) {
    let address = null;
    try {
      const candidate = BigInt(match[0]);
      if (regionOf(candidate)) address = candidate;
    } catch (error) {
      address = null; // not a number this can act on; leave it as text
    }
    if (address === null) continue;
    if (match.index > last) pieces.push({ text: text.slice(last, match.index), address: null });
    let end = match.index + match[0].length;
    const symbol = /^ <[^>]*>/.exec(text.slice(end));
    if (symbol) end += symbol[0].length; // the name belongs to the address, not to the sentence after it
    pieces.push({ text: text.slice(match.index, end), address });
    last = end;
  }
  if (last < text.length) pieces.push({ text: text.slice(last), address: null });
  return pieces;
}

// A target in the listing, drawn as the text it is and behaving as the place it names.
function instructionTarget(piece) {
  return h("button", {
    class: "ctarget",
    title: `jump to ${norm(piece.address)} and interpret it`,
    // The arrow is the rail's own affordance for "this value goes somewhere" — the same promise, so it is
    // written the same way.
    text: `${piece.text} →`,
    onclick: (event) => {
      event.stopPropagation();
      // An address is the *address* logic, not the line logic: clicking it goes where it points — the bytes at that
      // address, the instruction that lives at it, and the pane scrolled to show it. That is goTo, the one callback
      // every address link calls. Clicking the rest of the line stays the line logic: select this instruction, do not
      // move (conflating the two highlighted the .eq instead of what it branches to).
      goTo(piece.address);
    },
  });
}

function codeRailRow(instruction) {
  const crash = conditionCrash(instruction);
  const chosen = state.instruction === norm(instruction.address);
  return h(
    "div",
    {
      class: `cinsn ${crash ? "crashsite" : ""} ${chosen ? "selected" : ""}`,
      "data-address": norm(instruction.address),
      title: `${instruction.address}${crash ? " — the instruction the program died on" : ""} · click to link the bytes to it`,
      onclick: () => selectInstruction(instruction.address),
    },
    h("span", { class: "cln", text: "" }),
    h(
      "span",
      { class: "cop" },
      ...instructionPieces(instruction.text.replace(/\t/g, "  ")).map((piece) =>
        piece.address === null ? h("span", { text: piece.text }) : instructionTarget(piece),
      ),
    ),
  );
}

// Clicking an instruction in the bytes locates it here, the way clicking a field block locates its row in the
// typed rail. It does not move the hex pane: the bytes under the pointer are already the ones being asked
// about, and a listing that scrolled its own subject away would be the wrong answer to the wrong question.
function locateInCode(address) {
  state.revealCode = norm(address);
  render();
}

// Which instruction a byte belongs to, and — the other direction — which bytes an instruction covers.
//
// The length comes from the opcodes gdb printed, never from an architecture assumption: this file has been
// wrong before by assuming four bytes, and on x86 an instruction is anything from one to fifteen.
function instructionBytes(instruction) {
  const hex = (instruction?.bytes ?? "").replace(/\s+/g, "");
  return hex.length ? BigInt(hex.length / 2) : null;
}

function instructionAt(address) {
  if (address === null) return null;
  for (const reply of [...(codeData().window?.units ?? []), ...Object.values(codeData().frames ?? {})]) {
    for (const instruction of reply.instructions ?? []) {
      const start = BigInt(instruction.address);
      const length = instructionBytes(instruction);
      if (length !== null && start <= address && address < start + length) return instruction;
    }
  }
  return null;
}

// Selecting an instruction is one act with three visible effects, so it lives in one place — and it *fetches what it
// needs first*. `instructionAt` only knows about pages that have arrived, so consulting it before the page is here
// always found nothing and the selection fell back to a bare address that nothing could highlight: clicking a `bl`
// target in the listing jumped nowhere and lit nothing, because its page was still on the wire. Waiting is the fix,
// not a marker applied later — "remember what was wanted and apply it when the data arrives" was the same idea with
// two places to keep in step, and only one of the two callers remembered to set it.
async function selectInstruction(address) {
  const target = parseAddr(address) ?? (typeof address === "bigint" ? address : null);
  if (target !== null) await ensureCodePage(target);
  const instruction = instructionAt(address) ?? instructionAt(BigInt(address));
  const start = instruction ? BigInt(instruction.address) : BigInt(address);
  state.instruction = norm(start);
  state.address = norm(start);
  const length = instruction ? instructionBytes(instruction) : null;
  state.insnRange = length === null ? null : [start, start + length];
  state.revealCode = norm(start);
  // Show it in the bytes as well: the instruction may be far outside the rendered rows, and a selection the
  // reader cannot see is not a link. These are the steps a jump takes, minus its side effects — no trail entry
  // (this is a selection, not somewhere to walk back from) and no view switch (the panes are already here).
  state.reveal = true;
  const window = windowFor(start);
  if (window) state.window = state.data.memory.windows.indexOf(window);
  const region = regionOf(start);
  state.region = region ? state.data.memory_map.regions.indexOf(region) : null;
  render();
}

// On-demand disassembly: one request per page, the first time that page is on screen.
//
// The reply is cached — including a refusal, so a data page does not re-ask on every render — and it carries
// the source lines of the functions in it, because the rail draws them and the browser is never handed a path
// to open for itself.
async function ensureCodePage(address) {
  if (!state.live) return; // the fixture already carries its code
  const page = `0x${(BigInt(address) & ~0xfffn).toString(16)}`;
  if (state.codePages[page] !== undefined) return; // the reply, or a refusal, is already here
  // In flight: hand back the *same* promise, so an `await ensureCodePage(x)` actually waits for the data instead
  // of returning while the request is still on the wire. It used to return immediately, which is why a selection
  // made against an unfetched page could never be applied: the caller had already moved on.
  if (state.codePromise[page]) return state.codePromise[page];
  state.codePages[page] = null;
  state.codePromise[page] = (async () => {
    try {
      const response = await fetch(`/api/sessions/${state.live.id}/disassemble?address=${page}`);
      const reply = await response.json();
      if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
      state.codePages[page] = reply;
      for (const [recorded, file] of Object.entries(reply.files ?? {})) state.codeFiles[recorded] = file;
    } catch (error) {
      state.codePages[page] = { page, units: [], reason: String(error.message ?? error) };
    }
    delete state.codePromise[page];
    render();
  })();
  return state.codePromise[page];
}

// One request per window, the first time it is on screen — "one window per scroll", the cost row in §5.
//
// The reply is the same shape the fixture carries, so it is attached to the window object the pane is already
// reading: `chunks` for the bytes, `unread` for gdb's own account of what it could not read.
// The bytes for the part of the window that is on screen.
//
// A window is a whole region — 132 KB here, and a region is routinely megabytes or gigabytes in a real
// application. Fetching the entire window to draw forty visible rows meant one request per 4 KB page for the
// whole thing (thirty-three here, two thousand for a default 8 MB stack, a quarter of a million for a large
// `.text`), all of it retained in `window.chunks` and never released. The pane is virtualised, so it already
// knows which rows are on screen; this asks for those pages and a margin, keeps them, and drops what is far
// from the viewport.
const HEX_PAGE = 4096; // one read per page; `max_limit` is 4096, so this is also the transport's ceiling
// Four pages per ask: about a thousand rows, several screens of hex, so ordinary scrolling does not outrun the
// fetch — and a fixed number of *pages*, not a fraction of the window. A budget measured as a fraction of the
// window is how a 132 KB stack turned into thirty-two reads: the budget was 128 KB, which for a small window is
// the whole thing. On a 1 GB region this is still four requests.
const PAGE_BUDGET = 4 * HEX_PAGE;
const PAGE_KEEP = 256 * 1024; // what stays cached around the viewport, so scrolling back does not re-fetch

function pageOf(address) {
  const value = BigInt(address);
  return value - (value % BigInt(HEX_PAGE));
}

function evictFarPages(window, around) {
  const centre = BigInt(around);
  const low = centre - BigInt(PAGE_KEEP);
  const high = centre + BigInt(PAGE_KEEP);
  const kept = (window.chunks ?? []).filter((chunk) => {
    const at = BigInt(chunk.address);
    return at + BigInt(chunk.length) >= low && at <= high;
  });
  if (kept.length !== (window.chunks ?? []).length) {
    window.chunks = kept; // still in address order: the filter keeps the order of the list it walked
  }
}

async function ensurePages(window, from, budget = PAGE_BUDGET) {
  if (!state.live || !window || window.refused) return;
  const start = pageOf(from);
  // Never ask past the region: a budget that runs off the end produces a refusal for a page that was never
  // part of this window, and those refusals belong to a different question ("is this address in the dump").
  const windowEnd = BigInt(window.address) + BigInt(window.length);
  const pages = [];
  for (let offset = 0n; offset < BigInt(budget); offset += BigInt(HEX_PAGE)) {
    const page = start + offset;
    if (page >= windowEnd) break;
    pages.push(page);
  }
  const asked = (state.pageAsked[window.address] ??= new Set());
  const missing = pages.filter((page) => !asked.has(page.toString(16)));
  if (!missing.length) {
    evictFarPages(window, from);
    return;
  }
  missing.forEach((page) => asked.add(page.toString(16)));
  window.pending = (window.pending ?? 0) + missing.length;
  state.windowPending[window.address] = true;
  try {
    let done = pages.length - missing.length;
    for (const page of missing) {
      const address = `0x${page.toString(16)}`;
      const response = await fetch(`/api/sessions/${state.live.id}/memory?address=${address}&length=${HEX_PAGE}`);
      const reply = await response.json();
      if (response.status === 422) {
        // One page with no bytes in the core is a result, not a failure of the window: record the hole and keep
        // the rest of the range. Treating it as a window-level refusal stopped every later page from loading,
        // which is how a scroll would have shown nothing new forever.
        window.unread = [...(window.unread ?? []), { address, length: HEX_PAGE, reason: reply.detail ?? "not in this dump" }];
      } else {
        if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
        window.chunks = [...(window.chunks ?? []), ...(reply.chunks ?? [])];
        // Sorted, because `byteAt`/`bytesAt` binary-search this list: pages arrive in the order the reader
        // scrolled, and appending them unsorted would make a lookup missing for reasons that have nothing to do
        // with the dump. (It used to be a per-byte Map instead, which is why the order never mattered before.)
        window.chunks.sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));
        window.unread = [...(window.unread ?? []), ...(reply.unread ?? [])];
      }
      done += 1;
      state.windowProgress = Math.round((done / pages.length) * 100);
    }
    evictFarPages(window, from);
  } catch (error) {
    window.refused = String(error.message ?? error);
  }
  window.pending = Math.max(0, (window.pending ?? missing.length) - missing.length);
  if (!window.pending) delete state.windowPending[window.address];
  state.windowProgress = 0;
  render();
}

// A window with no bytes yet is not an empty window. Both states below are ordinary and neither is an error:
// one is a request in flight, the other is a request that came back refused — and a refusal in this project
// always carries the reason, so it is printed rather than replaced with a shrug.
function waitingPane(window, message) {
  return h(
    "div",
    { class: "hexpane" },
    h(
      "div",
      { class: "hexhead" },
      h("span", { text: `${window.address} · ${window.name}` }),
      h("span", { class: "dim", text: ` · ${bytes(window.length)}` }),
    ),
    h(
      "div",
      { class: "hexempty" },
      h("h3", { text: message }),
      h("p", { class: "dim", text: `${window.address} · ${bytes(window.length)} · read on demand, one window at a time` }),
    ),
  );
}

// Load the next page when the reader gets near the end of what is on screen.
//
// An IntersectionObserver rather than a scroll listener: it fires when the sentinel is *near* the viewport
// (one screenful early, so the wait happens while the reader is still scrolling), it needs no arithmetic about
// scroll positions, and it stops firing once the element is gone from the tree. The element is recreated by
// every render, so the observer is not kept — it disconnects as soon as it has fired.
function watchNear(element) {
  if (typeof IntersectionObserver !== "function") return;
  // **Only when there is something to scroll.** A deep stack whose frames are folded (`descend ×30000`) is two
  // flow steps tall — shorter than the screen — so a sentinel watched by the viewport alone sits "near the
  // end" for ever and pages the whole stack in the background: measured, it read 8 000 frames unprompted in
  // the first seconds, which is the run-away this paging exists to prevent (the unpaged request cost 420 146
  // commands). The reader's click is always there; this is the same action, and it is offered only when
  // scrolling is what would otherwise reach it.
  if (document.documentElement.scrollHeight <= window.innerHeight + 600) return;
  const observer = new IntersectionObserver((entries) => {
    if (!entries.some((entry) => entry.isIntersecting)) return;
    observer.disconnect();
    loadMoreStack();
  }, { rootMargin: "600px" });
  observer.observe(element);
  state.observers = state.observers ?? [];
  state.observers.push(observer);
}

// A short name for an address, for log lines: the window's own name when it has one (`heap`, `stack`), else
// the region it belongs to, else the address. `[anon]` is true and useless; `heap` is what the reader sees.
function window_label(address) {
  const target = parseAddr(String(address));
  const name = windowFor(target)?.name;
  if (name) return name;
  const region = regionOf(target);
  return region ? leaf(region.path) ?? `[${region.kind}]` : String(address);
}

// The objects overlapping the window on screen — the overlay is drawn from them, so they are read with it.
async function ensureObjects(address, length) {
  if (!state.live || state.objectPending) return;
  const key = `${address}:${length}`;
  if (state.objectPages[key]) return;
  state.objectPending = true;
  try {
    const response = await fetch(`/api/sessions/${state.live.id}/objects?address=${address}&length=${length}`);
    const reply = await response.json();
    if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
    const known = Object.keys(state.typedData).length;
    for (const object of reply) state.typedData[object.expression] = object;
    state.objectPages[key] = true;
    state.typed = null;
    // Logged as an event rather than left to the count above, which was taken at load: "the session walked
    // these" is a fact about the core that arrives *now*, and the log is where facts with a time on them go.
    if (reply.length && Object.keys(state.typedData).length !== known) {
      logEvent(`${window_label(address)}: ${reply.length} typed object${reply.length === 1 ? "" : "s"} on these bytes`);
    }
    render();
  } catch (error) {
    state.objectPages[key] = true; // a refusal is an answer: do not ask again on every render
  }
  state.objectPending = false;
}

// Which file an anonymous mapping's bytes came from — the last resort, and the only *inferred* answer on this
// screen. Asked for, never guessed at in the background: it reads files other than the core, and the reply is
// evidence rather than a name, so it belongs behind a click that says so.
async function identifyRegion(start) {
  if (!state.live || state.identifyPending) return;
  state.identifyPending = start;
  render();
  try {
    const response = await fetch(`/api/sessions/${state.live.id}/identify?address=${start}`);
    const reply = await response.json();
    if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
    state.identified[start] = reply;
    const inference = reply.inference;
    logEvent(
      inference
        ? `${window_label(start)}: ${inference.basis === "build-id" ? "same build-id as" : "same bytes as"} ` +
          `${leaf(inference.file)}` +
          (inference.basis === "build-id"
            ? ` (${shortId(inference.build_id)})`
            : ` at file offset ${inference.offset}${inference.verified ? "" : " (one window only)"}`)
        : `${window_label(start)}: nothing to identify — ${reply.reason}`,
    );
  } catch (error) {
    state.identified[start] = { error: String(error.message ?? error) };
  }
  state.identifyPending = null;
  render();
}

// Is this anonymous writable mapping a heap, and what is in it? Asked for, like everything else that reads
// something other than the summary: the walk itself is arithmetic over the dump, but it is still a question the
// reader asks about the mapping they are looking at rather than one the page answers in the background.
async function heapRegion(start) {
  if (!state.live || state.heapPending) return;
  state.heapPending = start;
  render();
  try {
    const response = await fetch(`/api/sessions/${state.live.id}/heap?address=${start}`);
    const reply = await response.json();
    if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
    state.heaps[start] = reply;
    const summary = reply.summary;
    logEvent(
      summary
        ? `${window_label(start)}: heap — ${summary.chunks} chunks, ${bytes(summary.covered)} of chunks, ` +
          `top ${bytes(summary.top)}` +
          (reply.arena?.symbol ? `, and gdb confirms main_arena` : "")
        : `${window_label(start)}: not a heap — ${reply.reason}`,
    );
    if (reply.arena && !reply.arena.symbol) logEvent(`arena not available: ${reply.arena.why}`);
  } catch (error) {
    state.heaps[start] = { error: String(error.message ?? error) };
  }
  state.heapPending = null;
  render();
}

// One object, for the rail: the typed tree is a lookup by address, so that is the question to ask.
async function ensureObject(address) {
  if (!state.live) return;
  const key = norm(address);
  if (state.objectAsked[key]) return;
  state.objectAsked[key] = true;
  try {
    const response = await fetch(`/api/sessions/${state.live.id}/object?address=${key}`);
    if (!response.ok) return; // "no type is known" is a real answer, and the rail already says it
    const object = await response.json();
    state.typedData[object.expression] = object;
    state.typed = null;
    render();
  } catch (error) {
    // A lookup that failed leaves the rail saying what it said before, which is still true.
  }
}

// A window for an address the report did not name: read on demand, like everything else on this screen.
//
// 256 bytes is sixteen rows — enough to see what a pointer points at, in the context it sits in. The reply is
// shaped like the other windows so nothing downstream has to know where it came from.
const ADHOC_BYTES = 256; // a pointer jump: enough to see what the pointer points at
const REGION_BYTES = 64 * 1024; // a mapping click: the mapping, bounded — libc's text is megabytes

function adhocWindow(address) {
  const key = norm(address);
  return state.adhoc[key] ?? null;
}

// The window read for an address no report window covers. `length` is the caller's question: a pointer jump
// wants a peephole, a mapping click wants the mapping. Reads are paged at the transport's ceiling.
async function ensureAdhoc(address, length = ADHOC_BYTES) {
  if (!state.live || address === null) return;
  const start = address - (address % 16n); // a hex view starts on a row, not mid-row
  const key = norm(start);
  const asked = state.adhocAsked[key];
  if (asked && asked >= length) return; // already read this much or more
  state.adhocAsked[key] = Math.max(asked ?? 0, length);
  try {
    const CHUNK = 4096;
    const chunks = [];
    for (let offset = 0; offset < length; offset += CHUNK) {
      const size = Math.min(CHUNK, length - offset);
      const at = `0x${(start + BigInt(offset)).toString(16)}`;
      const response = await fetch(`/api/sessions/${state.live.id}/memory?address=${at}&length=${size}`);
      const reply = await response.json();
      if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
      chunks.push(...(reply.chunks ?? []));
    }
    const region = regionOf(start);
    state.adhoc[key] = {
      address: norm(start),
      length: chunks.reduce((total, chunk) => total + chunk.length, 0),
      name: region ? `${leaf(region.path) ?? `[${region.kind}]`} · ${region.perms}` : "read on demand",
      chunks,
      unread: [],
      adhoc: true,
    };
    state.windows = null; // the lookup caches a list; a new window is a new list
    render();
  } catch (error) {
    state.adhocRefused[key] = String(error.message ?? error);
    render();
  }
}

function memoryView() {
  const { regions } = state.data.memory_map;
  const windows = state.data.memory.windows;
  const target = state.address ? parseAddr(state.address) : null;
  const covering = target !== null ? windowFor(target) : null;
  // `covering` is a window from the report; an address outside all of them gets a window read for it, so the
  // pane never has to fall back to "no bytes" while the bytes are in fact one request away.
  const adhoc = target !== null ? adhocWindow(target) : null;
  const shown = covering ?? adhoc ?? windows[state.window] ?? windows[0];
  const region = target !== null ? regionOf(target) : null;
  const missing = state.data.memory.missing;

  const low = BigInt(regions[0].start);
  const high = regions.reduce((max, item) => (BigInt(item.end) > max ? BigInt(item.end) : max), BigInt(regions[0].end));
  const span = Number(high - low) || 1;
  const strip = h(
    "div",
    { class: "strip" },
    regions.map((item, index) => {
      const left = (Number(BigInt(item.start) - low) / span) * 100;
      const width = Math.max(0.35, (Number(BigInt(item.end) - BigInt(item.start)) / span) * 100);
      return h("div", {
        class: `bar ${state.region === index ? "selected" : ""}`,
        style: `left:${left}%;width:${width}%;background:${colorOf(item)}`,
        title: `${regionKind(item)} · ${item.start}–${item.end} · ${item.perms} · ${leaf(item.path) ?? item.kind}`,
        onclick: () => {
          state.region = index;
          goTo(item.start);
        },
      });
    }),
    // Where the user is, in the whole address space. Without it the strip is a picture; with it, it is a
    // map you can find yourself on.
    target !== null
      ? h("div", {
          class: "here",
          style: `left:${(Number(target - low) / span) * 100}%`,
          title: `the address on screen: ${norm(target)}`,
        })
      : null,
  );

  // What the colours mean, with the bytes behind each kind — the distribution, not just a picture of it.
  const kindTotals = new Map();
  for (const item of regions) {
    const kind = regionKind(item);
    kindTotals.set(kind, (kindTotals.get(kind) ?? 0n) + BigInt(item.size));
  }
  const legend = h(
    "div",
    { class: "strip-legend" },
    [...kindTotals.entries()].map(([kind, size]) =>
      h(
        "button",
        {
          class: "legend-chip",
          title: `jump to the first ${REGION_KINDS[kind].label} mapping`,
          onclick: () => {
            const index = regions.findIndex((item) => regionKind(item) === kind);
            if (index >= 0) {
              state.region = index;
              goTo(regions[index].start);
            }
          },
        },
        h("span", { class: "swatch", style: `background:${REGION_KINDS[kind].color}` }),
        `${REGION_KINDS[kind].label} · ${bytes(Number(size))}`,
      ),
    ),
  );

  const header = h(
    "div",
    { class: "viewhead" },
    h("span", { class: "addr", text: state.address ?? "no address selected" }),
    h("span", {
      class: "dim",
      text: region
        ? `· ${leaf(region.path) ?? `[${region.kind}]`} · ${region.perms} · ${bytes(region.size)}` +
          (region.image?.build_id ? ` · build ${shortId(region.image.build_id)}` : "")
        : "· no mapping covers this address",
    }),
    h("span", { class: "spacer" }),
    // Skipping the uninteresting rows. A stack window is 132 KB of which the frames are 5 KB, so "next
    // name" is the difference between reading a stack and scrolling through zeros.
    h("button", {
      class: `twisty ${state.foldZeros ? "active" : ""}`,
      text: state.foldZeros ? "zeros: folded" : "zeros: shown",
      title: "fold runs of zero pages that have nothing named in them",
      onclick: () => {
        state.foldZeros = !state.foldZeros;
        state.unfolded.clear();
        render();
      },
    }),
    h("button", {
      class: "twisty",
      text: "sp",
      title: "back to the crashed thread's stack pointer",
      onclick: () => {
        const sp = state.data.detail[String(state.thread)]?.registers?.sp;
        if (sp) goTo(sp);
      },
    }),
    h("button", {
      class: "twisty",
      text: "crash",
      title: "jump to the instruction the program died at",
      onclick: () => {
        const pc = state.data.detail[String(state.thread)]?.frames?.[0]?.pc;
        if (pc) goTo(pc);
      },
    }),
    // Only where the dump leaves a question open: a mapping nothing named. Nothing is asked for in the
    // background — the answer compares this dump's bytes against files on this machine, and the button is how
    // the reader asks for that rather than having it done silently.
    state.live && region && !region.path
      ? h("button", {
          class: `twisty ${state.identified[region.start] ? "active" : ""}`,
          text: state.identifyPending === region.start ? "identifying…" : "identify",
          title: "compare this mapping's bytes with the files this session was given, and say which file they come from",
          onclick: () => identifyRegion(region.start),
        })
      : null,
    // A heap is the one anonymous mapping that explains itself, and only a writable one can be a heap: the
    // allocator writes into the memory it hands out.
    state.live && region && !region.path && region.perms.includes("w")
      ? h("button", {
          class: `twisty ${state.heaps[region.start]?.heap ? "active" : ""}`,
          // Not `heap`: the window switcher is already called that, and two buttons with one name is a
          // question the reader has to answer by clicking. This is the action — walk the mapping as chunks.
          text: state.heapPending === region.start ? "reading…" : "chunks",
          title: "walk this mapping as glibc chunk headers: what the allocator wrote into it",
          onclick: () => heapRegion(region.start),
        })
      : null,
    windows.map((window, index) =>
      h("button", {
        class: `twisty ${shown === window ? "active" : ""}`,
        text: `${window.name}`,
        onclick: () => {
          state.window = index;
          goTo(window.address);
        },
      }),
    ),
    h("button", { class: "twisty", text: `back${state.trail.length ? ` (${state.trail.length})` : ""}`, title: "walk the jumps back", onclick: goBack }),
    h("button", {
      class: `twisty ${state.asciiAligned ? "active" : ""}`,
      text: state.asciiAligned ? "ascii: byte-aligned" : "ascii: compact",
      title: "one character per byte cell (lines up with the bytes) or compact text (easier to read)",
      onclick: () => {
        state.asciiAligned = !state.asciiAligned;
        render();
      },
    }),
    // One toggle, not a pair of mode buttons: the map replaces the bytes while it is open, and clicking it
    // again puts the bytes back — which is the whole interaction. Choosing a mapping closes it for the same
    // reason (a list that stays open takes the height the bytes need), and `back` restores it.
    h("button", {
      class: `twisty ${state.mappings ? "active" : ""}`,
      text: `mappings · ${regions.length}`,
      title: "where everything in the core is mapped — click a row to look at it, click again to close",
      onclick: () => {
        state.mappings = !state.mappings;
        render();
      },
    }),
  );

  // A code window has no types to show, so the rail shows the code: the same slot, the other question.
  //
  // The first pages have to be asked for *here*, not inside `hexPane`: with no bytes the pane renders the
  // "reading…" card instead of rows, so a fetch that lived in the row builder could never start — no bytes, no
  // rows, no request, no bytes. This is the anchor the view will open on (the selected address), and once
  // anything has landed `hexPane` keeps the visible range fed as the reader scrolls.
  if (shown) ensurePages(shown, target ?? shown.address);
  // A stack is a stack from either view: the stack view shows frames, and the memory view shows a frame's
  // fields drawn on its bytes. Both need the parsed stack, and neither should show "no type is known for this
  // address" because one of them happened to be the only place that asked for it.
  const onStack = [region, target !== null ? regionOf(target) : null].some((item) => item?.kind === "stack");
  if (onStack && !state.stackData) ensureStack(state.thread);
  // Nothing covers this address, but the core does: read it rather than explaining why it was not read. This is
  // the step the old screen claimed had happened and had not.
  if (!covering && target !== null && regionOf(target) && !adhocWindow(target)) {
    // An address inside a mapping the report did not name: read the mapping (bounded and paged), because that
    // is what "show me this address" means when the address came from the mappings table.
    const here = regionOf(target);
    const size = Math.min(Number(here.size) || ADHOC_BYTES, REGION_BYTES);
    ensureAdhoc(target, Math.max(ADHOC_BYTES, size));
  }
  // The overlay is drawn from the objects on these bytes. Two small ranges rather than the whole window: the
  // window's start (what a fresh view shows) and the address in view (where a jump landed), because the page
  // ceiling is 4096 and a 132 KB stack window would be refused outright.
  const OBJECT_BYTES = 4096;
  if (shown) ensureObjects(shown.address, Math.min(shown.length, OBJECT_BYTES));
  if (target !== null) ensureObjects(target - (target % 16n), OBJECT_BYTES);
  if (isCode(region) && shown) ensureCodePage(shown.address);
  // And the page the address in view lives in, which is not always the window's first one: `crash_target`'s text
  // is two pages wide, so a jump to a function in the second page asked for the first page's code and then
  // could not find the instruction it had just jumped to. The listing needs the page the target is *in*.
  if (target !== null) {
    const at = regionOf(target);
    if (isCode(at)) ensureCodePage(target);
  }
  // A code region gets the code rail even before its page has arrived: "reading this page's code" is true,
  // and the typed rail's "no type is known for this address" is not. A fixture that carries no code for this
  // window still falls through to the typed rail, because then there is nothing to say.
  const rail =
    isCode(region) && ((codeData().window?.units ?? []).length || state.live)
      ? codeRail(shown)
      : fieldRail(target, region);
  // The window the pane is looking at: one the report named, or one read for this address.
  const paneWindow = covering ?? adhoc;
  // A window without bytes is either pending or refused; both get an honest pane instead of a page of holes.
  const bytesMissing = Boolean(paneWindow) && !paneWindow.chunks;
  const adhocPending = !paneWindow && target !== null && Boolean(regionOf(target));
  const body = paneWindow
    ? bytesMissing
      ? h(
          "div",
          { class: "hexsplit" },
          waitingPane(
            paneWindow,
            paneWindow.refused
              ? `These bytes could not be read: ${paneWindow.refused}`
              : adhocPending
                ? "Reading this address…"
                : `Reading this window's bytes… ${state.windowProgress}%`,
          ),
          rail,
        )
      : h("div", { class: "hexsplit" }, hexPane(paneWindow, target), rail)
    : region
      ? h("div", { class: "hexsplit" }, noBytesPane(target, region), rail)
      : h(
          "div",
          { class: "notindump" },
          h("h3", { text: `${state.address ?? "that address"} is not in this dump` }),
          h("p", {
            text:
              missing && missing.address === state.address
                ? `gdb says: ${missing.reason.replace(/^.*refused the command: /, "")}`
                : "No mapping in this core covers it, so there are no bytes to show — this is a result, not an error.",
          }),
          h("p", { class: "dim", text: "Every value that points outside the dump is marked the same way, wherever it appears." }),
        );

  return h(
    "div",
    { class: "view memview" },
    header,
    identifyNote(region),
    heapNote(region),
    strip,
    legend,
    state.mappings
      ? h(
          "table",
          { class: "regions" },
          libraryNote(regions),
          h("thead", {}, h("tr", {}, ["start", "end", "perm", "size", "object"].map((title) => h("th", { text: title })))),
          h(
            "tbody",
            {},
            regions.map((item, index) =>
              h(
                "tr",
                {
                  class: state.region === index ? "selected" : "",
                  onclick: () => {
                    // Asking to look at a mapping means looking at it. `goTo` runs first and pushes the trail entry
                    // (recording the map the reader is leaving, so `back` reopens it) and then closes the list
                    // itself — one place owns that, so this handler does not repeat it.
                    state.region = index;
                    goTo(item.start);
                  },
                },
                h("td", { text: item.start }),
                h("td", { text: item.end }),
                h("td", { class: "perm", text: item.perms }),
                h("td", { class: "size", text: bytes(item.size) }),
                h(
                  "td",
                  {
                    class: item.path ? "" : "anon",
                    // No file *and* no access are two different facts, and the reserved ranges are 64 MB of this
                    // core: printing `[anon]` for them said "anonymous memory" about pages with no contents.
                    text: leaf(item.path) ?? (regionKind(item) === "reserved" ? "[reserved]" : `[${item.kind}]`),
                  },
                  // Which source named this region, in the same cell as the name. The core's own NT_FILE note is
                  // the kernel's record; a name gdb reconstructed from the link map is a weaker claim and says so.
                  item.source === "gdb"
                    ? h(
                        "span",
                        {
                          class: "src",
                          title:
                            "named by gdb, from the dump's link map — the core's own NT_FILE note named nothing here",
                        },
                        "gdb",
                      )
                    : null,
                  // And the one that was identified by its content: a weaker claim than either source above, so it
                  // is marked as an inference and the mapping keeps saying `[anon]` beside it.
                  state.identified[item.start]?.inference
                    ? h(
                        "span",
                        {
                          class: "src",
                          title: "identified by comparing these bytes with the files this session was given",
                        },
                        "inferred",
                      )
                    : null,
                  // The mapping whose bytes are a chunk chain: an answer about the mapping's *structure*, read
                  // out of it, and the only one available for a heap at all.
                  state.heaps[item.start]?.heap
                    ? h(
                        "span",
                        {
                          class: "src",
                          title: `${state.heaps[item.start].summary.chunks} chunks, read from the mapping's own headers`,
                        },
                        `heap ${state.heaps[item.start].summary.chunks}`,
                      )
                    : null,
                  // And the mapping's own reading, when its bytes are an ELF image: not a name for the mapping,
                  // but the fact that names the *build* — which is exact, and which no amount of byte comparison
                  // can be.
                  item.image?.build_id
                    ? h(
                        "span",
                        {
                          class: "src",
                          title: `${item.image.class} ${item.image.type} ${item.image.machine}, build-id ${item.image.build_id}`,
                        },
                        `elf ${shortId(item.image.build_id)}`,
                      )
                    : null,
                ),
              ),
            ),
          ),
        )
      : body,
  );
}

// What content matching made of the mapping in view, once it has been asked for. It is the one line on this
// screen that is an *inference*, so it says so in the first word and carries its own evidence: which file, at
// which file offset of the region's first byte, how many bytes agree, and whether a second window in the same
// mapping agreed too. It never renames the region — the map keeps saying `[anon]`, because the dump does.
function identifyNote(region) {
  if (!region || !state.live) return null;
  const answer = state.identified[region.start];
  if (!answer) return null;
  if (answer.error) {
    return h("div", { class: "identify-note" }, h("span", { class: "dim", text: `could not identify: ${answer.error}` }));
  }
  const inference = answer.inference;
  if (!inference) {
    return h(
      "div",
      { class: "identify-note" },
      h("span", { class: "tag", text: "not identified" }),
      h("span", { class: "dim", text: ` ${answer.reason}` }),
    );
  }
  // Two kinds of answer, and the difference is the whole point: a build-id match is a record the mapping
  // carries, a content match is a resemblance counted byte by byte.
  const recorded = inference.basis === "build-id";
  const evidence = recorded
    ? `the same build-id ${shortId(inference.build_id)}` +
      (inference.matched ? `, and ${inference.matched} of ${inference.compared} bytes agree as well` : "")
    : `${inference.matched} of ${inference.compared} bytes agree` +
      (inference.verified
        ? `, and again ${inference.verified_matched} of ${inference.verified_compared} at +${inference.verified_offset}`
        : ", one window only — this mapping is too small for a second one");
  const where = answer.symbols?.found
    ? { text: ` · its symbols: ${answer.symbols.found.path}`, cls: "" }
    : answer.symbols?.searched?.length
      // The whole id, not the short form: this text is a command someone will paste, and half a build-id
      // fetches nothing.
      ? { text: ` · no debug file for this build here (debuginfod-find debuginfo ${inference.build_id})`, cls: "dim" }
      : null;
  return h(
    "div",
    { class: "identify-note" },
    h("span", { class: "tag on", text: recorded ? "same build-id" : "inferred" }),
    h("span", { text: ` ${leaf(inference.file)}${inference.offset !== null ? ` at file offset ${inference.offset}` : ""}` }),
    h("span", { class: "dim", text: ` · ${evidence}` }),
    where ? h("span", { class: where.cls || "dim", text: where.text }) : null,
    h("span", { class: "dim", text: " · not written into the dump's map: the mapping keeps its name" }),
  );
}

// A build-id is 40 hex characters and means nothing to read: the first eight identify it, and the whole thing
// travels in the element's title so it can be copied.
function shortId(id, length = 8) {
  if (!id) return "—";
  return id.slice(0, length);
}

// What the allocator wrote into the mapping: chunk headers, the wilderness, and the totals. A heap is the one
// anonymous mapping a dump can explain without a note, a symbol or a file — and the line says which of those
// three it did *not* need, because that is the point.
function heapNote(region) {
  if (!region || !state.live) return null;
  const answer = state.heaps[region.start];
  if (!answer) return null;
  if (answer.error) {
    return h("div", { class: "identify-note" }, h("span", { class: "dim", text: `could not read the heap: ${answer.error}` }));
  }
  const summary = answer.summary;
  if (!summary) {
    return h(
      "div",
      { class: "identify-note" },
      h("span", { class: "tag", text: "not a heap" }),
      h("span", { class: "dim", text: ` ${answer.reason}` }),
    );
  }
  const chunk = answer.heap?.address_chunk;
  const here = chunk
    ? ` · at this address: chunk ${chunk.address} (${bytes(chunk.size)}, ${chunk.in_use ? "in use" : "free"})`
    : "";
  const arena = answer.arena?.symbol
    ? " · gdb's own main_arena agrees"
    : " · no arena symbol in this libc, so this is the chunk headers alone";
  return h(
    "div",
    { class: "identify-note" },
    h("span", { class: "tag on", text: "heap" }),
    h("span", { text: ` ${answer.heap.kind} · ${summary.chunks} chunks` }),
    h("span", {
      class: "dim",
      text:
        ` · in use ${bytes(summary.in_use)}, free ${bytes(summary.free)}, top ${bytes(summary.top)}` +
        ` · ${Math.round(summary.coverage * 100)}% of the mapping is that chain` +
        (summary.scan_truncated ? " (scan stopped; more follow)" : "") +
        here +
        arena,
    }),
  );
}

// What gdb knows about this dump's objects and could not place. It is the answer to "why is this region still
// `[anon]` when the object clearly has a name?", and on a core whose NT_FILE note named nothing — the QNX shape
// — it is where the names appear at all. Nothing here is a region name: a library with `regions: 0` named no
// mapping, and one whose file gdb called the wrong version names none by design.
function libraryNote(regions) {
  const libraries = state.data?.memory_map?.libraries ?? [];
  // Shown only where the dump's own note named nothing: a core that names its files itself does not need a list
  // of what gdb could not place, and the same name in that list and in the table would read as a contradiction.
  if (!libraries.length || regions.some((region) => region.source === "nt_file")) return null;
  const unplaced = libraries.filter((library) => !library.regions);
  if (!unplaced.length) return null;
  const placed = libraries.length - unplaced.length;
  const parts = unplaced.map((library) => {
    const name = leaf(library.name) ?? library.name;
    if (library.mismatch) return `${name} (gdb found a file it calls the wrong version)`;
    if (!library.ranges?.length) return `${name} (no file for it was reachable, so gdb cannot place it)`;
    return `${name} (its range lands outside this dump's mappings)`;
  });
  return h("caption", {
    text:
      `no mapping in this dump names a file; gdb knows ${libraries.length} object${libraries.length === 1 ? "" : "s"}` +
      (placed ? ` and placed ${placed}` : "") +
      ` — it cannot place ${parts.join(", ")}`,
  });
}

// --------------------------------------------------------------------------- //
// state screens
// --------------------------------------------------------------------------- //
function card(...kids) {
  return h("div", { class: "screen" }, h("div", { class: "card" }, kids));
}

// The five fields the backend's `POST /api/sessions` takes for a core nobody ships. Their values come from the
// server (`GET /api/defaults`), because the only machine whose paths can be right is the one running the backend —
// they used to be the board's `/home/lyy/…`, which was true only while that was the case.
const FORM_FIELDS = [
  ["core", "core path"],
  ["exe", "executable (with symbols)"],
  ["gdb", "gdb (a path; a remote target later)"],
  ["sysroot", "sysroot"],
  ["solib_search_path", "solib search path"],
];

// The cores opened before, from the backend's state file. Fetched when the empty screen is shown rather than at
// boot, because the list is only ever read there — and a fetch that runs on every page load for a screen nobody
// opened is work with no reader.
// The empty screen's two fetches: what this server suggests (its own paths) and what was opened before. Both are
// only ever read on this screen, so neither runs on a page load that goes straight to a core.
async function ensureEmptyScreenData() {
  const jobs = [];
  if (!state.recent) {
    jobs.push(fetch("/api/recent")
      .then((reply) => (reply.ok ? reply.json() : []))
      .then((value) => { state.recent = value; })
      .catch(() => { state.recent = []; }));
  }
  if (!state.defaults) {
    jobs.push(fetch("/api/defaults")
      .then((reply) => (reply.ok ? reply.json() : null))
      .then((value) => { state.defaults = value; })
      .catch(() => { state.defaults = null; }));
  }
  if (!jobs.length) return;
  await Promise.all(jobs);
  render();
}

// The rail: one list of cores to open, the practice ones first and everything opened before after them.
//
// A click *fills the form* rather than opening the core. Opening is a heavier act than browsing — the core is read,
// the session replaced, the screen changes — and the form is right there showing exactly what would be opened, so
// the reader gets to look at the five paths and press Load. It also makes the two kinds of row behave the same way,
// which is the reason they are one list: what differs is only where the paths come from.
function coreRow({ title, subtitle, why, fields, gone, onForget }) {
  return h(
    "div",
    {
      class: `recent-row ${gone ? "gone" : ""}`,
      onclick: () => {
        if (gone) {
          toast(`${fields.core} is not there any more`, "error");
          return;
        }
        state.form = { ...state.form, ...fields };
        state.formError = null;
        // Filled, not loaded: say so, because the visible effect is five inputs changing under a card that does
        // not otherwise react.
        logEvent(`filled the form from ${leaf(fields.core) || fields.core}`);
        toast("paths filled in — press Load to open it");
        render();
      },
    },
    h("span", { class: "recent-open", text: title, title: fields.core ?? "" }),
    h("span", { class: "recent-dir dim", text: subtitle ?? "", title: fields.core ?? "" }),
    ...(why ? [h("span", { class: "recent-why dim", text: why })] : []),
    ...(onForget
      ? [
          h("button", {
            class: "recent-forget dim",
            text: "forget",
            title: "remove this entry from the list",
            // Its own click, and it must not also fill the form: the row listens for a click.
            onclick: async (event) => {
              event.stopPropagation();
              await onForget();
            },
          }),
        ]
      : []),
  );
}

function coreList() {
  const samples = state.samples ?? [];
  const entries = state.recent ?? [];
  const global = state.defaults ?? {};
  // One row per core. A practice core that has been opened is *already* in the history, so it is not listed again —
  // the two sources describe the same file, and showing it twice (once as `crash_target`, once as
  // `crash_target.<timestamp>.core`) was the list talking to itself. Keyed on the file name, because that is what a
  // core's identity is here and it survives a path spelled two ways.
  const opened = new Set(entries.map((entry) => leaf(entry.core)));
  const practice = samples
    .filter((sample) => !sample.core || !opened.has(leaf(sample.core)))
    .map((sample) =>
      coreRow({
        title: sample.label ?? sample.sample,
        subtitle: sample.core ? dirOf(sample.core) : "bundled fixture",
        why: sample.core ? "not opened yet" : "bundled fixture",
        fields: {
          core: sample.core ?? "",
          exe: sample.exe ?? "",
          gdb: global.gdb,
          sysroot: global.sysroot,
          solib_search_path: global.solib_search_path,
        },
      }),
    );
  const history = entries.map((entry) =>
    coreRow({
      title: leaf(entry.core),
      subtitle: dirOf(entry.core),
      gone: !entry.valid?.core,
      why: entry.valid?.core
        ? (entry.exe ? `symbols: ${leaf(entry.exe)}` : "no executable recorded")
        : `missing: ${Object.entries(entry.valid ?? {}).filter(([, ok]) => ok === false).map(([field]) => field).join(", ") || "core"}`,
      fields: {
        core: entry.core,
        exe: entry.exe,
        gdb: entry.gdb?.kind === "local" ? entry.gdb.path : undefined,
        sysroot: entry.sysroot,
        solib_search_path: entry.solib_search_path,
      },
      onForget: () => fetch(`/api/recent/${entries.indexOf(entry)}`, { method: "DELETE" })
        .catch(() => {})
        .finally(() => {
          state.recent = null;
          ensureEmptyScreenData();
        }),
    }),
  );
  if (!practice.length && !history.length) return [];
  return [
    h("div", { class: "section-title", text: `cores · ${practice.length + history.length}` }),
    // Opened ones first — that is what "recent" means — then anything on disk not opened yet, which is the only way
    // to reach a practice core on a fresh checkout.
    h("div", { class: "recent" }, ...history, ...practice),
  ];
}

// The directory part of a path, shown dimmed beside the file name. Both separators, because a core may have been
// opened on either platform and the path is displayed as it was given.
function dirOf(path) {
  const text = String(path ?? "");
  const at = Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\"));
  return at > 0 ? text.slice(0, at + 1) : "";
}

function emptyScreen() {
  // The cores opened before are the page's left column, the same `.aside` the threads pane uses on the ready
  // screen — a rail at the very left of the page, not a box inside the form's card. Keeping it the same width and
  // header as `threads` means the two screens read as one application.
  return h(
    "div",
    { class: "layout" },
    h("aside", { class: "aside" }, ...coreList()),
    h(
      "div",
      { class: "main" },
      card(
        h("h2", { text: "Load a coredump" }),
        h("p", { text: "The core is referenced by path only — never copied, never uploaded." }),
        // What went wrong last time, kept on the form rather than in a toast that disappears: the reader is here
        // to correct a path, and the reason it failed is what they need while correcting it.
        ...(state.formError ? [h("p", { class: "formerror", text: state.formError })] : []),
        h(
          "div",
          { class: "formcol" },
        ...FORM_FIELDS.flatMap(([key, label]) => {
          // Prefilled with what *this server* suggests — the only machine whose paths can be right. A suggestion
          // that is not on that filesystem is marked, not typed in as if it were real.
          const suggested = state.defaults?.[key] ?? "";
          const missing = state.form[key] === undefined && state.defaults?.valid?.[key] === false;
          return [
            h("label", { text: label }),
            h("input", {
              value: state.form[key] ?? suggested,
              title: suggested ? `this server suggests ${suggested}` : undefined,
              oninput: (event) => {
                state.form[key] = event.target.value;
              },
            }),
            ...(missing ? [h("p", { class: "formnote dim", text: `not on this server: ${suggested}` })] : []),
          ];
        }),
        h(
          "div",
          { class: "actions" },
          h("button", {
            class: "primary",
            text: "Load",
            // This button used to switch the screen to "loading" without reading a single input, so the form was a
            // picture of a feature. It now sends exactly what the fields hold — the five names the backend has
            // accepted all along.
            // Reads the inputs, not just `state.form`: a field prefilled from the server's suggestion never passed
            // through `oninput`, so the form object was empty while the boxes were full — and Load answered
            // "a core path is needed" with a core path on screen. `state.form` still wins for a field the reader
            // typed into, because that is what survives a re-render.
            onclick: () => {
              const boxes = [...document.querySelectorAll("#app .formcol input")];
              const fields = {};
              FORM_FIELDS.forEach(([key], index) => {
                fields[key] = state.form[key] ?? boxes[index]?.value ?? "";
              });
              bootFromPaths(fields);
            },
          }),
        ),
        ),
      ),
    ),
  );
}

function loadingScreen() {
  const seconds = Math.max(0, Math.round(state.loading.seconds ?? 0));
  return card(
    h("h2", { text: "Loading the core…" }),
    // gdb's own line, or an honest stand-in until it says something: an empty pane above a moving bar reads as
    // a stall, and the line is the only real progress signal there is (gdb reports phases, not a percentage —
    // which is why the bar shows motion instead of a number).
    h("p", { class: "code", text: state.loading.progress || `starting gdb — ${seconds}s` }),
    h("p", { text: `${seconds}s elapsed — a large core can take a minute or more.` }),
    h("div", { class: "bar-outer" }, h("div", { class: "bar-inner" })),
    h(
      "div",
      { class: "actions" },
      h("button", {
        text: "Cancel",
        onclick: () => {
          // Cancel has to mean it: invalidate the load that is waiting (or it would finish and paint anyway),
          // and close the session it opened — a resident gdb still reading a 25 MB core behind an empty screen
          // is exactly what §6's capacity-one rule is about.
          state.loadToken = (state.loadToken ?? 0) + 1;
          if (state.live?.id) fetch(`/api/sessions/${state.live.id}`, { method: "DELETE" }).catch(() => {});
          state.live = null;
          state.ui = "empty";
          state.loading = { progress: "", seconds: 0 };
          state.status = null;
          logEvent("load cancelled");
          paintState();
          paintLog();
          render();
        },
      }),
    ),
  );
}

function failedScreen() {
  return card(
    h("h2", { text: "The core could not be loaded" }),
    h("p", { text: "gdb started, but it has no core — so there is nothing to show. This is a failure, not an empty dump." }),
    h("p", { class: "code", text: `${state.failure.code}: ${state.failure.message}` }),
    h("p", { text: "Next: check that the core path is visible to the backend, and that the gdb matches the core's architecture." }),
    h(
      "div",
      { class: "actions" },
      h("button", {
        class: "primary",
        text: "Back to the form",
        onclick: () => {
          state.ui = "empty";
          render();
        },
      }),
      h("button", {
        text: "Retry",
        onclick: () => {
          state.ui = "loading";
          render();
        },
      }),
    ),
  );
}

function expiredScreen() {
  return card(
    h("h2", { text: "This session has expired" }),
    h("p", { text: "It was reclaimed after being idle, or the backend restarted. The paths below are kept." }),
    h("input", { value: "/home/lyy/cdwv-practice/out/crash_target.1789740493.2804926.11.core" }),
    h(
      "div",
      { class: "actions" },
      h("button", {
        class: "primary",
        text: "Load it again",
        onclick: () => {
          state.ui = "loading";
          render();
        },
      }),
    ),
  );
}

// --------------------------------------------------------------------------- //
// render
// --------------------------------------------------------------------------- //
function render() {
  const app = document.querySelector("#app");
  // Rows are built for the *scroll position*, and `app.textContent = ""` throws the pane away — so the
  // position is captured into `state` first, where `hexRows` can see it while it builds the new pane.
  const previous = document.querySelector(".hexscroll");
  if (previous) {
    state.scrollTop = previous.scrollTop;
    if (previous.clientHeight) state.viewportRows = Math.ceil(previous.clientHeight / ROW_HEIGHT);
  }
  // The right-hand rail is rebuilt too, and it is a scroller: without this, clicking an instruction anywhere
  // below the first screen snapped the listing back to the top.
  const previousRail = document.querySelector(".srail");
  if (previousRail) state.railScroll = previousRail.scrollTop;
  app.textContent = "";

  if (state.ui !== "ready") {
    app.appendChild(emptyScreenWhenNeeded());
    // The list of cores opened before is only read here, so it is fetched here — once per session, and again
    // after a "forget". `ensureEmptyScreenData` re-renders when it lands, so the form does not wait for it.
    if (state.ui === "empty") ensureEmptyScreenData();
    paintState();
    paintChooser();
    return;
  }

  app.appendChild(topbar());
  const detail = state.data.detail[String(state.thread)] ?? {};
  app.appendChild(
    h(
      "div",
      { class: `layout ${state.railCollapsed ? "rail-collapsed" : ""}` },
      threadsPane(),
      h(
        "div",
        { class: "main" },
        tabs(),
        state.view === "memory" ? memoryView() : state.view === "registers" ? registersView(detail) : stackView(detail),
      ),
    ),
  );
  paintState();
  paintChooser();

  const pane = document.querySelector(".hexscroll");
  if (pane) {
    // A jump lands on an address, so that address has to be *visible*: the crash instruction is 0xe8 bytes
    // past the function it is in, and a window that opens on the region's first byte would be showing the
    // thread's free stack instead of its frames.
    //
    // This is the **only** place that moves the pane, and it moves it only when something asked to be shown
    // (`state.reveal`) and the row for that address is known (`state.paneTop`, computed in `hexPane` from the
    // The single place the pane is moved to a selection, for every address link there is: the callbacks that mean
    // "show me this address" (`goTo`, the byte and field clicks, the code rail) set `state.reveal`; `hexPane` works out
    // where that address's row is in the layout it just built (`state.paneTop`, null when the row is not known yet,
    // in which case the request stands for a later render); and this applies it. Scrolling anywhere else — in a
    // callback, or in `hexPane` — is what produced the last-writer-wins bug this replaces.
    if (state.reveal && state.paneTop !== null) {
      state.scrollTop = state.paneTop;
      // A short move from where the pane was, so a jump *inside* one window — same rows, same listing, same thread —
      // is visible at all. Skipped when the jump changed window: those contents are different, and a slide between two
      // unrelated pictures is noise.
      if (state.animateFrom && state.animateFrom.window === state.window) {
        animateScrollTo(state.animateFrom.top, state.scrollTop);
      }
      state.animateFrom = null;
      state.reveal = false;
      // The position is remembered as the address now at the top, not as this number. Everything below is free to
      // change height — folding a zero run, unfolding one, bytes arriving — and the next render puts the reader back
      // on the same address.
      state.topAddress = topAddressAt(state.rowsSpec, state.scrollTop);
    } else if (state.topAddress !== null) {
      // No jump this time: re-derive the offset from the address that was at the top, now that the rows have been laid
      // out again. This is the line that keeps the visible range from moving when the folding changes.
      const offset = offsetOfTopAddress(state.rowsSpec, state.topAddress);
      if (offset !== null) state.scrollTop = offset;
    }
    pane.scrollTop = state.scrollTop;
    // The rows were built for wherever the pane *was*; if that is no longer where it is, rebuild them.
    paintRows(pane);
    // The minimap's backing store has to be the pane's real height, and this is the first moment that height
    // exists: `hexPane` builds the canvas before the pane is in the document, so anything it measures there
    // is the *previous* pane — or nothing at all, which is how a 600-line canvas ended up stretched to fit.
    const map = document.querySelector(".minimap");
    if (map && map.height !== pane.clientHeight) map.height = pane.clientHeight;
    paintMinimap(map);
    bindMinimap(map);
    bindScrolling(pane);
    // The code panel is built with the pane, but *where* it is scrolled to depends on the height the pane
    // has once it is in the document — the same trap the minimap fell into.
  }

  // Put the rail back where it was, before any reveal below asks it to move somewhere specific.
  const rail = document.querySelector(".srail");
  if (rail && state.railScroll) rail.scrollTop = state.railScroll;

  // Locating a row scrolls its rail to it — `revealRow` for the struct rail, `revealCode` for the listing.
  //
  // Done by arithmetic on the row's own offset *after the browser has laid the rows out*, not with
  // `scrollIntoView` in the same tick as the build. A code row's height is set by the listing printed beside it, so
  // at build time the rows below the fold have no height yet and a scroll computed then lands wherever the geometry
  // happened to be — sometimes on the row, sometimes short of it, which is a reader having to scroll the rest of the
  // way by hand. Measured: the same click landed in view once and out of view the next.
  // The reveal is applied on **every** render until it sticks, and only then cleared.
  //
  // One jump ends up rendering several times now: the selection renders, the window's bytes arrive and render, the
  // code page arrives and renders. Each of those rebuilds the tree, and a rebuilt scroller starts at `scrollTop` 0 —
  // so a scroll set once by the first render was undone by the last one, which is why the highlight could be on
  // screen and off it in the same click. Applying it repeatedly is idempotent and immune to which render lands last.
  const revealIn = (railSelector, rowSelector, clear) => {
    const row = document.querySelector(rowSelector);
    const rail = document.querySelector(railSelector);
    if (!row || !rail) return; // not laid out yet: keep the request for the next render
    const wanted = Math.max(0, Math.round(row.offsetTop - rail.clientHeight / 2 + row.offsetHeight / 2));
    window.requestAnimationFrame(() => {
      const stillRow = document.querySelector(rowSelector);
      const stillRail = document.querySelector(railSelector);
      if (!stillRow || !stillRail) return;
      if (Math.abs(stillRail.scrollTop - wanted) > 2) stillRail.scrollTop = wanted;
      clear();
    });
  };

  if (state.revealRow) {
    const expression = state.revealRow;
    revealIn(".srail", `.srail [data-expression="${expression}"]`, () => {
      state.revealRow = null;
    });
  }

  if (state.revealCode) {
    const address = state.revealCode;
    revealIn(".coderail", `.coderail [data-address="${address}"]`, () => {
      state.revealCode = null;
    });
  }
}

// Scrolling rebuilds the *rows*, never the pane.
//
// Rebuilding the pane is what "I can't scroll" was: the wheel and the momentum animation belong to the
// scrolling element, and `render()` empties the app — deleting that element mid-gesture cancels the scroll
// before it moves. Setting `scrollTop` from code does not show the bug, which is why it survived a check.
//
// So the pane stays where it is, its rows live in a container of their own, and a scroll replaces that
// container's children. The ruler is outside it and sticky, so the column numbers survive.
function bindScrolling(pane) {
  if (pane.dataset.bound === "1") return;
  pane.dataset.bound = "1";
  let queued = false;
  pane.addEventListener("scroll", () => {
    state.scrollTop = pane.scrollTop;
    // What the reader's scroll *means* is the address now at the top. Keeping only the pixel offset meant a later
    // render — after folding changed the heights, or after bytes arrived — applied that number to a different layout
    // and the reader was somewhere else (often clamped to the end). The address survives all of that.
    state.topAddress = topAddressAt(state.rowsSpec, pane.scrollTop);
    // This is where new pages are needed, and this handler is the only thing that runs on a scroll: the pane
    // repaints its rows without a full render ("a scroll must cost a scrollTop, not a rebuild"), so a fetch
    // living in the row builder would serve the first screenful and then never run again.
    if (state.rowsSpec) {
      const anchor = viewportAddress(state.rowsSpec);
      if (anchor !== null) ensurePages(state.rowsSpec.window, anchor);
    }
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      paintRows(pane);
      paintMinimap();
      });
  });
}

function paintRows(pane = document.querySelector(".hexscroll")) {
  const holder = pane?.querySelector(".rows");
  const spec = state.rowsSpec;
  if (!holder || !spec) return;
  holder.textContent = "";
  holder.append(...hexRows(spec));
}

function emptyScreenWhenNeeded() {
  if (state.ui === "loading") return loadingScreen();
  if (state.ui === "failed") return failedScreen();
  if (state.ui === "expired") return expiredScreen();
  return emptyScreen();
}

// --------------------------------------------------------------------------- //
// boot
// --------------------------------------------------------------------------- //
// The fixture carries two datasets, because one core cannot show both halves of a stack: `data/data.json` is
// `-O0` target (everything spilled, the whole awkward structure) and `data.opt.json` is the `-O2` one
// (variables in registers). Switching reloads the data and starts over — nothing is merged, because merging
// two dumps into one screen would be a lie about which dump an address came from.
// The practice cores are discovered, not declared: the backend can see `tmp/practice` and this page cannot, and a
// hard-coded pair meant editing the frontend whenever the practice suite gained a target. `samples.json` is written
// by `scripts/dump-fixture.py` and is only the offline fallback — it names the static fixtures, so opening `ui/`
// with no backend still works.
async function ensureSamples() {
  if (state.samples) return state.samples;
  try {
    const reply = await fetch("/api/samples");
    if (reply.ok) {
      state.samples = await reply.json();
      return state.samples;
    }
  } catch {
    /* no backend: fall through to the dumped list */
  }
  try {
    const reply = await fetch("data/samples.json");
    state.samples = reply.ok ? await reply.json() : [];
  } catch {
    state.samples = [];
  }
  return state.samples;
}

// One chip per core opened in this session, oldest first, no duplicates: opening something already in the bar just
// makes it current. The key is what identifies the core — its file, so the same core reached by name and by path is
// one tab; a sample with no core of its own (the offline fixture) falls back to its name.
function rememberLoaded(entry) {
  const existing = (state.loaded ?? []).find((item) => item.key === entry.key);
  if (existing) {
    Object.assign(existing, entry);
  } else {
    state.loaded = [...(state.loaded ?? []), entry];
  }
  state.loadedKey = entry.key;
}

// The tab strip: the cores loaded *in this session*, one tab each, the current one lit, each with an × to close it.
// The bar is a record of what has been opened, not a menu of what could be — everything still openable lives in the
// left rail of the empty screen.
//
// Rebuilt by `render()`, not only when a report is installed: closing a tab changes this list and nothing else, and
// when the strip was built inside `installReport` a closed tab stayed on the bar until the next load. The bar is
// part of the shell, so what it shows has to be repainted by whoever changes the state it reads.
function paintChooser() {
  const chooser = document.querySelector("#samples");
  if (!chooser) return;
  chooser.textContent = "";
  chooser.append(
    ...(state.loaded ?? []).map((entry) =>
      // A span, not a button, because it holds one: the name opens the core, the × closes its session. Two controls
      // in one tab is the whole shape of a tab strip, and a button inside a button is not a thing.
      h(
        "span",
        {
          class: `chip loaded ${entry.sample && !entry.core ? "" : "custom"} ${entry.key === state.loadedKey ? "active" : ""}`,
          title: entry.core ? `${entry.core}\nsymbols from ${entry.exe ?? "(the core itself)"}` : entry.sample,
        },
        h("button", {
          class: "name",
          text: entry.label,
          onclick: () => (entry.core ? bootFromPaths({ ...entry.fields }) : boot(entry.sample)),
        }),
        h("button", {
          class: "x",
          text: "×",
          title: "close this session",
          onclick: (event) => {
            event.stopPropagation();
            closeLoaded(entry);
          },
        }),
      ),
    ),
    // And the way to open one more: without it the rail is unreachable as soon as anything is loaded, because the
    // rail lives on the empty screen and the app leaves it at the first load. This is the "+" of a tab strip.
    h("button", {
      class: "chip open",
      text: "+",
      title: "open another core — the practice cores and everything opened before are listed there",
      onclick: () => {
        state.ui = "empty";
        state.recent = null; // the history has almost certainly gained the core just shown
        paintState();
        render();
      },
    }),
  );
}

// Closing a tab. Only one session is ever resident (§6), so the tab that is on screen is the only one with a
// session to delete; closing any other is forgetting a tab. Closing the current one leaves the empty screen rather
// than jumping to another core — the reader asked for it gone, not for something else to load.
async function closeLoaded(entry) {
  const current = entry.key === state.loadedKey;
  state.loaded = (state.loaded ?? []).filter((item) => item.key !== entry.key);
  if (!current) {
    paintChooser();
    render();
    return;
  }
  if (state.live?.id) {
    await fetch(`/api/sessions/${state.live.id}`, { method: "DELETE" }).catch(() => {});
  }
  state.live = null;
  state.loadedKey = null;
  state.sample = null;
  state.ui = "empty";
  state.status = null;
  logEvent(`closed ${entry.label}`);
  paintState();
  paintLog();
  paintChooser();
  render();
}

// The backend loads the core once and hands back *this* report, so the two sources are interchangeable and
// every line below is unchanged either way. Live first; the static files stay as the fallback for opening
// `ui/` with no backend running, which is how this has been developed all along.
//
// Opening a session there is asynchronous — a core takes seconds to minutes — so the poll *is* the progress
// display: `elapsed` moves, and a progress line that never changes is indistinguishable from a hang.
// Wait for a session that already exists. Split out of `loadFromBackend` because there is a second caller now:
// `reloadSession` gets its session id from the reload endpoint, and posting to `/api/sessions` again would open
// *another* core instead of waiting for that one.
async function awaitSession(id, token) {
  // Recorded now, not when the load finishes: this is the session `Cancel` has to close, and while a 25 MB core
  // is being read is precisely when cancelling matters (§6 — capacity one, so an abandoned load would hold the
  // resident gdb).
  state.live = { id };
  for (let attempt = 0; attempt < 2400; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    if (token !== state.loadToken) throw new Error("cancelled"); // a newer load, or the reader cancelled
    const response = await fetch(`/api/sessions/${id}`);
    if (!response.ok) throw new Error(`session ${id}: ${response.status}`);
    const session = await response.json();
    if (session.state === "ready") return { summary: session.summary, id };
    if (session.state === "failed" || session.state === "closed") throw new Error(session.error ?? session.state);
    // gdb's own line when there is one: `Reading symbols from …` says what is happening, the clock only says
    // that something is.
    const what = session.progress ? ` · ${session.progress}` : "";
    state.status = `loading ${session.core} · ${session.elapsed}s${what}`;
    // The loading screen reads these two, and until now nothing ever assigned them: the card showed a
    // hard-coded "Reading symbols from …" and a frozen 12s. Re-rendering here is cheap — while loading, this
    // branch builds one card and nothing else — and it is what makes the clock and the line move.
    state.loading = { progress: session.progress ?? "", seconds: session.elapsed };
    paintLog();
    render();
  }
  throw new Error("the session never became ready");
}

async function loadFromBackend(body, token) {
  const created = await fetch("/api/sessions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    // A sample name *or* a set of paths — the endpoint takes both, and the form on the empty screen sends the
    // paths the reader typed. Sending `{sample}` for a core nobody ships was the gap: the fields existed and
    // the backend accepted them, but nothing ever read the inputs.
    body: JSON.stringify(body),
  });
  if (!created.ok) throw new Error(`backend refused: ${created.status}`);
  const { id } = await created.json();
  return awaitSession(id, token);
}

// Everything downstream of "the report is here". Both entry points end here — a core this checkout ships,
// and a core the reader names by path — because from this line on the question is what the data *is*, not
// where it came from. `sample` is what the bar highlights as the current coredump; it may be a path.
function installReport(data, { origin, sample = null }) {
  state.data = data;

  // Every cache is derived from the data that was just replaced.
  state.typed = null;
  state.stack = null;
  state.expanded = new Set();
  state.railRoot = null;
  state.zoom = null;
  state.revealRow = null;
  state.selection = null;
  state.trail = [];
  state.codePages = {}; // code belongs to the session it was fetched from
  state.codeFiles = {};
  state.windowPending = {};
  // Page and window state belongs to *these* windows. A new session has new objects with the same addresses
  // in the same places, so carrying the old `pageAsked` over would make the pane believe pages it never
  // fetched for this core were already here — and draw nothing where bytes exist.
  state.pageAsked = {};
  state.adhoc = {};
  state.adhocAsked = {};
  state.adhocRefused = {};
  state.stackData = null;
  state.typedData = {};
  state.objectPages = {};
  state.objectAsked = {};
  state.identified = {};
  state.identifyPending = null;
  state.heaps = {};
  state.heapPending = null;
  state.stackPending = false;
  state.stackRefused = null;
  state.ui = "ready";

  const crashed = state.data.threads.find((thread) => thread.is_crashed) ?? state.data.threads[0];
  state.thread = crashed.num;

  // Open on the crashed thread's stack: for a crash, that is the only sensible first address.
  const sp = state.data.detail[String(crashed.num)]?.registers?.sp ?? null;
  if (sp) {
    state.address = norm(sp);
    state.reveal = true; // a region-sized window opens on the frames, not on the free stack below them
    const window = windowFor(BigInt(sp));
    if (window) state.window = state.data.memory.windows.indexOf(window);
    const region = regionOf(BigInt(sp));
    if (region) state.region = state.data.memory_map.regions.indexOf(region);
  }

  // "0 typed objects" was a number about nothing: the summary carries none because they are read on demand,
  // and a count of what is *not* in the payload is not a fact about the core. Worse, it stayed on screen: the
  // count was taken at load, so a live session that had since walked `head` and every node it reaches still
  // read "0 typed objects" beside the structure it was drawing.
  const typed = Object.keys(state.data.typed?.objects ?? {}).length
    ? `${Object.keys(typedObjects()).length} typed objects`
    : "typed objects: walked on demand";
  // Where the data came from, and what it holds, become one *event*: the sentence is the `ready` line of the
  // log rather than a label that the next event would overwrite without trace.
  state.sample = sample;
  state.status = null;
  logEvent(
    `${origin} — ${state.data.threads.length} threads, ${state.data.memory_map.regions.length} regions, ` +
      `${state.data.memory.windows.length} memory windows, ${typed}`,
  );

  paintChooser();
  render();

  // The crash frame's locals are on screen from the start: for a crash, that is the answer.
  loadFrameLocals(crashed.num, 0);
}

async function boot(which = null) {
  // The list comes from the backend; without one it comes from the dumped fixtures. Nothing is hard-coded, so a
  // sample the backend has never heard of simply is not in the bar.
  const samples = await ensureSamples();
  const chosen = samples.find((entry) => entry.sample === which) ?? samples[0] ?? null;
  if (!chosen) {
    // Nothing to demo and nothing to load: say so on the empty screen instead of pretending the page is loading.
    state.ui = "empty";
    state.formError = "this backend has no practice cores and no fixture was dumped — load a core by path";
    render();
    return;
  }
  // Every boot invalidates the one before it: switching sample mid-load, or cancelling, must leave the old load
  // unable to write its result onto the screen. A cancelled load that quietly finishes anyway is the same bug
  // as a Cancel button that does not cancel.
  const token = (state.loadToken = (state.loadToken ?? 0) + 1);
  let data = null;
  let origin = "";
  logEvent(`load ${chosen.sample}`);
  state.ui = "loading";
  state.loading = { progress: "", seconds: 0 };
  state.status = `loading ${chosen.sample}…`;
  paintState();
  paintLog();
  // Render, or the shell's own "app.js did not execute" placeholder stays on screen for the whole load — which
  // is exactly what it looked like: a page that had failed, next to a log line saying it was working.
  render();
  try {
    // `loadFromBackend` takes a request body, not a sample name: it serves both entry points, and passing the bare
    // name here sent a JSON string where the endpoint expects an object — a 422 that the catch below then read as
    // "no backend", quietly showing the fixture. The two are easy to confuse because both are "the thing to load".
    const live = await loadFromBackend({ sample: chosen.sample }, token);
    if (token !== state.loadToken) return; // superseded while it was loading
    state.live = { id: live.id };
    data = live.summary;
    origin = `live core · ${chosen.sample}`;
  } catch (error) {
    if (token !== state.loadToken) return; // cancelled: the reader asked for the empty screen, not the fixture
    // Not a failure: without a backend the fixture is the whole dataset. Which one is on screen is part of
    // the picture — a fixture and a live core look identical, and "am I looking at the dump or at a file"
    // is not a question the reader should have to guess at.
    //
    // `chosen.file` comes from the dumped `samples.json`; a sample the backend discovered has no fixture, and then
    // the bundled one is used. Either way the sample that ends up highlighted is the one the fixture *is*, looked
    // up by file — lighting the chip that was asked for, while a different core's bytes are on screen, is the
    // silent substitution this project keeps refusing.
    const fixture = chosen.file ?? "data/data.json";
    const shown = (state.samples ?? []).find((entry) => (entry.file ?? "data/data.json") === fixture) ?? null;
    origin = `static fixture · ${fixture} (no backend: ${error.message})`;
    logEvent(`no backend (${error.message}) — using ${fixture}`);
    state.live = null; // nothing live is behind the fixture, whatever was attempted
    data = await (await fetch(fixture)).json();
    if (token !== state.loadToken) return;
    installReport(data, { origin, sample: shown?.sample ?? null });
    return;
  }
  // Keyed by the core file, not by how it was opened: the same core reached by name (`{"sample": …}`) and by path
  // (`{"core": …}`) is one core, and keying on the sample name put the same file in the bar twice — which is what
  // "did you not de-duplicate?" was. A sample that has no core of its own (the offline fixture) is the only case
  // with nothing better to key on.
  rememberLoaded({
    key: chosen.core ?? chosen.sample,
    sample: chosen.sample,
    core: chosen.core,
    exe: chosen.exe,
    label: leaf(chosen.core) ?? chosen.sample,
    fields: chosen.core
      ? {
          core: chosen.core,
          exe: chosen.exe ?? "",
          gdb: state.defaults?.gdb,
          sysroot: state.defaults?.sysroot,
          solib_search_path: state.defaults?.solib_search_path,
        }
      : null,
  });
  installReport(data, { origin, sample: chosen.sample });
}

// A core the reader names, rather than one this checkout ships: the same token, the same cancel, the same log,
// the same report installation — and deliberately **no** fixture fallback. The fixture is a *different* core, so
// showing it after a path failed would be the silent substitution this project refuses. Instead the form stays,
// with the paths that were typed, and the reason it failed is printed on it.
// Read the same core again. The paths are the session's own — the server holds them, and a display path
// (`tmp/practice/…`, relative to this checkout) is not something to round-trip through the browser.
async function reloadSession() {
  if (!state.live || state.reloading) return;
  state.reloading = true;
  logEvent("reload: reading this core again");
  render();
  try {
    const response = await fetch(`/api/sessions/${state.live.id}/reload`, { method: "POST" });
    const reply = await response.json();
    if (!response.ok) throw new Error(reply.detail ?? `HTTP ${response.status}`);
    const token = (state.loadToken = (state.loadToken ?? 0) + 1);
    state.ui = "loading";
    state.loading = { progress: "", seconds: 0 };
    state.status = "re-reading the core…";
    paintState();
    paintLog();
    render();
    const live = await awaitSession(reply.id, token);
    if (token !== state.loadToken) return;
    state.live = { id: reply.id };
    installReport(live.summary, { origin: `live core (reloaded) · ${leaf(String(state.sample ?? ""))}`, sample: state.sample });
  } catch (error) {
    if (state.loadToken) logEvent(`reload failed: ${error.message}`);
    toast(`reload failed: ${error.message}`, "error");
  }
  state.reloading = false;
  render();
}

async function bootFromPaths(fields) {
  const core = String(fields.core ?? "").trim();
  if (!core) {
    toast("a core path is needed", "error");
    return;
  }
  const token = (state.loadToken = (state.loadToken ?? 0) + 1);
  logEvent(`load ${core}`);
  state.sample = core; // the bar lights this core, because this is what is on screen
  state.formError = null;
  state.ui = "loading";
  state.loading = { progress: "", seconds: 0 };
  state.status = `loading ${core}…`;
  paintState();
  paintLog();
  render();
  try {
    const body = { core };
    for (const key of ["exe", "gdb", "sysroot", "solib_search_path"]) {
      const value = String(fields[key] ?? "").trim();
      if (value) body[key] = value;
    }
    const live = await loadFromBackend(body, token);
    if (token !== state.loadToken) return;
    state.live = { id: live.id };
    rememberLoaded({ key: core, core, exe: body.exe, label: leaf(core), fields: { ...body } });
    installReport(live.summary, { origin: `live core · ${core}`, sample: core });
  } catch (error) {
    if (token !== state.loadToken) return;
    logEvent(`load failed: ${error.message}`);
    state.live = null;
    state.ui = "empty"; // back to the form, not to a stand-in dataset
    state.status = null;
    state.formError = `${core} — ${error.message}`;
    paintState();
    paintLog();
    render();
  }
}

// The log's newest line is always on the bar; the history is one click away. Wired once, here, because the bar
// is part of the static shell rather than something a render rebuilds.
document.getElementById("logline")?.addEventListener("click", () => {
  const panel = document.getElementById("logpanel");
  if (!panel) return;
  panel.hidden = !panel.hidden;
  paintLog();
});

boot().catch((error) => {
  // The stack, not just the message: "cannot set properties of null" without the line it happened on is a
  // riddle, and this is the one place a failure is reported to a human.
  logEvent(`the viewer failed to load: ${error}`);
  document.querySelector("#app").textContent = `the viewer failed to load: ${error}\n${error?.stack ?? ""}`;
});

// A resize changes the pane's height, and with it how many rows fit and how many lines the minimap has.
// Both are measured, not assumed, so both are re-measured.
window.addEventListener("resize", () => state.data && render());
