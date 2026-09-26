# AGENTS.md

> This is an index. It points at the documents.

---

## Documents

- **`docs/requirements.md`** — the specification: what to build, what not to build, what counts as done.
  This is the only specification in the repository; read it before building anything.
- **`docs/architecture.md`** — the architecture and code layout: layers, the resident-gdb decision,
  the module/file map, dependency direction, configuration.
- **`docs/api.md`** — the HTTP surface: the JSON contract, the error vocabulary, the observability that turns
  the promises into assertions, and the test matrix that follows from them.

---

## Rules

- **`scripts/` holds only gdb-facing scripts** — the payload that runs *inside* gdb (`scripts/gdb/`) and
  gdb probing tools run from a shell. **Do not put unrelated code there.** A helper that belongs to the
  backend goes in `src/`, next to the code that uses it; `scripts/` is not a dumping ground.
- **`tmp/` is the local scratch workspace** — practice cores, sysroots and downloaded tools (for example
  a Windows `gdb-multiarch`) live here. It is **gitignored, never committed, and safe to delete at any
  time**. Small sample data that tests *should* commit belongs in `tests/`, not here.
- **Cores are never committed** — they are gigabytes, they can contain keys or user data, and a blob once
  committed is never really removed. Reference them by path and add them to `.gitignore` instead.

---

## Commit messages

English, and shaped like git's own log:

```
subject: imperative mood, no trailing full stop, 50 characters or fewer

Body if the change needs one, wrapped at 72 columns, separated from the
subject by a blank line. Say why the change is right and what it replaces;
the diff already says what changed. One logical change per commit, and a
`type(scope):` prefix (`feat`, `fix`, `perf`, `refactor`, `docs`, `test`,
`chore`) so the log can be read by subject alone.
```

---

## What may be committed

The practice bundle's build path is part of the data: the cores record their sources under
`/home/lyy/cdwv-practice`, so paths below that root are allowed in code, tests and documentation —
`src/analysis/report.py`'s `SOURCE_ROOT` is exactly that, and it stays.

Nothing else about a machine belongs in the history:

- **no domains, hostnames or non-loopback IP addresses** — the Linux board that produces the dumps is
  described in `AGENTS.local.md`, which is gitignored, and never here;
- **no other absolute paths from a development machine** — use the practice root above, a relative path,
  or a placeholder such as `you@your-analysis-host`;
- loopback (`127.0.0.1`, `localhost`) carries nothing about a machine: it is how the app binds and what the
  documentation tells the reader to open, so it stays.

When in doubt, the test is whether the text tells a reader something about *whose* machine this is.

---

## Local development

Machine-specific setup for this checkout — which host, which gdb, how to reach the Linux board and build a
practice core — is in **`AGENTS.local.md`** next to this file. It is **gitignored**, so it may be absent on
a fresh clone; if it is absent, none of that tooling exists yet.

The committed half of it is `practice/`: practice targets plus a one-command generator that produces a real
core dump (`bash practice/collect.sh`, run on the Linux box). Read `practice/README.md` before using it.

---

## Language

**All documentation in this repository is written in English** — `docs/**` and this file.
Code comments, docstrings and user-facing messages are English as well.
Chinese is for talking to humans (chat, review notes); it is not committed.
