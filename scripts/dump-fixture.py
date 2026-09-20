"""Generate the demo datasets from a practice core.

The extraction lives in `analysis/report.py` — the server needs the same numbers — so this is only the part
that is a *script*: pick the cores, call the builder, write the two files the frontend reads.

    python scripts/dump-fixture.py
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
_VENDORED = ROOT / "tmp" / "pylibs"
if _VENDORED.is_dir():
    sys.path.insert(0, str(_VENDORED))

from analysis import report  # noqa: E402

SAMPLES = [("crash_target", "data.json"), ("opt_target", "data.opt.json")]


def main() -> None:
    out_dir = ROOT / "ui" / "data"
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for sample, filename in SAMPLES:
        data = report.build_from_paths(sample)
        path = out_dir / filename
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append({"sample": sample, "file": f"data/{filename}", "label": sample})
        print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size / 1024:.0f} KB)")
    # What the UI falls back to with no backend: the list of fixtures *this run* produced, rather than a list
    # hard-coded in the frontend. It is derived from what was dumped, so it cannot name a file that is not here.
    index = out_dir / "samples.json"
    index.write_text(json.dumps(written, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {index.relative_to(ROOT)} ({len(written)} sample(s))")


if __name__ == "__main__":
    main()
