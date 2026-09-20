"""pytest entry point.

`src/` is the Python source root, so both the test suite and the app import plain module paths
(`from analysis.gdb.mi import MiTransport`). Putting it on sys.path here — and in `main.py` — is the
whole reason this file exists at the repository root.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def pytest_configure(config) -> None:
    """Register the marker used by tests that need a real gdb and a real core."""
    config.addinivalue_line(
        "markers",
        "gdb: needs a real gdb and a real core; skipped when either is missing",
    )
