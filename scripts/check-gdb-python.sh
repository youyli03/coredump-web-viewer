#!/usr/bin/env bash
# Probe whether a gdb supports embedded Python — the first step before integrating any platform.
#
#   ./scripts/check-gdb-python.sh gdb
#   ./scripts/check-gdb-python.sh ntoaarch64-gdb      # QNX
#
# Exit codes: 0 = embedded Python supported; 1 = MI only; 2 = that gdb was not found
#
# Never guess capabilities from the gdb name: the same nto*-gdb ships different Python
# support in different versions.

set -u

GDB="${1:-gdb}"
MARKER="COREDUMP_PROBE_OK"

if ! command -v "$GDB" >/dev/null 2>&1; then
    echo "MISSING     gdb not found: $GDB (not on PATH?)"
    exit 2
fi

echo "=== probing: $GDB ==="
"$GDB" --version 2>&1 | head -n 1

OUT="$("$GDB" --batch -ex "python print('$MARKER')" -ex quit 2>&1)"

if printf '%s' "$OUT" | grep -q "$MARKER"; then
    echo "PYTHON_OK   embedded Python supported → use the embedded Python adapter (fuller capabilities)"
    exit 0
fi

echo "NO_PYTHON   embedded Python not supported → MI path only (DWARF type expansion and similar capabilities are degraded)"
printf '%s\n' "$OUT" | tail -n 3 | sed 's/^/            /'
exit 1
