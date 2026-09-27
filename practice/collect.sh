#!/usr/bin/env bash
# Build the practice targets, let them crash, and bundle the cores with everything needed to analyse them
# elsewhere (the executables plus a sysroot of the shared libraries they used).
#
# Run on Linux, from the repository root:
#     bash practice/collect.sh [outdir]
#
# STRIP=1 builds a second, stripped copy of the plugin so the "symbols missing" case can be studied too.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
src="$here/src"
out="${1:-$here/out}"
prog="crash_target"
# One core per corrupted-stack scenario; see src/smash_target.c. The kernel names a core after the
# executable, so the core file itself says which scenario produced it.
smash_modes="ra fp data"

mkdir -p "$out"
rm -f "$out"/*.core "$out/$prog" "$out"/smash_* "$out/libplugin.so" 2>/dev/null || true

# The shell that runs the program is the shell that needs the limit raised.
ulimit -c unlimited || { echo "cannot raise the core-file limit" >&2; exit 1; }

pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo '?')"
case "$pattern" in
  \|*)
    echo "WARNING: core_pattern is '$pattern' — cores are piped to a helper, so no core file appears." >&2
    echo "         Fix it (needs root) or use:  gdb -p <pid> -batch -ex 'gcore /path/core'" >&2
    ;;
esac

# The newest core for one program, so each scenario can check that *its own* crash produced a file.
newest_core() {
  ls -1t /tmp/"$1".*.core 2>/dev/null | head -n1 || true
}

# Run one program, expect it to die, copy its core into the bundle. A scenario that does not crash is a
# broken sample, and a broken sample is worse than a missing one: say so rather than ship it silently.
collect() {
  local name="$1" ; shift
  local before core
  before="$(newest_core "$name")"
  ( cd "$out" && "./$name" "$@" ) || true
  sleep 1
  core="$(newest_core "$name")"
  if [ -z "$core" ] || [ "$core" = "$before" ]; then
    echo "WARNING: $name produced no core" >&2
    return 1
  fi
  cp -f "$core" "$out/"
  echo "  $name -> $(basename "$core")"
}

echo "== building =="
( cd "$out" && cc -g -O0 -fPIC -shared -o libplugin.so "$src/libplugin.c" )
( cd "$out" && cc -g -O0 -o "$prog" "$src/crash_target.c" -ldl -lpthread )

echo "== building the corrupted-stack samples =="
# `-fno-omit-frame-pointer` so a frame chain is a given rather than a compiler default, and
# `-fno-stack-protector` so a deliberate write into a frame record is not turned into an abort by the
# canary check: these samples are about what a *silent* overflow leaves behind.
for mode in $smash_modes; do
  ( cd "$out" && cc -g -O0 -fno-omit-frame-pointer -fno-stack-protector \
      -o "smash_$mode" "$src/smash_target.c" )
done

echo "== building the optimised sample (variables in registers) =="
# `-O2` is the point: at -O0 everything is spilled to the stack and no variable ever lives in a register.
# Frame pointers are kept so the stack still walks.
( cd "$out" && cc -g -O2 -fno-omit-frame-pointer -o opt_target "$src/opt_target.c" )

if [ "${HEAVY:-0}" = "1" ]; then
  echo "== building the heavy target (scale: threads, depth, memory) =="
  # Opt-in, because it is the one target whose *cost* is the point: a gigabyte of core and tens of thousands of
  # frames. -O0 and kept frame pointers so the recursion is real rather than rolled into a loop, and the thread
  # stack is 32 MB so the depth fits comfortably instead of becoming a stack overflow. THREADS/DEPTH/HEAP_MB are
  # overridable so the same scenario can be run small on a small machine.
  ( cd "$out" && cc -g -O0 -fno-omit-frame-pointer \
      -DTHREADS="${HEAVY_THREADS:-48}" -DDEPTH="${HEAVY_DEPTH:-30000}" -DHEAP_MB="${HEAVY_HEAP_MB:-1024}" \
      -o heavy_target "$src/heavy_target.c" -ldl -lpthread )
fi

echo "== building the register-snapshot sample =="
# Also -O2, and for the same reason in reverse: a callee-saved register is only saved when something is kept
# in it, and at -O0 nothing is. This target is about what a stack holds when the *code* puts registers there
# (a `jmp_buf`, and the kernel's `sigcontext` for a fault inside a handler).
( cd "$out" && cc -g -O2 -fno-omit-frame-pointer -o snap_target "$src/snap_target.c" )

if [ "${STRIP:-0}" = "1" ]; then
  echo "== also building a stripped plugin (debug info split out) =="
  cp "$out/libplugin.so" "$out/libplugin.stripped.so"
  objcopy --only-keep-debug "$out/libplugin.stripped.so" "$out/libplugin.stripped.debug"
  strip --strip-debug "$out/libplugin.stripped.so"
fi

echo "== running the main target (it is supposed to crash) =="
collect "$prog"

echo "== running the corrupted-stack samples (each is supposed to crash) =="
for mode in $smash_modes; do
  collect "smash_$mode" || true
done

echo "== running the optimised sample (it is supposed to crash) =="
collect opt_target || true

echo "== running the register-snapshot sample (it is supposed to crash) =="
collect snap_target || true

if [ -e "$out/heavy_target" ]; then
  echo "== running the heavy target (it is supposed to crash, and it takes a moment) =="
  # The deep recursion runs on the main thread, so the *process* stack limit is what has to hold 30 000
  # frames. Raised here rather than in the target because it is a property of the run, not of the program.
  ulimit -s 16384 || true
  collect heavy_target || true
fi

echo "== collecting a sysroot =="
while read -r lib; do
  [ -n "$lib" ] || continue
  dest="$out/sysroot$lib"
  mkdir -p "$(dirname "$dest")"
  cp -Lf "$lib" "$dest" 2>/dev/null || true
done < <( { ldd "$out/$prog"; ldd "$out/libplugin.so"; ldd "$out/opt_target"; ldd "$out/snap_target"; \
            [ -e "$out/heavy_target" ] && ldd "$out/heavy_target"; \
            for mode in $smash_modes; do ldd "$out/smash_$mode"; done; } 2>/dev/null \
          | awk '/=> \// {print $3} /^\// {print $1}' | sort -u )

{
  echo "host:        $(uname -a)"
  echo "compiler:    $(cc --version | head -n1)"
  echo "core_pattern:$pattern"
  echo "program:     ./$prog   (cwd = the bundle directory)"
  echo "plugin:      ./libplugin.so  (dlopen'ed, relative path)"
  echo "smashers:    ./smash_ra (return address), ./smash_fp (frame pointer), ./smash_data (a local pointer)"
  echo "built with:  cc -g -O0   (STRIP=${STRIP:-0})"
  echo
  echo "cores in this bundle:"
  for core in "$out"/*.core; do
    [ -e "$core" ] || continue
    echo "  $(basename "$core")"
  done
  echo
  # What the cores contain, asked of the core rather than described by hand. Everything above is about the
  # build; this is about the samples, and it is the part that changes when a target changes — which is why it
  # is generated here instead of written down in the README, where it would go stale in silence.
  #
  # Every target that produced a core, not just the main one: the interesting differences between the samples
  # (a fault inside a handler, a deliberately smashed frame record) are exactly what these lines show.
  if command -v gdb >/dev/null 2>&1; then
    for exe in "$out/$prog" "$out/snap_target" "$out/opt_target" \
               "$out/smash_ra" "$out/smash_fp" "$out/smash_data" "$out/heavy_target"; do
      [ -e "$exe" ] || continue
      crash_core="$(ls -1t "$exe".*.core 2>/dev/null | head -n1 || true)"
      [ -n "$crash_core" ] || continue
      echo "crash frames of $(basename "$exe") (top 3):"
      # No `thread 1`: gdb already selects the thread that stopped, and asking explicitly makes it echo the
      # stop location twice more — three copies of `#0` and the actual backtrace pushed off the end.
      gdb -batch -q "$exe" "$crash_core" \
          -ex "set sysroot $out/sysroot" -ex "set solib-search-path $out" \
          -ex "bt 3" 2>/dev/null \
        | grep -E '^#[0-9]|^  [0-9]+\s' | sed 's/^/  /' || true
      echo
    done
  fi
} > "$out/manifest.txt"

echo
echo "bundle written to: $out"
ls -la "$out"
echo
echo "copy the whole directory to the analysis machine, e.g.:"
echo "  scp -r $(whoami)@$(hostname):$out ."
