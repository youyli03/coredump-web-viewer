/* Corrupted stacks, on purpose: the samples that the viewer's "is this chain trustworthy?" checks are
 * built and tested against.
 *
 * A stack is untrusted input, and a viewer that has only ever seen intact stacks has untested corruption
 * handling. gdb will not let a core be edited after the fact — memory writes and register writes both
 * answer "You can't do that without a process to debug" — so a corrupted stack cannot be simulated on an
 * existing dump. It has to be *manufactured*, which is what this file is for.
 *
 * Three modes, one per way a stack really breaks. Every one of them writes through an address computed
 * from `__builtin_frame_address(0)` rather than overflowing a buffer into the frame record: this is a
 * harness, and a fixture that depends on where the compiler happened to put a 16-byte array is a
 * coincidence, not a fixture. The *state* left behind is the state a real overflow leaves.
 *
 *   ra    both words of the frame record are overwritten, so `ret` jumps to the marker. The crash PC is
 *         the marker and gdb's own unwinding has nothing sane to follow — the "control flow is gone" case.
 *   fp    only the saved frame pointer is overwritten. The function returns normally and the crash happens
 *         later, in valid code: DWARF CFI still unwinds correctly while the frame pointer chain is a lie.
 *         This is the case where a naive `[fp]` walker — and a viewer that believes it — is simply wrong.
 *   data  a local pointer is overwritten and control flow is untouched: the crash is a *data* access to
 *         the marker, with a perfectly good stack underneath. The viewer's job here is to show which
 *         bytes were overwritten, not to doubt the stack.
 *
 * The mode is the executable's own name (`smash_ra`, `smash_fp`, `smash_data`), so the core file — which
 * the kernel names from the executable — says which scenario produced it. `argv[1]` overrides it.
 *
 * Build and run them with `bash practice/collect.sh`.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What `strcpy` past an 8-byte buffer writes: `AAAA…`. Recognisable on sight in a hex dump, which is the
 * whole point — the viewer should be able to say "this is overwritten data, not a return address". */
#define MARKER 0x4141414141414141ULL

#define NOINLINE __attribute__((noinline))

/* The frame record of the calling function, as AAPCS64 lays it out: `[fp]` is the caller's frame pointer
 * and `[fp+8]` is the return address. `-fno-omit-frame-pointer` is set by `collect.sh` for these targets,
 * so the chain exists on purpose here: a sample has to be defined, not left to a compiler default.
 *
 * The address is passed in rather than taken with `__builtin_frame_address(1)`: asking for the caller's
 * frame is a promise about inlining and frame layout, and a harness should not need one. */
static void smash(uint64_t *record, int word)
{
    record[word] = MARKER;
}

NOINLINE static void ra_mode(void)
{
    fprintf(stderr, "smash_target: ra — frame record at %p, both words -> %#llx\n",
            __builtin_frame_address(0), (unsigned long long)MARKER);
    fflush(stderr);
    smash((uint64_t *)__builtin_frame_address(0), 0);   /* the saved frame pointer */
    smash((uint64_t *)__builtin_frame_address(0), 1);   /* the return address: `ret` uses it */
}

NOINLINE static void crash_here(void)
{
    /* A NULL write: a real fault in real code, reached with a broken chain above us (fp mode) or with a
     * perfectly good stack (data mode). */
    *(volatile int *)(uintptr_t)0 = 1;
}

NOINLINE static void fp_mode(void)
{
    fprintf(stderr, "smash_target: fp — frame record at %p, saved frame pointer -> %#llx\n",
            __builtin_frame_address(0), (unsigned long long)MARKER);
    fflush(stderr);
    smash((uint64_t *)__builtin_frame_address(0), 0);   /* only the frame pointer stays valid */
}

NOINLINE static void data_mode(void)
{
    void *local = (void *)&local;      /* something addressable, so the pointer is not optimised away */
    memset(&local, 0x41, sizeof local);
    fprintf(stderr, "smash_target: data — local pointer at %p now reads %p\n", (void *)&local, local);
    fflush(stderr);
    *(volatile int *)local = 1;        /* the crash: a store through the overwritten pointer */
}

static const char *mode_from(const char *argv0, int argc, char **argv)
{
    if (argc > 1) {
        return argv[1];
    }
    const char *slash = strrchr(argv0, '/');
    const char *name = slash != NULL ? slash + 1 : argv0;
    if (strncmp(name, "smash_", 6) == 0) {
        return name + 6;               /* the core file is named after the executable, so it says this */
    }
    return "ra";
}

int main(int argc, char **argv)
{
    const char *mode = mode_from(argv[0], argc, argv);

    if (strcmp(mode, "ra") == 0) {
        ra_mode();
        fprintf(stderr, "smash_target: ra — returned without crashing?\n");
        return 3;                      /* not reached: the return address is the marker */
    }
    if (strcmp(mode, "fp") == 0) {
        /* Return cleanly, then crash in the next call: the crash frame is valid and symbolised, while the
         * frame pointer chain above it is broken. */
        fp_mode();
        crash_here();
        return 3;
    }
    if (strcmp(mode, "data") == 0) {
        data_mode();
        return 3;
    }

    fprintf(stderr, "smash_target: unknown mode %s (expected ra, fp or data)\n", mode);
    return 2;
}
