/* A frame whose variables live in *registers*, because that is what an optimised build does.
 *
 * The other practice targets are compiled `-O0`, where every argument and local is spilled to the stack and
 * every variable has a byte address. Real dumps from a release build are the opposite: `frame_slots` asks
 * gdb for `&name`, gdb refuses (there is no address), and a viewer that only draws what it can place would
 * silently drop the variable from the frame. The information is not missing — the variable is in a register,
 * and gdb knows which: `info address` answers with a DWARF location expression (`DW_OP_reg0`), which is a
 * *fact about the register file*, not a guess.
 *
 * Built `-O2 -g -fno-omit-frame-pointer` by `collect.sh`:
 *
 *   - the crash is a store through `target`, which is a small integer rather than an address, so the fault
 *     address itself says what went wrong;
 *   - the crash frame's `target` is live in a register at the fault;
 *   - `main` keeps a `volatile` local, which cannot live in a register, so the *same* build also produces a
 *     variable with a real stack slot — the mixed case a viewer has to render side by side.
 *
 * The binary is called `opt_target`, not `optimized_target`, because a core file is named after the
 * process's `comm` and the kernel caps that at **15 characters**. A longer name produces a core whose name is
 * silently truncated — `optimized_targe.…core` — and every tool that looks a core up by program name then
 * finds nothing at all.
 */
#include <stdint.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))

/* Arguments arrive in w0/w1/w2 and are used in a loop, so they stay there. */
NOINLINE static int accumulate(int seed, int step, int limit)
{
    int total = seed;
    for (int i = 0; i < limit; i++) {
        total += step;
    }
    return total;
}

/* `target` is read once, from a register, to form the store address: a fault at 0x7, not at 0x0 — the
 * difference between "someone dereferenced NULL" and "someone dereferenced a number". */
NOINLINE static void crash_now(int target)
{
    fprintf(stderr, "optimized_target: about to store through %d (%#x)\n", target, (unsigned)target);
    fflush(stderr);
    *(volatile int *)(uintptr_t)target = 1;
}

int main(void)
{
    volatile int pinned = 0; /* a volatile local cannot be kept in a register: this one has a stack slot */
    int seed = 1;
    int step = 2;
    int limit = 3;

    int total = accumulate(seed, step, limit);
    pinned = total;

    fprintf(stderr, "optimized_target: accumulate(%d, %d, %d) = %d\n", seed, step, limit, total);
    fflush(stderr);

    crash_now(pinned);
    return 0; /* not reached */
}
