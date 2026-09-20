/* A core whose stack holds two register snapshots.
 *
 * Every other practice target saves only what a small function needs, which is the frame pointer and the
 * return address — so `info registers` in an outer frame has nothing real to restore and gdb falls back to
 * "assume the same as the inner frame". That is an assumption, not a fact, and a viewer that repeats it as
 * fact is inventing values.
 *
 * Two mechanisms put a whole register file on the stack, and this target uses both at once:
 *
 *   1. `setjmp` writes a `jmp_buf` — on AArch64 glibc that is x19-x30, sp and d8-d15. Declared as a **local**,
 *      so the snapshot lives in `main`'s stack frame and not in .bss.
 *   2. A SIGSEGV handler crashes again. The kernel pushes a `sigcontext` (every general register, sp, pc,
 *      pstate, plus an `fpsimd_context`) before entering the handler, so the core is taken with the handler
 *      frame *and* the original register state still on the stack — gdb shows the kernel's frame as
 *      `<signal handler called>`.
 *
 * Built `-O2`, unlike the other targets: at -O0 nothing is kept in a callee-saved register in the first
 * place, so the saving behaviour this sample exists to exercise never happens.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "target.h"

static struct node *g_chain;
static jmp_buf *g_snapshot; /* pointed at main's local, so it is visibly on the stack */

void crash_inside(unsigned long a, unsigned long c, unsigned long d, unsigned long e, unsigned long f,
                  unsigned long g);

/* Faults a second time. A SIGSEGV inside a SIGSEGV handler is fatal: the default action is restored for the
 * duration, so the process dies here and the core carries this frame, the kernel's `sigcontext` under it, and
 * `main`'s `jmp_buf` further up. */
static void on_fault(int sig)
{
    /* Read both globals so neither is "set but unused": this is the frame the core is taken in, and the
     * snapshot it points at has to still be live for the stack to hold it. */
    if (g_snapshot != NULL && g_chain != NULL) {
        (void)sig;
    }
    *(volatile unsigned long *)0x4141414141414141UL = 1;
}

/* Six values that have to stay live across the call to `crash_inside`, which is what makes a compiler keep
 * them in callee-saved registers (and therefore save them into this frame). */
static void keep_registers_busy(struct node *n, struct node *m, struct blob *b)
{
    unsigned long a = (unsigned long)n->id + 11;
    unsigned long c = (unsigned long)n->id + 22;
    unsigned long d = (unsigned long)m->id + 33;
    unsigned long e = (unsigned long)b->len + 44;
    unsigned long f = (unsigned long)(uintptr_t)n->name + 55;
    unsigned long g = (unsigned long)(uintptr_t)m->name + 66;

    crash_inside(a, c, d, e, f, g);
}

/* Dereferences the stray pointer, exactly like the plugin does — the handler is what makes this core
 * different from the others. */
void crash_inside(unsigned long a, unsigned long c, unsigned long d, unsigned long e, unsigned long f,
                  unsigned long g)
{
    struct node *stray = (struct node *)0xdead0000dead0000UL;

    if (a + c + d + e + f + g == 0) {
        printf("unreachable %lu\n", a);
    }
    printf("%d\n", stray->id); /* SIGSEGV: the handler runs, and faults again */
}

int main(void)
{
    jmp_buf snapshot; /* a local: setjmp records the registers into *this* stack frame */
    struct sigaction sa;
    struct blob blob;
    struct node first;
    struct node second;

    memset(&blob, 0, sizeof blob);
    memset(&first, 0, sizeof first);
    memset(&second, 0, sizeof second);
    first.id = 1;
    second.id = 2;
    blob.len = 64;
    first.next = &second;
    second.next = &first; /* a cycle, like the other targets: walking it must not run forever */
    first.payload = &blob;
    g_chain = &first;
    g_snapshot = &snapshot;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    if (setjmp(snapshot) == 0) {
        keep_registers_busy(&first, &second, &blob);
    }
    /* Not reached: the second fault is fatal. */
    return 0;
}
