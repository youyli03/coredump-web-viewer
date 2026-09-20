/* The dlopen'ed half of the practice target.
 *
 * Crashing *inside* a shared object is the point: the crash frame lives in libplugin.so, so the
 * memory view has to map an address range back to this object through the core's NT_FILE note.
 */
#include "target.h"

#include <stdint.h>
#include <stdio.h>

void plugin_crash(struct node *head)
{
    struct node *n = head;
    int hops = 0;

    /* Walk the chain and stop before the cycle closes, printing what we saw. */
    while (n != NULL && hops < 4) {
        fprintf(stderr, "plugin: node %d '%s' at %p  next=%p  peer=%p  payload=%p\n",
                n->id, n->name, (void *)n, (void *)n->next, (void *)n->peer, (void *)n->payload);
        n = n->next;
        hops++;
    }

    /* A stray pointer: the viewer must report "not in this dump" rather than fall over. */
    struct node *stray = (struct node *)(uintptr_t)0xdead0000dead0000ULL;
    fprintf(stderr, "plugin: dereferencing a stray pointer %p on purpose\n", (void *)stray);
    fflush(stderr);

    printf("%d\n", stray->id);   /* SIGSEGV lands here, inside libplugin.so */
}
