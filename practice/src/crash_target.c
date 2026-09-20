/* The practice target: a deliberately messy program whose core dump exercises
 * every awkward case the viewer has to survive.
 *
 *   - three extra threads in different states (one holds a mutex, one is blocked on it, one works)
 *   - a linked structure with a cycle, a NULL field and a multi-level pointer chain
 *   - a 24-frame recursion below main
 *   - the actual crash happens one frame inside libplugin.so
 *   - heap allocations that are never freed
 *
 * Build and crash it with:  bash practice/collect.sh
 */
#include "target.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static struct node *g_head;

/* A global with external linkage, on purpose: a `static` one is only nameable from a frame inside this
 * file, and the crash frame lives in libplugin.so — so `expand("g_wide")` would answer "no symbol in
 * current context" and the viewer would have nothing to draw. */
struct wide g_wide;

static void build_wide(void)
{
    memset(&g_wide, 0, sizeof g_wide);

    g_wide.flags = 0x5a;
    g_wide.kind = 0x1234;
    g_wide.nested.tag = 7;
    strcpy(g_wide.nested.label, "inner");

    for (int i = 0; i < 3; i++) {
        g_wide.nodes[i].id = 100 + i;
        snprintf(g_wide.nodes[i].name, sizeof g_wide.nodes[i].name, "wide%02d", i);
        g_wide.nodes[i].next = &g_wide.nodes[(i + 1) % 3];   /* a cycle inside the array */
    }

    g_wide.choice.as_number = 0x0123456789abcdefULL;
    strcpy(g_wide.name, "wide-struct");
    g_wide.bits = 5;
    g_wide.more = 17;
    for (size_t i = 0; i < sizeof g_wide.blob; i++) {
        g_wide.blob[i] = (unsigned char)i;
    }
}

/* Holds the mutex and waits on a condition that is never signalled. */
static void *holder_thread(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_lock);
    for (;;) {
        pthread_cond_wait(&g_cond, &g_lock);
    }
    return NULL;
}

/* Blocks on the mutex that holder_thread never releases. */
static void *waiter_thread(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_lock);
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

/* Keeps allocating, so the heap is not empty in the dump. */
static void *worker_thread(void *arg)
{
    (void)arg;
    for (;;) {
        struct blob *b = calloc(1, sizeof *b);
        if (b == NULL) {
            return NULL;
        }
        b->len = 4096;
        b->data = malloc(b->len);
        if (b->data != NULL) {
            memset(b->data, 0xa5, b->len);
        }
        usleep(200000);
    }
    return NULL;
}

static struct node *build_chain(void)
{
    struct node *a = calloc(1, sizeof *a);
    struct node *b = calloc(1, sizeof *b);
    struct node *c = calloc(1, sizeof *c);
    struct blob *blob = calloc(1, sizeof *blob);

    a->id = 1; strcpy(a->name, "alpha");
    b->id = 2; strcpy(b->name, "beta");
    c->id = 3; strcpy(c->name, "gamma");

    a->next = b;
    b->next = c;
    c->next = a;        /* the cycle: next/next/next brings you back to the start */
    c->peer = NULL;     /* the NULL field */

    blob->len = 32;
    blob->data = malloc(blob->len);
    memset(blob->data, 0x5a, blob->len);
    blob->child = NULL;
    b->payload = blob;

    return a;
}

/* More arguments than the ABI has registers for.
 *
 * AAPCS64 passes the first eight in x0-x7 and the rest on the stack, so this frame has both kinds — which is
 * the case a frame view has to render: a dozen values of mixed types, some of them only readable from the
 * stack. It is called at the bottom of the recursion and calls the plugin itself, so it is live at the crash
 * and appears between `descend` and `plugin_crash`.
 */
static void stacked_args(struct node *n, void (*crash)(struct node *), int a1, int a2, int a3, int a4,
                         int a5, int a6, const char *label, struct blob *b, struct inner by_value,
                         double ratio, uint64_t big)
{
    volatile int pad[8];
    pad[0] = a1 + a2 + a3 + a4 + a5 + a6 + (int)ratio + (int)big;
    /* `b` may legitimately be NULL — the chain's payload pointer is NULL on purpose, so the viewer has a
     * non-clickable field to show. Reading it here would crash *before* the plugin does, which moves the crash
     * site into this file and takes the plugin's frame off the stack. */
    pad[1] = by_value.tag + by_value.label[0] + label[0] + (b ? (int)b->len : 0);
    pad[2] = (int)(uintptr_t)n + (int)(uintptr_t)crash;
    crash(n);
}

/* Recurses to `depth`, then calls back into the plugin, which crashes.
 * So the frame at the crash site sits under 24 frames of this function. */
static void descend(struct node *n, int depth, void (*crash)(struct node *))
{
    volatile int pad[32];
    pad[0] = depth;

    if (depth > 0) {
        descend(n, depth - 1, crash);
        return;
    }
    struct inner inner = {7, "arg-inner"};
    stacked_args(n, crash, 1, 2, 3, 4, 5, 6, "many-arguments", n->payload, inner, 2.5, 0x1122334455667788ull);
}

int main(void)
{
    pthread_t threads[3];
    void *lib;
    void (*crash)(struct node *);

    g_head = build_chain();
    build_wide();
    fprintf(stderr, "chain head = %p   (head->next->next->next == head)\n", (void *)g_head);
    fprintf(stderr, "wide struct = %p   (nested, nodes[3], union, bit-fields, blob[512])\n", (void *)&g_wide);
    fflush(stderr);

    if (pthread_create(&threads[0], NULL, holder_thread, NULL) != 0) {
        perror("pthread_create holder");
        return 2;
    }
    usleep(100000);   /* let the holder take the mutex before the waiter asks for it */

    if (pthread_create(&threads[1], NULL, waiter_thread, NULL) != 0) {
        perror("pthread_create waiter");
        return 2;
    }
    if (pthread_create(&threads[2], NULL, worker_thread, NULL) != 0) {
        perror("pthread_create worker");
        return 2;
    }
    usleep(100000);

    lib = dlopen("./libplugin.so", RTLD_NOW);
    if (lib == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }
    *(void **)(&crash) = dlsym(lib, "plugin_crash");
    if (crash == NULL) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 2;
    }

    descend(g_head, 24, crash);
    return 0;   /* not reached: descend() -> plugin_crash() crashes */
}
