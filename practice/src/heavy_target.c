/* heavy_target.c — the practice suite's *scale* case: many threads, a deep stack, a lot of live memory.
 *
 * The other targets are awkward; this one is big, because size is a claim the viewer makes
 * (`requirements.md` §5: "cores are GB-scale and a stack can have tens of thousands of frames") and a core
 * the size of a laptop's memory is the only thing that can test it. Everything here is a number that costs
 * the viewer something:
 *
 *   threads   48 of them, in four different states — one holding a mutex, the rest blocked on it, some
 *             sleeping, some working — so the thread list has to stay readable when it is a *list*;
 *   depth     30 000 frames of recursion, each holding a 64-byte buffer it writes to so the pages are really
 *             there, and the fault is at the **bottom**: a stack that deep is what the first screen has to
 *             page, not a formality;
 *   memory    1 GB of touched, live, never-freed heap. The bulk of a core *is* memory, so a core that is not
 *             mostly memory does not test the viewer's real cost.
 *
 * -O0 and kept frame pointers, because a `-O2` build could roll the recursion into a loop or tail-call it
 * away, and "deep" is the whole point.
 *
 * The deep recursion happens on the **main** thread, whose stack is the process's `ulimit -s` (the collector
 * raises it to 16 MB for this scenario): 30 000 frames at a hundred-odd bytes each need a few megabytes, and a
 * stack that runs into its guard page is a stack overflow rather than a reproducible fault. The 48 helper
 * threads ask for 1 MB each, and that number is deliberate rather than tidy — **an anonymous mapping is dumped
 * in full**, whether or not its pages were ever touched, so measured on this target a 32 MB stack per thread
 * put 1.5 GB of mostly-zeroes into the core and drowned the heap that this scenario is about.
 *
 * Build and crash it with:   HEAVY=1 bash practice/collect.sh
 * Scale it with:             HEAVY=1 HEAVY_HEAP_MB=2048 HEAVY_DEPTH=60000 bash practice/collect.sh
 *
 * Every knob has a default that fits a 4 GB machine, so the scenario is reproducible without an argument.
 */
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#ifndef THREADS
#define THREADS 48
#endif
#ifndef DEPTH
#define DEPTH 30000
#endif
#ifndef HEAP_MB
#define HEAP_MB 1024
#endif

#define MARKER 0xdead0000dead0000ULL
/* The address the recursion dereferences at depth 0: the same deliberate stray pointer `crash_target` uses,
 * so "this address is not in this dump" stays one recognisable answer across the whole practice suite. */

static pthread_mutex_t g_busy = PTHREAD_MUTEX_INITIALIZER;
static unsigned char *g_heap;
static size_t g_heap_bytes;
static unsigned long g_spins;
static pthread_t g_threads[THREADS];

/* One page at a time, with the page number written into it: cheap, and it gives the memory view something
 * readable instead of a uniform field of zeroes. */
static void touch_the_heap(void)
{
    for (size_t offset = 0; offset < g_heap_bytes; offset += 4096) {
        g_heap[offset] = (unsigned char)(offset >> 12);
        g_heap[offset + 4095] = (unsigned char)(offset >> 12);
    }
}

static void *holds_the_lock(void *argument)
{
    (void)argument;
    pthread_mutex_lock(&g_busy);
    for (;;) {
        pause();  /* holds it for the life of the process: every waiter below is stuck behind this */
    }
}

static void *waits_for_the_lock(void *argument)
{
    (void)argument;
    pthread_mutex_lock(&g_busy);  /* never returns while the holder above is alive */
    return NULL;
}

static void *sleeps(void *argument)
{
    (void)argument;
    struct timespec nap = {1, 0};
    for (;;) {
        nanosleep(&nap, NULL);
    }
}

static void *works(void *argument)
{
    (void)argument;
    for (;;) {
        __sync_fetch_and_add(&g_spins, 1);
    }
}

/* The stack the viewer has to page. `scratch` is written so the frame is really on the stack, and the
 * arguments are carried down so the crash frame's own variables name something the memory view can follow —
 * `heap` is the 1 GB mapping. */
static void descend(int depth, unsigned char *heap, size_t heap_bytes, int threads)
{
    volatile unsigned char scratch[64];

    scratch[0] = (unsigned char)depth;

    if (depth > 0) {
        descend(depth - 1, heap, heap_bytes, threads);
    } else {
        unsigned char *nowhere = (unsigned char *)(uintptr_t)MARKER;
        printf("heavy_target: %d threads, %d frames down, %zu MB of heap — storing through %p now\n",
               threads, DEPTH, heap_bytes >> 20, (void *)nowhere);
        fflush(stdout);
        *nowhere = 0x41;  /* the fault, at the bottom of DEPTH frames */
    }

    /* Touched after the call, so no compiler may drop the buffer for being dead. */
    if (scratch[0] == 0xff) {
        heap[0] = scratch[0];
    }
}

int main(void)
{
    g_heap_bytes = (size_t)HEAP_MB * 1024 * 1024;

    g_heap = mmap(NULL, g_heap_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_heap == MAP_FAILED) {
        perror("heavy_target: mmap");
        return 2;
    }
    touch_the_heap();

    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    // 1 MB: these threads only ever hold a lock, sleep or spin, and every byte of their mapping is written to
    // the core whether it was touched or not (see the note at the top).
    pthread_attr_setstacksize(&attributes, 1u << 20);

    for (int index = 0; index < THREADS; index++) {
        void *(*body)(void *) = index == 0     ? holds_the_lock
                                : index < THREADS / 2 ? waits_for_the_lock
                                : index % 3 == 0      ? sleeps
                                                      : works;
        if (pthread_create(&g_threads[index], &attributes, body, NULL) != 0) {
            perror("heavy_target: pthread_create");
            return 2;
        }
    }
    pthread_attr_destroy(&attributes);

    /* Let the helpers reach their states before the crash, so the dump is not a snapshot of the startup. */
    struct timespec settle = {0, 200 * 1000 * 1000};
    nanosleep(&settle, NULL);

    printf("heavy_target: %d threads started, %zu MB touched, descending %d frames\n",
           THREADS, g_heap_bytes >> 20, DEPTH);
    fflush(stdout);

    descend(DEPTH, g_heap, g_heap_bytes, THREADS);
    return 0;  /* not reached */
}
