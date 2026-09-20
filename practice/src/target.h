/* Structures shared by the practice target and its plugin.
 *
 * They are deliberately shaped like real application data: pointer chains, a back-pointer, a NULL
 * field, and a nested allocation. Walking them is what the viewer's jump/back navigation (C4/C5) is
 * supposed to make easy.
 */
#ifndef PRACTICE_TARGET_H
#define PRACTICE_TARGET_H

#include <stddef.h>
#include <stdint.h>

struct blob {
    size_t len;
    unsigned char *data;
    struct blob *child;
};

struct node {
    int id;
    char name[16];
    struct node *next;   /* forms a cycle: the last node points back at the first */
    struct node *peer;   /* left NULL, so the viewer has a non-clickable field */
    struct blob *payload;
};

/* A deliberately awkward structure: everything the memory view has to stay honest about, in one object.
 *
 *   - `nested` is a struct *by value*: its fields live inside this one, at a composed offset;
 *   - `nodes[3]` is an array of structs: three 48-byte elements, each with its own fields;
 *   - `choice` is a union: three members at the same offset, and only one of them is the truth;
 *   - `bits`/`more` are bit-fields: `&((struct wide *)0)->bits` is an error, so they have **no offset**
 *     to draw with — the viewer has to say so instead of guessing;
 *   - `blob[512]` is too big to label per row: it spans 32 rows and needs a band, not a box;
 *   - and it is wide enough that no single column can hold all of it comfortably.
 */
struct inner {
    int tag;
    char label[8];
};

union either {
    uint64_t as_number;
    unsigned char as_bytes[8];
    struct inner *as_pointer;   /* NULL unless something points at it */
};

struct wide {
    uint8_t flags;
    uint16_t kind;
    struct inner nested;
    struct node nodes[3];
    union either choice;
    char name[12];
    unsigned int bits : 3;
    unsigned int more : 5;
    unsigned char blob[512];
};

/* Implemented by libplugin.so; dereferences a stray pointer on purpose. */
void plugin_crash(struct node *head);

#endif /* PRACTICE_TARGET_H */
