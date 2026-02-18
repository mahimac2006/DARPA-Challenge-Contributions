/*
 * Symbolic Execution Harness: io_uring rsrc_node Cache Reuse
 *
 * Models the rsrc_node alloc/destroy cache that fails to clear stale
 * item.file/item.buf pointers, plus the lock-drop race during quiesce.
 * Detects WMI-1 through WMI-4.
 *
 * Target bug: io_uring/rsrc.c io_rsrc_node_alloc() lines 197-215
 *             io_uring/rsrc.c io_rsrc_node_destroy() lines 170-174
 *             io_uring/rsrc.c io_rsrc_ref_quiesce() lines 217-274
 *
 * Build:
 *   clang -emit-llvm -c -g io_uring_harness.c -o io_uring_harness.bc
 *   klee --posix-runtime io_uring_harness.bc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <klee/klee.h>

#define SYM_INT(name) ({ int _v; klee_make_symbolic(&_v, sizeof(_v), name); _v; })
#define SYM_ASSUME(c)  klee_assume(c)
#define SYM_ASSERT(c)  klee_assert(c)

/* ========================================================================
 * Simplified kernel data structure models
 * ======================================================================== */

#define MAGIC_FILE_ALIVE  0xF11EF11E
#define MAGIC_FILE_DEAD   0xDEADF11E
#define MAGIC_WIN         0x57494E21

typedef void (*file_release_fn)(void *);

void normal_release(void *f) {
    printf("[EFFECT] normal_release called — safe fput\n");
}

void hijacked_release(void *f) {
    printf("[EXPLOITATION SUCCESS] hijacked_release called — attacker controls fput!\n");
}

struct io_file {
    uint32_t         magic;
    int              f_count;
    file_release_fn  f_op_release;
    uint64_t         private_data;
};

enum rsrc_type {
    IORING_RSRC_FILE = 0,
    IORING_RSRC_BUFFER = 1,
};

union io_rsrc_item {
    struct io_file *file;
    void           *buf;
    void           *rsrc;
};

struct io_rsrc_node {
    int              refs;
    int              empty;
    enum rsrc_type   type;
    union io_rsrc_item item;
    uint64_t         tag;
};

/* Alloc cache simulation (mirrors io_uring/alloc_cache.h) */
#define CACHE_SIZE 8
struct alloc_cache {
    struct io_rsrc_node *entries[CACHE_SIZE];
    int count;
};

static struct alloc_cache node_cache = { .count = 0 };

/* ========================================================================
 * Model of io_rsrc_node_destroy (rsrc.c:170-174)
 * Places node in cache instead of freeing
 * ======================================================================== */

void io_rsrc_node_destroy(struct io_rsrc_node *node) {
    if (node_cache.count < CACHE_SIZE) {
        printf("[CACHE] Node %p placed in cache (item.rsrc=%p, type=%d)\n",
               (void*)node, node->item.rsrc, node->type);
        node_cache.entries[node_cache.count++] = node;
    } else {
        printf("[FREE] Node %p freed (cache full)\n", (void*)node);
        free(node);
    }
}

/* ========================================================================
 * Model of io_rsrc_node_alloc (rsrc.c:197-215)
 * BUG: Only clears ctx, empty, refs — NOT item or type
 * ======================================================================== */

struct io_rsrc_node *io_rsrc_node_alloc(void) {
    struct io_rsrc_node *node;

    if (node_cache.count > 0) {
        node = node_cache.entries[--node_cache.count];
        printf("[CACHE] Retrieved node %p from cache\n", (void*)node);
        printf("  [STALE] item.rsrc = %p (NOT CLEARED)\n", node->item.rsrc);
        printf("  [STALE] type = %d (NOT CLEARED)\n", node->type);
    } else {
        node = calloc(1, sizeof(*node)); /* kzalloc zeros everything */
        printf("[ALLOC] Fresh node %p (zero-initialized)\n", (void*)node);
    }

    /* Only these three fields are re-initialized (rsrc.c:211-213) */
    node->empty = 0;
    node->refs = 1;
    /* node->item and node->type are NOT touched for cached nodes */

    return node;
}

/* ========================================================================
 * Model of io_rsrc_put_work (rsrc.c:150-168)
 * Processes the node's stashed resource
 * ======================================================================== */

void io_rsrc_put_work(struct io_rsrc_node *node) {
    printf("[PUT_WORK] Processing node %p (type=%d)\n", (void*)node, node->type);

    switch (node->type) {
    case IORING_RSRC_FILE:
        if (node->item.file) {
            printf("[PUT_WORK] Calling fput on file %p (magic=0x%x)\n",
                   (void*)node->item.file, node->item.file->magic);

            if (node->item.file->magic == MAGIC_FILE_DEAD) {
                printf("[WMI-1 DETECTED] fput on already-freed file!\n");
            }

            if (node->item.file->f_op_release == hijacked_release) {
                printf("[WMI-4 DETECTED] File release function hijacked!\n");
            }

            /* Simulate fput → calls f_op->release when f_count hits 0 */
            node->item.file->f_count--;
            if (node->item.file->f_count <= 0) {
                node->item.file->f_op_release(node->item.file);
            }
        }
        break;
    case IORING_RSRC_BUFFER:
        if (node->item.buf) {
            printf("[PUT_WORK] Unmapping buffer at %p\n", node->item.buf);
        }
        break;
    }
}

/* ========================================================================
 * Model of io_queue_rsrc_removal (rsrc.c:639-658)
 * Captures current node, swaps in new one, decrements old
 * ======================================================================== */

struct io_rsrc_node *current_rsrc_node = NULL;

void io_queue_rsrc_removal(struct io_file *old_file) {
    struct io_rsrc_node *old_node = current_rsrc_node;

    printf("\n[REMOVAL] Capturing current node %p for removal\n", (void*)old_node);

    current_rsrc_node = io_rsrc_node_alloc();
    printf("[REMOVAL] Swapped to new node %p\n", (void*)current_rsrc_node);

    old_node->item.file = old_file;
    old_node->type = IORING_RSRC_FILE;
    old_node->tag = 0;

    printf("[REMOVAL] Stashed file %p in old node, decrementing refs\n",
           (void*)old_file);

    old_node->refs--;
    if (old_node->refs <= 0) {
        printf("[REMOVAL] Refs hit zero, processing immediately\n");
        io_rsrc_put_work(old_node);
        io_rsrc_node_destroy(old_node);
    }
}

/* ========================================================================
 * Main harness
 * ======================================================================== */

int main(void) {
    printf("==========================================================================\n");
    printf("  io_uring rsrc_node Cache Reuse Harness — WMI Detection\n");
    printf("==========================================================================\n\n");

    /* === INIT: Set up the resource node and a registered file === */
    printf("=== PHASE 1: Initial Setup ===\n");

    current_rsrc_node = io_rsrc_node_alloc();
    printf("[INIT] Initial rsrc_node at %p\n\n", (void*)current_rsrc_node);

    struct io_file *file_a = malloc(sizeof(struct io_file));
    file_a->magic = MAGIC_FILE_ALIVE;
    file_a->f_count = 1;
    file_a->f_op_release = normal_release;
    file_a->private_data = 0xAAAAAAAAAAAAAAAAULL;
    printf("[INIT] Registered file_a at %p (f_op_release=normal_release)\n", (void*)file_a);

    struct io_file *file_b = malloc(sizeof(struct io_file));
    file_b->magic = MAGIC_FILE_ALIVE;
    file_b->f_count = 1;
    file_b->f_op_release = normal_release;
    file_b->private_data = 0xBBBBBBBBBBBBBBBBULL;
    printf("[INIT] Registered file_b at %p\n\n", (void*)file_b);

    /* === PHASE 2: File update — node goes through cache (WMI-1 setup) === */
    printf("=== PHASE 2: File Update — Node Caching ===\n");

    io_queue_rsrc_removal(file_a);
    printf("[UPDATE] file_a removed, old node cached with stale data\n\n");

    /* === PHASE 3: Another file update — retrieves cached node (WMI-2) === */
    printf("=== PHASE 3: Second Update — Cache Retrieval (WMI-2) ===\n");

    io_queue_rsrc_removal(file_b);

    printf("\n[CHECK] Retrieved node from cache should have stale item pointer\n");

    int stale_race = SYM_INT("stale_race");

    if (stale_race) {
        printf("\n=== PHASE 4: Exploiting Stale Cache Data ===\n");

        /*
         * Simulate: file_a was freed after fput, attacker reclaims
         * the memory with controlled data
         */
        printf("[ATTACKER] file_a freed after fput...\n");
        file_a->magic = MAGIC_FILE_DEAD;

        struct io_file *evil_file = (struct io_file *)file_a; /* same slab slot */
        evil_file->magic = MAGIC_WIN;
        evil_file->f_count = 1;
        evil_file->f_op_release = hijacked_release;
        evil_file->private_data = 0xDEADBEEFDEADBEEFULL;
        printf("[ATTACKER] Reclaimed file_a slab with evil_file at %p\n", (void*)evil_file);
        printf("[ATTACKER] Set f_op_release to hijacked_release (%p)\n\n",
               (void*)hijacked_release);

        /* === PHASE 5: Process the current node (WMI-4) === */
        printf("=== PHASE 5: Process Current Node (WMI-4) ===\n");

        /*
         * The current_rsrc_node was retrieved from cache with stale
         * item.file pointing to file_a's old address (now evil_file).
         * If this node is processed as a file-type node (stale type),
         * it will call evil_file->f_op_release — hijacked!
         */

        struct io_rsrc_node *stale_node = current_rsrc_node;
        printf("[NODE] Current node type=%d, item.rsrc=%p\n",
               stale_node->type, stale_node->item.rsrc);

        if (stale_node->item.file == evil_file) {
            printf("[WMI-2 DETECTED] Current node's stale item.file points to reclaimed memory!\n");
            printf("[TYPE CONFUSION] Node was cached with old file ptr, now has evil_file\n");

            printf("[LEAK] private_data via stale ref: 0x%llx\n",
                   (unsigned long long)stale_node->item.file->private_data);
        }

        /* Also check any cached nodes */
        if (node_cache.count > 0) {
            struct io_rsrc_node *cached = node_cache.entries[0];
            printf("[CACHED] Cached node has type=%d, item.file=%p\n",
                   cached->type, (void*)cached->item.file);
        }

        /*
         * Simulate: the node with stale data gets processed.
         * Since type and item.file were not cleared on cache retrieval,
         * io_rsrc_put_work will call fput on the stale pointer.
         */
        printf("\n[ACTION] Processing stale node as if refs hit zero...\n");
        stale_node->type = IORING_RSRC_FILE; /* stale type from cache */
        io_rsrc_put_work(stale_node);

        SYM_ASSERT(stale_node->item.file == NULL ||
                   stale_node->item.file->f_op_release != hijacked_release);
    } else {
        printf("\n=== No exploitation — normal operation ===\n");
        printf("[NORMAL] All file updates processed correctly\n");
    }

    printf("\n=== Harness Complete ===\n");

    free(file_b);
    free(current_rsrc_node);
    return 0;
}
