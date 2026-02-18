/*
 * Symbolic Execution Harness: nf_tables Set Element GC Race
 *
 * Models the race between the async GC worker (nft_rhash_gc) and
 * userspace delsetelem + commit. Detects WMI-1 through WMI-4.
 *
 * Target bug: net/netfilter/nft_set_hash.c nft_rhash_gc() lines 312-385
 *             net/netfilter/nf_tables_api.c nft_trans_gc_work_done() lines 9547-9573
 *
 * Build:
 *   clang -emit-llvm -c -g netfilter_harness.c -o netfilter_harness.bc
 *   klee --posix-runtime netfilter_harness.bc
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

#define MAGIC_ALIVE   0xA1A1A1A1
#define MAGIC_DEAD    0xDEADDEAD
#define MAGIC_WIN     0x57494E21  /* "WIN!" */
#define MAGIC_LOSE    0x4C4F5345  /* "LOSE" */

typedef void (*eval_fn_t)(void *ctx);

void lose_eval(void *ctx) {
    printf("[EFFECT] lose_eval called — normal execution\n");
}

void win_eval(void *ctx) {
    printf("[EXPLOITATION SUCCESS] win_eval called — attacker hijacked control flow!\n");
}

struct nft_expr_ops {
    eval_fn_t eval;
    uint32_t  marker;
};

struct nft_set_elem {
    uint32_t        magic;
    uint64_t        key;
    uint64_t        expiry;
    int             dead;
    int             active;
    struct nft_expr_ops *ops;
};

struct nft_trans_gc {
    void     *priv[16];
    unsigned  count;
    uint32_t  seq;
};

struct nft_set {
    struct nft_set_elem *elems[64];
    int                  nelems;
    int                  dead;
};

static uint32_t gc_seq_global = 0;
static int      commit_mutex_held = 0;

/* ========================================================================
 * Slab allocator simulation
 *
 * Models SLUB behavior: free(p) followed by malloc(same_size) may return p
 * ======================================================================== */

#define SLAB_POOL_SIZE 8
static void *slab_pool[SLAB_POOL_SIZE];
static int   slab_pool_count = 0;

void *slab_alloc(size_t size) {
    if (slab_pool_count > 0) {
        void *p = slab_pool[--slab_pool_count];
        return p;
    }
    return malloc(size);
}

void slab_free(void *p) {
    if (p && slab_pool_count < SLAB_POOL_SIZE) {
        slab_pool[slab_pool_count++] = p;
    } else {
        free(p);
    }
}

/* ========================================================================
 * Model of nft_rhash_gc (GC worker, runs without commit_mutex)
 * Corresponds to nft_set_hash.c:312-385
 * ======================================================================== */

struct nft_trans_gc *gc_worker_iterate(struct nft_set *set, uint32_t gc_seq) {
    struct nft_trans_gc *gc = calloc(1, sizeof(*gc));
    gc->seq = gc_seq;

    printf("[GC] Worker starts, gc_seq=%u\n", gc_seq);

    for (int i = 0; i < set->nelems; i++) {
        struct nft_set_elem *elem = set->elems[i];
        if (!elem) continue;

        if (gc_seq_global != gc_seq) {
            printf("[GC] gc_seq changed during iteration, aborting\n");
            free(gc);
            return NULL;
        }

        if (elem->dead)
            goto dead_elem;

        if (elem->expiry == 0) /* expired */
            goto needs_gc_run;

        continue;

needs_gc_run:
        elem->dead = 1;
        printf("[GC] Marked element %d dead\n", i);
dead_elem:
        gc->priv[gc->count++] = elem;
        printf("[GC] Collected element %d (ptr=%p) into trans batch\n", i, (void*)elem);
    }

    return gc;
}

/* ========================================================================
 * Model of nft_trans_gc_work_done (runs with commit_mutex)
 * Corresponds to nf_tables_api.c:9547-9573
 * ======================================================================== */

int gc_work_done(struct nft_trans_gc *gc, struct nft_set *set) {
    printf("[GC_WORK] Acquiring commit_mutex...\n");
    commit_mutex_held = 1;

    /*
     * The real code checks: READ_ONCE(nft_net->gc_seq) != trans->seq
     * The TOCTOU gap: if a transaction started AFTER the GC read gc_seq
     * but completed BEFORE gc_work_done runs, gc_seq may have been
     * bumped twice (begin+end), returning to the original value.
     * In that case, this check PASSES despite stale elements.
     *
     * We model this with a symbolic choice: does the gc_seq check
     * catch the race or not?
     */
    int toctou_miss = SYM_INT("toctou_miss");

    if (!toctou_miss && (gc_seq_global != gc->seq || set->dead)) {
        printf("[GC_WORK] gc_seq check CAUGHT the race (gc_seq=%u vs trans_seq=%u)\n",
               gc_seq_global, gc->seq);
        commit_mutex_held = 0;
        return 0;
    }

    if (toctou_miss) {
        printf("[GC_WORK] TOCTOU: gc_seq bumped twice, check MISSED the race!\n");
    }

    printf("[GC_WORK] Processing %u elements\n", gc->count);
    for (unsigned i = 0; i < gc->count; i++) {
        struct nft_set_elem *elem = gc->priv[i];

        /* WMI-1 CHECK: Is this pointer still valid? */
        printf("[GC_WORK] Deactivating element at %p (magic=0x%x)\n",
               (void*)elem, elem->magic);

        if (elem->magic == MAGIC_DEAD) {
            printf("[WMI-1 DETECTED] GC work accessing freed element at %p!\n",
                   (void*)elem);
        }

        elem->active = 0;

        for (int j = 0; j < set->nelems; j++) {
            if (set->elems[j] == elem) {
                set->elems[j] = NULL;
                break;
            }
        }
    }

    commit_mutex_held = 0;
    return 1;
}

/* ========================================================================
 * Model of nf_tables_delsetelem + commit (userspace path)
 * Corresponds to nf_tables_api.c:7210+ and commit path
 * ======================================================================== */

void userspace_delsetelem(struct nft_set *set, int idx) {
    printf("\n[USER] Deleting set element %d\n", idx);

    if (idx >= set->nelems || !set->elems[idx])
        return;

    struct nft_set_elem *elem = set->elems[idx];

    elem->active = 0;
    set->elems[idx] = NULL;

    printf("[USER] Element deactivated and removed from set\n");

    gc_seq_global++;
    printf("[USER] Commit: gc_seq bumped to %u\n", gc_seq_global);

    printf("[USER] Freeing element at %p via call_rcu path\n", (void*)elem);
    elem->magic = MAGIC_DEAD;
    slab_free(elem);
    printf("[FREE] Element freed to slab cache\n");

    gc_seq_global++;
    printf("[USER] Commit complete: gc_seq=%u\n", gc_seq_global);
}

/* ========================================================================
 * Main harness: models the GC vs delsetelem race
 * ======================================================================== */

int main(void) {
    printf("==========================================================================\n");
    printf("  Netfilter nf_tables GC Race Harness — WMI Detection\n");
    printf("==========================================================================\n\n");

    struct nft_expr_ops normal_ops = { .eval = lose_eval, .marker = MAGIC_LOSE };
    struct nft_expr_ops evil_ops   = { .eval = win_eval,  .marker = MAGIC_WIN  };

    /* INIT: Create a set with an expiring element */
    struct nft_set set = { .nelems = 0, .dead = 0 };

    struct nft_set_elem *elem0 = slab_alloc(sizeof(struct nft_set_elem));
    memset(elem0, 0, sizeof(*elem0));
    elem0->magic  = MAGIC_ALIVE;
    elem0->key    = 0x4141414141414141ULL;
    elem0->expiry = 0; /* already expired — GC will collect it */
    elem0->dead   = 0;
    elem0->active = 1;
    elem0->ops    = &normal_ops;

    set.elems[0] = elem0;
    set.nelems   = 1;

    printf("[INIT] Created set with 1 expiring element at %p\n", (void*)elem0);
    printf("[INIT] Element ops->eval = lose_eval (%p)\n", (void*)lose_eval);
    printf("[INIT] win_eval at %p (target for hijack)\n\n", (void*)win_eval);

    /* === PHASE 1: GC worker starts iterating (no commit_mutex) === */
    printf("=== PHASE 1: GC Worker Iteration (WMI-1 Setup) ===\n");

    uint32_t gc_snapshot = gc_seq_global;
    struct nft_trans_gc *gc = gc_worker_iterate(&set, gc_snapshot);
    if (!gc) {
        printf("[GC] Aborted, no race window\n");
        return 0;
    }

    printf("[GC] Worker collected %u elements, returning to workqueue\n\n", gc->count);

    /* Symbolic choice: does userspace race in before GC work runs? */
    int race_occurs = SYM_INT("race_occurs");

    if (race_occurs) {
        /* === PHASE 2: Userspace races in, frees the element (WMI-1) === */
        printf("=== PHASE 2: Userspace Delsetelem Race (WMI-1) ===\n");
        userspace_delsetelem(&set, 0);

        /* === PHASE 3: Reclaim freed memory with different type (WMI-2) === */
        printf("\n=== PHASE 3: Slab Reclamation — Type Confusion (WMI-2) ===\n");

        struct nft_set_elem *reclaimed = slab_alloc(sizeof(struct nft_set_elem));
        printf("[RECLAIM] Got allocation at %p", (void*)reclaimed);
        if (reclaimed == elem0)
            printf(" (SAME ADDRESS as freed element!)\n");
        else
            printf(" (different address)\n");

        memset(reclaimed, 0x42, sizeof(*reclaimed));
        reclaimed->ops = &evil_ops;
        reclaimed->magic = 0x42424242;
        printf("[RECLAIM] Filled reclaimed memory with controlled data\n");
        printf("[RECLAIM] Set ops->eval to win_eval (%p)\n\n", (void*)win_eval);

        /* === PHASE 4: GC work runs on stale pointers (WMI-3) === */
        printf("=== PHASE 4: GC Work Processes Stale Batch (WMI-3) ===\n");

        int success = gc_work_done(gc, &set);

        if (success) {
            printf("[WMI-3] GC work processed stale elements — double free possible!\n\n");

            printf("=== PHASE 5: Packet Path Evaluation (WMI-4) ===\n");
            struct nft_set_elem *stale = gc->priv[0];

            printf("[EVAL] Packet path evaluating expression via stale element at %p\n",
                   (void*)stale);
            printf("[EVAL] ops = %p, ops->eval = %p\n",
                   (void*)stale->ops, (void*)stale->ops->eval);

            if (stale->ops->eval == win_eval) {
                printf("[WMI-4 DETECTED] Function pointer hijacked!\n");
            }

            stale->ops->eval(NULL);

            /* This assertion should FAIL if WMI-4 is triggered */
            SYM_ASSERT(stale->ops->marker != MAGIC_WIN);
        }
    } else {
        printf("=== No race — GC work runs normally ===\n");
        gc_work_done(gc, &set);

        if (gc->count > 0) {
            struct nft_set_elem *e = gc->priv[0];
            printf("[NORMAL] Calling ops->eval on properly collected element\n");
            if (e->ops && e->ops->eval)
                e->ops->eval(NULL);
        }
    }

    printf("\n=== Harness Complete ===\n");
    free(gc);
    return 0;
}
