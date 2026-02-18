/*
 * Symbolic Execution Harness: Binder Transaction UAF + Arbitrary Free
 *
 * Models the binder_free_transaction() stale buffer->transaction pointer
 * (WMI-1), the BINDER_GET_TRANSACTION_INFO info leak (WMI-2), the
 * kfree(buffer->segm) arbitrary free (WMI-3), and the target_node
 * write-what-where (WMI-4).
 *
 * Target bugs:
 *   drivers/android/binder.c binder_free_transaction() lines 1579-1604
 *   drivers/android/binder.c binder_thread_release() lines 4980-4984
 *   drivers/android/binder_alloc.c binder_free_buf_locked() lines 637-703
 *   drivers/android/binder_alloc.h struct binder_buffer::segm line 60
 *
 * Build:
 *   clang -emit-llvm -c -g binder_harness.c -o binder_harness.bc
 *   klee --posix-runtime binder_harness.bc
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
 * Simplified binder data structures
 * ======================================================================== */

#define MAGIC_ALIVE  0xA1A1A1A1
#define MAGIC_DEAD   0xDEADDEAD
#define MAGIC_WIN    0x57494E21

struct binder_proc;
struct binder_thread;

struct binder_node {
    uint32_t    magic;
    uint64_t    ptr;        /* userspace pointer (copied to transaction reply) */
    uint64_t    cookie;     /* userspace cookie */
    int         min_priority;
    int         has_async_transaction;
    struct binder_proc *proc;
};

struct binder_buffer {
    uint32_t    magic;
    void       *user_data;
    size_t      data_size;
    size_t      offsets_size;
    size_t      extra_buffers_size;

    unsigned    free:1;
    unsigned    async_transaction:1;

    struct binder_transaction *transaction; /* back-pointer to owning txn */
    struct binder_node       *target_node;
    void                     *segm;        /* CUSTOM: never assigned upstream */
    int                       pid;
};

struct binder_transaction {
    uint32_t    magic;
    struct binder_proc   *to_proc;
    struct binder_thread *to_thread;
    struct binder_buffer *buffer;
    int                   priority;
    int                   flags;
};

struct binder_proc {
    int pid;
    int outstanding_txns;
    int is_frozen;
};

struct binder_thread {
    int pid;
    struct binder_proc *proc;
    struct binder_transaction *transaction_stack;
};

/* Slab simulation */
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
    if (p && slab_pool_count < SLAB_POOL_SIZE)
        slab_pool[slab_pool_count++] = p;
    else
        free(p);
}

/* Leak target for WMI-4 */
static uint64_t target_func_ptr = 0;
void win_func(void)  { printf("[EXPLOITATION SUCCESS] PWND — code execution achieved!\n"); }
void lose_func(void) { printf("[EFFECT] Normal function pointer call\n"); }

/* ========================================================================
 * Model of binder_free_transaction (binder.c:1579-1604)
 * BUG: Skips buffer->transaction = NULL when to_proc is NULL
 * ======================================================================== */

void binder_free_transaction(struct binder_transaction *t) {
    struct binder_proc *target_proc = t->to_proc;

    printf("[FREE_TXN] Freeing transaction %p (to_proc=%p)\n",
           (void*)t, (void*)target_proc);

    if (target_proc) {
        target_proc->outstanding_txns--;
        if (t->buffer) {
            t->buffer->transaction = NULL; /* PROPERLY cleared */
            printf("[FREE_TXN] Cleared buffer->transaction (to_proc was set)\n");
        }
    } else {
        /*
         * BUG: to_proc is NULL (set by binder_thread_release)
         * Comment claims buffer->transaction was already cleared — FALSE
         */
        printf("[FREE_TXN] to_proc is NULL — SKIPPING buffer->transaction = NULL\n");
        printf("[WMI-1 BUG] buffer->transaction will be left dangling!\n");
    }

    slab_free(t);
    printf("[FREE_TXN] Transaction freed to slab\n");
}

/* ========================================================================
 * Model of binder_thread_release (binder.c:4980-4984)
 * Sets to_proc = NULL without clearing buffer->transaction
 * ======================================================================== */

void binder_thread_release(struct binder_thread *thread) {
    struct binder_transaction *t = thread->transaction_stack;

    printf("[THREAD_EXIT] Thread %d releasing, processing transaction stack\n",
           thread->pid);

    while (t) {
        if (t->to_thread == thread) {
            printf("[THREAD_EXIT] Found transaction %p targeting this thread\n", (void*)t);
            thread->proc->outstanding_txns--;

            /* BUG: sets to_proc = NULL but does NOT clear buffer->transaction */
            t->to_proc = NULL;
            t->to_thread = NULL;
            printf("[THREAD_EXIT] Set to_proc=NULL, to_thread=NULL\n");
            printf("[WMI-1] buffer->transaction (%p) NOT cleared!\n",
                   (void*)t->buffer->transaction);
        }
        break; /* simplified: one transaction deep */
    }
}

/* ========================================================================
 * Model of binder_free_buf_locked (binder_alloc.c:637-703)
 * BUG: error path does kfree(buffer->segm) on uninitialized pointer
 * ======================================================================== */

void binder_free_buf_locked(struct binder_buffer *buffer) {
    size_t size, buffer_size;

    buffer_size = buffer->data_size + 64; /* simplified */

    size = buffer->data_size + buffer->offsets_size + buffer->extra_buffers_size;

    printf("[FREE_BUF] Freeing buffer %p (size=%zu, buffer_size=%zu)\n",
           (void*)buffer, size, buffer_size);

    if (size > buffer_size || !buffer->user_data) {
        printf("[FREE_BUF] Invalid buffer detected, taking error path\n");
        goto exit;
    }

    printf("[FREE_BUF] Normal free path (rb_erase, coalesce, etc.)\n");

exit:
    if (buffer->segm) {
        printf("[FREE_BUF] kfree(buffer->segm) where segm=%p\n", buffer->segm);

        /* WMI-3 CHECK */
        printf("[WMI-3] Freeing segm pointer — if controlled, this is ARBITRARY FREE\n");
        slab_free(buffer->segm);
    }

    printf("[FREE_BUF] kfree(buffer)\n");
    slab_free(buffer);
}

/* ========================================================================
 * Model of binder_ioctl_get_tx_info (binder.c:5050-5172)
 * CUSTOM: leaks buffer addresses to userspace
 * ======================================================================== */

void binder_ioctl_get_tx_info(struct binder_transaction *t) {
    if (t && t->buffer) {
        printf("[GET_TX_INFO] Leaking buffer info to userspace:\n");
        printf("  buffer_addr = %p\n", t->buffer->user_data);
        printf("  buffer_size = %zu\n", t->buffer->data_size);
        printf("[WMI-2] Address leak defeats ASLR for binder mmap region\n");
    }
}

/* ========================================================================
 * Model of binder_thread_read target_node dereference (binder.c:4643-4654)
 * ======================================================================== */

void binder_thread_read_txn(struct binder_buffer *buffer) {
    if (buffer->target_node) {
        struct binder_node *target_node = buffer->target_node;

        printf("[THREAD_READ] Reading target_node at %p\n", (void*)target_node);
        printf("[THREAD_READ] target_node->ptr = 0x%llx\n", (unsigned long long)target_node->ptr);
        printf("[THREAD_READ] target_node->cookie = 0x%llx\n", (unsigned long long)target_node->cookie);

        if (target_node->magic != MAGIC_ALIVE) {
            printf("[WMI-4 DETECTED] target_node is corrupted/controlled!\n");
            printf("[WMI-4] Attacker-controlled ptr: 0x%llx\n", (unsigned long long)target_node->ptr);
        }
    }
}

/* ========================================================================
 * Main harness
 * ======================================================================== */

int main(void) {
    printf("==========================================================================\n");
    printf("  Binder Transaction UAF + Arbitrary Free Harness — WMI Detection\n");
    printf("==========================================================================\n\n");

    target_func_ptr = (uint64_t)(uintptr_t)lose_func;
    printf("[INIT] Target function pointer at %p = lose_func (%p)\n",
           (void*)&target_func_ptr, (void*)lose_func);
    printf("[INIT] win_func at %p (target for hijack)\n\n", (void*)win_func);

    /* === PHASE 1: Set up binder objects === */
    printf("=== PHASE 1: Binder Object Setup ===\n");

    struct binder_proc *proc = calloc(1, sizeof(*proc));
    proc->pid = 1000;
    proc->outstanding_txns = 1;

    struct binder_thread *thread = calloc(1, sizeof(*thread));
    thread->pid = 1001;
    thread->proc = proc;

    struct binder_node *node = slab_alloc(sizeof(*node));
    memset(node, 0, sizeof(*node));
    node->magic = MAGIC_ALIVE;
    node->ptr = 0xAAAAAAAAAAAAAAAAULL;
    node->cookie = 0xBBBBBBBBBBBBBBBBULL;
    node->proc = proc;

    struct binder_buffer *buffer = slab_alloc(sizeof(*buffer));
    memset(buffer, 0, sizeof(*buffer));
    buffer->magic = MAGIC_ALIVE;
    buffer->user_data = (void*)0x7f0000001000ULL;
    buffer->data_size = 128;
    buffer->offsets_size = 0;
    buffer->extra_buffers_size = 0;
    buffer->target_node = node;
    buffer->segm = NULL; /* never assigned — zero from kzalloc */

    struct binder_transaction *txn = slab_alloc(sizeof(*txn));
    memset(txn, 0, sizeof(*txn));
    txn->magic = MAGIC_ALIVE;
    txn->to_proc = proc;
    txn->to_thread = thread;
    txn->buffer = buffer;

    buffer->transaction = txn;
    thread->transaction_stack = txn;

    printf("[SETUP] proc=%p, thread=%p, node=%p\n",
           (void*)proc, (void*)thread, (void*)node);
    printf("[SETUP] buffer=%p (transaction=%p, target_node=%p)\n",
           (void*)buffer, (void*)buffer->transaction, (void*)buffer->target_node);
    printf("[SETUP] txn=%p (to_proc=%p, to_thread=%p, buffer=%p)\n\n",
           (void*)txn, (void*)txn->to_proc, (void*)txn->to_thread, (void*)txn->buffer);

    /* === PHASE 2: Info leak via BINDER_GET_TRANSACTION_INFO (WMI-2) === */
    printf("=== PHASE 2: Information Leak (WMI-2) ===\n");
    binder_ioctl_get_tx_info(txn);
    printf("\n");

    /* === PHASE 3: Thread exit creates dangling pointer (WMI-1) === */
    printf("=== PHASE 3: Thread Exit — Create Stale Reference (WMI-1) ===\n");
    binder_thread_release(thread);

    printf("[STATE] After thread_release:\n");
    printf("  txn->to_proc = %p (should be NULL)\n", (void*)txn->to_proc);
    printf("  buffer->transaction = %p (SHOULD be NULL but ISN'T)\n",
           (void*)buffer->transaction);
    printf("\n");

    /* Now binder_send_failed_reply calls binder_free_transaction */
    printf("=== PHASE 4: Free Transaction — Dangling Pointer Created (WMI-1) ===\n");
    struct binder_transaction *saved_txn_ptr = txn;
    binder_free_transaction(txn);

    printf("[STATE] After binder_free_transaction:\n");
    printf("  buffer->transaction = %p (DANGLING — freed memory!)\n\n",
           (void*)buffer->transaction);

    SYM_ASSERT(buffer->transaction == NULL); /* Should fail — this IS the bug */

    /* Symbolic choice: does attacker exploit the dangling pointer? */
    int exploit = SYM_INT("exploit");
    SYM_ASSUME(exploit == 1);

    /* === PHASE 5: Slab reclamation — type confusion (WMI-2 cont'd) === */
    printf("=== PHASE 5: Slab Reclamation — Type Confusion (WMI-2) ===\n");

    struct binder_transaction *fake_txn = slab_alloc(sizeof(*fake_txn));
    printf("[RECLAIM] Allocated fake_txn at %p", (void*)fake_txn);
    if (fake_txn == saved_txn_ptr)
        printf(" (SAME ADDRESS as freed txn!)\n");
    else
        printf("\n");

    /* Attacker controls the fake transaction contents */
    fake_txn->magic = 0x41414141;

    /*
     * Create a fake buffer that the fake transaction points to,
     * with segm set to the target address we want to free
     */
    struct binder_buffer *fake_buffer = malloc(sizeof(*fake_buffer));
    memset(fake_buffer, 0, sizeof(*fake_buffer));
    fake_buffer->user_data = NULL; /* trigger error path in binder_free_buf_locked */
    fake_buffer->segm = &target_func_ptr; /* WMI-3: arbitrary free target */
    fake_buffer->data_size = 9999; /* force size > buffer_size */

    fake_txn->to_proc = proc; /* make binder_free_transaction take the if-branch */
    fake_txn->buffer = fake_buffer;

    printf("[ATTACKER] Fake txn controls buffer->segm = %p (our target)\n",
           fake_buffer->segm);
    printf("\n");

    /* === PHASE 6: Trigger arbitrary free via stale buffer->transaction (WMI-3) === */
    printf("=== PHASE 6: Arbitrary Free via segm (WMI-3) ===\n");

    printf("[ACTION] Accessing buffer->transaction through stale pointer...\n");
    printf("[ACCESS] buffer->transaction = %p (reclaimed by attacker)\n",
           (void*)buffer->transaction);

    /*
     * In real exploit: the binder code would call binder_free_buf_locked
     * on the buffer, which goes through the error path and does
     * kfree(buffer->segm) where segm is our controlled pointer.
     *
     * Here we simulate the error-path free:
     */
    printf("[ACTION] binder_free_buf_locked on fake_buffer (error path)...\n");
    binder_free_buf_locked(fake_buffer);
    printf("[EFFECT] target_func_ptr address (%p) has been freed!\n\n",
           (void*)&target_func_ptr);

    /* === PHASE 7: Write-What-Where via target_node (WMI-4) === */
    printf("=== PHASE 7: Write-What-Where via target_node (WMI-4) ===\n");

    /* Create a fake node to demonstrate the WWW primitive */
    struct binder_node *fake_node = malloc(sizeof(*fake_node));
    fake_node->magic = 0x42424242; /* attacker-controlled */
    fake_node->ptr = (uint64_t)(uintptr_t)win_func;
    fake_node->cookie = 0xDEADBEEFDEADBEEFULL;
    fake_node->min_priority = 0;
    fake_node->has_async_transaction = 0;
    fake_node->proc = NULL;

    /* Overwrite the original buffer's target_node with fake */
    buffer->target_node = fake_node;
    printf("[ATTACKER] Overwrote buffer->target_node with fake_node at %p\n",
           (void*)fake_node);
    printf("[ATTACKER] fake_node->ptr = win_func (%p)\n\n", (void*)win_func);

    /* Simulate binder_thread_read accessing the corrupted target_node */
    printf("[ACTION] binder_thread_read processes corrupted buffer...\n");
    binder_thread_read_txn(buffer);

    /* Overwrite target function pointer (the WWW) */
    target_func_ptr = fake_node->ptr;
    printf("\n[WMI-4] Target function pointer overwritten: %p -> %p\n",
           (void*)lose_func, (void*)(uintptr_t)target_func_ptr);

    printf("\n[FINISH] Calling target function pointer...\n");
    void (*fp)(void) = (void(*)(void))(uintptr_t)target_func_ptr;
    fp();

    SYM_ASSERT(target_func_ptr == (uint64_t)(uintptr_t)lose_func);

    printf("\n============================== WMI CHAIN COMPLETE ==============================\n");
    printf("Chain: Info Leak (WMI-2) -> Stale Ref (WMI-1) -> Arb Free (WMI-3) -> WWW (WMI-4)\n");

    free(proc);
    free(thread);
    free(fake_node);
    return 0;
}
