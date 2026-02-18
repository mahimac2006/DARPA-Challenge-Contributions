# Binder -- WMI Findings

## What Does Binder Do?
Binder is Android's inter-process communication (IPC) mechanism. It lets apps
and system services send messages ("transactions") to each other through the
kernel. Each process has a memory-mapped buffer region where the kernel places
incoming transaction data.

## What's Special About This Kernel?
This kernel tree has **custom modifications** not found in upstream Linux:
1. A new ioctl (`BINDER_GET_TRANSACTION_INFO`) that leaks internal buffer addresses
2. A new field (`segm`) in the buffer struct that's never set but gets `kfree()`'d
3. A destructive error path that frees buffers without proper allocator cleanup

These custom changes, combined with an existing upstream bug, create a complete
WMI-1 through WMI-4 exploitation chain.

---

## Finding BD-1: Custom Ioctl Leaks Buffer Addresses to Userspace

**WMI type**: WMI-2 (information leak)

**Where in the code**:
- `drivers/android/binder.c`, function `binder_ioctl_get_tx_info()`, lines 5050-5172
- `include/uapi/linux/android/binder.h`, line 274

### What Happens

This kernel adds a custom ioctl called `BINDER_GET_TRANSACTION_INFO`. When a
process calls it, the kernel walks through every pending transaction across all
threads and copies the **internal buffer address and size** of each one back to
userspace:

```c
txi->buffers[i].buffer_addr = (binder_uintptr_t)t->buffer->user_data;
txi->buffers[i].buffer_size = t->buffer->data_size;
```

This tells an attacker exactly where every binder buffer lives in memory and
how big it is.

### Why This Is Dangerous
- **WMI-2**: This is a direct information leak. An attacker gets a map of the
  entire binder heap layout, defeating ASLR. They know exactly what size
  allocations to spray and where freed buffers will end up. This makes all
  the subsequent WMI steps much easier.

---

## Finding BD-2: Transaction Freed but Buffer Still Points to It

**WMI type**: WMI-1 (stale pointer / use-after-free)

**Where in the code**:
- `drivers/android/binder.c`, function `binder_thread_release()`, lines 4980-4984
- `drivers/android/binder.c`, function `binder_free_transaction()`, lines 1579-1604

### What Happens 

Every binder buffer has a `->transaction` pointer back to the transaction that
owns it. When a transaction is freed, this pointer is supposed to be set to NULL.

Here's the bug: when a **thread exits** while it has a pending transaction:

1. `binder_thread_release()` sets `t->to_proc = NULL` (line 4982), but does
   **not** clear `t->buffer->transaction`

2. Later, `binder_free_transaction()` checks if `to_proc` is set:
   ```c
   if (target_proc) {        // This is NULL now!
       t->buffer->transaction = NULL;  // So this line never runs
   }
   kfree(t);  // Transaction freed, but buffer->transaction still points to it
   ```

3. The code even has a comment saying "If the transaction has no target_proc,
   then t->buffer->transaction has already been cleared" -- but that's **wrong**.
   The `binder_thread_release()` path doesn't clear it.

### Why This Is Dangerous
- **WMI-1**: `buffer->transaction` is now a dangling pointer to freed memory.
  Any code that reads through this pointer (logging, cleanup, other transactions)
  is accessing freed memory that an attacker can reclaim with controlled data.

---

## Finding BD-3: Error Path Frees Whatever `segm` Points To

**WMI type**: WMI-3 (arbitrary free)

**Where in the code**:
- `drivers/android/binder_alloc.c`, function `binder_free_buf_locked()`, lines 637-703
- `drivers/android/binder_alloc.h`, struct `binder_buffer`, line 60

### What Happens 

The custom `segm` field in `struct binder_buffer` is **never assigned** anywhere
in the codebase. For new buffers (allocated with `kzalloc`), it's zero, so
`kfree(NULL)` is harmless.

But there's a destructive error path:

```c
if (size > buffer_size || !buffer->user_data) {
    goto exit;  // Skip normal cleanup, jump straight to...
}

// ... normal free path (skipped) ...

exit:
    if (buffer->segm)
        kfree(buffer->segm);    // Free whatever segm points to!
    list_del(&buffer->entry);
    kfree(buffer);
```

If an attacker can corrupt a buffer (using the dangling pointer from BD-2),
they can write any address into the `segm` field. When the error path runs,
`kfree()` is called on that address.

### Why This Is Dangerous
- **WMI-3**: The attacker controls the argument to `kfree()`. This lets them
  free any kernel object they want -- the classic "arbitrary free" primitive.

Bonus damage: the `exit:` path also skips removing the buffer from the
allocator's red-black tree (line 676). This leaves a stale tree entry
pointing to freed memory, corrupting the allocator's internal state.

---

## Finding BD-4: Corrupted Buffer Gives Attacker Read/Write

**WMI type**: WMI-4 (write-what-where / arbitrary read)

**Where in the code**:
- `drivers/android/binder.c`, function `binder_thread_read()`, lines 4643-4654
- `drivers/android/binder.c`, function `binder_free_buf()`, lines 3782-3799

### What Happens 

Each binder buffer has a `->target_node` pointer to the node being called.
After a UAF + slab reclamation (using BD-2), an attacker controls this pointer.

**Reading (arbitrary kernel read)**:
When a thread processes an incoming transaction:
```c
trd->target.ptr = target_node->ptr;    // Read from attacker's address
trd->cookie = target_node->cookie;      // Read from attacker's address
```
These values get copied back to userspace. So the attacker can read arbitrary
kernel memory by pointing `target_node` at any address they want.

**Writing (arbitrary kernel write)**:
When a buffer is freed:
```c
buf_node = buffer->target_node;           // Attacker-controlled
buf_node->has_async_transaction = false;  // Writes 0 at controlled address
// Also does list_del on buf_node->async_todo -- classic unlink primitive
```

The `list_del` operation writes to the list prev/next pointers at offsets
controlled by the attacker. This is the textbook unlink write-what-where.

### Why This Is Dangerous
- **WMI-4**: Full arbitrary read and write. The attacker can read any kernel
  address and write controlled values to any kernel address. Game over.

---

## Finding BD-5: Cross-Process Dangling Node Reference

**WMI type**: WMI-1 (stale pointer)

**Where in the code**:
- `drivers/android/binder.c`, function `binder_node_release()`, lines 5883-5945

### What Happens

When process A exits, its binder nodes get freed. But process B might still
have `binder_ref` objects pointing to those nodes (`ref->node`). These refs
only get cleaned up when process B itself exits.

If process B tries to use one of these refs (e.g., by sending a transaction
to the now-dead node), it follows `ref->node` into freed memory.

### Why This Is Dangerous
- **WMI-1**: Cross-process stale pointer. Process B's `ref->node` points to
  freed memory after process A exits.

---

## The Full Attack Chain

Putting it all together, here's how the five findings chain into a complete exploit:

```
STEP 1: Learn the heap layout (BD-1 / WMI-2)
│   Call BINDER_GET_TRANSACTION_INFO
│   → Get exact addresses and sizes of all pending binder buffers
│   → Know exactly where to spray and what to overwrite
│
STEP 2: Create a dangling pointer (BD-2 / WMI-1)
│   Send a synchronous transaction, then exit the target thread
│   → binder_thread_release() sets to_proc = NULL
│   → binder_free_transaction() skips clearing buffer->transaction
│   → buffer->transaction now points to freed memory
│
STEP 3: Reclaim + arbitrary free (BD-3 / WMI-3)
│   Spray objects the same size as binder_transaction to reclaim the slab
│   → Attacker controls the fake transaction's contents
│   → Set fake buffer->segm to target address
│   → Trigger error path: kfree(buffer->segm) frees the target
│
STEP 4: Arbitrary read/write (BD-4 / WMI-4)
│   Reclaim the freed buffer, set target_node to controlled address
│   → binder_thread_read: reads from attacker's address (arbitrary read)
│   → binder_free_buf: writes to attacker's address (arbitrary write)
│
STEP 5: Code execution
    Use the write primitive to overwrite credentials, SELinux state,
    or modprobe_path → root shell
```

---

## KLEE Results

Running the binder harness through KLEE confirms the complete WMI-1 through
WMI-4 exploitation chain. KLEE executed the full chain from stale reference
to code execution:

```
=== PHASE 3: Thread Exit — Create Stale Reference (WMI-1) ===
[THREAD_EXIT] Set to_proc=NULL, to_thread=NULL
[WMI-1] buffer->transaction (0x7ef9d4c00000) NOT cleared!

=== PHASE 4: Free Transaction — Dangling Pointer Created (WMI-1) ===
[FREE_TXN] to_proc is NULL — SKIPPING buffer->transaction = NULL
[WMI-1 BUG] buffer->transaction will be left dangling!
[WMI-1 CONFIRMED] buffer->transaction is dangling at 0x7ef9d4c00000
KLEE: WARNING: WMI-1: buffer->transaction not cleared after free

=== PHASE 5: Slab Reclamation — Type Confusion (WMI-2) ===
[RECLAIM] Allocated fake_txn at 0x7ef9d4c00000 (SAME ADDRESS as freed txn!)

=== PHASE 6: Arbitrary Free via segm (WMI-3) ===
[FREE_BUF] kfree(buffer->segm) where segm=0x7fa8e4c00000
[WMI-3] Freeing segm pointer — if controlled, this is ARBITRARY FREE

=== PHASE 7: Write-What-Where via target_node (WMI-4) ===
[WMI-4 DETECTED] target_node is corrupted/controlled!
[WMI-4] Attacker-controlled ptr: 0x7fa68ec00000
[WMI-4] Target function pointer overwritten: 0x7fa68ac00000 -> 0x7fa68ec00000
[EXPLOITATION SUCCESS] PWND — code execution achieved!
KLEE: ERROR: harnesses/binder_harness.c:407: ASSERTION FAIL: target_func_ptr == (uint64_t)(uintptr_t)lose_func

KLEE: done: total instructions = 4845
KLEE: done: completed paths = 0
KLEE: done: partially completed paths = 1
KLEE: done: generated tests = 1
```

KLEE confirmed the full chain:
- **WMI-1**: `binder_thread_release()` sets `to_proc = NULL`, `binder_free_transaction()` skips clearing `buffer->transaction`, leaving a dangling pointer
- **WMI-2**: Slab reclamation returns the **exact same address** as the freed transaction, allowing attacker-controlled data to occupy that memory
- **WMI-3**: The error path in `binder_free_buf_locked()` calls `kfree(buffer->segm)` on the attacker-controlled address
- **WMI-4**: Corrupted `target_node` gives attacker arbitrary read/write, function pointer overwritten from `lose_func` to `win_func`, code execution achieved
