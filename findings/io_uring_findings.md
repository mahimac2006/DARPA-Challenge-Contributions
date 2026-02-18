# io_uring -- WMI Findings

## What Does io_uring Do?
io_uring is Linux's high-performance async I/O interface. It lets userspace
submit I/O operations (read, write, network calls, etc.) into a shared ring
buffer, and the kernel processes them asynchronously. For speed, it **recycles
internal objects through caches** instead of freeing and reallocating them.

## Where Are the WMIs?
The recycling caches don't fully clear old data when handing out reused objects.
Also, when the kernel unregisters files or buffers, it has to drop its main lock
temporarily, creating a window where in-flight operations can get confused.

---

## Finding 1: Recycled Resource Nodes Keep Old Pointers

**WMI types**: WMI-2 (info leak / type confusion), WMI-4 (function pointer hijack)

**Where in the code**:
- `io_uring/rsrc.c`, function `io_rsrc_node_destroy()`, lines 170-174
- `io_uring/rsrc.c`, function `io_rsrc_node_alloc()`, lines 197-215

### What Happens 

When a resource node (which tracks registered files/buffers) is done being
used, instead of freeing it, the kernel puts it in a cache for reuse:

```c
// "Destroying" a node just puts it in the cache
io_alloc_cache_put(&ctx->rsrc_node_cache, &node->cache);
```

When a new node is needed, it pulls one from the cache. But it only resets
**three fields** (ctx, empty, refs). It does **not** clear the `item` union
(which holds file/buffer pointers) or the `type` field:

```c
ref_node->ctx = ctx;
ref_node->empty = 0;
ref_node->refs = 1;
// item.file and type are STILL set from the previous use!
```

So a recycled node still "remembers" the file pointer from its previous life.

### Why This Is Dangerous

- **WMI-2**: If the old file was freed between uses, the recycled node's
  `item.file` now points to freed memory. If that memory was reclaimed by
  a different object, reading through the stale pointer leaks data from
  the new object (type confusion).

- **WMI-4**: When the node is eventually processed by `io_rsrc_put_work()`,
  it calls `fput()` on whatever `item.file` points to. If an attacker
  reclaimed that memory with a fake file object containing a controlled
  `f_op->release` function pointer, `fput()` calls it -- code execution.

Note: freshly allocated nodes (via `kzalloc`) are zero-initialized and safe.
Only **cached** nodes have this problem. Since caching is the fast path,
most nodes in practice are recycled.

---

## Finding 2: Lock Gets Dropped During File Unregistration

**WMI types**: WMI-1 (stale pointer)

**Where in the code**:
- `io_uring/rsrc.c`, function `io_rsrc_ref_quiesce()`, lines 217-274
- `io_uring/rsrc.c`, function `io_sqe_files_unregister()`, lines 680-698

### What Happens 

When userspace unregisters its fixed files, the kernel needs to wait for all
in-flight operations using those files to finish. To do this, it calls
`io_rsrc_ref_quiesce()`, which **drops the main lock** (`uring_lock`) while
waiting.

During this lock-drop window:
1. The file table still exists and contains pointers
2. Background threads (like SQPOLL) can run
3. The resource node gets swapped out

If a request had already grabbed the old resource node (during SQE setup,
before the lock was dropped) but hasn't incremented its reference count yet,
it's now holding a pointer to a node that's about to be destroyed.

### Why This Is Dangerous
- **WMI-1**: The in-flight request has a stale pointer to a resource node
  that gets freed during the quiesce. Any subsequent use of that node
  is a use-after-free.

---

## Finding 3: Recycled Requests Keep Old Operation Data

**WMI types**: WMI-2 (data leak across operations), WMI-4 (stale function pointers)

**Where in the code**:
- `io_uring/io_uring.c`, function `__io_req_complete_post()`, lines 1129-1179
- `io_uring/io_uring.c`, function `io_preinit_req()`, lines 1216-1224

### What Happens 

When an I/O request completes, instead of being freed, it goes onto a free
list for reuse. The initialization function (`io_preinit_req`) only runs on
**brand new** allocations from the slab allocator, not on recycled requests.

Recycled requests go through `io_init_req()` which sets common fields, but
each operation type's `prep` function is responsible for initializing its
own specific data in a shared union. If a `prep` function doesn't overwrite
**every** field in the union, leftover data from the previous operation
survives.

### Why This Is Dangerous
- **WMI-2**: Data from operation type A (say, a network read) leaks into
  operation type B (say, a file write) through the shared union. This is
  type confusion within the same struct.
- **WMI-4**: If function pointer fields (like `io_task_work.func`) aren't
  overwritten by the new operation, the old function pointer is called.

---

## Finding 4: Resource Node Ref Count Race During File Updates

**WMI types**: WMI-1 (stale pointer), WMI-3 (arbitrary fput)

**Where in the code**:
- `io_uring/rsrc.c`, function `io_queue_rsrc_removal()`, lines 639-658

### What Happens

When a fixed file slot is updated (replaced with a different file):
1. The kernel grabs the **current** resource node
2. Swaps in a fresh node as the new current
3. Stashes the old file in the captured node
4. Decrements the captured node's reference count

The problem: between step 1 (a request captures the node) and when it
actually uses the file, another thread can do the swap (steps 2-4). If the
reference count hits zero, the node gets processed and destroyed -- while
the request still thinks it has a valid reference.

### Why This Is Dangerous
- **WMI-1**: The request holds a pointer to a destroyed resource node
- **WMI-3**: `io_rsrc_put_work()` calls `fput()` on whatever file pointer
  is stashed in the node. If the node was recycled with a controlled value
  (see Finding IU-1), this becomes an arbitrary `fput()` on an attacker-
  chosen address

---

## KLEE Results

Running the io_uring harness through KLEE confirms both WMI-2 (type confusion
leak) and WMI-4 (function pointer hijack) are reachable. KLEE explored 1
complete path and 1 partial path, generating 2 test cases:

```
=== PHASE 2: File Update — Node Caching ===
[REMOVAL] Capturing current node 0x77c96f600000 for removal
[REMOVAL] Stashed file 0x77c56f600000 in old node, decrementing refs
[REMOVAL] Refs hit zero, processing immediately
[PUT_WORK] Calling fput on file 0x77c56f600000 (magic=0xf11ef11e)
[EFFECT] normal_release called — safe fput
[CACHE] Node 0x77c96f600000 placed in cache (item.rsrc=0x77c56f600000, type=0)

=== PHASE 3: Second Update — Cache Retrieval (WMI-2) ===
[CACHE] Retrieved node 0x77c96f600000 from cache
  [STALE] item.rsrc = 0x77c56f600000 (NOT CLEARED)
  [STALE] type = 0 (NOT CLEARED)

=== PHASE 4: Exploiting Stale Cache Data ===
[ATTACKER] Reclaimed file_a slab with evil_file at 0x77c56f600000
[ATTACKER] Set f_op_release to hijacked_release (0x7881f5600000)

=== PHASE 5: Process Current Node (WMI-4) ===
[NODE] Current node type=0, item.rsrc=0x77c56f600000
[WMI-2 DETECTED] Current node's stale item.file points to reclaimed memory!
[TYPE CONFUSION] Node was cached with old file ptr, now has evil_file
[LEAK] private_data via stale ref: 0xdeadbeefdeadbeef

[ACTION] Processing stale node as if refs hit zero...
[PUT_WORK] Calling fput on file 0x77c56f600000 (magic=0x57494e21)
[WMI-4 DETECTED] File release function hijacked!
[EXPLOITATION SUCCESS] hijacked_release called — attacker controls fput!
KLEE: ERROR: harnesses/io_uring_harness.c:291: ASSERTION FAIL: stale_node->item.file == ((void*)0) || stale_node->item.file->f_op_release != hijacked_release

KLEE: done: total instructions = 1904
KLEE: done: completed paths = 1
KLEE: done: partially completed paths = 1
KLEE: done: generated tests = 2
```

KLEE confirmed the full chain:
- **WMI-2**: A cached node retains a stale `item.file` pointer (`0x77c56f600000`) from its previous lifecycle. The `item.rsrc` and `type` fields are **NOT CLEARED** on cache retrieval. After the file is freed and reclaimed with attacker data, reading through the stale pointer leaks `0xdeadbeefdeadbeef` (type confusion).
- **WMI-4**: `io_rsrc_put_work()` calls `fput()` on the stale pointer, which invokes the attacker's `hijacked_release` function -- code execution achieved.
