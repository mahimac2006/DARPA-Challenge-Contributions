# Netfilter (nf_tables) -- WMI Findings

## What Does Netfilter Do?
Netfilter is the Linux kernel's firewall framework. `nf_tables` is the modern
subsystem that lets users create firewall rules with "sets" -- collections of
IP addresses, ports, etc. that rules can match against. Set elements can have
**timeouts**, and the kernel runs a **garbage collector (GC)** in the background
to clean up expired ones.

## Where Are the WMIs?
The GC runs as an async worker **without holding the main lock** (`commit_mutex`).
Meanwhile, userspace can delete the same elements through netlink. When both
try to touch the same element at the same time, bad things happen.

---

## Finding NF-1: GC Worker Races with Element Deletion

**WMI types**: WMI-1 (stale pointer), WMI-3 (double free), WMI-4 (function pointer hijack)

**Where in the code**:
- `net/netfilter/nft_set_hash.c`, function `nft_rhash_gc()`, lines 312-385
- `net/netfilter/nf_tables_api.c`, function `nft_trans_gc_work_done()`, lines 9547-9573

### What Happens 

1. The GC worker wakes up and starts scanning the hash table for expired elements.
   It reads a sequence number (`gc_seq`) at the start to detect if anything changed.

2. It finds an expired element and saves a pointer to it in a batch list.

3. **Meanwhile**, userspace sends a "delete this element" command via netlink.
   The kernel processes it: removes the element from the table, commits the
   change, and frees the element's memory.

4. The GC worker doesn't know this happened. It still has the old pointer in its
   batch. The sequence number check (`gc_seq`) is supposed to catch this, but
   there's a **timing gap**: if the userspace operation started *after* the GC
   read the sequence number but *before* it reached that element, the check
   passes even though the element is already freed.

5. The GC worker now tries to process the freed element -- **use-after-free**.

### Why This Is Dangerous
- **WMI-1**: The GC batch holds a pointer to freed memory (stale reference)
- **WMI-3**: Both the GC and the userspace commit try to free the same element (double free)
- **WMI-4**: An attacker can reclaim the freed element's memory with controlled data.
  The element contains an `ops` structure with function pointers (like `eval`).
  When the packet-processing path calls `ops->eval()`, it jumps to whatever
  address the attacker wrote there.

This pattern is the root cause of real-world CVEs: CVE-2023-4244, CVE-2024-1085, CVE-2024-1086.

---

## Finding NF-2: Pipapo GC Hardcodes Sequence Number to Zero

**WMI types**: WMI-1 (stale pointer), WMI-2 (info leak via type confusion)

**Where in the code**:
- `net/netfilter/nft_set_pipapo.c`, function `pipapo_gc()`, lines 1578-1641

### What Happens 

The pipapo set type (used for range-based matching like IP subnets) has its
own GC. When it allocates a GC transaction, it hardcodes the sequence number
to `0` instead of reading the current value:

```c
gc = nft_trans_gc_alloc(set, 0, GFP_KERNEL);  // should use real gc_seq!
```

This means the staleness check that's supposed to detect races will
**incorrectly pass** whenever the global sequence number happens to be 0
(at startup, or after an even number of commits wrap it back to 0).

Additionally, pipapo uses a "clone and swap" design: the GC removes elements
from the clone, but the **old copy** (still in use for packet lookups) still
references the freed elements until the swap happens.

### Why This Is Dangerous
- **WMI-1**: Packet lookups through the old copy follow pointers to freed elements
- **WMI-2**: If that freed memory is reclaimed by a different object type, the
  packet path reads the new object's data through the stale pointer -- leaking
  kernel memory contents

---

## Finding NF-3: Catchall GC Forgets to Clean Up the Container

**WMI types**: WMI-1 (stale pointer), WMI-3 (arbitrary free)

**Where in the code**:
- `net/netfilter/nf_tables_api.c`, function `nft_trans_gc_catchall_async()`, lines 9688-9713

### What Happens 

Sets can have a "catchall" element (a default match). The async GC for catchall
elements frees the element data but **forgets to remove the container** from
the catchall list. The container (`struct nft_set_elem_catchall`) stays on the
list with its `->elem` pointer now pointing to freed memory.

The synchronous version of this code (`nft_trans_gc_catchall_sync`) correctly
removes the container. The async version just... doesn't.

The next time anything iterates the catchall list (another GC cycle, a flush
operation), it follows the dangling `->elem` pointer into freed memory.

### Why This Is Dangerous
- **WMI-1**: Container on the list still points to freed element
- **WMI-3**: A subsequent iteration that tries to free through this stale
  pointer can be manipulated to free an attacker-chosen address

---

## KLEE Results

Running the netfilter harness through KLEE confirms the WMI-4 function pointer
hijack is reachable. KLEE explored 3 complete paths and 1 partial path,
generating 4 test cases. The assertion violation proves the exploit path exists:

```
=== PHASE 5: Packet Path Evaluation (WMI-4) ===
[EVAL] Packet path evaluating expression via stale element at 0x734163000000
[EVAL] ops = 0x72cfe3000000, ops->eval = 0x73e9e9000000
[WMI-4 DETECTED] Function pointer hijacked!
[EXPLOITATION SUCCESS] win_eval called — attacker hijacked control flow!
KLEE: ERROR: harnesses/netfilter_harness.c:319: ASSERTION FAIL: stale->ops->marker != 0x57494E21
KLEE: NOTE: now ignoring this error at this location

KLEE: done: total instructions = 9844
KLEE: done: completed paths = 3
KLEE: done: partially completed paths = 1
KLEE: done: generated tests = 4
```

KLEE found that when the TOCTOU race is exploited (gc_seq bumped twice,
returning to the original value), the GC processes stale element pointers.
After slab reclamation, the attacker-controlled `ops->eval` function pointer
is called, confirming WMI-4.
