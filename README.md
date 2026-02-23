## Target Kernel Modules
- **netfilter** (nf_tables set element GC subsystem)
- **io_uring** (resource node lifecycle, request recycling)
- **binder** (transaction/buffer lifecycle, custom modifications)

---

### Initial Prompt & Understanding the Task

My first prompt to the LLM (I used the Opus 4.6 model on Cursor):
> For this challenge, focus on the following Linux kernel modules:
> - netfilter
> - io_uring
> - binder
>
> Identify potential Sample3 WMIs in these modules and write symbolic execution harnesses to detect them.

I also provided the exploitation chain:
- WMI-1: Stale Reference (use-after-free)
- WMI-2: Type Confusion Leak (read freed memory reclaimed by different type)
- WMI-3: Arbitrary Free (kfree on attacker-controlled pointer)
- WMI-4: Write-What-Where (overwrite function pointer via reclaimed memory)

---

### How the LLM Found WMI Patterns

Once the WMI model was clear, the LLM launched parallel searches across all three modules 
simultaneously, looking for vulnerability patterns matching WMI-1 through WMI-4.

For each module, it:
1. Read the key source files (the main .c files and headers)
2. Looked for object lifecycle issues: places where objects get freed while
   something still points to them
3. Identified specific functions and line numbers
4. Classified each finding as WMI-1, 2, 3, or 4

The LLM found a lot of candidates. Some turned out to be false positives --
for example, it initially flagged `binder_translate_handle()` as a TOCTOU
race on `node->proc`, but that's actually serialized by `node->lock` so
both code paths can't run at the same time. The LLM caught this itself when
it re-read the source to verify.

### How the Harnesses Were Written

The harnesses are modeled after the structure of the original WMI sample:

```
1. INIT:    Set up simplified versions of the kernel data structures
2. ALLOC:   Create objects that point to each other
3. PHASE 1: Free one object while the other still points to it  (WMI-1)
4. PHASE 2: Reclaim the freed memory with attacker-controlled data (WMI-2)
5. PHASE 3: Use the stale pointer to trigger a free on a target  (WMI-3)
6. PHASE 4: Reclaim the target, overwrite a function pointer      (WMI-4)
7. ASSERT:  Check if the function pointer was hijacked
```

### Slab Simulation
In the real kernel, when you kfree() something, the allocator doesn't throw the memory away -- it puts it on a freelist. The next kmalloc() of the same size hands back the same address. That's how attackers reclaim freed memory with controlled data.
The harnesses can't use the real kernel allocator, so they fake this with a simple pool. When you free a pointer, it goes into an array. When you allocate, it checks the array first and returns the same pointer. That's why KLEE's output shows "SAME ADDRESS as freed txn!"

### What Each Harness Detects
- **netfilter_harness**: (3 findings) Detects WMI-1 through WMI-4 (GC race → slab reclaim → double free → function pointer hijack)
- **io_uring_harness**: (4 findings) Detects WMI-2 (stale cache data leak) and WMI-4 (hijacked file release)
- **binder_harness**: (5 findings) Detects WMI-1 through WMI-4 (dangling pointer → slab reclaim → arbitrary free via segm → write-what-where → code execution)

### Refinements During Development
The binder harness originally used `klee_assert` for the intermediate WMI-1
check. Since `klee_assert` **terminates the path** on failure, KLEE would
stop at WMI-1 and never reach WMI-3 or WMI-4. The fix was to replace the
intermediate assertion with `klee_warning`, which logs the detection without
killing the path. The final WMI-4 assertion remains as `klee_assert`.

