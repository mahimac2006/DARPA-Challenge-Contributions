## Target Kernel Modules
- **netfilter** (nf_tables set element GC subsystem)
- **io_uring** (resource node lifecycle, request recycling)
- **binder** (transaction/buffer lifecycle, custom modifications)

## WMI Primitive Definitions (from Sample)
| Primitive | Description |
|-----------|-------------|
| **WMI-1** | Stale Reference (UAF) -- object freed while another object still holds a pointer |
| **WMI-2** | Type Confusion Leak -- freed memory reclaimed by different type, read through stale ref |
| **WMI-3** | Arbitrary Free -- stale/confused reference triggers `kfree()` on controlled address |
| **WMI-4** | Write-What-Where -- reclaim freed memory to overwrite function pointers / critical data |

---

## Methodology

### Phase 1: Initial Prompt & Understanding the Task

My first prompt to the LLM:
> For this challenge, we'll be focusing on the following Linux kernel modules:
> - netfilter
> - io_uring
> - binder
>
> Your task is to manually identify potential Sample3 WMIs in these modules
> and write symbolic execution harnesses to detect them.

I also provided the WMI sample output showing the 4-stage exploitation chain:
- WMI-1: Stale Reference (use-after-free)
- WMI-2: Type Confusion Leak (read freed memory reclaimed by different type)
- WMI-3: Arbitrary Free (kfree on attacker-controlled pointer)
- WMI-4: Write-What-Where (overwrite function pointer via reclaimed memory)

---

### Phase 2: How the LLM Found WMI Patterns

Once the WMI model was clear, the LLM did everything in a single pass. It
launched parallel searches across all three modules simultaneously, looking
for vulnerability patterns matching WMI-1 through WMI-4.

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

### What It Found

**Netfilter** (3 findings): The nf_tables garbage collector runs without
the main lock and can race with userspace element deletion. Related to real
CVEs (CVE-2023-4244, CVE-2024-1085).

**io_uring** (4 findings): Resource nodes get recycled through a cache
without clearing old file pointers. Also, the main lock gets dropped during
resource quiesce, creating a window for stale references.

**Binder** (5 findings): This kernel tree has custom modifications (a new
ioctl that leaks addresses, a `segm` field that gets kfree'd in an error
path). Combined with an upstream bug where `binder_free_transaction()` skips
clearing a back-pointer when `to_proc` is NULL, this gives a full chain.

---

### Phase 3: How the Harnesses Were Written

The LLM wrote all three harnesses after the analysis, modeled after the
structure of the original WMI sample:

```
1. INIT:    Set up simplified versions of the kernel data structures
2. ALLOC:   Create objects that point to each other
3. PHASE 1: Free one object while the other still points to it  (WMI-1)
4. PHASE 2: Reclaim the freed memory with attacker-controlled data (WMI-2)
5. PHASE 3: Use the stale pointer to trigger a free on a target  (WMI-3)
6. PHASE 4: Reclaim the target, overwrite a function pointer      (WMI-4)
7. ASSERT:  Check if the function pointer was hijacked
```

The harnesses use KLEE symbolic APIs (`klee_make_symbolic`, `klee_assume`,
`klee_assert`). To build and run:

```bash
clang -I /path/to/klee/include -emit-llvm -c -g harnesses/<harness>.c -o <harness>.bc
klee --posix-runtime <harness>.bc
```

### Slab Simulation
The harnesses simulate the Linux SLUB allocator's behavior: after `free(p)`,
a subsequent `malloc` of the same size may return `p`. This is modeled with
a simple pool where freed pointers are stored and returned on the next
allocation.

### What Each Harness Detects
KLEE explores all symbolic paths and flags assertion violations:
- **netfilter_harness**: Detects WMI-4 (function pointer hijack via GC race)
- **io_uring_harness**: Detects WMI-2 (stale cache data) and WMI-4 (hijacked release)
- **binder_harness**: Detects WMI-1 (dangling buffer->transaction pointer)

### Refinements During Development
The io_uring harness initially checked the wrong node (a cached node instead
of the current node that was retrieved from cache with stale data). The
assertion was firing on a node that had file_b, not the one with the evil
file. This was fixed to check `current_rsrc_node` which actually holds the
stale `item.file` pointer from its previous cache cycle.

The netfilter harness initially always took the path where the gc_seq check
caught the race (which is what happens in the non-buggy case). A symbolic
choice was added to model the TOCTOU gap where gc_seq gets bumped twice
(returning to the original value), causing the check to miss the race.

---

### Phase 4: Limitations

1. **Simplified concurrency**: Real races depend on CPU scheduling; the
   harnesses use nondeterministic choice to model interleavings instead
2. **Simplified heap**: Real exploitation needs precise slab cache alignment;
   we just model "malloc may return the same address after free"
3. **Stubbed kernel APIs**: Things like `rcu_read_lock` and `spin_lock` are
   no-ops in the harnesses, since the symbolic engine explores all paths
4. **Focused scope**: Each harness covers one specific bug path, not the
   entire module
5. **LLM-driven analysis**: The vulnerability identification was done by an
   LLM reading source code, not by manual auditing or dynamic analysis.
   The findings are based on code patterns and known vulnerability classes,
   not on confirmed exploitation.
