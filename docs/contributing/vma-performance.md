# VMA performance measurements

The changes remove unused metadata reads and repeated current-task acquisition,
and add one recovery attempt for a busy fork-time stack lookup. The measurements
below use production lookup headers with ordinary-memory adapters.

## Native benchmark method

The comparison was recorded on 2026-11-25, before and after the metadata-read
and current-task changes. Both versions used the same benchmark, GCC 14.2.0,
`-O2`, and x86_64 execution. Each run performed 200,000 operations per scenario
across 30 scenarios. Seven paired runs alternated execution order. The table
reports medians; [the CSV contains all scenarios](vma-performance.csv).

The adapters supply kernel structures, memory reads and helper results in
userspace. Their timings include fixture, branch and counter costs. The helper
adapter selects a VMA in constant time; the legacy adapter traverses a tree.
These measurements describe the native fixtures.

| Lookup scenario | Native mock ns/op, before → after | Scalar reads/op, before → after | Scalar bytes/op, before → after |
| --- | ---: | ---: | ---: |
| Main-stack pivot check | 27.13 → 17.88 | 9 → 6 | 72 → 48 |
| Main-stack syscall-source classification | 26.22 → 20.70 | 9 → 7 | 72 → 56 |
| Heap pivot check | 26.44 → 23.91 | 9 → 8 | 72 → 64 |
| Go-heap pivot check | 26.08 → 23.42 | 9 → 8 | 72 → 64 |
| File-backed source | 11.94 → 3.74 | 4 → 1 | 32 → 8 |
| File-backed pivot check | 11.60 → 12.53 | 4 → 4 | 32 → 32 |
| Anonymous source | 26.43 → 26.83 | 9 → 9 | 72 → 72 |
| Bounds-only lookup | 6.60 → 6.42 | 2 → 2 | 16 → 16 |
| VDSO pivot check | 32.79 → 33.24 | 10 → 10 | 80 → 80 |

Main-stack classification skips heap metadata after establishing the class.
Stack checks skip VDSO-name reads when a higher-priority class determines the
result. Source checks retain independent VDSO exclusion.

The modern file-source path returns `VMA_LOOKUP_EXCLUDED` after reading
`vm_file`, leaving `valid == false`. Legacy file-source lookup revalidates
the interval and skips unused flags. Its single-VMA scenario changed from eight
to seven total scalar reads and from 23.06 to 20.35 native mock ns/op.

File-backed pivot, anonymous-source and VDSO-pivot medians increased while their
read counts stayed unchanged. Keep these rows in subsequent comparisons.

## Work performed by the lookup and recovery paths

The dispatcher obtains one typed current-task pointer and passes it to both
event checks. Each event retains its own policy-scope evaluation. The modern
raw syscall hook consults selection data for unselected syscalls.

The legacy tree walk has a 35-iteration bound. Native fixtures cover balanced
trees with 1, 64 and 1,024 VMAs, chains near, at and beyond the bound, and a
cyclic fixture. Tests check the returned range or miss and termination; the
benchmark separately reports read counts.

The modern path has no tree walk or retry loop. A successful fork lookup uses
one bounds-only helper call. An initial `-EBUSY` stores the original SP for one
attempt at `schedule_tail`, before userspace execution. Recovery consumes
pending state before the lookup. A second failure leaves the stack unknown and
records `BPF_LOG_THREAD_STACK_UNAVAILABLE`.

The recovery entry probe obtains PID/TGID for each new task. Group leaders
return before a task-map lookup; nonleaders look up task state; pending threads
perform the VMA lookup. Recovery adds no syscall retry, context-switch hook,
map scan or kretprobe instance. It belongs to the helper backend and Tracee's
own-hook inventory.

## Compiled memory and object measurements

Compiled type metadata on x86_64 gave these sizes:

| Value | Before | After | Storage |
| --- | ---: | ---: | --- |
| `task_info_t` | 200 B | 200 B | Pending boolean uses padding; original SP uses the invalid range storage. |
| `vma_snapshot` | 32 B | 32 B | Snapshot purpose uses padding. |
| Bounds result | 16 B | 16 B | Two scalar addresses. |

The task map capacity remains 10,240 entries, corresponding to 2,048,000 bytes
of configured value payload. Keys and kernel bookkeeping are separate.
Recovery adds one BPF program and an entry kprobe/link. It adds no map or
dynamic allocation to the lookup/state functions.

Clang 19 object inspection recorded:

| Program or callback | Instruction slots, before → after | Individual compiler frame, before → after |
| --- | ---: | ---: |
| Modern syscall checker | 3,981 → 3,958 | 288 B → 296 B |
| Snapshot callback | 189 → 232 | 72 B → 56 B |
| Added recovery program | 196 | 56 B |

These are compiled-object sizes. Runtime instruction counts, verifier stack
accounting, total kernel allocation and event-path latency have separate cases
in the [verification plan](vma-validation.md).

Seven Go benchmark scenarios cover backend selection, probe planning and JIT
selection using injected capabilities and sysctl contents. Each reported
`0 B/op` and `0 allocs/op` in three 100 ms repetitions.

Native memory and state fixtures passed AddressSanitizer and UBSan with
`detect_leaks=0`. LeakSanitizer execution stopped because the environment used
ptrace. The long-running resource cases in the verification plan measure map,
link, descriptor and process-memory lifetimes.

## Reproduction

After preparing the repository's build dependencies and building Tracee:

```bash
sh scripts/vma_logic_test.sh
sh scripts/vma_stack_test.sh
sh scripts/vma_memory_test.sh
make benchmark-vma
```

The C benchmark includes production `common/memory.h` and
`common/vma_logic.h`. Its `VMA_BENCH_BASELINE_API` adapter supports the earlier
header interface. Fixtures check returned values, bounds, classes and flags
before timing. Native tests inject read failures and exercise state recovery,
stale task identity, cancellation, malformed ranges and classification
precedence.

The `VMA logic and build checks` workflow compiles objects and runs native,
Go and synthetic-event checks on x86_64 and ARM64. Each run records its source
commit and benchmark output in the job summaries.

## Kernel measurement plan

Use the complete matrix and case IDs in
[VMA changes and verification plan](vma-validation.md). Record syscall and task
creation latency distributions, throughput, CPU, lookup outcomes, recovery
rates, event loss and resource time series on the same workload and kernel for
each comparison. Set numeric budgets and measurement durations before running
the workloads. Keep functioning legacy comparisons and newly exercised modern
detector paths in separate result tables.
