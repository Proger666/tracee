# VMA performance measurements

The historical measurements below cover removal of unused metadata reads and
repeated current-task acquisition, together with one recovery attempt for a
busy fork-time stack lookup. They use production lookup headers with
ordinary-memory adapters. The later dispatcher and process-leader changes have
the separate compiled-object comparison below; their kernel costs require the
measurement plan at the end of this document.

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
event checks. After ABI normalization, one syscall-selection map supplies the
source/pivot event bits. Each event retains its own initialization, reset and
policy-scope evaluation. The raw syscall hook still consults selection data
for unselected syscalls.

Selection registration runs during initialization and combines the requested
bits for overlapping policies and event syscall sets. Removing a runtime policy
does not clear registration bits; current event-policy filtering is separate.
The behavior cases O01–O08 in the [verification plan](vma-validation.md) cover
registration errors, ABI normalization, independent event state and lifecycle.

The fork path checks already available child IDs before VMA policy
lookups or typed task acquisition for process leaders. It preserves stack-state
reset and ordinary process tracking. Process and thread creation therefore
need separate performance measurements.

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

Historical compiled type metadata on x86_64, recorded on 2026-11-25 before the
dispatcher, registration and process-leader optimizations, gave these sizes:

| Value | Before | After | Storage |
| --- | ---: | ---: | --- |
| `task_info_t` | 200 B | 200 B | Pending boolean uses padding; original SP uses the invalid range storage. |
| `vma_snapshot` | 32 B | 32 B | Snapshot purpose uses padding. |
| Bounds result | 16 B | 16 B | Two scalar addresses. |

The task map capacity remains 10,240 entries, corresponding to 2,048,000 bytes
of configured value payload. Keys and kernel bookkeeping are separate.
Recovery adds one BPF program and an entry kprobe/link. It adds no map or
dynamic allocation to the lookup/state functions.

Clang 19 object inspection in that comparison recorded:

| Program or callback | Instruction slots, before → after | Individual compiler frame, before → after |
| --- | ---: | ---: |
| Modern syscall checker | 3,981 → 3,958 | 288 B → 296 B |
| Snapshot callback | 189 → 232 | 72 B → 56 B |
| Added recovery program | 196 | 56 B |

These are compiled-object sizes. Runtime instruction counts, verifier stack
accounting, total kernel allocation and event-path latency have separate cases
in the [verification plan](vma-validation.md).

In the same historical record, seven Go benchmark scenarios covered backend
selection, probe planning and JIT selection using injected capabilities and
sysctl contents. Each reported `0 B/op` and `0 allocs/op` in three 100 ms
repetitions. These results do not measure the later syscall-map registration
changes.

The later `BenchmarkVMASyscallMaskMerge` covers new selection, adding the second
check and an already selected check. Its userspace fixture reset and copying
costs are part of the measurement. Record its allocation and timing results
separately from the historical selector benchmarks and from kernel map access.

The historical native memory and state fixtures passed AddressSanitizer and
UBSan with `detect_leaks=0`. LeakSanitizer execution stopped because the
environment used ptrace. The long-running resource cases in the verification
plan measure map, link, descriptor and process-memory lifetimes.

## Dispatcher and fork object comparison on 2026-11-26

The comparison used the preceding VMA implementation at
`ee1ef6ec2ec042bc9fc54d051cd9d9ee8f40db99` and the C changes in this revision.
Both objects used Clang 19.1.7, x86_64 target definitions, `-target bpf`,
`-O2 -g` and `-mcpu=v2`, with the same headers and libbpf checkout. The objects
were compiled without loading them. Instruction slots below are each ELF
function symbol's byte size divided by eight, obtained with
`readelf --wide --symbols`.

| Program | Instruction slots, before | Instruction slots, after |
| --- | ---: | ---: |
| Legacy syscall checker | 4,899 | 4,799 |
| Modern syscall checker | 3,958 | 3,957 |
| Legacy fork tracking | 4,763 | 4,361 |
| Modern fork tracking | 4,247 | 3,939 |

The dispatcher replaces two selection hash maps with one map of event bits.
It performs one selection lookup after ABI normalization and copies the mask
before either event check. Fork tracking tests the already available child IDs
before consulting VMA policy maps for process leaders. Independent event
initialization remains in place. These are changes to work and compiled size;
the table does not measure executed instructions, kernel allocations, syscall
latency or contention. Cases P01–P10 measure those effects.

## Reproduction

After preparing the repository's build dependencies and building Tracee:

```bash
make test-vma-native
make benchmark-vma
```

The C benchmark includes production `common/memory.h` and
`common/vma_logic.h`. Its `VMA_BENCH_BASELINE_API` adapter supports the earlier
header interface. Fixtures check returned values, bounds, classes and flags
before timing. Native tests inject read failures and exercise state recovery,
stale task identity, cancellation, malformed ranges and classification
precedence. The native target also exercises actual syscall-dispatch event
data flow using ordinary-memory adapters.

The `VMA logic and build checks` workflow compiles objects and runs native,
Go and synthetic-event checks on x86_64 and ARM64. Each run records its source
commit and benchmark output in the job summaries.

## Kernel measurement plan

Use the complete matrix and case IDs in
[VMA changes and verification plan](vma-validation.md). The written kernel plan
does not execute or add these workloads to CI.

Record the exact executable, BPF object, plugins, kernel/BTF, build inputs and
policy. Confirm all requested detectors register and the benchmark's actual
syscall and process identifier select the intended in-scope path. Keep
unselected and out-of-scope workloads as separate measurements.

Compare no Tracee, patched VMA-disabled, each event alone, both events and the
upstream comparison binary under identical conditions. Treat same-binary
configuration cost and baseline-to-patch cost as different comparisons. Keep
functioning legacy comparisons and newly exercised modern detector coverage
in separate result tables.

Start with seven paired repetitions, alternating order, with 30 seconds of
warm-up and at least 60 seconds of measurement per repetition. Retain at least
10,000 operations for each latency distribution, extending lower-rate runs.
Report raw samples, paired variation and p50/p95/p99, together with CPU,
throughput, helper outcomes, event loss and owned-resource time series.
Measure process `fork`/wait and `pthread_create`/join separately.

Use separate diagnostic runs to attribute cost to initialization, dispatch,
event checks, initial capture, recovery and transport. Successful EBUSY
recovery needs the initial busy result, same-task identity, original SP,
successful retry and subsequent detector controls; a warning count cannot
supply that evidence. Measure persistent busy, RT, CPU migration and
simultaneous-instance behavior as distinct cases.

Set numeric latency, CPU, memory, coverage and loss budgets before measurement.
Section 10 of the verification plan defines the evidence for a deployment
decision, including repeated cleanup, longer churn, unexpected ordinary-process
alerts, independent reproduction and a staged deployment with rollback.
