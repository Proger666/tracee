# VMA changes and verification plan

This document records implemented changes, executed checks and test cases for
VMA lookup, `suspicious_syscall_source`, `stack_pivot` and initial thread-stack
tracking. Each test case specifies inputs, expected observations and evidence.

## 1. Implemented changes

- Added helper-backed lookup selected before BPF object loading from kernel
  version, JIT configuration and helper availability.
- Kept legacy RB-tree lookup in separate program variants. Selection controls
  autoload before object loading.
- Added scalar snapshots copied inside the VMA helper callback. Fork-time
  stack capture uses a bounds-only result.
- Added one recovery attempt after a modern fork-time `-EBUSY`. It uses the
  original child SP at `schedule_tail`, checks task identity and consumes
  pending state before lookup.
- Added clearing of inherited and pending stack state during child
  initialization and exec.
- Added an excluded-source result for file-backed syscall sources. Modern
  lookup avoids unused metadata; legacy lookup retains interval revalidation.
- Removed repeated current-task acquisition from the syscall checker dispatch
  path while preserving separate policy checks for each event.
- Added the recovery probe to Tracee's own-hook accounting and existing probe
  cleanup.
- Added native tests for interval handling, classification, read errors,
  excluded results, state transitions, bounded traversal and stale data.
- Added native benchmarks and a workflow for compilation, Go tests, synthetic
  event tests and static analysis.

The changed paths are
[`memory.h`](https://github.com/Proger666/tracee/blob/fix/vma-maple-tree/pkg/ebpf/c/common/memory.h),
[`vma_logic.h`](https://github.com/Proger666/tracee/blob/fix/vma-maple-tree/pkg/ebpf/c/common/vma_logic.h),
[`vma_stack.h`](https://github.com/Proger666/tracee/blob/fix/vma-maple-tree/pkg/ebpf/c/common/vma_stack.h),
[`tracee.bpf.c`](https://github.com/Proger666/tracee/blob/fix/vma-maple-tree/pkg/ebpf/c/tracee.bpf.c),
[`vma_programs.go`](https://github.com/Proger666/tracee/blob/fix/vma-maple-tree/pkg/ebpf/vma_programs.go) and
[`tracee.go`](https://github.com/Proger666/tracee/blob/fix/vma-maple-tree/pkg/ebpf/tracee.go).

## 2. Recorded executions

The following results were recorded on 2026-11-25 before the documentation and
synthetic kernel-fixture edits. A new execution records its own source commit.

| Check | Recorded result |
| --- | --- |
| BPF-object and Tracee compilation on x86_64 and ARM64 | Passed. |
| Native scalar VMA tests | Passed. |
| Native thread-stack state-transition tests | Passed. |
| Production-header tests with injected memory-read failures | Passed with GCC and Clang. |
| Go loader/probe tests with the race detector | Passed. |
| Synthetic detector-event and result-validator tests | Passed. |
| Formatting, lint, vet, staticcheck and errcheck | Passed. |
| AddressSanitizer and UBSan on native fixtures | Passed with `detect_leaks=0`. |
| LeakSanitizer | Execution stopped because the environment used ptrace. |
| Seven Go startup benchmark scenarios, three repetitions | `0 B/op`, `0 allocs/op`. |
| Compiled `task_info_t` size | 200 bytes before and after. |
| Compiled `vma_snapshot` size | 32 bytes before and after. |
| Earlier full repository quality check | Stopped at dependency vulnerability findings in unchanged dependencies. |
| Earlier full unit suite | Encountered CPU-sysfs and Unix-socket environment restrictions, also reproduced on the upstream base. |
| Kernel loading, live event fixtures and kernel performance cases in sections 6–9 | No execution recorded. |

The paired native comparison used GCC 14.2.0, `-O2`, 200,000 operations per
scenario, 30 scenarios and seven alternating baseline/patch repetitions.
Production lookup headers used ordinary-memory adapters for kernel structures,
reads and helpers. Results and scope are recorded in
[VMA performance measurements](vma-performance.md) and its CSV.

Source review covered callers, task-map lifecycle, backend isolation, recovery
ordering, own-hook accounting and cleanup. Findings and implementation changes
are recorded in [the Ponytail review](vma-ponytail-review.md).

## 3. Execution manifest and test conventions

Create a manifest for each kernel-test configuration containing:

- Patch commit/tree, comparison commit, BPF-object hash and build flags.
- Kernel version, architecture, relevant memory-management and BPF backports,
  kernel-configuration hash and BTF hash.
- JIT configuration and observed setting, helper support by program type,
  `PREEMPT_RT`, preemption mode and page size.
- Compiler, Go and libbpf versions.
- CPU count, memory, CPU placement and other measurement instrumentation.
- Policies, selected syscalls, scope filters, map capacities and event-buffer
  configuration.
- Fixture revision, input seed, repetition count, warm-up interval,
  measurement duration and cleanup observation window.
- Numeric CPU, throughput, latency, memory, event-loss and recovery-loss budgets
  fixed before the measurements.
- Case IDs, timestamps, raw outputs and the person recording each result.

Use synthetic workload identifiers in published artifacts. Record architecture
and kernel properties separately from the container image.

Tests assert behavior and data flow: selected backend, enabled program set,
returned errors, preserved or cleared state, complete scalar results, emitted
events and resource ownership. Source-text matching, private struct layout,
exact instruction counts and helper-call ordering are outside unit-test
assertions. Formatting and compiler diagnostics are repository checks.
Read/helper counters belong to measurements.

For each positive detector case, retain a matched negative control and evidence
that its intended syscall workload actually executed. For every lookup record
complete snapshot, excluded source, missing mapping and read/helper failure as
separate outcomes. Correlate events using task start time as well as TID.

Sections 6–9 describe kernel-test inputs and observations. They do not add those
workloads to the native CI workflow.

## 4. Repository and userspace checks

| ID | Check | Evidence |
| --- | --- | --- |
| U01 | Compile BPF objects and Tracee for x86_64 and ARM64 using the repository toolchain. | Compiler versions, commands, exit results and object hashes. |
| U02 | Run scalar, stack-state and production-header native tests with GCC and Clang. | Case results, including boundary values, errors, state clearing, malformed/deep/cyclic trees and excluded sources. |
| U03 | Run Go loader/probe tests with the race detector. | Backend decisions, enabled programs, error propagation, own-hook inventory and race output. |
| U04 | Run synthetic detector and shell result-validation tests. | Cases with both events, missing/duplicate/reordered/malformed events, cross-thread evidence, late errors, fixture failure and timeout. A success marker followed by failure must produce a failed validation result. |
| U05 | Run AddressSanitizer and UBSan on native fixtures, and LeakSanitizer where its execution is available. | Exact sanitizer options and complete diagnostics for each tool. |
| U06 | Run formatting, lint, vet, staticcheck and errcheck. | Output for the tested revision and any differing result on the same upstream base. |
| U07 | Inspect all steps of the repository quality and script/unit targets, then execute their userspace portions. | Per-target results, vulnerability reports, skipped case IDs and reproduced baseline failures. |
| U08 | Check event documentation against generated man pages and the documentation index; render the changed documentation. | Matching event fields, valid links, generated-file comparison and rendering output. |
| U09 | Collect Go coverage for changed loader/probe paths using the repository coverage rules. | Coverage report, changed-code branches exercised and uncovered behavior cases. |
| U10 | Repeat native and Go startup benchmarks using the manifest parameters. | Raw samples, returned-value checks before timing, allocations and measurement variation. |

Useful userspace commands after preparing build dependencies:

```bash
make bpf
make tracee
make test-unit PKG=pkg/ebpf TEST=VMA
make test-unit PKG=pkg/ebpf/probes TEST=TestProbeGroupSelectProgram
make test-e2e-detectors
bash tests/e2e/test-vma-validation.sh
sh scripts/vma_logic_test.sh
sh scripts/vma_stack_test.sh
sh scripts/vma_memory_test.sh
make benchmark-vma
```

The dedicated workflow is
[`VMA logic and build checks`](https://github.com/Proger666/tracee/blob/fix/vma-maple-tree/.github/workflows/vma-logic.yaml).
It records the source commit, runner and benchmark output. Build artifacts are
compiled without loading them. Synthetic events are supplied as test data.

Repository conventions are described in the
[style guide](guidelines.md), [code-quality guide](checkpatch.md) and
[coverage guide](testing-coverage.md).

## 5. Kernel and startup matrix

Run each selected row on an actual kernel instance. Record backend selection,
program loading, attachment and lookup outcomes independently.

| Kernel/configuration input | Architectures | Required observations |
| --- | --- | --- |
| 4.18, 5.4, 5.10, 5.15 and 6.0 | x86_64 and ARM64 combinations under test | Legacy selection; modern callback programs excluded from loading; comparison with the upstream base on the same configuration. |
| 6.1 | x86_64 and ARM64 | Helper-backend version boundary; callback loading, recovery attachment and both event checks. |
| 6.6 and 6.12 | x86_64 and ARM64 | Functional, lifecycle, concurrency and performance cases below. |
| Each additional intended kernel version | Each intended architecture | The same matrix, with exact version/configuration recorded. |
| Relevant memory-management or BPF backports | Each affected architecture | Backports, chosen backend and actual lookup result. Include Maple Tree below the version gate. |
| `PREEMPT_RT` | Modern configurations under test | Initial lookup and recovery results separately, including IRQ-disabled recovery. |
| BTF present, unavailable or mismatched | Relevant configurations | Object-load outcome, exact diagnostic and owned-resource cleanup. |
| Different page sizes and supported preemption modes | Relevant architectures | Range calculations, task-creation behavior and repeated lookup outcomes. |

Exercise these startup inputs independently:

| ID | Input | Expected observation |
| --- | --- | --- |
| S01 | Kernel version at or above 6.1, confirmed JIT, both required helpers for raw tracepoints and kprobes | Helper backend selected. Record actual load/attach results. |
| S02 | Kernel version below 6.1, including a helper backport | Legacy selected. Callback programs remain excluded. |
| S03 | Each of `bpf_find_vma` and `bpf_get_current_task_btf` unavailable for either required program type | Legacy selected; record lookup availability for that kernel's memory-management layout. |
| S04 | Kernel/JIT check error, injected helper-checker error, and raw libbpf helper-probe error | Errors returned to the selector produce legacy selection and an error diagnostic. The production libbpf wrapper logs its raw probe error at debug level and returns the supported boolean with no error; record selection from that boolean separately. |
| S05 | `CONFIG_BPF_JIT_ALWAYS_ON=y`, with a hidden or unreadable sysctl | JIT eligibility established from configuration. |
| S06 | JIT values 0, 1 and 2; whitespace; empty, malformed, unsupported or unreadable setting | 1 and 2 enable JIT eligibility; 0 retains legacy; invalid/unreadable settings retain legacy with the corresponding error. |
| S07 | JIT setting hidden by a network namespace without an always-on configuration result | Record legacy selection, diagnostic and actual detector outcomes. |
| S08 | Legacy selected on a kernel without `mm_rb` | Snapshot lookup returns `-EOPNOTSUPP`; record the unsupported warning and absent lookup-based events. |
| S09 | Start without VMA events, then select them dynamically | Backend remains legacy; modern callback/recovery programs are not loaded by the policy change. |
| S10 | Start with one VMA event, then both; remove and re-enable policies | Backend remains fixed. Each event follows its own syscall selection and policy scope. |
| S11 | Selected BPF program rejected by the verifier, or recovery/syscall attachment fails | Initialization error and cleanup of acquired resources; no automatic reload with another backend. |
| S12 | Module lookup or autoload-setting failure | Error identifies the affected operation and program; no partially configured detector continues initialization. |

For a baseline startup failure, retain the baseline and patch results with
their failure stages and diagnostics. A row with legacy selection on a
Maple Tree layout records unavailable lookup separately from startup outcome.

## 6. Functional and concurrency cases

### Ranges, reads and classification

| ID | Input or transition | Expected observation |
| --- | --- | --- |
| F01 | Address at VMA start, last contained byte, exclusive end, a gap and adjacent mappings | VMA lookup uses `start <= address < end`. Empty/reversed ranges and noncontaining results produce no usable snapshot. |
| F02 | Initial child SP at stack start/end, zero, unreadable, outside a mapping and near the 64-bit limit | Bounds lookup queries `SP - 1` after rejecting zero. Record the returned mapping and absence of inherited parent bounds after failure. No underflow or fabricated interval. |
| F03 | `start_stack` and tracked-thread SP at the stored range boundaries | Main-stack classification and `address_in_thread_stack` retain their inclusive upper-bound comparisons. Test them separately from half-open VMA containment. |
| F04 | Failure at each mandatory metadata read; missing task/mm/VMA; failure after a prior success | Negative result and invalid snapshot; prior bounds, flags or classification are not reused for an event. |
| F05 | Optional VDSO pointer/name absent, unreadable, malformed or `[vdso]` followed by extra characters | Where VDSO recognition is evaluated, these inputs yield `is_vdso == false` while mandatory metadata stays usable; exact `[vdso]` matches. Source lookup applies its independent exclusion. Stack lookup evaluates the name only after earlier classes leave ANON; MAIN_STACK, HEAP and GOLANG_HEAP stack results skip this optional read. |
| F06 | File-backed, main-stack, heap, Go-arena, VDSO and anonymous mappings; overlapping conditions | Classification order is FILE_BACKED, MAIN_STACK, HEAP, GOLANG_HEAP, VDSO, ANON. VDSO source exclusion is also applied independently of higher-priority classes. |
| F07 | ANON syscall source inside and outside a tracked thread range | Source caller changes ANON to THREAD_STACK only when the source IP lies in the saved range. The classifier itself does not assign THREAD_STACK. |
| F08 | Modern and legacy file-backed syscall sources; file-backed stack destination | Source returns `VMA_LOOKUP_EXCLUDED` with `valid == false`, with no event or dedup insertion. Stack lookup returns a complete snapshot. |
| F09 | Legacy mapping changes after tree selection; subsequent interval read fails | Interval revalidation rejects an unreadable or noncontaining mapping before source exclusion. Retain the mutation timeline and read outcome. |
| F10 | Controlled syscall execution from anonymous, heap and stack code mappings | Source event identifies the selected syscall, correct task and complete mapping fields. Include a file-backed and VDSO control with ordinary syscall evidence. |
| F11 | Tracked initial thread stack followed by SP in another ANON VMA, strictly outside the saved inclusive range | Stack-pivot event contains the task identity and the containing destination mapping. |
| F12 | SP in MAIN_STACK or GOLANG_HEAP; SP in ANON with no tracked initial range; SP in ANON inside a tracked range | Record the corresponding suppressed pivot result. Include a normal process mapped into the fixed Go-address heuristic range and a Go workload with a different arena layout. |
| F13 | Native range fixtures and synthetic detector-event fixtures with maximum addresses/sizes, empty or reversed ranges, overflowing event intervals, missing/truncated fields, wrong types and inconsistent evidence | Native lookup rejects invalid ranges without a usable snapshot. The event validator rejects malformed or overflowing metadata without emitting a successful validation result. |

For F01–F13 retain input addresses, mapping bounds/permissions, mandatory versus
optional read outcomes, class, validity/exclusion result, stored stack state
and the event stream. Distinguish SP exactly at a range end from an IP used for
half-open VMA lookup.
Use native flag patterns `0`, individual high bits and `UINT64_MAX` to check
exact `vm_flags` preservation in complete snapshots and `valid == false` after
read failure. In live cases, compare event `vma_flags` with the reference
mapping flags.

### Busy lookups and task lifecycle

| ID | Input or transition | Expected observation |
| --- | --- | --- |
| F14 | One selected syscall requiring both source and stack checks | Both expected events identify the same thread and their respective mappings. Record both lookup outcomes to detect one check systematically blocking the other through deferred unlock work. |
| F15 | Modern fork lookup returns `-EBUSY`; lock becomes available before first scheduling | The same child consumes the pending original SP and stores a containing range before userspace. Subsequent normal and positive-control workloads produce their respective expected events. |
| F16 | Initial modern lookup returns `-ENOENT`, `-EFAULT` or another nonbusy failure; SP is absent/unreadable/zero | Stack stays unknown without scheduling deferred recovery. |
| F17 | Writer contention persists through recovery | Pending state is consumed; no range is fabricated; failed recovery records `BPF_LOG_THREAD_STACK_UNAVAILABLE`. Record resulting detector losses. |
| F18 | Per-CPU deferred-unlock work remains busy at recovery | Record original and recovery helper returns, final pending/range state, warning and detector losses independently of writer-contention results. |
| F19 | IRQ-disabled recovery on `PREEMPT_RT` | Record `-EBUSY`, consumed pending state, unknown range and warning for the kernel implementation under test. |
| F20 | Address remapped before first scheduling and again after userspace starts | Pre-userspace capture uses the original kernel-initialized SP and the mapping present at capture. Later syscalls do not learn a replacement stack from the saved or current SP. |
| F21 | Zero or mismatched task start time during recovery | Pending state is consumed without VMA lookup or a terminal recovery-warning; no range is published for another task identity. |
| F22 | TID reuse, exec and task exit | Inherited/pending ranges are cleared on initialization and exec; exit removes existing task state. Reused TIDs cannot restore the prior task's stack. |
| F23 | Task-map LRU eviction or missing entry before recovery; missed recovery hook | Recovery does not create a replacement entry. Record missed capture separately; the absence of a terminal warning does not count the miss. |
| F24 | Group leader, kernel thread, nonpending thread, or child created with VMA events deselected | No inherited pending recovery is used. Measure work by task category and verify child-state reset after policy changes. |
| F25 | Legacy initial lookup fails, then its immediate second lookup succeeds or fails | Record both lookup outcomes. Each traversal remains bounded; legacy keeps its second attempt after an initial error. |
| F26 | Temporary busy syscall lookup followed by a later available lookup | The failed lookup neither fabricates an alert nor reuses old data; later independent lookups use current mapping data. |

For F14–F26 retain the child/leader start times, TID/TGID, initial SP, helper
returns, pending/range state, warning stream and mapping/execution timeline.
An `-EBUSY` value alone does not identify which contention condition occurred.

### Policies, deduplication, ABIs and concurrent mutation

| ID | Input or transition | Expected observation |
| --- | --- | --- |
| F27 | Concurrent unmap, remap, split, merge and protection changes | Complete scalar snapshots, excluded sources and lookup losses are counted separately. Retain invalid-access, locking and other kernel diagnostics. |
| F28 | Ordinary main-thread and newly created thread activity during mapping churn | Ordinary selected-syscall activity is observed without the corresponding VMA alerts. An empty overall event stream is insufficient evidence. |
| F29 | Different policies for the two events, deselected syscalls and processes outside scope | Each event uses its own policy and syscall selection; one event's policy does not substitute for the other. |
| F30 | Repeat the same `(syscall, host TGID, leader start time, VMA start)` | Existing dedup entry suppresses repeat submission on `-EEXIST`. Record key and event output. |
| F31 | Change syscall, process, leader start time or VMA start; remap the same address; force a non-`EEXIST` insertion error | Record behavior for the actual key. Non-`EEXIST` insertion errors allow submission. Excluded sources and VDSO do not occupy an entry. |
| F32 | Attached recovery hook; absent/failed probe; separate controlled external hook | Tracee counts its attached recovery hook as its own. An unattached probe does not suppress reporting of an external hook. |
| F33 | Native x86_64, native ARM64, i386 compat, AArch32 and x32 | Compare original and normalized syscall IDs, IP/SP and selection-map match against reference tracing. Missing compat translation ends processing. Record outcomes separately for each ABI. |
| F34 | Balanced legacy trees and chains near, at and beyond the traversal bound; cyclic native fixtures | Traversals terminate within their bound and produce a range or recorded miss. Keep traversal-limit losses separate from absent mappings. |
| F35 | Policy removal/re-enable during task creation and repeated event activity | New children created with VMA events deselected receive cleared stack state. Existing pending recovery checks task identity and can finish after policy removal; the recovery hook does not recheck current policy selection. Record backend, selected events and task-state transitions. |

For F27–F35 retain complete event streams, reference syscall traces, policy
versions, dedup inputs/results and mutation schedules. Repeat races using a
recorded seed and schedule or retain sufficient timing evidence to reproduce
the observed transition.

## 7. Load, attachment and resource lifecycle

| ID | Test | Required evidence and expected observation |
| --- | --- | --- |
| L01 | Load each selected program set on every kernel matrix configuration | Complete verifier/load output, loaded and excluded program names, processed instructions and verifier stack information where reported. Selected programs either load or return their actual error. |
| L02 | Attach recovery and event probes | Program/link identities and results; recovery attachment precedes fork tracking that can create pending state. |
| L03 | Inject failure after object creation, loading, map setup and each attachment stage | Original error and resource inventory before/after cleanup. Owned links, programs, maps, buffers and descriptors are released. |
| L04 | Cancel initialization and event handling; shut down after partial initialization | Goroutine/thread completion and resource cleanup; retain panic, deadlock and double-close diagnostics. |
| L05 | Repeat start/stop and failed-start/retry cycles | Per-cycle descriptor, link, map and process-memory measurements, using the manifest's cycle count and cleanup window. |
| L06 | Create/exit threads and processes through and beyond task-map capacity | Occupancy time series, evictions, exit cleanup, lookup misses and behavior after TID reuse. |
| L07 | Sustained mapping/event churn, followed by workload removal | RSS/heap profiles, kernel map/program/link accounting and event-loss counters during and after the workload. |
| L08 | Shutdown with active event producers and partially consumed pending recovery | No owned probe or state resource survives cleanup; correlate producer termination and final resource inventory. |

Identify resources by ownership and ID. Distinguish bounded caches reaching
capacity from continued growth. Compare steady-state windows after warm-up
and inspect cleanup after both successful and failed initialization.

## 8. Kernel performance plan

Use the same kernel, hardware allocation, workload, policy and event-collection
settings for each baseline/patch pair. Alternate order and keep at least five
measured repetitions per profile. Set duration, workload scale and numeric
budgets in the manifest before execution.

| ID | Profile | Measurements |
| --- | --- | --- |
| P01 | VMA events disabled | Process CPU, syscall throughput/latency, startup time and memory. |
| P02 | VMA events enabled, syscalls unselected | Raw-hook selection cost, CPU and throughput/latency. |
| P03 | Selected syscalls outside policy scope | Scope-filter cost, event rate and lookup activity. |
| P04 | One selected VMA event, then both | CPU, throughput, p50/p95/p99 latency, event rate, lookup outcomes and losses. |
| P05 | File source, main stack, heap, anonymous memory, Go-address range and VDSO | Cost and event behavior per class, distinguishing lookup from event-submission work. |
| P06 | Increasing VMA counts and legacy tree depths | Cost versus input size, bounded completion, traversal-limit losses and both legacy fork attempts when the first fails. |
| P07 | Process creation and thread creation, measured separately | Creation latency, CPU, throughput and recovery-hook work for leaders and nonleaders. |
| P08 | Successful fork capture, recoverable busy lookup and persistent busy lookup | Initial/recovery success counts, recovery latency, warnings and lost positive detector cases. |
| P09 | Sustained churn and repeated initialization | RSS, Go allocations, kernel allocations, map occupancy, descriptors, links and post-cleanup inventories. |
| P10 | Event-buffer pressure and concurrent mapping churn | Event drops, CPU, latency distribution, lookup failures and memory growth. |

Record raw samples, distributions and variation. Report changes against the
numeric budgets fixed in the manifest and retain each outlier's workload
context.

Compare legacy against legacy on older kernels. Where the baseline lacks the
requested detector behavior, report its event coverage together with resource
cost. Keep that result separate from a comparison between functioning
detectors.

Record lookup attempts, helper/read counters and compiled sizes as
measurements. Keep native adapter timings, static BPF-object measurements and
live-kernel timings in separate tables.

## 9. Execution record

Maintain one row per case and kernel configuration:

| Field | Content |
| --- | --- |
| Case/configuration ID | Matrix row and case ID. |
| Source revision | Commit/tree and BPF-object hash tested. |
| Inputs | Workload, seed, policy and fault/transition schedule. |
| Expected observation | Relevant table entry. |
| Observed result | Events, return values, task state and resource measurements. |
| Execution result | Matched, differed or not executed. |
| Evidence | Raw logs, event stream, profiles and measurement files. |
| Follow-up | Reproduction, code change or additional measurement prompted by the observed difference. |

The resulting record contains execution manifests, kernel/configuration/BTF
identities, verifier and attachment logs, correlated event streams, resource
time series, benchmark distributions and the case IDs whose observations
differed or whose execution was not performed.
