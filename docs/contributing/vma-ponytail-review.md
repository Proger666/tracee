# Ponytail review: VMA lookup and EBUSY recovery

## Scope and method

The review was performed on 2026-11-25 before the corresponding GitHub CI
execution. It covered the VMA patch against upstream
`2f9dc40c20b17c2ba27f6d92b25e62790bd48a62`, including added files, the busy
lookup recovery path and metadata-read changes.

The review used the
[`ponytail-review` instructions](https://github.com/DietrichGebert/ponytail/blob/ebd8654c2c627f721eb8f9c0d1bd4090a29f9e10/skills/ponytail-review/SKILL.md),
pinned to `ebd8654c2c627f721eb8f9c0d1bd4090a29f9e10`.
Ponytail supplies a review workflow for an AI agent. The review read the
instructions and repository files; it ran no Ponytail installer or lifecycle
hook.

Independent passes covered C lookup/state logic and Go integration, tests and
CI. They followed connected callers and callees. Reviewers reported findings;
implementation changes and focused follow-up reviews addressed the affected
paths.

The workload considered during source review was a runtime-security collector
observing frequent syscalls and concurrent task creation. Measured native costs
are recorded in [VMA performance measurements](vma-performance.md).

## Findings and changes

### Recovery-hook accounting test

Files: `pkg/ebpf/vma_programs_test.go`, `pkg/ebpf/tracee.go`.

The recovery probe belongs to an extra probe group outside ordinary event
dependencies. The original test called the counting helper without exercising
the collector that adds the extra group. Removing that collection path could
make Tracee report its own recovery hook while the original test still passed.

`TestVMARecoveryHookInSelfLoadedPrograms` now calls the actual
`getSelfLoadedPrograms` collector with an empty dependency manager and a real
probe group containing public fake metadata. It exercises attached, failed,
absent and typed-nil cases in both modes. All five scenarios passed the
race-enabled Go unit target. The test uses observable hook inventory and
does not modify private probe fields.

### Discarded file-source metadata

Files: `pkg/ebpf/c/common/memory.h`, `pkg/ebpf/c/tracee.bpf.c`.

The source checker excluded file-backed mappings after reading their bounds
and flags. The native fixture recorded four scalar reads for this path.

Modern file-source lookup now reads `vm_file` and returns the explicit
`VMA_LOOKUP_EXCLUDED` result. The helper establishes containment while holding
`mmap_lock`; the snapshot remains invalid. Legacy lookup retains interval
revalidation and skips unused flags. Source callers return before event
submission or deduplication. Stack checks retain complete snapshots.

Follow-up review inspected output reset, excluded-result handling, legacy
interval validation and the source and stack callers.

## Other source observations

- Pending recovery retains the original scalar SP in an invalid range and a
  boolean in existing task-state padding.
- Recovery validates task start time, consumes pending state before the helper
  call and does not recreate a missing task-map entry.
- Child initialization clears inherited state even when VMA events are
  deselected. Exec clears it; exit uses existing task-map deletion.
- Modern metadata reads occur inside the helper callback. The stored result
  contains scalars.
- Recovery attaches before fork tracking. The extra probe group owns cleanup;
  attachment failures propagate as initialization errors.
- Group leaders return before the recovery task-map lookup. The implementation
  adds no syscall retry, context-switch hook, map scan or unbounded loop.
- Tests cover returned values, errors, state transitions and event/probe data
  flow. Benchmark counters are measurements.
- The workflow builds BPF objects and runs native, Go and synthetic checks.
  Its jobs do not load the objects or run kernel fixtures.

## Documentation and fixture review on 2026-11-26

The follow-up review checked the plan against the lookup, event, recovery and
loader callers before the next CI execution. It also checked the synthetic
kernel releases against the production release parser.

- The fixture's zero OS identifier is valid for the provider type. The version
  requirement has no distribution condition. Synthetic suffixes preserve the
  intended version comparisons.
- The startup cases distinguish errors returned to backend selection from raw
  libbpf probe errors logged inside its wrapper.
- The VDSO cases identify the paths that read optional mapping names.
- The pivot cases separate half-open VMA containment, inclusive saved-stack
  bounds and ANON-specific suppression.
- The policy cases distinguish clearing new-child state from consuming
  existing pending recovery after a policy change.
- The metadata cases separate native range tests from synthetic event-field
  validation.

## Recorded execution

The subsequent x86_64 and ARM64 workflow jobs completed compilation, native
logic/state/memory tests, race-enabled Go tests, synthetic event checks,
benchmarks, formatting and static analysis on 2026-11-25. Native sanitizer
results and benchmark methodology are recorded in
[VMA performance measurements](vma-performance.md).

## Verification cases

The [verification plan](vma-validation.md) specifies kernel loading, attachment,
event behavior, busy lookup recovery, ABI decoding, policy behavior,
concurrency, memory lifetime and performance measurements. Each case records
inputs, expected observations, actual results and evidence.
