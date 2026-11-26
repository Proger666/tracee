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

## VMA dispatch review on 2026-11-26

The follow-up used the same pinned Ponytail workflow before publishing the
next revision and starting GitHub CI. Independent passes followed the C
dispatcher, fork-state handoff, Go registration, probe ownership and test
adapters. The workload assumption remained concurrent syscall and task
creation on multiple CPUs.

### Selection union and failed registration

Files: `pkg/ebpf/event_parameters.go`, `pkg/ebpf/c/common/vma_checks.h`.

The two per-event syscall-selection maps are combined into a `uint32` event
mask. Userspace registration preserves existing bits, accepts only `ENOENT` as
absence and propagates other lookup/update errors. Native-endian decoding
matches the BPF value. The only production registration caller is sequential
initialization; runtime policy toggles do not concurrently write this map.

A probe handle could remain registered after a failed legacy attachment.
Previously a later registration could publish selection for that handle
without retrying the attachment. VMA registration now calls the existing
idempotent attachment method for registered handles as well. The selection
bit is published only after attachment succeeds. Modern attachment errors
remain fatal; legacy errors retain the existing warn-and-skip behavior.

Behavior tests cover disjoint and overlapping selections, either registration
order, duplicate policies, malformed map data, preserved error chains, failed
attachment, retry and persistent failure. The real nil-module case returns
before any libbpf operation.

### Event state and concurrent execution

The dispatcher copies the selection mask to a scalar before running either
check. Each event retains its own initialization and policy evaluation. A
proposed shared initialization was removed during review: a per-CPU buffer
alone does not establish exclusion against other tracing programs. Review did
not establish a concrete default-hook regression; the existing refresh
boundary was retained.

The native fixture includes the production checker header and supplies
ordinary-memory adapters. It checks emitted arguments, scopes, configuration,
ABI normalization, early exits, output failure and interposed scratch-state
changes. Modeled CPU-local buffers check data separation. Actual nested
contexts and migration remain kernel cases in the verification plan.

Fork tracking skips VMA policy lookups for process leaders while clearing
inherited stack state. The reviewed
[kernel fork sequence](https://github.com/torvalds/linux/blob/v6.1/kernel/fork.c)
records the child before waking it. Recovery validates task start time and consumes its original
SP once. The changed paths add no lock, allocation, map scan or retry loop.

### Existing 2024 implementation

The review compared the original implementation from
[PR #3953](https://github.com/aquasecurity/tracee/pull/3953), its
[compatibility discussion](https://github.com/aquasecurity/tracee/pull/3953#issuecomment-2034373753)
and the
[helper-removal commit](https://github.com/oshaked1/tracee/commit/c45b5fcd1439b73f3eace23c3fc083a5171d222c).
The old code was recovered from the public history at
`e7c427c818a14535b8e19a8d86b6aff273b79c5e`.

That version selected the helper inside the same BPF program. The discussion
records why conditional program loading was needed for older kernels with
callback/tail-call restrictions. The current patch uses separate selected
program variants and excludes the modern variants before object loading.

The old callback returned a `vm_area_struct` pointer for later reads. The
current callback completes metadata reads while the helper holds the lock and
returns scalar values. The existing legacy walk, event classification,
policy handling and extra-probe ownership are retained and extended at their
VMA boundaries; the removed pointer-returning implementation is not restored.

### Scope and connected cleanup findings

Generic probe cleanup and dependency changes are outside this VMA patch. The
review found two existing failure paths to include when validating VMA-owned
attachments:

- Optional compatibility attachment can append a nil link after an ignored
  attachment error. Existing cleanup then calls `Destroy` on that nil link.
- In the pinned libbpfgo dependency, a nonlegacy `Destroy` error returns before
  clearing its pointer, while libbpf's `bpf_link__destroy` frees the wrapper on
  that path. Subsequent module cleanup can retry the stale pointer.

No generic cleanup workaround or dependency-field mutation is included.
S12 and L03 require attachment-failure and cleanup evidence for the selected
VMA configuration, including optional compatibility attachment and destroy
errors. These source findings have not been exercised against a live kernel
in this review.

## Recorded execution

The scoped changes were checked locally on 2026-11-26 before the GitHub push:

- BPF-object and Tracee compilation on x86_64 with Clang 19.1.7 and Go 1.26.5
  completed without loading the objects.
- All four native suites passed with GCC and Clang. The new dispatcher fixture
  passed ASan and UBSan with `detect_leaks=0`.
- The `pkg/ebpf/...` unit target passed with the race detector. Synthetic
  detector-event and shell result-validation checks passed.
- Formatting, lint, vet, staticcheck and errcheck passed after correcting a
  new import-shadowing diagnostic.
- Native VMA benchmarks and all ten Go benchmark scenarios completed. The
  three selection-map scenarios include fixture allocation costs; the seven
  existing selection/planning scenarios reported zero allocations.
- The three VMA Markdown documents rendered with table support and their
  relative links resolved. This did not run the full MkDocs site build.

The earlier x86_64 and ARM64 workflow jobs completed compilation, native
logic/state/memory tests, race-enabled Go tests, synthetic event checks,
benchmarks, formatting and static analysis on 2026-11-25. Native sanitizer
results and benchmark methodology are recorded in
[VMA performance measurements](vma-performance.md).

## Verification cases

The [verification plan](vma-validation.md) specifies kernel loading, attachment,
event behavior, busy lookup recovery, ABI decoding, policy behavior,
concurrency, memory lifetime and performance measurements. Each case records
inputs, expected observations, actual results and evidence.
