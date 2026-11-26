#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <common/memory.h>

// All data below lives in ordinary userspace memory. The production header
// supplies the lookup/classification logic; only kernel reads and the helper
// are adapted. The mock helper does not traverse a kernel VMA tree. These
// timings therefore are not actual kernel-helper, eBPF or syscall latency.
static volatile uint64_t consumed;
static struct vm_area_struct areas[1024];
static struct mm_struct mm;
static struct file mapped_file;
static struct vm_special_mapping vdso = {.name = "[vdso]"};

enum fixture_properties {
    FIXTURE_FILE = 1,
    FIXTURE_MAIN_STACK = 2,
    FIXTURE_HEAP = 4,
    FIXTURE_GO = 8,
    FIXTURE_VDSO = 16,
    FIXTURE_CHAIN = 32,
    FIXTURE_CYCLE = 64,
};

struct benchmark_case {
    const char *name;
    bool helper;
    bool bounds_only;
    bool check_source;
    unsigned int vma_count;
    unsigned int properties;
    enum vma_type want_type;
    long helper_result;
};

// These API adapters also permit a reproducible comparison with the published
// preliminary patch by compiling against its unmodified headers. No lookup or
// classification algorithm is duplicated here.
static long
lookup_snapshot(bool helper, u64 address, struct vma_snapshot *snapshot, bool check_source)
{
#ifdef VMA_BENCH_BASELINE_API
    (void) check_source;
    return helper ? find_vma_snapshot_current(address, snapshot)
                  : find_vma_snapshot_legacy(NULL, &benchmark_task, address, snapshot);
#else
    return helper
               ? find_vma_snapshot_current(&benchmark_task, address, snapshot, check_source)
               : find_vma_snapshot_legacy(NULL, &benchmark_task, address, snapshot, check_source);
#endif
}

static long lookup_bounds(bool helper, u64 address, address_range_t *bounds)
{
    if (!helper)
        return find_vma_bounds_legacy(NULL, &benchmark_task, address, bounds);
#ifdef VMA_BENCH_BASELINE_API
    return find_vma_bounds_current(address, bounds);
#else
    return find_vma_bounds_current(&benchmark_task, address, bounds);
#endif
}

static uint64_t ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        exit(2);
    return (uint64_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static struct rb_node *build_tree(unsigned int lo, unsigned int hi)
{
    if (lo == hi)
        return NULL;
    unsigned int mid = lo + (hi - lo) / 2;
    areas[mid].vm_rb.rb_left = build_tree(lo, mid);
    areas[mid].vm_rb.rb_right = build_tree(mid + 1, hi);
    return &areas[mid].vm_rb;
}

static void setup(const struct benchmark_case *test)
{
    memset(&mm, 0, sizeof(mm));
    memset(areas, 0, sizeof(areas));
    u64 base = test->properties & FIXTURE_GO ? GOLANG_ARENA_HINT : 0x100000;
    for (unsigned int i = 0; i < test->vma_count; i++) {
        areas[i].vm_start = base + i * 0x2000;
        areas[i].vm_end = areas[i].vm_start + 0x1000;
        areas[i].vm_flags = 3;
        areas[i].vm_mm = &mm;
    }
    struct vm_area_struct *vma = &areas[0];
    if (test->properties & FIXTURE_FILE)
        vma->vm_file = &mapped_file;
    if (test->properties & FIXTURE_MAIN_STACK)
        mm.start_stack = vma->vm_end;
    if (test->properties & FIXTURE_HEAP) {
        mm.start_brk = vma->vm_start;
        mm.brk = vma->vm_end;
    }
    if (test->properties & FIXTURE_VDSO)
        vma->vm_private_data = &vdso;
    if (test->properties & FIXTURE_CHAIN) {
        for (unsigned int i = 0; i + 1 < test->vma_count; i++)
            areas[i].vm_rb.rb_right = &areas[i + 1].vm_rb;
        mm.mm_rb.rb_node = &areas[0].vm_rb;
    } else if (test->properties & FIXTURE_CYCLE) {
        areas[0].vm_rb.rb_right = &areas[0].vm_rb;
        mm.mm_rb.rb_node = &areas[0].vm_rb;
    } else {
        mm.mm_rb.rb_node = build_tree(0, test->vma_count);
    }
    benchmark_task.mm = &mm;
    benchmark_helper_vma = vma;
    benchmark_helper_result = test->helper_result;
}

static void bench(const struct benchmark_case *test)
{
    setup(test);
    const uint64_t iterations = 200000;
    uint64_t sum = 0;
    struct vma_snapshot snapshot;
    address_range_t bounds;

    // Validate known output before timing: a failed lookup must not silently
    // turn a successful-path benchmark into an error-path measurement.
    struct vm_area_struct *expected_area =
        &areas[(test->properties & FIXTURE_CHAIN) ? test->vma_count - 1 : 0];
    u64 query_base = test->properties & FIXTURE_CYCLE ? areas[0].vm_end : expected_area->vm_start;
    unsigned long check_address = query_base + 7;
    long check_result =
        test->bounds_only
            ? lookup_bounds(test->helper, check_address, &bounds)
            : lookup_snapshot(test->helper, check_address, &snapshot, test->check_source);
    long expected_result = test->helper_result;
#ifndef VMA_BENCH_BASELINE_API
    if (expected_result == 0 && !test->bounds_only && test->check_source &&
        (test->properties & FIXTURE_FILE)) {
        expected_result = VMA_LOOKUP_EXCLUDED;
        assert(snapshot.source_is_legitimate && !snapshot.valid);
    }
#endif
    assert(check_result == expected_result);
    if (expected_result == 0) {
        if (test->bounds_only) {
            assert(bounds.start == expected_area->vm_start && bounds.end == expected_area->vm_end);
        } else {
            assert(snapshot.valid);
            assert(snapshot.start == expected_area->vm_start &&
                   snapshot.end == expected_area->vm_end);
            assert(snapshot.flags == 3 && snapshot.type == test->want_type);
            if (test->check_source || test->want_type == VMA_VDSO)
                assert(snapshot.is_vdso == ((test->properties & FIXTURE_VDSO) != 0));
        }
    } else {
        if (test->bounds_only)
            assert(bounds.start == 0 && bounds.end == 0);
        else
            assert(!snapshot.valid);
    }

    benchmark_counts = (struct benchmark_counts) {0};
    uint64_t start = ns();
    for (uint64_t i = 0; i < iterations; i++) {
        unsigned long address = query_base + (i & 0x7ff);
        long result;
        if (test->bounds_only) {
            result = lookup_bounds(test->helper, address, &bounds);
            sum += bounds.start + bounds.end;
        } else {
            result = lookup_snapshot(test->helper, address, &snapshot, test->check_source);
            if (result == 0)
                sum +=
                    snapshot.start + snapshot.end + snapshot.flags + snapshot.type + snapshot.valid;
        }
        sum += (uint64_t) result;
    }
    uint64_t elapsed = ns() - start;
    consumed += sum;
    printf("%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
           test->name,
           (double) elapsed / iterations,
           (double) benchmark_counts.reads / iterations,
           (double) benchmark_counts.bytes / iterations,
           (double) benchmark_counts.strings / iterations,
           (double) benchmark_counts.helpers / iterations,
           (double) benchmark_counts.task_helpers / iterations);
}

int main(void)
{
    const struct benchmark_case cases[] = {
        {"helper_bounds", true, true, false, 1, 0, VMA_UNKNOWN, 0},
        {"helper_source_file", true, false, true, 1, FIXTURE_FILE, VMA_FILE_BACKED, 0},
        {"helper_stack_file", true, false, false, 1, FIXTURE_FILE, VMA_FILE_BACKED, 0},
        {"helper_stack_main", true, false, false, 1, FIXTURE_MAIN_STACK, VMA_MAIN_STACK, 0},
        {"helper_source_main", true, false, true, 1, FIXTURE_MAIN_STACK, VMA_MAIN_STACK, 0},
        {"helper_stack_heap", true, false, false, 1, FIXTURE_HEAP, VMA_HEAP, 0},
        {"helper_source_heap", true, false, true, 1, FIXTURE_HEAP, VMA_HEAP, 0},
        {"helper_stack_go", true, false, false, 1, FIXTURE_GO, VMA_GOLANG_HEAP, 0},
        {"helper_source_go", true, false, true, 1, FIXTURE_GO, VMA_GOLANG_HEAP, 0},
        {"helper_stack_anon", true, false, false, 1, 0, VMA_ANON, 0},
        {"helper_source_anon", true, false, true, 1, 0, VMA_ANON, 0},
        {"helper_source_vdso", true, false, true, 1, FIXTURE_VDSO, VMA_VDSO, 0},
        {"helper_stack_vdso", true, false, false, 1, FIXTURE_VDSO, VMA_VDSO, 0},
        {"helper_stack_main_vdso",
         true,
         false,
         false,
         1,
         FIXTURE_MAIN_STACK | FIXTURE_VDSO,
         VMA_MAIN_STACK,
         0},
        {"helper_source_main_vdso",
         true,
         false,
         true,
         1,
         FIXTURE_MAIN_STACK | FIXTURE_VDSO,
         VMA_MAIN_STACK,
         0},
        {"helper_stack_heap_vdso", true, false, false, 1, FIXTURE_HEAP | FIXTURE_VDSO, VMA_HEAP, 0},
        {"helper_source_heap_vdso", true, false, true, 1, FIXTURE_HEAP | FIXTURE_VDSO, VMA_HEAP, 0},
        {"helper_stack_go_vdso",
         true,
         false,
         false,
         1,
         FIXTURE_GO | FIXTURE_VDSO,
         VMA_GOLANG_HEAP,
         0},
        {"helper_source_go_vdso",
         true,
         false,
         true,
         1,
         FIXTURE_GO | FIXTURE_VDSO,
         VMA_GOLANG_HEAP,
         0},
        {"helper_busy", true, false, true, 1, 0, VMA_UNKNOWN, -EBUSY},
        {"legacy_bounds_1_vma", false, true, false, 1, 0, VMA_UNKNOWN, 0},
        {"legacy_bounds_64_vmas", false, true, false, 64, 0, VMA_UNKNOWN, 0},
        {"legacy_bounds_1024_vmas", false, true, false, 1024, 0, VMA_UNKNOWN, 0},
        {"legacy_source_anon_1024_vmas", false, false, true, 1024, 0, VMA_ANON, 0},
        {"legacy_source_file", false, false, true, 1, FIXTURE_FILE, VMA_FILE_BACKED, 0},
        {"legacy_stack_file", false, false, false, 1, FIXTURE_FILE, VMA_FILE_BACKED, 0},
        {"legacy_chain_near_limit",
         false,
         true,
         false,
         MAX_VMA_RB_TREE_DEPTH - 1,
         FIXTURE_CHAIN,
         VMA_UNKNOWN,
         0},
        {"legacy_chain_at_limit",
         false,
         true,
         false,
         MAX_VMA_RB_TREE_DEPTH,
         FIXTURE_CHAIN,
         VMA_UNKNOWN,
         0},
        {"legacy_chain_over_limit",
         false,
         true,
         false,
         MAX_VMA_RB_TREE_DEPTH + 1,
         FIXTURE_CHAIN,
         VMA_UNKNOWN,
         -ENOENT},
        {"legacy_cycle", false, true, false, 1, FIXTURE_CYCLE, VMA_UNKNOWN, -ENOENT},
    };
    printf("scenario,native_mock_ns_per_op,mock_reads_per_op,mock_read_bytes_per_op,mock_string_"
           "reads_per_op,mock_vma_helper_calls_per_op,mock_task_helper_calls_per_op\n");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        bench(&cases[i]);
    fprintf(stderr,
            "snapshot_bytes=%zu,bounds_bytes=%zu,checksum=%" PRIu64 "\n",
            sizeof(struct vma_snapshot),
            sizeof(address_range_t),
            consumed);
    return 0;
}
