#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <common/memory.h>

// Exercise the production header with ordinary memory. Fault injection marks
// readable local fields as unavailable; it never uses invalid native pointers.
static struct mm_struct mm;
static struct vm_area_struct area;
static struct file mapped_file;
static struct vm_special_mapping special;

static void reset_fixture(void)
{
    mm = (struct mm_struct) {0};
    area = (struct vm_area_struct) {
        .vm_start = 0x1000,
        .vm_end = 0x2000,
        .vm_flags = 0x123,
        .vm_mm = &mm,
    };
    special = (struct vm_special_mapping) {.name = "[vdso]"};
    mm.mm_rb.rb_node = &area.vm_rb;
    benchmark_task.mm = &mm;
    benchmark_helper_vma = &area;
    benchmark_helper_result = 0;
    benchmark_has_rb_tree = true;
    benchmark_failed_read = NULL;
    benchmark_fail_string_read = false;
    benchmark_skip_callback = false;
    benchmark_ignore_helper_range = false;
    benchmark_after_read = NULL;
}

static long snapshot_lookup(bool helper, u64 address, struct vma_snapshot *snapshot, bool source)
{
    return helper ? find_vma_snapshot_current(&benchmark_task, address, snapshot, source)
                  : find_vma_snapshot_legacy(NULL, &benchmark_task, address, snapshot, source);
}

static void expect_snapshot(bool helper, bool source, enum vma_type type, bool is_vdso)
{
    struct vma_snapshot snapshot = {};
    long result = snapshot_lookup(helper, area.vm_start, &snapshot, source);
    if (source && type == VMA_FILE_BACKED) {
        assert(result == VMA_LOOKUP_EXCLUDED);
        assert(snapshot.source_is_legitimate && !snapshot.valid);
        return;
    }
    assert(result == 0);
    assert(snapshot.valid);
    assert(snapshot.start == area.vm_start && snapshot.end == area.vm_end);
    assert(snapshot.flags == area.vm_flags && snapshot.type == type);
    // An independent VDSO decision is requested for syscall sources. For
    // stack checks, an earlier class may already settle the decision.
    if (source || type == VMA_VDSO)
        assert(snapshot.is_vdso == is_vdso);
}

static void test_classes_and_precedence(bool helper, bool source)
{
    reset_fixture();
    expect_snapshot(helper, source, VMA_ANON, false);

    area.vm_file = &mapped_file;
    area.vm_mm = NULL;
    area.vm_private_data = &special;
    expect_snapshot(helper, source, VMA_FILE_BACKED, false);

    reset_fixture();
    mm.start_stack = area.vm_end;
    mm.start_brk = area.vm_start;
    mm.brk = area.vm_end;
    area.vm_private_data = &special;
    expect_snapshot(helper, source, VMA_MAIN_STACK, true);
    // The known main stack remains usable without irrelevant heap metadata.
    benchmark_failed_read = &mm.start_brk;
    expect_snapshot(helper, source, VMA_MAIN_STACK, true);

    reset_fixture();
    mm.start_brk = area.vm_start;
    mm.brk = area.vm_end;
    area.vm_private_data = &special;
    expect_snapshot(helper, source, VMA_HEAP, true);

    reset_fixture();
    area.vm_start = GOLANG_ARENA_HINT;
    area.vm_end = area.vm_start + 0x1000;
    area.vm_private_data = &special;
    expect_snapshot(helper, source, VMA_GOLANG_HEAP, true);
    // Ordinary heap metadata keeps precedence at a Go arena address.
    mm.start_brk = area.vm_start;
    mm.brk = area.vm_end;
    expect_snapshot(helper, source, VMA_HEAP, true);

    reset_fixture();
    area.vm_private_data = &special;
    expect_snapshot(helper, source, VMA_VDSO, true);
}

static void test_required_read_failures(bool helper)
{
    reset_fixture();
    const void *fields[] = {
        &area.vm_start,
        &area.vm_end,
        &area.vm_flags,
        &area.vm_file,
        &area.vm_mm,
        &mm.start_stack,
        &mm.start_brk,
        &mm.brk,
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        reset_fixture();
        benchmark_failed_read = fields[i];
        struct vma_snapshot snapshot = {.valid = true};
        assert(snapshot_lookup(helper, area.vm_start, &snapshot, true) != 0);
        assert(!snapshot.valid);
    }
    reset_fixture();
    area.vm_mm = NULL;
    struct vma_snapshot snapshot = {.valid = true};
    assert(snapshot_lookup(helper, area.vm_start, &snapshot, true) == -EFAULT);
    assert(!snapshot.valid);
}

static void test_optional_vdso_data(bool helper, bool source)
{
    reset_fixture();
    area.vm_private_data = &special;
    benchmark_failed_read = &area.vm_private_data;
    expect_snapshot(helper, source, VMA_ANON, false);

    benchmark_failed_read = &special.name;
    expect_snapshot(helper, source, VMA_ANON, false);

    benchmark_failed_read = NULL;
    benchmark_fail_string_read = true;
    expect_snapshot(helper, source, VMA_ANON, false);

    benchmark_fail_string_read = false;
    const char *names[] = {NULL, "", "[vds]", "[vdso]x", "[vdso32]"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        special.name = names[i];
        expect_snapshot(helper, source, VMA_ANON, false);
    }
}

static void test_helper_errors_and_stale_outputs(void)
{
    const long errors[] = {-EBUSY, -ENOENT, -EINVAL, -EOPNOTSUPP};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
        reset_fixture();
        benchmark_helper_result = errors[i];
        struct vma_snapshot snapshot = {.start = 1, .end = 2, .valid = true};
        address_range_t bounds = {.start = 1, .end = 2};
        assert(snapshot_lookup(true, area.vm_start, &snapshot, true) == errors[i]);
        assert(!snapshot.valid);
        assert(find_vma_bounds_current(&benchmark_task, area.vm_start, &bounds) == errors[i]);
        assert(bounds.start == 0 && bounds.end == 0);
    }

    reset_fixture();
    benchmark_skip_callback = true;
    struct vma_snapshot snapshot = {.valid = true};
    address_range_t bounds = {.start = 1, .end = 2};
    assert(snapshot_lookup(true, area.vm_start, &snapshot, true) == -EFAULT);
    assert(!snapshot.valid);
    assert(find_vma_bounds_current(&benchmark_task, area.vm_start, &bounds) == -EFAULT);
    assert(bounds.start == 0 && bounds.end == 0);

    reset_fixture();
    area.vm_private_data = &special;
    assert(snapshot_lookup(true, area.vm_start, &snapshot, true) == 0);
    assert(snapshot.valid && snapshot.type == VMA_VDSO && snapshot.is_vdso);
    area.vm_private_data = NULL;
    area.vm_file = &mapped_file;
    assert(snapshot_lookup(true, area.vm_start, &snapshot, false) == 0);
    assert(snapshot.valid && snapshot.type == VMA_FILE_BACKED && !snapshot.is_vdso);
}

static void move_mapping_after_file_read(const void *source)
{
    if (source == &area.vm_file) {
        area.vm_start = 0x3000;
        area.vm_end = 0x4000;
    }
}

static void lose_bounds_after_file_read(const void *source)
{
    if (source == &area.vm_file)
        benchmark_failed_read = &area.vm_start;
}

static void test_file_source_exclusion(bool helper)
{
    reset_fixture();
    area.vm_file = &mapped_file;
    benchmark_failed_read = &area.vm_flags;
    struct vma_snapshot snapshot = {.valid = true, .start = 1, .end = 2};
    assert(snapshot_lookup(helper, area.vm_start, &snapshot, true) == VMA_LOOKUP_EXCLUDED);
    assert(snapshot.source_is_legitimate && !snapshot.valid);
    // A stack-file event still requires a complete snapshot including flags.
    assert(snapshot_lookup(helper, area.vm_start, &snapshot, false) == -EFAULT);
    assert(!snapshot.valid && !snapshot.source_is_legitimate);

    benchmark_failed_read = &area.vm_file;
    assert(snapshot_lookup(helper, area.vm_start, &snapshot, true) == -EFAULT);
    assert(!snapshot.valid && !snapshot.source_is_legitimate);

    benchmark_failed_read = NULL;
    assert(snapshot_lookup(helper, area.vm_start, &snapshot, true) == VMA_LOOKUP_EXCLUDED);
    assert(snapshot.source_is_legitimate && !snapshot.valid);
    assert(snapshot_lookup(helper, area.vm_start, &snapshot, false) == 0);
    assert(snapshot.valid && !snapshot.source_is_legitimate);
    assert(snapshot.type == VMA_FILE_BACKED && snapshot.flags == area.vm_flags);
    assert(snapshot.start == area.vm_start && snapshot.end == area.vm_end);

    if (helper) {
        const long errors[] = {-EBUSY, -ENOENT};
        for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
            assert(snapshot_lookup(true, area.vm_start, &snapshot, true) == VMA_LOOKUP_EXCLUDED);
            benchmark_helper_result = errors[i];
            assert(snapshot_lookup(true, area.vm_start, &snapshot, true) == errors[i]);
            assert(!snapshot.valid && !snapshot.source_is_legitimate);
            benchmark_helper_result = 0;
        }
        // The helper already found a containing VMA while locked. Optional
        // range/flags metadata need not be available to exclude a source.
        const void *unused[] = {&area.vm_start, &area.vm_end, &area.vm_flags};
        for (size_t i = 0; i < sizeof(unused) / sizeof(unused[0]); i++) {
            benchmark_failed_read = unused[i];
            assert(snapshot_lookup(true, area.vm_start, &snapshot, true) == VMA_LOOKUP_EXCLUDED);
            assert(!snapshot.valid && snapshot.source_is_legitimate);
        }
        benchmark_failed_read = NULL;
    }

    area.vm_file = NULL;
    assert(snapshot_lookup(helper, area.vm_start, &snapshot, true) == 0);
    assert(snapshot.valid && !snapshot.source_is_legitimate);
    assert(snapshot.type == VMA_ANON && snapshot.flags == area.vm_flags);
    assert(snapshot.start == area.vm_start && snapshot.end == area.vm_end);
}

static void test_legacy_file_source_revalidation(void)
{
    reset_fixture();
    area.vm_file = &mapped_file;
    u64 original_address = area.vm_start;
    benchmark_after_read = move_mapping_after_file_read;
    struct vma_snapshot snapshot = {.valid = true};
    assert(snapshot_lookup(false, original_address, &snapshot, true) == -EFAULT);
    assert(!snapshot.valid && !snapshot.source_is_legitimate);

    reset_fixture();
    area.vm_file = &mapped_file;
    benchmark_after_read = lose_bounds_after_file_read;
    assert(snapshot_lookup(false, original_address, &snapshot, true) == -EFAULT);
    assert(!snapshot.valid && !snapshot.source_is_legitimate);
}

static void test_ranges(bool helper)
{
    reset_fixture();
    struct vma_snapshot snapshot;
    const u64 present[] = {area.vm_start, area.vm_end - 1};
    for (size_t i = 0; i < sizeof(present) / sizeof(present[0]); i++) {
        assert(snapshot_lookup(helper, present[i], &snapshot, true) == 0);
        assert(snapshot.valid);
    }
    const u64 absent[] = {area.vm_start - 1, area.vm_end, UINT64_MAX};
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); i++) {
        assert(snapshot_lookup(helper, absent[i], &snapshot, true) == -ENOENT);
        assert(!snapshot.valid);
    }

    if (!helper)
        return;
    benchmark_ignore_helper_range = true;
    assert(snapshot_lookup(true, area.vm_end, &snapshot, true) == -EFAULT);
    assert(!snapshot.valid);
    address_range_t bounds = {.start = 1, .end = 2};
    assert(find_vma_bounds_current(&benchmark_task, area.vm_end, &bounds) == -EFAULT);
    assert(bounds.start == 0 && bounds.end == 0);

    area.vm_end = area.vm_start;
    assert(snapshot_lookup(true, area.vm_start, &snapshot, true) == -EFAULT);
    assert(!snapshot.valid);
    assert(find_vma_bounds_current(&benchmark_task, area.vm_start, &bounds) == -EFAULT);
    assert(bounds.start == 0 && bounds.end == 0);
}

static void test_bounds_and_legacy_support(void)
{
    reset_fixture();
    area.vm_mm = NULL;
    benchmark_failed_read = &area.vm_flags;
    address_range_t bounds;
    // Fork tracking only requires a valid range, even when classification
    // metadata is unavailable.
    assert(find_vma_bounds_current(&benchmark_task, area.vm_start, &bounds) == 0);
    assert(bounds.start == area.vm_start && bounds.end == area.vm_end);
    assert(find_vma_bounds_legacy(NULL, &benchmark_task, area.vm_start, &bounds) == 0);
    assert(bounds.start == area.vm_start && bounds.end == area.vm_end);

    reset_fixture();
    benchmark_failed_read = &area.vm_end;
    assert(find_vma_bounds_current(&benchmark_task, area.vm_start, &bounds) == -EFAULT);
    assert(bounds.start == 0 && bounds.end == 0);

    reset_fixture();
    benchmark_has_rb_tree = false;
    struct vma_snapshot snapshot = {.valid = true};
    assert(snapshot_lookup(false, area.vm_start, &snapshot, true) == -EOPNOTSUPP);
    assert(!snapshot.valid);
}

static void test_legacy_depth_and_cycles(void)
{
    reset_fixture();
    struct vm_area_struct chain[MAX_VMA_RB_TREE_DEPTH + 1] = {};
    for (size_t i = 0; i < sizeof(chain) / sizeof(chain[0]); i++) {
        chain[i] = area;
        chain[i].vm_start = 0x4000 + i * 0x2000;
        chain[i].vm_end = chain[i].vm_start + 0x1000;
        if (i + 1 < sizeof(chain) / sizeof(chain[0]))
            chain[i].vm_rb.rb_right = &chain[i + 1].vm_rb;
    }
    mm.mm_rb.rb_node = &chain[0].vm_rb;
    struct vma_snapshot snapshot;
    assert(snapshot_lookup(false, chain[MAX_VMA_RB_TREE_DEPTH - 2].vm_start, &snapshot, true) == 0);
    assert(snapshot.valid && snapshot.start == chain[MAX_VMA_RB_TREE_DEPTH - 2].vm_start);
    assert(snapshot_lookup(false, chain[MAX_VMA_RB_TREE_DEPTH - 1].vm_start, &snapshot, true) == 0);
    assert(snapshot.valid && snapshot.start == chain[MAX_VMA_RB_TREE_DEPTH - 1].vm_start);
    // An unavailable range beyond the traversal budget must not become a
    // plausible snapshot, even for a malformed, unbalanced input tree.
    assert(snapshot_lookup(false, chain[MAX_VMA_RB_TREE_DEPTH].vm_start, &snapshot, true) ==
           -ENOENT);
    assert(!snapshot.valid);

    reset_fixture();
    area.vm_rb.rb_right = &area.vm_rb;
    assert(snapshot_lookup(false, area.vm_end, &snapshot, true) == -ENOENT);
    assert(!snapshot.valid);
}

int main(void)
{
    // A traversal regression must terminate the userspace test promptly.
    alarm(5);
    for (int helper = 0; helper <= 1; helper++) {
        for (int source = 0; source <= 1; source++) {
            test_classes_and_precedence(helper, source);
            test_optional_vdso_data(helper, source);
        }
        test_required_read_failures(helper);
        test_ranges(helper);
        test_file_source_exclusion(helper);
    }
    test_helper_errors_and_stale_outputs();
    test_bounds_and_legacy_support();
    test_legacy_depth_and_cycles();
    test_legacy_file_source_revalidation();
    alarm(0);
    puts("VMA memory dataflow tests: OK");
    return 0;
}
