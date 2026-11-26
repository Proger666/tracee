#ifndef __COMMON_MEMORY_H__
#define __COMMON_MEMORY_H__

#include <vmlinux.h>

#include <asm-generic/errno.h>

#include <common/common.h>
#include <common/vma_logic.h>

// A source lookup can exclude a known legitimate mapping without a snapshot.
// Complete snapshots return zero; unavailable lookups return a negative errno.
#define VMA_LOOKUP_EXCLUDED 1

// Keep only values that remain valid after a VMA lookup releases mmap_lock.
// In particular, no kernel pointer may escape the bpf_find_vma callback.
struct vma_snapshot {
    u64 start;
    u64 end;
    u64 flags;
    enum vma_type type;
    bool is_vdso;
    bool valid;
    bool check_source;
    bool source_is_legitimate;
};

// PROTOTYPES

statfunc struct mm_struct *get_mm_from_task(struct task_struct *);
statfunc unsigned long get_arg_start_from_mm(struct mm_struct *);
statfunc unsigned long get_arg_end_from_mm(struct mm_struct *);
statfunc unsigned long get_env_start_from_mm(struct mm_struct *);
statfunc unsigned long get_env_end_from_mm(struct mm_struct *);
statfunc unsigned long get_vma_flags(struct vm_area_struct *);
statfunc struct vm_area_struct *find_vma(void *ctx, struct task_struct *task, u64 addr);
statfunc bool vma_is_vdso(struct vm_area_struct *vma);
statfunc bool address_in_thread_stack(task_info_t *task_info, u64 address);
statfunc int
find_vma_bounds_legacy(void *ctx, struct task_struct *task, u64 addr, address_range_t *bounds);
statfunc long find_vma_bounds_current(struct task_struct *task, u64 addr, address_range_t *bounds);
statfunc int find_vma_snapshot_legacy(void *ctx,
                                      struct task_struct *task,
                                      u64 addr,
                                      struct vma_snapshot *snapshot,
                                      bool check_source);
statfunc long find_vma_snapshot_current(struct task_struct *task,
                                        u64 addr,
                                        struct vma_snapshot *snapshot,
                                        bool check_source);

// FUNCTIONS

statfunc struct mm_struct *get_mm_from_task(struct task_struct *task)
{
    return BPF_CORE_READ(task, mm);
}

statfunc unsigned long get_arg_start_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, arg_start);
}

statfunc unsigned long get_arg_end_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, arg_end);
}

statfunc unsigned long get_env_start_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, env_start);
}

statfunc unsigned long get_env_end_from_mm(struct mm_struct *mm)
{
    return BPF_CORE_READ(mm, env_end);
}

statfunc unsigned long get_vma_flags(struct vm_area_struct *vma)
{
    return BPF_CORE_READ(vma, vm_flags);
}

statfunc struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

/**
 * A busy process can have somewhere in the ballpark of 1000 VMAs.
 * In an ideally balanced tree, this means that the max depth is ~10.
 * A poorly balanced tree can have a leaf node that is up to twice as deep
 * as another leaf node, which in the worst case scenario places its depth
 * at 2*10 = 20.
 * To be extra safe and accomodate for VMA counts higher than 1000,
 * we define the max traversal depth as 35.
 */
#define MAX_VMA_RB_TREE_DEPTH 35

static bool alerted_find_vma_unsupported = false;

// Given a task, find the first VMA which contains the given address.
statfunc struct vm_area_struct *find_vma(void *ctx, struct task_struct *task, u64 addr)
{
    // Legacy lookup for kernels which track VMAs in an RB tree. Newer kernels
    // use the helper-backed snapshot lookup, in a separately loaded program.
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!bpf_core_field_exists(mm->mm_rb)) {
        if (!alerted_find_vma_unsupported) {
            tracee_log(ctx, BPF_LOG_LVL_WARN, BPF_LOG_FIND_VMA_UNSUPPORTED, 0);
            alerted_find_vma_unsupported = true;
        }
        return NULL;
    }

    struct vm_area_struct *vma = NULL;
    struct rb_node *rb_node = BPF_CORE_READ(mm, mm_rb.rb_node);

    for (int i = 0; i < MAX_VMA_RB_TREE_DEPTH; i++) {
        if (rb_node == NULL)
            break;

        struct vm_area_struct *tmp = container_of(rb_node, struct vm_area_struct, vm_rb);
        unsigned long vm_start = BPF_CORE_READ(tmp, vm_start);
        unsigned long vm_end = BPF_CORE_READ(tmp, vm_end);

        if (vm_end > addr) {
            if (vm_start <= addr) {
                vma = tmp;
                break;
            }
            rb_node = BPF_CORE_READ(rb_node, rb_left);
        } else {
            rb_node = BPF_CORE_READ(rb_node, rb_right);
        }
    }

    return vma;
}

// The golang heap consists of arenas which are memory regions mapped using mmap.
// When allocating areans, golang supplies mmap with an address hint, which is an
// address that the kernel should place the mapping at.
// Hints for x86_64 begin at 0xc000000000 and for ARM64 at 0x4000000000.
// This is only an address heuristic: other processes can use these addresses,
// and Go versions with randomized arena addresses need separate handling.
#if defined(bpf_target_x86)
    #define GOLANG_ARENA_HINT (0xc0UL << 32)
#elif defined(bpf_target_arm64)
    #define GOLANG_ARENA_HINT (0x40UL << 32)
#else
    #error Unsupported architecture
#endif
// We define a max hint that we assume golang allocations will never exceed.
// This translates to the address 0xff00000000.
// This means that we assume that a golang program will never allocate more than
// 256GB of memory on x86_64, or 768GB on ARM64.
#define GOLANG_ARENA_HINT_MAX (0xffUL << 32)

statfunc bool vma_is_vdso(struct vm_area_struct *vma)
{
    // vm_private_data is optional and need not be a vm_special_mapping. A
    // failed name read does not invalidate otherwise usable VMA metadata.
    struct vm_special_mapping *special_mapping = NULL;
    if (BPF_CORE_READ_INTO(&special_mapping, vma, vm_private_data) || special_mapping == NULL)
        return false;

    const char *name = NULL;
    if (BPF_CORE_READ_INTO(&name, special_mapping, name) || name == NULL)
        return false;
    // One extra byte distinguishes the exact name from a truncated prefix.
    char mapping_name[8] = {};
    if (bpf_probe_read_str(mapping_name, sizeof(mapping_name), name) != 7)
        return false;
    return strncmp("[vdso]", mapping_name, 7) == 0;
}

statfunc int copy_vma_bounds(struct vm_area_struct *vma, address_range_t *bounds)
{
    if (BPF_CORE_READ_INTO(&bounds->start, vma, vm_start) ||
        BPF_CORE_READ_INTO(&bounds->end, vma, vm_end) || bounds->start >= bounds->end) {
        *bounds = (address_range_t) {0};
        return -EFAULT;
    }
    return 0;
}

statfunc int
copy_vma_snapshot(struct vm_area_struct *vma, struct vma_snapshot *snapshot, bool helper_locked)
{
    snapshot->valid = false;
    snapshot->is_vdso = false;
    snapshot->source_is_legitimate = false;

    struct file *file = NULL;
    if (BPF_CORE_READ_INTO(&file, vma, vm_file))
        return -EFAULT;
    if (helper_locked && snapshot->check_source && file != NULL) {
        // File-backed sources never emit an event. Do not read bounds and
        // flags that the caller will discard, or label a partial snapshot valid.
        // The helper already established containment while holding mmap_lock.
        snapshot->source_is_legitimate = true;
        return 0;
    }

    if (BPF_CORE_READ_INTO(&snapshot->start, vma, vm_start) ||
        BPF_CORE_READ_INTO(&snapshot->end, vma, vm_end) || snapshot->start >= snapshot->end)
        return -EFAULT;
    if (snapshot->check_source && file != NULL) {
        // Legacy lookup is unlocked. Its caller must recheck these bounds
        // before treating this source as legitimate; flags remain unnecessary.
        snapshot->source_is_legitimate = true;
        return 0;
    }
    if (BPF_CORE_READ_INTO(&snapshot->flags, vma, vm_flags))
        return -EFAULT;

    if (file != NULL) {
        snapshot->type = VMA_FILE_BACKED;
    } else {
        struct mm_struct *mm = NULL;
        u64 start_stack = 0;
        if (BPF_CORE_READ_INTO(&mm, vma, vm_mm) || mm == NULL ||
            BPF_CORE_READ_INTO(&start_stack, mm, start_stack))
            return -EFAULT;

        // Main-stack classification takes precedence over heap metadata. Do
        // not read brk fields after this decision has already been made.
        snapshot->type =
            classify_vma(snapshot->start, snapshot->end, false, start_stack, 0, 0, false, false);
        if (snapshot->type != VMA_MAIN_STACK) {
            u64 start_brk = 0, brk = 0;
            if (BPF_CORE_READ_INTO(&start_brk, mm, start_brk) || BPF_CORE_READ_INTO(&brk, mm, brk))
                return -EFAULT;
            snapshot->type = classify_vma(
                snapshot->start,
                snapshot->end,
                false,
                start_stack,
                start_brk,
                brk,
                vma_in_golang_arena(snapshot->start, GOLANG_ARENA_HINT, GOLANG_ARENA_HINT_MAX),
                false);
        }

        // Syscall sources exclude VDSO regardless of classification precedence.
        // Stack checks only need its name when earlier classes did not match.
        if (snapshot->check_source || snapshot->type == VMA_ANON) {
            snapshot->is_vdso = vma_is_vdso(vma);
            if (snapshot->type == VMA_ANON && snapshot->is_vdso)
                snapshot->type = VMA_VDSO;
        }
    }
    snapshot->valid = true;
    return 0;
}

statfunc int
find_vma_bounds_legacy(void *ctx, struct task_struct *task, u64 addr, address_range_t *bounds)
{
    *bounds = (address_range_t) {0};
    struct vm_area_struct *vma = find_vma(ctx, task, addr);
    if (vma == NULL)
        return -ENOENT;
    int ret = copy_vma_bounds(vma, bounds);
    if (ret != 0)
        return ret;
    if (!vma_contains_address(bounds->start, bounds->end, addr)) {
        *bounds = (address_range_t) {0};
        return -EFAULT;
    }
    return 0;
}

statfunc int find_vma_snapshot_legacy(
    void *ctx, struct task_struct *task, u64 addr, struct vma_snapshot *snapshot, bool check_source)
{
    *snapshot = (struct vma_snapshot) {.type = VMA_UNKNOWN, .check_source = check_source};

    struct vm_area_struct *vma = find_vma(ctx, task, addr);
    if (vma == NULL) {
        if (!bpf_core_field_exists(((struct mm_struct *) 0)->mm_rb))
            return -EOPNOTSUPP;
        return -ENOENT;
    }

    int ret = copy_vma_snapshot(vma, snapshot, false);
    if (ret != 0)
        return ret;
    if (!vma_contains_address(snapshot->start, snapshot->end, addr)) {
        snapshot->valid = false;
        snapshot->source_is_legitimate = false;
        return -EFAULT;
    }
    if (snapshot->source_is_legitimate)
        return VMA_LOOKUP_EXCLUDED;
    return 0;
}

// This callback must stay in a subprogram reachable only from the modern
// program variants. Merely guarding a helper call at runtime is insufficient
// on old kernels that cannot combine callbacks with Tracee's tail calls.
static long find_vma_bounds_callback(struct task_struct *task,
                                     struct vm_area_struct *vma,
                                     address_range_t *bounds)
{
    (void) task;
    copy_vma_bounds(vma, bounds);
    return 0;
}

static long find_vma_snapshot_callback(struct task_struct *task,
                                       struct vm_area_struct *vma,
                                       struct vma_snapshot *snapshot)
{
    (void) task;
    // The helper holds mmap_lock here. Finish all VMA reads and classification
    // before returning; callers receive only a small, self-contained snapshot.
    copy_vma_snapshot(vma, snapshot, true);
    return 0;
}

// Fork tracking only needs an address range, not full VMA classification.
statfunc long find_vma_bounds_current(struct task_struct *task, u64 addr, address_range_t *bounds)
{
    *bounds = (address_range_t) {0};
    long ret = bpf_find_vma(task, addr, find_vma_bounds_callback, bounds, 0);
    if (ret != 0)
        return ret;
    if (!vma_contains_address(bounds->start, bounds->end, addr)) {
        *bounds = (address_range_t) {0};
        return -EFAULT;
    }
    return 0;
}

// snapshot must point to the caller's BPF stack, as required by bpf_find_vma.
// Lookup is deliberately limited to current's address space: use the typed
// task pointer expected by the verifier, not a cast of bpf_get_current_task().
// Only zero provides a complete snapshot. VMA_LOOKUP_EXCLUDED tells source
// checks to skip a legitimate mapping; negative results include -EBUSY.
statfunc long find_vma_snapshot_current(struct task_struct *task,
                                        u64 addr,
                                        struct vma_snapshot *snapshot,
                                        bool check_source)
{
    *snapshot = (struct vma_snapshot) {.type = VMA_UNKNOWN, .check_source = check_source};

    long ret = bpf_find_vma(task, addr, find_vma_snapshot_callback, snapshot, 0);
    if (ret != 0)
        return ret;
    if (snapshot->source_is_legitimate)
        return VMA_LOOKUP_EXCLUDED;
    if (!snapshot->valid || !vma_contains_address(snapshot->start, snapshot->end, addr)) {
        snapshot->valid = false;
        return -EFAULT;
    }
    return 0;
}

statfunc const char *get_vma_type_str(enum vma_type vma_type)
{
    switch (vma_type) {
        case VMA_FILE_BACKED:
            return "file backed";
        case VMA_ANON:
            return "anonymous";
        case VMA_MAIN_STACK:
            return "main stack";
        case VMA_THREAD_STACK:
            return "thread stack";
        case VMA_HEAP:
            return "heap";
        case VMA_GOLANG_HEAP:
            // Goroutine stacks are allocated on the golang heap
            return "golang heap/stack";
        case VMA_VDSO:
            return "vdso";
        case VMA_UNKNOWN:
        default:
            return "unknown";
    }
}

statfunc bool address_in_thread_stack(task_info_t *task_info, u64 address)
{
    // Get the stack area for this task
    address_range_t *stack = &task_info->stack;
    if (stack->start == 0 && stack->end == 0)
        // This thread's stack isn't tracked
        return false;

    return address >= stack->start && address <= stack->end;
}

#endif
