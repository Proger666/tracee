// Note: This file is licenced differently from the rest of the project
// SPDX-License-Identifier: GPL-2.0
// Copyright (C) Aqua Security inc.

#ifndef __COMMON_VMA_CHECKS_H__
#define __COMMON_VMA_CHECKS_H__

// Event/context, map and VMA helpers are supplied by the including program.
// The userspace tests exercise these same checks through ordinary-memory adapters.
#define VMA_CHECK_SOURCE (1U << 0)
#define VMA_CHECK_STACK  (1U << 1)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} vma_syscall_checks SEC(".maps");

statfunc void check_suspicious_syscall_source(
    void *ctx, struct pt_regs *regs, struct task_struct *task, u32 syscall, bool use_vma_helper)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SUSPICIOUS_SYSCALL_SOURCE))
        return;

    if (!evaluate_scope_filters(&p))
        return;

    // Get instruction pointer
    u64 ip = PT_REGS_IP_CORE(regs);

    // Find VMA which contains the instruction pointer
    struct vma_snapshot vma = {};
    long ret = use_vma_helper ? find_vma_snapshot_current(task, ip, &vma, true)
                              : find_vma_snapshot_legacy(ctx, task, ip, &vma, true);
    if (ret != 0)
        return;

    // In 32-bit compat mode, syscalls may be invoked by calling into a VDSO provided
    // syscall handler (the vsyscall mechanism).
    // Even the 64-bit VDSO may invoke syscalls, as a fallback mechanism.
    // In such cases, we don't know where was the code that called into the VDSO.
    if (vma.is_vdso)
        return;

    // Build a key that identifies the combination of syscall,
    // source VMA and process so we don't submit it multiple times
    syscall_source_key_t key = {.syscall = syscall,
                                .tgid = get_task_host_tgid(task),
                                .tgid_start_time = get_task_start_time(get_leader_task(task)),
                                .vma_addr = vma.start};
    bool val = true;

    // Try updating the map with the requirement that this key does not exist yet
    if ((int) bpf_map_update_elem(&syscall_source_map, &key, &val, BPF_NOEXIST) == -EEXIST)
        // This key already exists, no need to submit the same syscall-vma-process combination again
        return;

    enum vma_type vma_type = vma.type;
    if (vma_type == VMA_ANON && address_in_thread_stack(p.task_info, ip))
        vma_type = VMA_THREAD_STACK;

    const char *vma_type_str = get_vma_type_str(vma_type);
    unsigned long vma_start = vma.start;
    unsigned long vma_size = vma.end - vma.start;
    unsigned long vma_flags = vma.flags;

    save_to_submit_buf(&p.event->args_buf, &syscall, sizeof(syscall), 0);
    save_to_submit_buf(&p.event->args_buf, &ip, sizeof(ip), 1);
    save_str_to_buf(&p.event->args_buf, (void *) vma_type_str, 2);
    save_to_submit_buf(&p.event->args_buf, &vma_start, sizeof(vma_start), 3);
    save_to_submit_buf(&p.event->args_buf, &vma_size, sizeof(vma_size), 4);
    save_to_submit_buf(&p.event->args_buf, &vma_flags, sizeof(vma_flags), 5);

    events_perf_submit(&p);
}

statfunc void check_stack_pivot(
    void *ctx, struct pt_regs *regs, struct task_struct *task, u32 syscall, bool use_vma_helper)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, STACK_PIVOT))
        return;

    if (!evaluate_scope_filters(&p))
        return;

    // Get stack pointer
    u64 sp = PT_REGS_SP_CORE(regs);

    // Find VMA which contains the stack pointer
    struct vma_snapshot vma = {};
    long ret = use_vma_helper ? find_vma_snapshot_current(task, sp, &vma, false)
                              : find_vma_snapshot_legacy(ctx, task, sp, &vma, false);
    if (unlikely(ret != 0))
        return;

    // Check if the stack pointer points to the stack region.
    //
    // Goroutine stacks are allocated on golang's heap, which means that an
    // exploit performing a stack pivot on a go program will result in a false
    // negative if the new stack location is on golang's heap.
    //
    // To identify thread stacks, they need to be tracked when new threads are
    // created. This means that we cannot identify stacks of threads that were
    // created before tracee started. To avoid false positives, we ignore events
    // where the stack pointer's VMA might be a thread stack but it was not
    // tracked for this thread. This may result in false negatives.
    enum vma_type vma_type = vma.type;
    if (vma_type == VMA_MAIN_STACK || vma_type == VMA_GOLANG_HEAP || vma_type == VMA_THREAD_STACK ||
        (vma_type == VMA_ANON &&
         (!thread_stack_tracked(p.task_info) || address_in_thread_stack(p.task_info, sp))))
        return;

    const char *vma_type_str = get_vma_type_str(vma_type);
    unsigned long vma_start = vma.start;
    unsigned long vma_size = vma.end - vma.start;
    unsigned long vma_flags = vma.flags;

    save_to_submit_buf(&p.event->args_buf, &syscall, sizeof(syscall), 0);
    save_to_submit_buf(&p.event->args_buf, &sp, sizeof(sp), 1);
    save_str_to_buf(&p.event->args_buf, (void *) vma_type_str, 2);
    save_to_submit_buf(&p.event->args_buf, &vma_start, sizeof(vma_start), 3);
    save_to_submit_buf(&p.event->args_buf, &vma_size, sizeof(vma_size), 4);
    save_to_submit_buf(&p.event->args_buf, &vma_flags, sizeof(vma_flags), 5);

    events_perf_submit(&p);
}

statfunc int
handle_syscall_checker(void *ctx, struct pt_regs *regs, u32 syscall, bool use_vma_helper)
{
    // Reuse one task pointer for ABI normalization and both independent
    // event checks. The modern pointer must retain its verifier BTF type.
    struct task_struct *task = use_vma_helper ? bpf_get_current_task_btf()
                                              : (struct task_struct *) bpf_get_current_task();
    if (is_compat(task)) {
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &syscall);
        if (id_64 == NULL)
            return 0;
        syscall = *id_64;
    }

    u32 *selected = bpf_map_lookup_elem(&vma_syscall_checks, &syscall);
    if (selected == NULL)
        return 0;

    // Copy the selection before event processing so both checks use the same
    // decision even if policy registration changes the map in the meantime.
    u32 checks = *selected;
    if (!(checks & (VMA_CHECK_SOURCE | VMA_CHECK_STACK)))
        return 0;

    // Initialize event state independently: another tracing program can use
    // the same per-CPU scratch buffer between these checks.
    if (checks & VMA_CHECK_SOURCE)
        check_suspicious_syscall_source(ctx, regs, task, syscall, use_vma_helper);

    if (checks & VMA_CHECK_STACK)
        check_stack_pivot(ctx, regs, task, syscall, use_vma_helper);

    return 0;
}

#endif
