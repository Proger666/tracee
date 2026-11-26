#ifndef __COMMON_VMA_STACK_H__
#define __COMMON_VMA_STACK_H__

#include <common/vma_logic.h>

// Callers provide task_info_t, address_range_t, u64, bool, and EBUSY. These
// transitions use scalar data only so userspace tests exercise the same logic.
static inline __attribute__((always_inline)) void reset_thread_stack(task_info_t *task_info)
{
    task_info->stack_lookup_pending = false;
    task_info->stack = (address_range_t) {0};
}

static inline __attribute__((always_inline)) bool record_thread_stack_lookup(
    task_info_t *task_info, u64 thread_sp, long result, address_range_t bounds, bool allow_retry)
{
    reset_thread_stack(task_info);
    if (thread_sp == 0)
        return false;

    if (result == 0 && vma_contains_address(bounds.start, bounds.end, thread_sp - 1)) {
        task_info->stack = bounds;
        return true;
    }

    if (result == -EBUSY && allow_retry) {
        // Keep the original SP, never a VMA pointer or a later userspace SP.
        // end == 0 prevents this pending anchor from being used as a range.
        task_info->stack.start = thread_sp;
        task_info->stack_lookup_pending = true;
    }
    return false;
}

static inline __attribute__((always_inline)) u64 consume_thread_stack_retry(task_info_t *task_info,
                                                                            u64 start_time)
{
    if (!task_info->stack_lookup_pending)
        return 0;

    u64 thread_sp = task_info->stack.start;
    bool valid = task_info->stack.end == 0 && thread_sp != 0 && start_time != 0 &&
                 task_info->context.start_time == start_time;
    // Consume before the helper call. Even a second EBUSY must not leave a
    // retry that could later learn a stack after the child has run userspace.
    reset_thread_stack(task_info);
    return valid ? thread_sp : 0;
}

#endif
