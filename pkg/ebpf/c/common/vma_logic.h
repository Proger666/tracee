#ifndef __COMMON_VMA_LOGIC_H__
#define __COMMON_VMA_LOGIC_H__

// Scalar VMA decisions are shared with userspace unit tests. Keep this header
// independent of kernel structures and BPF helpers.
enum vma_type {
    VMA_FILE_BACKED,
    VMA_ANON,
    VMA_MAIN_STACK,
    VMA_THREAD_STACK,
    VMA_HEAP,
    VMA_GOLANG_HEAP,
    VMA_VDSO,
    VMA_UNKNOWN,
};

static inline __attribute__((always_inline)) int
vma_contains_address(unsigned long long start, unsigned long long end, unsigned long long address)
{
    return start < end && start <= address && address < end;
}

static inline __attribute__((always_inline)) int vma_in_golang_arena(unsigned long long start,
                                                                     unsigned long long arena_hint,
                                                                     unsigned long long arena_max)
{
    unsigned long long arena = start & 0xffffffff00000000ULL;
    return arena >= arena_hint && arena <= arena_max;
}

static inline __attribute__((always_inline)) enum vma_type
classify_vma(unsigned long long start,
             unsigned long long end,
             int file_backed,
             unsigned long long start_stack,
             unsigned long long start_brk,
             unsigned long long brk,
             int golang_arena,
             int vdso)
{
    if (start >= end)
        return VMA_UNKNOWN;
    if (file_backed)
        return VMA_FILE_BACKED;
    // Preserve the existing initial-stack heuristic, including its inclusive
    // upper bound. Actual address lookups use vma_contains_address().
    if (start <= start_stack && start_stack <= end)
        return VMA_MAIN_STACK;
    if (start < brk && start_brk < end)
        return VMA_HEAP;
    if (golang_arena)
        return VMA_GOLANG_HEAP;
    if (vdso)
        return VMA_VDSO;
    return VMA_ANON;
}

#endif
