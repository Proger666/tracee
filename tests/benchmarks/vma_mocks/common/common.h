#ifndef VMA_BENCH_COMMON_H
#define VMA_BENCH_COMMON_H
// Ordinary memory adapters and performance counters. Counter values are
// diagnostics, never test assertions about how production code is written.
#include <errno.h>
#include <stddef.h>
#include <string.h>
#define statfunc                        static inline __attribute__((always_inline))
#define container_of(ptr, type, member) ((type *) ((char *) (ptr) - offsetof(type, member)))
typedef struct {
    u64 start, end;
} address_range_t;
typedef struct {
    bool stack_lookup_pending;
    address_range_t stack;
} task_info_t;
struct benchmark_counts {
    uint64_t reads, bytes, strings, helpers, task_helpers;
};
static struct benchmark_counts benchmark_counts;
static struct task_struct benchmark_task;
static struct vm_area_struct *benchmark_helper_vma;
static long benchmark_helper_result;
static int benchmark_has_rb_tree = 1;
// Faults refer to fields in the local fixtures. No invalid native pointer is
// dereferenced to simulate a failed kernel read.
static const void *benchmark_failed_read;
static bool benchmark_fail_string_read;
static bool benchmark_skip_callback;
static bool benchmark_ignore_helper_range;
static void (*benchmark_after_read)(const void *source);
static __attribute__((noinline)) int benchmark_read(void *dst, const void *src, size_t size)
{
    benchmark_counts.reads++;
    benchmark_counts.bytes += size;
    if (!src || src == benchmark_failed_read) {
        memset(dst, 0, size);
        return -EFAULT;
    }
    memcpy(dst, src, size);
    if (benchmark_after_read != NULL)
        benchmark_after_read(src);
    return 0;
}
#define BPF_CORE_READ_INTO(dst, src, field)                                                        \
    benchmark_read((dst), (src) ? &(src)->field : NULL, sizeof(*(dst)))
#define BPF_CORE_READ(src, field)                                                                  \
    ({                                                                                             \
        __typeof__((src)->field) value = {0};                                                      \
        BPF_CORE_READ_INTO(&value, (src), field);                                                  \
        value;                                                                                     \
    })
#define bpf_core_field_exists(field)    (benchmark_has_rb_tree)
#define BPF_LOG_LVL_WARN                0
#define BPF_LOG_FIND_VMA_UNSUPPORTED    0
#define tracee_log(ctx, level, id, ret) ((void) 0)
static inline struct task_struct *bpf_get_current_task_btf(void)
{
    benchmark_counts.task_helpers++;
    return &benchmark_task;
}
#define bpf_find_vma(task, addr, callback, context, flags)                                         \
    ({                                                                                             \
        benchmark_counts.helpers++;                                                                \
        long result = benchmark_helper_result;                                                     \
        struct vm_area_struct *area = benchmark_helper_vma;                                        \
        if (!result && (!area || (!benchmark_ignore_helper_range &&                                \
                                  ((addr) < area->vm_start || (addr) >= area->vm_end))))           \
            result = -ENOENT;                                                                      \
        if (!result && !benchmark_skip_callback)                                                   \
            (callback)((task), area, (context));                                                   \
        result;                                                                                    \
    })
static __attribute__((noinline)) long
bpf_probe_read_str(void *dst, unsigned long size, const char *src)
{
    benchmark_counts.strings++;
    if (!src || !size || benchmark_fail_string_read)
        return -EFAULT;
    size_t len = strnlen(src, size - 1);
    memcpy(dst, src, len);
    ((char *) dst)[len] = 0;
    return len + 1;
}
#endif
