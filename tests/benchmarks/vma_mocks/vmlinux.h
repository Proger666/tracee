#ifndef VMA_BENCH_VMLINUX_H
#define VMA_BENCH_VMLINUX_H
// Minimal shapes for the userspace benchmark, not a kernel ABI definition.
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t u64;
struct rb_node {
    struct rb_node *rb_left, *rb_right;
};
struct rb_root {
    struct rb_node *rb_node;
};
struct mm_struct {
    unsigned long arg_start, arg_end, env_start, env_end;
    unsigned long start_stack, start_brk, brk;
    struct rb_root mm_rb;
};
struct file {
    int unused;
};
struct vm_area_struct {
    unsigned long vm_start, vm_end, vm_flags;
    struct file *vm_file;
    struct mm_struct *vm_mm;
    void *vm_private_data;
    struct rb_node vm_rb;
};
struct task_struct {
    struct mm_struct *mm;
};
struct vm_special_mapping {
    const char *name;
};
struct vfsmount {
    int unused;
};
struct mount {
    struct vfsmount mnt;
};
#endif
