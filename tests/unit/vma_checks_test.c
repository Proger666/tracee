#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <common/vma_logic.h>

// Exercise the production event checks with ordinary-memory adapters for the
// unchanged context, VMA, map and output APIs. Assertions inspect emitted event
// data and selection semantics, not helper counts or BPF structure layouts.
typedef uint32_t u32;
typedef uint64_t u64;
#define statfunc        static inline __attribute__((always_inline))
#define unlikely(value) (value)
#define SEC(name)
#define __uint(name, value)   int(*name)[value]
#define __type(name, type)    type *name
#define BPF_MAP_TYPE_HASH     1
#define BPF_NOEXIST           1
#define MAX_EVENT_ID          1024
#define PT_REGS_IP_CORE(regs) ((regs)->ip)
#define PT_REGS_SP_CORE(regs) ((regs)->sp)

enum {
    SUSPICIOUS_SYSCALL_SOURCE = 1,
    STACK_PIVOT,
    NO_EVENT_SUBMIT,
};

struct pt_regs {
    u64 ip, sp;
};

struct task_struct {
    u32 tgid, tid, uid;
    u64 start_time, cgroup_id;
    bool compat, container;
};

typedef struct {
    u64 start, end;
} address_range_t;

typedef struct {
    address_range_t stack;
} task_info_t;

struct vma_snapshot {
    u64 start, end, flags;
    enum vma_type type;
    bool is_vdso;
};

typedef struct {
    u32 syscall, tgid;
    u64 tgid_start_time, vma_addr;
} syscall_source_key_t;

struct saved_argument {
    unsigned int index;
    size_t size;
    unsigned char data[32];
};

typedef struct {
    size_t count;
    struct saved_argument values[12];
} args_buffer_t;

typedef struct {
    u64 submit_for_policies;
    u64 field_types;
    u64 data_filter;
} event_config_t;

typedef struct {
    struct {
        u32 eventid;
        u64 matched_policies;
        u64 ts;
        u32 processor_id, policies_version;
        struct {
            u32 host_pid, host_tid, uid, flags;
            u64 cgroup_id;
        } task;
    } context;
    event_config_t config;
    args_buffer_t args_buf;
} event_data_t;

typedef struct {
    void *ctx;
    event_data_t *event;
    task_info_t *task_info;
} program_data_t;

struct event_fixture {
    bool configured;
    event_config_t config;
    u64 scope;
    bool require_container, filter_uid;
    u32 allowed_uid;
    struct vma_snapshot snapshot;
    long lookup_result;
    int submit_result;
};

struct submission {
    event_data_t event;
    int result;
};

static int sys_32_to_64_map, syscall_source_map;
static struct task_struct current_task;
static struct pt_regs registers;
static task_info_t task_info;
static event_data_t event_buffers[2];
static u32 current_cpu, policy_version;
static u64 current_time;
static struct event_fixture source, stack;
static struct submission submissions[8];
static size_t submission_count;
static bool initialized, selected, translate_compat, change_selection_on_submit;
static bool interpose_other_event;
static u32 failed_init_event;
static u32 selected_syscall, selected_checks, compat_syscall, native_syscall;
static syscall_source_key_t dedup_keys[8];
static size_t dedup_count;
static int dedup_error;

static struct event_fixture *event_fixture(u32 event_id)
{
    switch (event_id) {
        case SUSPICIOUS_SYSCALL_SOURCE:
            return &source;
        case STACK_PIVOT:
            return &stack;
        default:
            return NULL;
    }
}

static int init_program_data(program_data_t *p, void *ctx, u32 event_id)
{
    if (!initialized || event_id == failed_init_event)
        return 0;
    p->ctx = ctx;
    p->event = &event_buffers[current_cpu];
    p->task_info = &task_info;
    p->event->args_buf = (args_buffer_t) {0};
    p->event->context.eventid = event_id;
    p->event->context.ts = current_time;
    p->event->context.processor_id = current_cpu;
    p->event->context.policies_version = policy_version;
    memset(&p->event->context.task, 0, sizeof(p->event->context.task));
    p->event->context.task.host_pid = current_task.tgid;
    p->event->context.task.host_tid = current_task.tid;
    p->event->context.task.cgroup_id = current_task.cgroup_id;
    p->event->context.task.flags = current_task.container ? 1 : 0;
    p->event->config.submit_for_policies = ~0ULL;
    if (event_id != NO_EVENT_SUBMIT) {
        p->event->config.submit_for_policies = 0;
        struct event_fixture *fixture = event_fixture(event_id);
        if (fixture != NULL && fixture->configured)
            p->event->config = fixture->config;
    }
    p->event->context.matched_policies = p->event->config.submit_for_policies;
    return 1;
}

static bool evaluate_scope_filters(program_data_t *p)
{
    struct event_fixture *fixture = event_fixture(p->event->context.eventid);
    if (fixture == NULL)
        return false;
    p->event->context.matched_policies &= fixture->scope;
    if (fixture->require_container && !(p->event->context.task.flags & 1))
        p->event->context.matched_policies = 0;
    if (fixture->filter_uid) {
        p->event->context.task.uid = current_task.uid;
        if (p->event->context.task.uid != fixture->allowed_uid)
            p->event->context.matched_policies = 0;
    }
    return p->event->context.matched_policies != 0;
}

static void *bpf_map_lookup_elem(void *map, const void *key);

static long bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags)
{
    if (map != &syscall_source_map || flags != BPF_NOEXIST || !*(const bool *) value)
        return -EINVAL;
    if (dedup_error)
        return dedup_error;
    const syscall_source_key_t *candidate = key;
    for (size_t i = 0; i < dedup_count; i++) {
        const syscall_source_key_t *saved = &dedup_keys[i];
        if (saved->syscall == candidate->syscall && saved->tgid == candidate->tgid &&
            saved->tgid_start_time == candidate->tgid_start_time &&
            saved->vma_addr == candidate->vma_addr)
            return -EEXIST;
    }
    if (dedup_count == sizeof(dedup_keys) / sizeof(dedup_keys[0]))
        return -ENOSPC;
    dedup_keys[dedup_count++] = *candidate;
    return 0;
}

static struct task_struct *bpf_get_current_task_btf(void)
{
    return &current_task;
}

static struct task_struct *bpf_get_current_task(void)
{
    return &current_task;
}

static bool is_compat(struct task_struct *task)
{
    return task->compat;
}

static u32 get_task_host_tgid(struct task_struct *task)
{
    return task->tgid;
}

static struct task_struct *get_leader_task(struct task_struct *task)
{
    return task;
}

static u64 get_task_start_time(struct task_struct *task)
{
    return task->start_time;
}

static long find_vma_snapshot_current(struct task_struct *task,
                                      u64 address,
                                      struct vma_snapshot *snapshot,
                                      bool check_source)
{
    if (task != &current_task)
        return -EINVAL;
    struct event_fixture *fixture = check_source ? &source : &stack;
    if (fixture->lookup_result)
        return fixture->lookup_result;
    if (!vma_contains_address(fixture->snapshot.start, fixture->snapshot.end, address))
        return -ENOENT;
    *snapshot = fixture->snapshot;
    return 0;
}

static long find_vma_snapshot_legacy(void *ctx,
                                     struct task_struct *task,
                                     u64 address,
                                     struct vma_snapshot *snapshot,
                                     bool check_source)
{
    if (ctx != &registers)
        return -EINVAL;
    return find_vma_snapshot_current(task, address, snapshot, check_source);
}

static bool thread_stack_tracked(task_info_t *task)
{
    return task->stack.start < task->stack.end;
}

static bool address_in_thread_stack(task_info_t *task, u64 address)
{
    return (task->stack.start != 0 || task->stack.end != 0) && task->stack.start <= address &&
           address <= task->stack.end;
}

static const char *get_vma_type_str(enum vma_type type)
{
    const char *names[] = {
        "file backed",
        "anonymous",
        "main stack",
        "thread stack",
        "heap",
        "golang heap/stack",
        "vdso",
        "unknown",
    };
    return names[type];
}

static void
save_to_submit_buf(args_buffer_t *args, const void *value, size_t size, unsigned int index)
{
    assert(args->count < sizeof(args->values) / sizeof(args->values[0]));
    struct saved_argument *argument = &args->values[args->count++];
    assert(size <= sizeof(argument->data));
    argument->index = index;
    argument->size = size;
    memcpy(argument->data, value, size);
}

static void save_str_to_buf(args_buffer_t *args, const void *value, unsigned int index)
{
    save_to_submit_buf(args, value, strlen(value) + 1, index);
}

static int events_perf_submit(program_data_t *p)
{
    assert(submission_count < sizeof(submissions) / sizeof(submissions[0]));
    // Like production submission, enrich task context before copying the event.
    // The next event must retain the container bit while adding the compat bit.
    p->event->context.task.uid = current_task.uid;
    if (current_task.compat)
        p->event->context.task.flags |= 2;
    int result = event_fixture(p->event->context.eventid)->submit_result;
    submissions[submission_count++] = (struct submission) {.event = *p->event, .result = result};
    if (change_selection_on_submit)
        selected_checks = 0;
    if (interpose_other_event && p->event->context.eventid == SUSPICIOUS_SYSCALL_SOURCE) {
        // Model another program reusing the scratch buffer after the source
        // event was copied out. The subsequent check must rebuild its context.
        p->event->context.eventid = NO_EVENT_SUBMIT;
        p->event->context.ts++;
        p->event->context.processor_id++;
        p->event->context.policies_version++;
        p->event->context.matched_policies = 0;
        memset(&p->event->context.task, 0x5a, sizeof(p->event->context.task));
        p->event->config = (event_config_t) {0};
    }
    return result;
}

#include <common/vma_checks.h>

static void *bpf_map_lookup_elem(void *map, const void *key)
{
    u32 syscall = *(const u32 *) key;
    if (map == &sys_32_to_64_map)
        return translate_compat && syscall == compat_syscall ? &native_syscall : NULL;
    if (map == &vma_syscall_checks)
        return selected && syscall == selected_syscall ? &selected_checks : NULL;
    return NULL;
}

static void reset_fixture(void)
{
    current_task = (struct task_struct) {
        .tgid = 41,
        .tid = 42,
        .uid = 73,
        .start_time = 100,
        .cgroup_id = 121,
        .container = true,
    };
    current_cpu = 0;
    current_time = 123456;
    policy_version = 7;
    registers = (struct pt_regs) {.ip = 0x1234, .sp = 0x4567};
    task_info = (task_info_t) {0};
    // Simulate a per-CPU event buffer left by an earlier, unrelated event.
    memset(event_buffers, 0xa5, sizeof(event_buffers));
    source = (struct event_fixture) {
        .configured = true,
        .config = {.submit_for_policies = 1, .field_types = 11, .data_filter = 12},
        .scope = ~0ULL,
        .snapshot = {.start = 0x1000, .end = 0x2000, .flags = 5, .type = VMA_ANON},
    };
    stack = (struct event_fixture) {
        .configured = true,
        .config = {.submit_for_policies = 2, .field_types = 21, .data_filter = 22},
        .scope = ~0ULL,
        .snapshot = {.start = 0x4000, .end = 0x5000, .flags = 3, .type = VMA_FILE_BACKED},
    };
    submission_count = dedup_count = 0;
    dedup_error = 0;
    initialized = selected = true;
    translate_compat = change_selection_on_submit = false;
    interpose_other_event = false;
    failed_init_event = 0;
    selected_syscall = native_syscall = 100;
    compat_syscall = 200;
    selected_checks = VMA_CHECK_SOURCE | VMA_CHECK_STACK;
}

static void dispatch(bool helper, u32 syscall)
{
    assert(handle_syscall_checker(&registers, &registers, syscall, helper) == 0);
}

static void
assert_argument(const event_data_t *event, unsigned int index, const void *expected, size_t size)
{
    const struct saved_argument *argument = &event->args_buf.values[index];
    assert(argument->index == index);
    assert(argument->size == size);
    assert(memcmp(argument->data, expected, size) == 0);
}

static void assert_event(size_t submission, u32 event_id, u32 syscall, const char *type)
{
    assert(submission < submission_count);
    const event_data_t *event = &submissions[submission].event;
    const struct event_fixture *fixture = event_fixture(event_id);
    assert(event->context.eventid == event_id);
    assert(event->context.matched_policies ==
           (fixture->config.submit_for_policies & fixture->scope));
    assert(event->config.submit_for_policies == fixture->config.submit_for_policies);
    assert(event->config.field_types == fixture->config.field_types);
    assert(event->config.data_filter == fixture->config.data_filter);
    assert(event->context.ts == current_time);
    assert(event->context.processor_id == current_cpu);
    assert(event->context.policies_version == policy_version);
    assert(event->context.task.host_pid == current_task.tgid);
    assert(event->context.task.host_tid == current_task.tid);
    assert(event->context.task.cgroup_id == current_task.cgroup_id);
    assert(event->context.task.uid == current_task.uid);
    assert(event->context.task.flags ==
           ((current_task.container ? 1U : 0U) | (current_task.compat ? 2U : 0U)));
    assert(event->args_buf.count == 6);
    u64 address = event_id == SUSPICIOUS_SYSCALL_SOURCE ? registers.ip : registers.sp;
    unsigned long start = fixture->snapshot.start;
    unsigned long size = fixture->snapshot.end - fixture->snapshot.start;
    unsigned long flags = fixture->snapshot.flags;
    assert_argument(event, 0, &syscall, sizeof(syscall));
    assert_argument(event, 1, &address, sizeof(address));
    assert_argument(event, 2, type, strlen(type) + 1);
    assert_argument(event, 3, &start, sizeof(start));
    assert_argument(event, 4, &size, sizeof(size));
    assert_argument(event, 5, &flags, sizeof(flags));
}

static void test_selection(bool helper)
{
    const u32 masks[] = {
        0, VMA_CHECK_SOURCE, VMA_CHECK_STACK, VMA_CHECK_SOURCE | VMA_CHECK_STACK, 0x80};
    for (size_t i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
        reset_fixture();
        selected_checks = masks[i];
        dispatch(helper, selected_syscall);
        size_t expected = 0;
        if (masks[i] & VMA_CHECK_SOURCE)
            assert_event(expected++, SUSPICIOUS_SYSCALL_SOURCE, selected_syscall, "anonymous");
        if (masks[i] & VMA_CHECK_STACK)
            assert_event(expected++, STACK_PIVOT, selected_syscall, "file backed");
        assert(submission_count == expected);
    }

    reset_fixture();
    selected = false;
    dispatch(helper, selected_syscall);
    assert(submission_count == 0);

    reset_fixture();
    change_selection_on_submit = true;
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);
    assert_event(1, STACK_PIVOT, selected_syscall, "file backed");
    submission_count = 0;
    dispatch(helper, selected_syscall);
    assert(submission_count == 0);
}

static void test_independent_policies(bool helper)
{
    reset_fixture();
    source.config.submit_for_policies = 0x5;
    source.scope = 0x4;
    stack.config.submit_for_policies = 0xa;
    stack.scope = 0x8;
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);
    assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, selected_syscall, "anonymous");
    assert_event(1, STACK_PIVOT, selected_syscall, "file backed");

    for (int absent = 0; absent < 3; absent++) {
        reset_fixture();
        if (absent == 0)
            source.configured = false;
        else if (absent == 1)
            source.config.submit_for_policies = 0;
        else
            source.scope = 0;
        dispatch(helper, selected_syscall);
        assert(submission_count == 1);
        assert_event(0, STACK_PIVOT, selected_syscall, "file backed");
    }

    reset_fixture();
    stack.scope = 0;
    dispatch(helper, selected_syscall);
    assert(submission_count == 1);
    assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, selected_syscall, "anonymous");
}

static void test_first_check_failure(bool helper)
{
    // Positive results exclude legitimate sources; negative results mean
    // unavailable metadata. Neither outcome suppresses the independent SP check.
    const long results[] = {1, -EBUSY, -ENOENT, -EFAULT, -EINVAL};
    for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
        reset_fixture();
        source.lookup_result = results[i];
        dispatch(helper, selected_syscall);
        assert(submission_count == 1);
        assert_event(0, STACK_PIVOT, selected_syscall, "file backed");
    }

    reset_fixture();
    source.snapshot.is_vdso = true;
    dispatch(helper, selected_syscall);
    assert(submission_count == 1);
    assert_event(0, STACK_PIVOT, selected_syscall, "file backed");

    reset_fixture();
    source.submit_result = -ENOSPC;
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);
    assert(submissions[0].result == -ENOSPC && submissions[1].result == 0);
    assert_event(1, STACK_PIVOT, selected_syscall, "file backed");

    reset_fixture();
    initialized = false;
    dispatch(helper, selected_syscall);
    assert(submission_count == 0);
    initialized = true;
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);

    reset_fixture();
    failed_init_event = SUSPICIOUS_SYSCALL_SOURCE;
    dispatch(helper, selected_syscall);
    assert(submission_count == 1);
    assert_event(0, STACK_PIVOT, selected_syscall, "file backed");
}

static void test_deduplication(bool helper)
{
    reset_fixture();
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);
    submission_count = 0;
    dispatch(helper, selected_syscall);
    assert(submission_count == 1);
    assert_event(0, STACK_PIVOT, selected_syscall, "file backed");

    current_task.start_time++;
    submission_count = 0;
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);
    assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, selected_syscall, "anonymous");

    reset_fixture();
    dedup_error = -ENOMEM;
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);
}

static void test_compat_normalization(bool helper)
{
    reset_fixture();
    current_task.compat = translate_compat = true;
    dispatch(helper, compat_syscall);
    assert(submission_count == 2);
    assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, native_syscall, "anonymous");
    assert_event(1, STACK_PIVOT, native_syscall, "file backed");

    reset_fixture();
    current_task.compat = true;
    selected_syscall = compat_syscall;
    dispatch(helper, compat_syscall);
    assert(submission_count == 0);

    reset_fixture();
    current_task.compat = translate_compat = true;
    selected_syscall = compat_syscall;
    dispatch(helper, compat_syscall);
    assert(submission_count == 0);

    reset_fixture();
    translate_compat = true;
    dispatch(helper, compat_syscall);
    assert(submission_count == 0);
}

static void test_stack_classification(bool helper)
{
    const enum vma_type safe[] = {VMA_MAIN_STACK, VMA_THREAD_STACK, VMA_GOLANG_HEAP, VMA_ANON};
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); i++) {
        reset_fixture();
        stack.snapshot.type = safe[i];
        dispatch(helper, selected_syscall);
        assert(submission_count == 1);
        assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, selected_syscall, "anonymous");
    }

    reset_fixture();
    task_info.stack = (address_range_t) {.start = 0x1000, .end = 0x2000};
    stack.snapshot.type = VMA_ANON;
    dispatch(helper, selected_syscall);
    assert(submission_count == 2);
    assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, selected_syscall, "thread stack");
    assert_event(1, STACK_PIVOT, selected_syscall, "anonymous");

    reset_fixture();
    task_info.stack = (address_range_t) {.start = 0x4000, .end = 0x5000};
    stack.snapshot.type = VMA_ANON;
    dispatch(helper, selected_syscall);
    assert(submission_count == 1);
}

static void test_common_context_and_cpu_storage(bool helper)
{
    reset_fixture();
    current_task.compat = translate_compat = true;
    source.filter_uid = stack.filter_uid = true;
    source.allowed_uid = stack.allowed_uid = current_task.uid;
    source.require_container = stack.require_container = true;
    interpose_other_event = true;
    dispatch(helper, compat_syscall);
    assert(submission_count == 2);
    assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, native_syscall, "anonymous");
    assert_event(1, STACK_PIVOT, native_syscall, "file backed");

    // Interleave a different task on another modeled CPU, then revisit the
    // first buffer. These are dataflow fixtures, not a kernel concurrency test.
    current_cpu = 1;
    current_time++;
    current_task.tgid++;
    current_task.tid++;
    current_task.uid++;
    current_task.cgroup_id++;
    current_task.container = false;
    source.require_container = stack.require_container = false;
    source.allowed_uid = stack.allowed_uid = current_task.uid;
    policy_version++;
    source.config =
        (event_config_t) {.submit_for_policies = 4, .field_types = 41, .data_filter = 42};
    stack.config =
        (event_config_t) {.submit_for_policies = 8, .field_types = 81, .data_filter = 82};
    submission_count = 0;
    dispatch(helper, compat_syscall);
    assert(submission_count == 2);
    assert_event(0, SUSPICIOUS_SYSCALL_SOURCE, native_syscall, "anonymous");
    assert_event(1, STACK_PIVOT, native_syscall, "file backed");

    current_cpu = 0;
    current_time++;
    submission_count = 0;
    selected_checks = VMA_CHECK_STACK;
    dispatch(helper, compat_syscall);
    assert(submission_count == 1);
    assert_event(0, STACK_PIVOT, native_syscall, "file backed");
}

int main(void)
{
    for (int helper = 0; helper <= 1; helper++) {
        test_selection(helper);
        test_independent_policies(helper);
        test_first_check_failure(helper);
        test_deduplication(helper);
        test_compat_normalization(helper);
        test_stack_classification(helper);
        test_common_context_and_cpu_storage(helper);
    }
    puts("VMA syscall event dataflow tests passed");
    return 0;
}
