#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t u64;

typedef struct {
    u64 start;
    u64 end;
} address_range_t;

typedef struct {
    struct {
        u64 start_time;
    } context;
    bool stack_lookup_pending;
    address_range_t stack;
} task_info_t;

#include <common/vma_stack.h>

static int failures;

static void check(const char *name, u64 actual, u64 expected)
{
    if (actual == expected)
        return;
    fprintf(stderr,
            "%s: got %llu, want %llu\n",
            name,
            (unsigned long long) actual,
            (unsigned long long) expected);
    failures++;
}

static void check_unknown(const char *name, const task_info_t *task_info)
{
    check(name, task_info->stack.start, 0);
    check(name, task_info->stack.end, 0);
    check(name, task_info->stack_lookup_pending, false);
}

static void test_busy_recovery(void)
{
    task_info_t task = {.context.start_time = 100};
    address_range_t empty = {0};
    address_range_t bounds = {0x1000, 0x3000};

    check("busy fork has no range",
          record_thread_stack_lookup(&task, 0x3000, -EBUSY, empty, true),
          false);
    check("busy fork awaits first schedule", task.stack_lookup_pending, true);
    check("pending anchor is not a range", task.stack.end, 0);

    u64 thread_sp = consume_thread_stack_retry(&task, 100);
    check("retry uses original fork SP", thread_sp, 0x3000);
    check_unknown("retry consumed before lookup", &task);
    check("consumed retry cannot run twice", consume_thread_stack_retry(&task, 100), 0);

    check("released lock recovers stack",
          record_thread_stack_lookup(&task, thread_sp, 0, bounds, false),
          true);
    check("recovered lower bound", task.stack.start, 0x1000);
    check("recovered upper bound", task.stack.end, 0x3000);
    check("recovered stack has no pending retry", task.stack_lookup_pending, false);
    check("successful range cannot be retried", consume_thread_stack_retry(&task, 100), 0);
    check("later consume preserves recovered range", task.stack.start, 0x1000);
    check("later consume preserves recovered end", task.stack.end, 0x3000);
}

static void test_final_failure(void)
{
    const long results[] = {-EBUSY, -ENOENT, -EFAULT, -EOPNOTSUPP, -EINVAL};
    const address_range_t stale_bounds = {0x1000, 0x3000};

    for (unsigned int i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
        task_info_t task = {.context.start_time = 100};
        record_thread_stack_lookup(&task, 0x3000, -EBUSY, stale_bounds, true);
        u64 thread_sp = consume_thread_stack_retry(&task, 100);
        check("final failure does not accept stale bounds",
              record_thread_stack_lookup(&task, thread_sp, results[i], stale_bounds, false),
              false);
        check_unknown("final failure leaves no trusted stack", &task);
        check("final failure has no userspace retry", consume_thread_stack_retry(&task, 100), 0);
    }
}

static void test_fork_errors(void)
{
    const long results[] = {-ENOENT, -EFAULT, -EOPNOTSUPP, -EINVAL};
    const address_range_t stale_bounds = {0x1000, 0x3000};

    for (unsigned int i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
        task_info_t task = {.context.start_time = 100, .stack = stale_bounds};
        check("nonbusy fork error does not accept bounds",
              record_thread_stack_lookup(&task, 0x3000, results[i], stale_bounds, true),
              false);
        check_unknown("nonbusy fork error is not retried", &task);
    }

    task_info_t legacy = {.context.start_time = 100, .stack = stale_bounds};
    record_thread_stack_lookup(&legacy, 0x3000, -EBUSY, stale_bounds, false);
    check_unknown("legacy lookup does not schedule helper retry", &legacy);
}

static void test_stack_bounds(void)
{
    const struct {
        const char *name;
        u64 thread_sp;
        address_range_t bounds;
        bool valid;
    } cases[] = {
        {"top of stack", 0x3000, {0x1000, 0x3000}, true},
        {"interior stack", 0x2000, {0x1000, 0x3000}, true},
        {"first contained byte", 0x1001, {0x1000, 0x3000}, true},
        {"SP at lower bound has no byte below", 0x1000, {0x1000, 0x3000}, false},
        {"SP beyond upper bound", 0x3001, {0x1000, 0x3000}, false},
        {"zero SP", 0, {0, UINT64_MAX}, false},
        {"empty result", 0x2000, {0, 0}, false},
        {"empty range", 0x2000, {0x1000, 0x1000}, false},
        {"reversed range", 0x2000, {0x3000, 0x1000}, false},
        {"different mapping", 0x2000, {0x4000, 0x5000}, false},
        {"mapping at zero", 1, {0, 0x1000}, true},
        {"largest valid SP", UINT64_MAX, {UINT64_MAX - 1, UINT64_MAX}, true},
        {"wrapped range", UINT64_MAX, {UINT64_MAX - 1, 1}, false},
    };

    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        task_info_t task = {.context.start_time = 100, .stack = {0x9000, 0xa000}};
        check(cases[i].name,
              record_thread_stack_lookup(&task, cases[i].thread_sp, 0, cases[i].bounds, true),
              cases[i].valid);
        check("successful result never arms retry", task.stack_lookup_pending, false);
        if (cases[i].valid) {
            check(cases[i].name, task.stack.start, cases[i].bounds.start);
            check(cases[i].name, task.stack.end, cases[i].bounds.end);
        } else {
            check_unknown(cases[i].name, &task);
        }
    }

    task_info_t task = {.context.start_time = 100};
    record_thread_stack_lookup(&task, 0, -EBUSY, (address_range_t) {0}, true);
    check_unknown("zero SP busy cannot underflow or retry", &task);
    record_thread_stack_lookup(&task, UINT64_MAX, -EBUSY, (address_range_t) {0}, true);
    check("largest SP survives retry", consume_thread_stack_retry(&task, 100), UINT64_MAX);
    record_thread_stack_lookup(&task, 1, -EBUSY, (address_range_t) {0}, true);
    check("SP one survives retry without becoming sentinel",
          consume_thread_stack_retry(&task, 100),
          1);
}

static void test_task_lifetime(void)
{
    task_info_t task = {.context.start_time = 100};
    record_thread_stack_lookup(&task, 0x3000, -EBUSY, (address_range_t) {0}, true);
    check("reused TID cannot consume another task's anchor",
          consume_thread_stack_retry(&task, 200),
          0);
    check_unknown("stale identity cancels pending lookup", &task);
    check("stale anchor cannot be resurrected", consume_thread_stack_retry(&task, 100), 0);

    record_thread_stack_lookup(&task, 0x3000, -EBUSY, (address_range_t) {0}, true);
    check("failed current identity read cancels retry", consume_thread_stack_retry(&task, 0), 0);
    check_unknown("failed identity read leaves no range", &task);

    task.context.start_time = 0;
    record_thread_stack_lookup(&task, 0x3000, -EBUSY, (address_range_t) {0}, true);
    check(
        "zero identities cannot establish task identity", consume_thread_stack_retry(&task, 0), 0);
    check_unknown("zero identities cancel retry", &task);

    task.context.start_time = 100;
    record_thread_stack_lookup(&task, 0x3000, -EBUSY, (address_range_t) {0}, true);
    reset_thread_stack(&task);
    check("exec cancels pending lookup", consume_thread_stack_retry(&task, 100), 0);
    check_unknown("exec discards original anchor", &task);
    check("stack reset preserves task identity", task.context.start_time, 100);

    task_info_t replacement = {.context.start_time = 200};
    check("replacement after exit has no retry", consume_thread_stack_retry(&replacement, 200), 0);
    check("replacement after map eviction has no retry",
          consume_thread_stack_retry(&replacement, 100),
          0);
    check_unknown("replacement cannot inherit old bounds", &replacement);
}

static void test_child_reset(void)
{
    const task_info_t parents[] = {
        {.context.start_time = 100, .stack = {0x1000, 0x3000}},
        {.context.start_time = 100, .stack_lookup_pending = true, .stack = {0x3000, 0}},
    };

    for (unsigned int i = 0; i < sizeof(parents) / sizeof(parents[0]); i++) {
        task_info_t child = parents[i];
        child.context.start_time = 200;
        reset_thread_stack(&child);
        check_unknown("forked child discards parent's range and pending anchor", &child);
        check("child keeps its own identity", child.context.start_time, 200);
        check("child never retries parent's anchor", consume_thread_stack_retry(&child, 200), 0);
    }
}

static void test_invalid_pending_state(void)
{
    task_info_t task = {.context.start_time = 100, .stack_lookup_pending = true};
    check("empty pending anchor cannot be retried", consume_thread_stack_retry(&task, 100), 0);
    check_unknown("empty pending anchor is consumed", &task);

    task.stack_lookup_pending = true;
    task.stack = (address_range_t) {0x1000, 0x3000};
    check("a range cannot be mistaken for pending SP", consume_thread_stack_retry(&task, 100), 0);
    check_unknown("inconsistent pending range is discarded", &task);
}

int main(void)
{
    test_busy_recovery();
    test_final_failure();
    test_fork_errors();
    test_stack_bounds();
    test_task_lifetime();
    test_child_reset();
    test_invalid_pending_state();
    if (failures != 0)
        return 1;
    puts("VMA stack state tests passed");
    return 0;
}
