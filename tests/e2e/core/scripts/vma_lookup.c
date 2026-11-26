#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

// getpid(); return. Keeping a single syscall in this payload makes the two
// events in "both" mode unambiguously belong to the same invocation.
#if defined(__x86_64__)
static const unsigned char payload[] = {0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3};

__asm__(".text\n"
        ".globl call_on_stack\n"
        ".type call_on_stack,@function\n"
        "call_on_stack:\n"
        "push %r12\n"
        "mov %rsp,%r12\n"
        "mov %rsi,%rsp\n"
        "call *%rdi\n"
        "mov %r12,%rsp\n"
        "pop %r12\n"
        "ret\n"
        ".size call_on_stack,.-call_on_stack\n");
#elif defined(__aarch64__)
static const unsigned char payload[] = {
    0x88,
    0x15,
    0x80,
    0xd2, // mov x8, #172 (__NR_getpid)
    0x01,
    0x00,
    0x00,
    0xd4, // svc #0
    0xc0,
    0x03,
    0x5f,
    0xd6 // ret
};

__asm__(".text\n"
        ".globl call_on_stack\n"
        ".type call_on_stack,%function\n"
        "call_on_stack:\n"
        "stp x19,x30,[sp,#-16]!\n"
        "mov x19,sp\n"
        "mov sp,x1\n"
        "blr x0\n"
        "mov sp,x19\n"
        "ldp x19,x30,[sp],#16\n"
        "ret\n"
        ".size call_on_stack,.-call_on_stack\n");
#else
    #error "Unsupported architecture"
#endif

void call_on_stack(void *code, void *stack);

static size_t page_size;

static void fail(const char *operation)
{
    perror(operation);
    exit(EXIT_FAILURE);
}

static void *normal_thread(void *unused)
{
    (void) unused;

    // Mutate the address space while both ordinary stacks make syscalls. This
    // exercises thread-stack tracking and rejection of unrelated VMA changes.
    for (int i = 0; i < 512; i++) {
        void *region = mmap(NULL, 3 * page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region == MAP_FAILED)
            fail("mmap");
        if (mprotect((char *) region + page_size, page_size, PROT_READ | PROT_WRITE) != 0)
            fail("mprotect");
        if (syscall(SYS_getpid) <= 0)
            fail("getpid");
        if (mprotect((char *) region + page_size, page_size, PROT_READ) != 0)
            fail("mprotect");
        if (munmap(region, 3 * page_size) != 0)
            fail("munmap");
    }

    return NULL;
}

static void run_normal(void)
{
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, normal_thread, NULL);
    if (ret != 0) {
        errno = ret;
        fail("pthread_create");
    }
    for (int i = 0; i < 512; i++) {
        if (syscall(SYS_getpid) <= 0)
            fail("getpid");
    }
    ret = pthread_join(thread, NULL);
    if (ret != 0) {
        errno = ret;
        fail("pthread_join");
    }
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "normal") && strcmp(argv[1], "start") &&
                      strcmp(argv[1], "end") && strcmp(argv[1], "both"))) {
        fprintf(stderr, "Usage: %s normal|start|end|both\n", argv[0]);
        return EXIT_FAILURE;
    }

    long configured_page_size = sysconf(_SC_PAGESIZE);
    if (configured_page_size <= 0)
        fail("sysconf");
    page_size = (size_t) configured_page_size;
    char name[16];
    snprintf(name, sizeof(name), "vma_%s", argv[1]);
    if (prctl(PR_SET_NAME, name) != 0)
        fail("prctl");

    if (strcmp(argv[1], "normal") == 0) {
        run_normal();
        return EXIT_SUCCESS;
    }

    // Guard pages keep the executable VMA exactly one page and prevent merging
    // with adjacent anonymous mappings. Test near both ends of that VMA.
    char *region = mmap(NULL, 3 * page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED)
        fail("mmap");
    char *code_page = region + page_size;
    if (mprotect(code_page, page_size, PROT_READ | PROT_WRITE) != 0)
        fail("mprotect");

    char *code = code_page;
    if (strcmp(argv[1], "end") == 0)
        code += page_size - sizeof(payload);
    memcpy(code, payload, sizeof(payload));
    __builtin___clear_cache(code, code + sizeof(payload));
    if (mprotect(code_page, page_size, PROT_READ | PROT_EXEC) != 0)
        fail("mprotect");

    if (strcmp(argv[1], "both") == 0) {
        // sbrk guarantees the primary heap, unlike malloc's mmap arenas. No C
        // or libc code runs on this temporary stack; assembly restores it.
        const size_t stack_size = 16384;
        char *heap = sbrk(stack_size);
        if (heap == (void *) -1)
            fail("sbrk");
        uintptr_t sp = (uintptr_t) (heap + stack_size - 16) & ~(uintptr_t) 15;
        call_on_stack(code, (void *) sp);
    } else {
        ((void (*)(void)) code)();
    }

    if (munmap(region, 3 * page_size) != 0)
        fail("munmap");
    return EXIT_SUCCESS;
}
