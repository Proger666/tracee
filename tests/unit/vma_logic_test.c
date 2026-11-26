#include <stdint.h>
#include <stdio.h>

#include <common/vma_logic.h>

static int failures;

static void check(const char *name, int actual, int expected)
{
    if (actual == expected)
        return;
    fprintf(stderr, "%s: got %d, want %d\n", name, actual, expected);
    failures++;
}

static void test_contains_address(void)
{
    const struct {
        const char *name;
        unsigned long long start;
        unsigned long long end;
        unsigned long long address;
        int contains;
    } cases[] = {
        {"first byte", 0x1000, 0x2000, 0x1000, 1},
        {"last byte", 0x1000, 0x2000, 0x1fff, 1},
        {"exclusive end", 0x1000, 0x2000, 0x2000, 0},
        {"before start", 0x1000, 0x2000, 0xfff, 0},
        {"after end", 0x1000, 0x2000, 0x2001, 0},
        {"empty range", 0x1000, 0x1000, 0x1000, 0},
        {"reversed range", 0x2000, 0x1000, 0x1800, 0},
        {"cleared result", 0, 0, 0, 0},
        {"mapping at zero", 0, 0x1000, 0, 1},
        {"largest contained address", UINT64_MAX - 1, UINT64_MAX, UINT64_MAX - 1, 1},
        {"largest excluded address", UINT64_MAX - 1, UINT64_MAX, UINT64_MAX, 0},
        {"wrapped range", UINT64_MAX - 1, 1, UINT64_MAX, 0},
        {"changed mapping no longer contains address", 0x2000, 0x3000, 0x1800, 0},
    };

    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        check(cases[i].name,
              vma_contains_address(cases[i].start, cases[i].end, cases[i].address),
              cases[i].contains);
}

static void test_classification(void)
{
    const struct {
        const char *name;
        unsigned long long start;
        unsigned long long end;
        int file_backed;
        unsigned long long start_stack;
        unsigned long long start_brk;
        unsigned long long brk;
        int golang_arena;
        int vdso;
        enum vma_type type;
    } cases[] = {
        {"file", 0x1000, 0x2000, 1, 0, 0, 0, 0, 0, VMA_FILE_BACKED},
        {"file precedence", 0x1000, 0x2000, 1, 0x1800, 0x1000, 0x2000, 1, 1, VMA_FILE_BACKED},
        {"initial stack", 0x1000, 0x2000, 0, 0x1800, 0, 0, 0, 0, VMA_MAIN_STACK},
        {"initial stack lower bound", 0x1000, 0x2000, 0, 0x1000, 0, 0, 0, 0, VMA_MAIN_STACK},
        {"initial stack upper bound", 0x1000, 0x2000, 0, 0x2000, 0, 0, 0, 0, VMA_MAIN_STACK},
        {"stack precedence", 0x1000, 0x2000, 0, 0x1800, 0x1000, 0x2000, 1, 1, VMA_MAIN_STACK},
        {"heap", 0x1000, 0x2000, 0, 0, 0x1000, 0x2000, 0, 0, VMA_HEAP},
        {"heap overlap", 0x1000, 0x2000, 0, 0, 0x1800, 0x2800, 0, 0, VMA_HEAP},
        {"heap precedence", 0x1000, 0x2000, 0, 0, 0x1000, 0x2000, 1, 1, VMA_HEAP},
        {"heap ends at mapping start", 0x1000, 0x2000, 0, 0, 0x800, 0x1000, 0, 0, VMA_ANON},
        {"heap starts at mapping end", 0x1000, 0x2000, 0, 0, 0x2000, 0x2800, 0, 0, VMA_ANON},
        {"Go arena", 0x1000, 0x2000, 0, 0, 0, 0, 1, 0, VMA_GOLANG_HEAP},
        {"Go arena precedence", 0x1000, 0x2000, 0, 0, 0, 0, 1, 1, VMA_GOLANG_HEAP},
        {"VDSO", 0x1000, 0x2000, 0, 0, 0, 0, 0, 1, VMA_VDSO},
        {"anonymous", 0x1000, 0x2000, 0, 0, 0, 0, 0, 0, VMA_ANON},
        {"stack address outside mapping", 0x1000, 0x2000, 0, 0x2001, 0, 0, 0, 0, VMA_ANON},
        {"empty mapping", 0x1000, 0x1000, 1, 0x1000, 0, 0, 1, 1, VMA_UNKNOWN},
        {"reversed mapping", 0x2000, 0x1000, 1, 0, 0, 0, 0, 0, VMA_UNKNOWN},
    };

    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check(cases[i].name,
              classify_vma(cases[i].start,
                           cases[i].end,
                           cases[i].file_backed,
                           cases[i].start_stack,
                           cases[i].start_brk,
                           cases[i].brk,
                           cases[i].golang_arena,
                           cases[i].vdso),
              cases[i].type);
    }
}

static void test_golang_arenas(void)
{
    const unsigned long long hints[] = {0xc000000000ULL, 0x4000000000ULL};
    const unsigned long long max = 0xff00000000ULL;
    for (unsigned int i = 0; i < sizeof(hints) / sizeof(hints[0]); i++) {
        check("Go arena first address", vma_in_golang_arena(hints[i], hints[i], max), 1);
        check(
            "Go arena interior address", vma_in_golang_arena(hints[i] + 0x1234, hints[i], max), 1);
        check("before Go arena", vma_in_golang_arena(hints[i] - 1, hints[i], max), 0);
        check("Go arena final region", vma_in_golang_arena(max + 0xffffffffULL, hints[i], max), 1);
        check("after Go arena", vma_in_golang_arena(max + 0x100000000ULL, hints[i], max), 0);
        check("largest address is not Go arena", vma_in_golang_arena(UINT64_MAX, hints[i], max), 0);
    }
}

int main(void)
{
    test_contains_address();
    test_classification();
    test_golang_arenas();
    if (failures != 0)
        return 1;
    puts("VMA scalar logic tests passed");
    return 0;
}
