#!/bin/sh
# Exercise production VMA lookups with ordinary memory and injected read errors.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/tracee-vma-memory.XXXXXX")
trap 'rm -f "$test_dir/vma_memory_test"; rmdir "$test_dir"' 0

case $(uname -m) in
    x86_64) target=x86 ;;
    aarch64|arm64) target=arm64 ;;
    *) echo "unsupported native test architecture" >&2; exit 1 ;;
esac

"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
    -D"bpf_target_${target}" \
    -I"$repo_dir/tests/benchmarks/vma_mocks" -I"$repo_dir/pkg/ebpf/c" \
    "$repo_dir/tests/unit/vma_memory_test.c" -o "$test_dir/vma_memory_test"
"$test_dir/vma_memory_test"
