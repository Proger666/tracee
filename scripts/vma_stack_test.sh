#!/bin/sh
# Exercise production stack transitions using ordinary userspace data only.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/tracee-vma-stack.XXXXXX")
trap 'rm -f "$test_dir/vma_stack_test"; rmdir "$test_dir"' 0

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$repo_dir/pkg/ebpf/c" \
    "$repo_dir/tests/unit/vma_stack_test.c" -o "$test_dir/vma_stack_test"
"$test_dir/vma_stack_test"
