#!/bin/sh
# Exercise production syscall event dispatch with ordinary-memory adapters.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/tracee-vma-checks.XXXXXX")
trap 'rm -f "$test_dir/vma_checks_test"; rmdir "$test_dir"' 0

"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -I"$repo_dir/pkg/ebpf/c" \
    "$repo_dir/tests/unit/vma_checks_test.c" -o "$test_dir/vma_checks_test"
"$test_dir/vma_checks_test"
