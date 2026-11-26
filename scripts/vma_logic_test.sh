#!/bin/sh
# Exercise production scalar logic using ordinary userspace data only.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/tracee-vma-logic.XXXXXX")
trap 'rm -f "$test_dir/vma_logic_test"; rmdir "$test_dir"' 0

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$repo_dir/pkg/ebpf/c" \
    "$repo_dir/tests/unit/vma_logic_test.c" -o "$test_dir/vma_logic_test"
"$test_dir/vma_logic_test"
