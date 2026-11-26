#!/bin/sh
# Measure production VMA lookup logic with ordinary userspace mock adapters.
# This does not measure eBPF, kernel helper or syscall latency.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bench_dir=$(mktemp -d "${TMPDIR:-/tmp}/tracee-vma-bench.XXXXXX")
trap 'rm -f "$bench_dir/vma_memory_bench"; rmdir "$bench_dir"' 0

case $(uname -m) in
    x86_64) target=x86 ;;
    aarch64|arm64) target=arm64 ;;
    *) echo "unsupported native benchmark architecture" >&2; exit 1 ;;
esac

"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
    -D"bpf_target_${target}" \
    -I"$repo_dir/tests/benchmarks/vma_mocks" -I"$repo_dir/pkg/ebpf/c" \
    "$repo_dir/tests/benchmarks/vma_memory_bench.c" -o "$bench_dir/vma_memory_bench"
"$bench_dir/vma_memory_bench"
