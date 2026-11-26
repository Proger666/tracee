#!/usr/bin/bash

set -euo pipefail

dir=tests/e2e/core/scripts
build=false
run=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) build=true; run=false ;;
        --run) run=true ;;
        *) echo "Usage: $0 [--build] [--run]" >&2; exit 1 ;;
    esac
    shift
done

if [[ "${build}" == true ]]; then
    gcc -std=gnu11 -O2 -Wall -Wextra -Werror -pthread "${dir}/vma_lookup.c" -o "${dir}/vma_lookup"
fi

if [[ "${run}" == true ]]; then
    for mode in normal start end both; do
        echo "INFO: running VMA lookup mode ${mode}"
        "${dir}/vma_lookup" "${mode}"
    done
fi
