#!/bin/bash

# Regression checks for VMA result validation; no BPF privileges are required.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/e2e/common.sh
. "${script_dir}/common.sh"
# shellcheck source=tests/e2e/lib-core.sh
. "${script_dir}/lib-core.sh"

# Expected failure cases should not print the runner's ordinary error messages.
info() { :; }
error() { :; }

expect_failure() {
    if "$@"; then
        printf 'Expected failure: %s\n' "$*" >&2
        exit 1
    fi
}

vma_test_dir=$(mktemp -d)
trap 'rm -rf -- "${vma_test_dir}"' EXIT
logfile="${vma_test_dir}/tracee.log"
outputfile="${vma_test_dir}/events.json"

declare -A TEST_CONFIG_MAP
core_init_test_config
INSTTESTS_CORE='VMA_LOOKUP'
KERNEL='6.6.0-test.1.x86_64'

# A real success marker satisfies the existing JSON result parser.
printf '%s\n' '{"name":"VMA_LOOKUP","policies":{"matched":["vma-lookup-test"]}}' > "${outputfile}"
printf '%s\n' 'DEBUG Selected VMA lookup backend {"backend": "bpf_find_vma"}' > "${logfile}"
core_update_vma_test_support "${logfile}"
[[ "${core_vma_backend_missing}" -eq 0 && "${core_skip_vma_lookup}" -eq 0 ]]
core_test_check VMA_LOOKUP "${outputfile}" "${logfile}"

# An error arriving after success must invalidate the completed run.
printf '%s\n' 'ERROR VMA_LOOKUP validation failed' >> "${logfile}"
expect_failure core_test_check VMA_LOOKUP "${outputfile}" "${logfile}"

# A legacy fallback must fail the modern target even if success was recorded.
printf '%s\n' 'DEBUG Selected VMA lookup backend {"backend": "legacy"}' > "${logfile}"
core_update_vma_test_support "${logfile}"
[[ "${core_vma_backend_missing}" -eq 1 && "${core_skip_vma_lookup}" -eq 0 ]]
expect_failure core_test_check VMA_LOOKUP "${outputfile}" "${logfile}"

# Missing diagnostics are not evidence that the modern backend was exercised.
core_vma_backend_missing=0
: > "${logfile}"
core_update_vma_test_support "${logfile}"
[[ "${core_vma_backend_missing}" -eq 1 && "${core_skip_vma_lookup}" -eq 0 ]]
expect_failure core_test_check VMA_LOOKUP "${outputfile}" "${logfile}"

# Selecting unrelated tests does not impose VMA requirements on those tests.
core_vma_backend_missing=0
INSTTESTS_CORE='BPF_ATTACH'
core_update_vma_test_support "${logfile}"
[[ "${core_vma_backend_missing}" -eq 0 ]]

# The VMA fixtures cannot pass after failure or timeout, even with a success event.
for test in SUSPICIOUS_SYSCALL_SOURCE STACK_PIVOT VMA_LOOKUP; do
    core_check_fixture_exit "${test}" 0
    expect_failure core_check_fixture_exit "${test}" 1
    expect_failure core_check_fixture_exit "${test}" 143
done

# DNS success does not require an ICMP reply. Preserve unrelated tests' existing
# result contract when their fixture returns nonzero after producing its event.
printf '%s\n' '{"name":"DNS_DATA_STORE","policies":{"matched":["dns-ds-test"]}}' > "${outputfile}"
core_check_fixture_exit DNS_DATA_STORE 1
core_check_fixture_exit DNS_DATA_STORE 143
core_test_check DNS_DATA_STORE "${outputfile}" "${logfile}"
core_check_fixture_exit BPF_ATTACH 1

printf '%s\n' 'VMA result validation regressions passed'
