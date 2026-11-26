#!/bin/sh
# The shared script runner invokes tests with sh; the E2E helpers require Bash.

script_dir=$(cd "$(dirname "$0")" && pwd) || exit 1
exec bash "${script_dir}/../tests/e2e/test-vma-validation.sh"
