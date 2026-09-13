#!/usr/bin/env bash
set -eu

TEST_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_DIR=$(cd "$TEST_DIR/.." && pwd)
PIN_ROOT=${PIN_ROOT:?Set PIN_ROOT to the Intel PIN installation}
TRACER=${TRACER:-$ROOT_DIR/Tracer}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/tracerpin-tests.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

g++ -O0 -g -gdwarf-4 -fno-omit-frame-pointer \
    "$TEST_DIR/interior_pointer_test.cpp" -o "$WORK_DIR/interior_pointer_test"

run_trace() {
    local output=$1
    shift
    "$TRACER" -excl 0 -o "$WORK_DIR/$output" "$@" \
        -- "$WORK_DIR/interior_pointer_test" "$output"
}

assert_lines() {
    local file=$1
    local expected=$2
    local actual
    actual=$(wc -l < "$file")
    if [[ "$actual" -ne "$expected" ]]; then
        echo "FAIL: $file has $actual lines; expected $expected" >&2
        cat "$file" >&2
        exit 1
    fi
}

assert_value() {
    local file=$1
    local value=$2
    if ! grep -Eq "[[:space:]]$value$" "$file"; then
        echo "FAIL: $file does not contain value $value" >&2
        cat "$file" >&2
        exit 1
    fi
}

# Existing exact-pointer behavior: pointer assignment plus four stores.
run_trace exact -fname exact_case -vname buffer -interior 0
assert_lines "$WORK_DIR/exact" 6
for value in 0x00000010 0x00000011 0x00000012 0x00000013; do
    assert_value "$WORK_DIR/exact" "$value"
done

# Interior pointers are ignored when the opt-in switch is disabled.
run_trace interior -fname interior_case -vname section -interior 0
assert_lines "$WORK_DIR/interior" 0

# With the switch and a four-byte logical section, the four stores are found.
run_trace interior -fname interior_case -vname section \
    -interior 1 -interior-size 4
assert_lines "$WORK_DIR/interior" 6
for value in 0x000000a0 0x000000a1 0x000000a2 0x000000a3; do
    assert_value "$WORK_DIR/interior" "$value"
done

# A requested section extending past the allocation is rejected safely.
run_trace oversize -fname oversize_case -vname section \
    -interior 1 -interior-size 8
assert_lines "$WORK_DIR/oversize" 0

echo "TracerPIN regression tests passed"
