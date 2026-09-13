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
for name in exact interior oversize; do
    cp "$WORK_DIR/interior_pointer_test" "$WORK_DIR/$name"
done

g++ -O0 -g -gdwarf-4 -fno-omit-frame-pointer -pthread \
    "$ROOT_DIR/examples.cpp" -o "$WORK_DIR/examples"

run_trace() {
    local output=$1
    shift
    "$TRACER" -excl 0 -o "$WORK_DIR/$output.trace" "$@" \
        -- "$WORK_DIR/$output"
}

run_example() {
    local output=$1
    shift
    "$TRACER" -excl 0 -o "$WORK_DIR/$output.trace" "$@" \
        -- "$WORK_DIR/examples"
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

assert_example_lines() {
    local example=$1
    local expected=$2
    assert_lines "$WORK_DIR/$example.trace" "$expected"
}

# Existing exact-pointer behavior: pointer assignment plus four stores.
run_trace exact -fname exact_case -vname buffer -interior 0
assert_lines "$WORK_DIR/exact.trace" 6
for value in 0x10 0x11 0x12 0x13; do
    assert_value "$WORK_DIR/exact.trace" "$value"
done

# Interior pointers are ignored when the opt-in switch is disabled.
run_trace interior -fname interior_case -vname section -interior 0
assert_lines "$WORK_DIR/interior.trace" 0

# With the switch and a four-byte logical section, the four stores are found.
run_trace interior -fname interior_case -vname section \
    -interior 1 -interior-size 4
assert_lines "$WORK_DIR/interior.trace" 6
for value in 0xa0 0xa1 0xa2 0xa3; do
    assert_value "$WORK_DIR/interior.trace" "$value"
done

# A requested section extending past the allocation is rejected safely.
run_trace oversize -fname oversize_case -vname section \
    -interior 1 -interior-size 8
assert_lines "$WORK_DIR/oversize.trace" 0

# Documented examples.cpp regression.  Addresses are intentionally not
# checked because they vary between executions; event counts are stable.
run_example global -vname globalArray -vs 16 -interior 1
assert_example_lines global 4

run_example primitive -fname primitiveType -vname myVar -vs 4 -interior 1
assert_example_lines primitive 3

run_example fixed -fname fixedArray -vname myTenPositionVector -vs 40 -interior 1
assert_example_lines fixed 11

run_example malloc -fname mallocAndWriteArray -vname otherArr -interior 1
assert_example_lines malloc 7

run_example arr -fname main -vname arr -interior 1
assert_example_lines arr 7

run_example otherArr -fname main -vname otherArr -interior 1
assert_example_lines otherArr 7

run_example thread -fname main -vname anotherArray -td 1 -interior 1
assert_example_lines thread 7

run_example string -fname main -vname hello -interior 1
assert_example_lines string 4

run_example matrix -fname main -vname matrix -interior 1
assert_example_lines matrix 16

echo "TracerPIN regression tests passed"
