#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${PIN_ROOT:-}" ]]; then
    echo "Set PIN_ROOT to the Intel PIN installation before running this script." >&2
    exit 1
fi

if [[ ! -d "$PIN_ROOT" ]]; then
    echo "PIN_ROOT does not exist: $PIN_ROOT" >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
TEMPLATE="$PROJECT_DIR/TracerPIN_modified/.clangd.example"
OUTPUT="$PROJECT_DIR/TracerPIN_modified/.clangd"

if [[ ! -f "$TEMPLATE" ]]; then
    echo "Missing clangd template: $TEMPLATE" >&2
    exit 1
fi

PIN_ROOT_ESCAPED=$(printf '%s' "${PIN_ROOT%/}" | sed 's/[&|]/\\&/g')
sed "s|@PIN_ROOT@|$PIN_ROOT_ESCAPED|g" "$TEMPLATE" > "$OUTPUT"

echo "Generated $OUTPUT using PIN_ROOT=$PIN_ROOT"
