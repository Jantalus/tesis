#!/usr/bin/env python3
"""Filter a Valgrind Lackey trace to one destination range."""
import sys

if len(sys.argv) != 4:
    raise SystemExit("usage: analyze_lackey.py TRACE ADDRESS CAPACITY")

trace, address_text, capacity_text = sys.argv[1:]
base = int(address_text, 16)
capacity = int(capacity_text)
end = base + capacity
selected = reads = writes = 0
shown = 0

with open(trace, encoding="ascii", errors="replace") as stream:
    for line in stream:
        fields = line.split()
        if len(fields) < 2 or fields[0] not in {"L", "S", "M"}:
            continue
        try:
            address_text, size_text = fields[1].split(",", 1)
            address = int(address_text, 16)
            size = int(size_text)
        except ValueError:
            continue
        if address >= end or address + size <= base:
            continue
        selected += 1
        if fields[0] in {"L", "M"}:
            reads += 1
        if fields[0] in {"S", "M"}:
            writes += 1
        if shown < 20:
            print(f"event[{shown}] op={fields[0]} offset=0x{address-base:x} size={size}")
            shown += 1

print(f"selected_events={selected} reads={reads} writes={writes}")
