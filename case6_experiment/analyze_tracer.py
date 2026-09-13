#!/usr/bin/env python3
"""Summarize TracerPIN memory events for a destination range.

Usage: analyze_tracer.py TRACE ADDRESS CAPACITY
"""
import re
import sys

if len(sys.argv) != 4:
    raise SystemExit(__doc__)

trace, address_text, capacity_text = sys.argv[1:]
base = int(address_text, 16)
capacity = int(capacity_text)
events = []

pattern = re.compile(r"^\[([RW])\](?:\[\d+\])?(?:\[\d+\])?0x([0-9a-fA-F]+)\s+(.*)$")
with open(trace, encoding="utf-8", errors="replace") as stream:
    for line in stream:
        match = pattern.match(line.strip())
        if not match:
            continue
        operation, address_text, value = match.groups()
        address = int(address_text, 16)
        events.append((operation, address, value))

selected = [e for e in events if base <= e[1] < base + capacity]
writes = [e for e in selected if e[0] == "W"]
print(f"all_events={len(events)} selected_events={len(selected)} writes={len(writes)}")
for index, (operation, address, value) in enumerate(writes):
    print(f"write[{index}] offset=0x{address - base:x} value={value}")
