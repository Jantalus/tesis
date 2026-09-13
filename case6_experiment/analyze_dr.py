#!/usr/bin/env python3
import os
import struct
import sys

trace, address_text, capacity_text = sys.argv[1:]
base = int(address_text, 16)
capacity = int(capacity_text)
events = []
with open(trace, "rb") as stream:
    for raw in iter(lambda: stream.read(12), b""):
        if len(raw) != 12:
            break
        operation, size, address = struct.unpack("<HHQ", raw)
        if operation in (0, 1) and base <= address < base + capacity:
            events.append((operation, size, address - base))
print(f"selected_events={len(events)} writes={sum(x[0] == 1 for x in events)}")
print(events[:20])
