# Case 6 experiment workload

`study.cpp` provides a known-write control and a zlib workload. Build it with
`-O0` for the control experiment and retain the disassembly, because source
statements do not necessarily correspond one-to-one with machine stores.

Examples:

```bash
g++ -O0 -g -gdwarf-4 -fno-omit-frame-pointer study.cpp -lz -o study
./study known 16 64
./study known 16 64 unaligned bad
./study zlib 4096 8192
```

The output includes the destination address, capacity, zlib result/output
length, guard status, and checksum. Use the address and capacity from the
same run when filtering a trace.
