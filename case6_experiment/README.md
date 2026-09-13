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

## TracerPIN interior-pointer experiment

The normal guarded layout passes `compressed` as a pointer into a larger
`malloc` allocation. TracerPIN can opt into resolving that interior pointer
with `-interior 1`. To restrict tracing to the logical section rather than the
whole allocation, provide its size with `-interior-size`:

```bash
export PIN_ROOT=/path/to/pin
STUDY_MODE=known STUDY_CAPACITY=64 \
  ../TracerPIN_modified/Tracer -fname run_known -vname compressed \
  -interior 1 -interior-size 64 -excl 0 \
  -o known_interior_guarded.trace -- ./study

STUDY_MODE=zlib STUDY_INPUT=4096 STUDY_CAPACITY=8192 \
  ../TracerPIN_modified/Tracer -fname run_zlib -vname compressed \
  -interior 1 -interior-size 8192 -excl 0 \
  -o zlib_interior_guarded.trace -- ./study
```

`-interior` is disabled by default. The containing allocation is found with
the predecessor of `std::map::upper_bound()`, giving `O(log M)` lookup for `M`
active allocations. `-interior-size` is validated so the logical section
cannot extend beyond the original allocation.
