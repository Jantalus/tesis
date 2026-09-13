# Case 6 — Study results

## 1. Experimental setup

The experiment ran on the remote x86-64 Debian host using the same `study`
binary for every tool:

```bash
g++ -O0 -g -gdwarf-4 -fno-omit-frame-pointer \
    -rdynamic study.cpp -lz -o study
```

The study has two paths:

- `known_writes()`: a synthetic control with 12 known writes, including a
  four-byte write and a final overwrite of offset `0x08`.
- `compress2()`: the real third-party-library case, with 4096 input bytes and
  an 8192-byte destination. zlib produced 334 bytes and returned success.

`STUDY_DIRECT=1` was used so the pointer observed by TracerPIN matched the
exact pointer returned by `malloc()`. This is a requirement of the TracerPIN
configuration used here, not of zlib.

## 2. Questions

1. Which reads and writes does the library perform on the caller's buffer?
2. What byte values are read or written, and in what order?

The common target format is:

```text
order | operation | address | size | bytes | instruction | thread
```

## 3. Commands used

### TracerPIN

```bash
STUDY_MODE=zlib STUDY_INPUT=4096 STUDY_CAPACITY=8192 \
STUDY_DIRECT=1 Tracer -fname run_zlib -vname compressed -excl 0 \
    -o zlib.trace -- ./study
```

### Frida page monitor

```bash
STUDY_MODE=zlib STUDY_INPUT=4096 STUDY_CAPACITY=8192 \
STUDY_DIRECT=1 frida -f ./study -l frida_monitor.js
```

`MemoryAccessMonitor` reports the first access to monitored pages. It detects
activity, but is not an instruction-by-instruction value trace.

### Frida instruction/value prototype

```bash
STUDY_MODE=known STUDY_CAPACITY=64 STUDY_DIRECT=1 \
    frida -f ./study -l frida_value_trace.js

STUDY_MODE=zlib STUDY_INPUT=4096 STUDY_CAPACITY=8192 \
STUDY_DIRECT=1 frida -f ./study -l frida_value_trace.js
```

`frida_value_trace.js` combines `Interceptor` and `Stalker`: it follows the
main thread, decodes memory operands, calculates effective addresses, filters
accesses intersecting the target buffer, and executes a callout after each
instruction. Each event contains operation, address, size, bytes, instruction
address, and thread ID.

The central instrumentation is:

```javascript
const capturedAccess = operand.access === "w" ? "write" :
    operand.access === "rw" ? "readwrite" : "read";

iterator.putCallout(context => {
    recordAccess(context, instructionAddress,
                 capturedAccess, operand);
});
```

This is an experimental x86-64 implementation. `bytes_after` means the
callout reads the bytes resident at the operand address after the instruction.
For a store, this verifies what was written to memory. For a normal load, it
shows the source bytes in memory, but does not expose the value later held in a
register or temporary.

### Valgrind Lackey

```bash
valgrind --tool=lackey --trace-mem=yes \
    ./study zlib 4096 8192 2> lackey.log
```

Lackey reports ordered reads and writes with addresses and sizes, but its
standard output does not include the data bytes.

### DynamoRIO

```bash
drrun -t drmemtrace -offline -outdir dr_trace -- \
    ./study zlib 4096 8192
```

`drmemtrace` reports detailed memory references. The raw trace was converted
and filtered to retain references intersecting `compressed`. DynamoRIO's
`memval_simple.c` sample is a possible basis for a future value-enabled client.

## 4. Results

The first table below is the original baseline, which used `STUDY_DIRECT=1`
to accommodate the previous TracerPIN pointer-resolution behavior. The updated
guarded-buffer results are reported immediately after it.

The synthetic control has these 12 expected writes:

```text
0:11, 1:22, 4:ddccbbaa,
8:08, 9:09, 10:0a, 11:0b, 12:0c, 13:0d, 14:0e, 15:0f,
8:99
```

| Tool/configuration | Known control | zlib | Values? |
| --- | ---: | ---: | --- |
| TracerPIN | 28 selected events, 12 writes | 351 selected events, 17 writes | Yes for recorded writes |
| Frida `MemoryAccessMonitor` | 1 callback | 2 callbacks: one read, one write | No; page-level notification |
| Frida `Stalker` value prototype | 12 ordered writes | 16 events: 13 reads, 3 writes | Yes for captured memory operands |
| Valgrind Lackey | 31 selected events, 14 writes | 358 selected events, 20 writes | No in standard configuration |
| DynamoRIO `drmemtrace` | 31 selected events, 14 writes | 358 selected events, 20 writes | No in standard configuration |

### Updated guarded-buffer run with interior-pointer tracking

After implementing `-interior 1` and `-interior-size`, the same normal guarded
layout was run without `STUDY_DIRECT=1`:

```text
known:  13 [W] records total = 1 pointer-variable assignment + 12 buffer writes
zlib:  352 records total    = 18 writes, including 1 pointer-variable assignment
```

The 12 `known_writes()` stores were recovered in order and the zlib run
returned success with 334 output bytes. Of the 18 zlib writes, 17 target
zlib's destination contents and one is the assignment of the `compressed`
pointer itself. The `-interior-size` limit prevents the tracked logical region
from expanding into the surrounding guard bytes.

### Why Valgrind and DynamoRIO report 14 writes

The control function itself performs exactly 12 writes. The two additional
writes are caused by the later `free(buffer.allocation)`. Because the direct
mode makes `compressed == allocation`, the allocator's bookkeeping writes can
land at the beginning of the same memory block that we selected as the target.
Valgrind and DynamoRIO trace the complete process, so they include those
allocator writes. They are not additional writes performed by
`known_writes()`.

This is an attribution issue, not a disagreement about the control sequence:

```text
known_writes():       12 application writes
free():                2 allocator writes observed in the target range
total in raw traces:  14 writes
```

The Frida value prototype avoids these two events because it activates the
target filter only while `known_writes()` or `compress2()` is executing. The
new TracerPIN run avoids them for the logical section because the interior
region is explicitly limited with `-interior-size`.

### Regression against the TracerPIN examples

The remote build was also compiled from `TracerPIN_modified/examples.cpp` with
`-O0 -g -gdwarf-4 -fno-omit-frame-pointer -pthread` and every documented
example was executed with `-interior 1`. All processes exited successfully and
the traces matched the operations in the source:

| Example | Observed trace |
| --- | --- |
| Global array | 4 writes |
| Primitive local | 2 writes, 1 read |
| Fixed stack array | 10 writes, 1 read |
| Local malloc array | 6 writes, 1 read |
| Main malloc array | 5 writes, 1 read |
| Indirection function | 6 writes |
| Two-thread array | 6 writes, split across both threads |
| Malloc string | 2 writes, 1 read |
| Pointer-to-pointer matrix | 16 read/write events |

The dynamic examples `arr`, `otherArr`, and `matrix` were repeated with
`-interior 0`; their trace lengths remained identical (7, 7, and 16 lines).
This confirms that interior-pointer tracking is opt-in and does not alter the
existing exact-pointer examples. The first exploratory global-array command
incorrectly supplied `-fname main`; the documented invocation omits `-fname`
and completed normally.

### Frida value-trace examples

The known-control output included events equivalent to:

```json
{"operation":"write", "address":"...", "size":1,
 "bytes_after":"11"}
{"operation":"write", "address":"...", "size":4,
 "bytes_after":"ddccbbaa"}
{"operation":"write", "address":"...", "size":1,
 "bytes_after":"99"}
```

For zlib, the prototype observed a one-byte write of `78`, several 32-byte
reads from the destination range, and two four-byte writes of `1309f0f2` at a
later address. The complete raw output remains on the remote host in
`~/tesis/case6_experiment/frida_value_zlib.log`.

## 5. Interpretation

The results distinguish two meanings of “Frida support”:

- Standard `MemoryAccessMonitor` answers whether monitored pages were touched.
- The new `Stalker` prototype answers the value/order question for the tested
  x86-64 instructions and buffer accesses.

Frida is therefore not inherently unable to obtain values. It requires a
custom instruction-level tracer. The cost is additional implementation work,
JavaScript callouts, architecture-specific effective-address handling, and
future coverage work for vector instructions, string instructions, split
accesses, concurrent threads, and special memory operations.

TracerPIN remains the most direct solution for “what values did this library
write to my buffer?” in this experiment. DynamoRIO is the most promising basis
for a maintainable general-purpose value tracer. Valgrind remains a useful
access baseline, but standard Lackey does not provide values.

## 6. Files and raw traces

The raw traces and filtered reports remain on the remote host under
`~/tesis/case6_experiment/`, including `known_v2.trace`, `zlib_v2.trace`,
`lackey_*_v4.log`, `dr_*_v2_processed/`, and
`frida_value_zlib.log`.
