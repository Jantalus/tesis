# Case 6 — Comparative Study Plan

## Third-party library behavior on a caller-owned buffer

This document defines an experiment to compare TracerPIN with three external
alternatives:

1. Frida `MemoryAccessMonitor`;
2. Valgrind Lackey; and
3. DynamoRIO `drmemtrace`.

The target scenario is a caller-owned destination buffer passed to an opaque
third-party library. The primary example is zlib's `compress()` function.

## 1. Objective

Determine how well each tool answers two questions:

1. Was the destination buffer accessed, including possible accesses outside
   the intended range?
2. Can the tool recover the ordered sequence of memory writes performed on the
   buffer?

The study must distinguish page-level detection from instruction-level memory
tracing. A tool that reports that a page was touched has not necessarily
reported every write to the buffer.

## 2. Research questions

### RQ1 — Access detection

Can the tool detect all accesses to the selected destination and detect an
out-of-bounds access to a guard region?

### RQ2 — Write-sequence recovery

Can the tool recover the ordered write operations, their addresses, access
sizes, and stored values?

### RQ3 — Practicality

What are the setup effort, source/library requirements, runtime overhead,
memory overhead, and trace volume of each approach?

## 3. Tools under comparison

| Tool | Configuration | Role in the study |
| --- | --- | --- |
| TracerPIN | Variable filter, `-excl 0` | Subject under evaluation |
| Frida | Function interception plus `MemoryAccessMonitor` | Low-effort page-access baseline |
| Valgrind Lackey | `--tool=lackey --trace-mem=yes` | General-purpose detailed memory-trace baseline |
| DynamoRIO | `drmemtrace` with a destination-range filter | Dynamic-binary-instrumentation baseline |

An API wrapper may be included as a practical control. It records the
function arguments, return code, output length, and before/after contents, but
does not claim to observe internal writes.

## 4. Test programs

Use two programs: a synthetic control and an opaque-library test.

### 4.1 Synthetic control

The synthetic library must contain stores whose exact sequence is known:

```cpp
extern "C" void known_writes(unsigned char* dst) {
    dst[0] = 0x11;
    dst[1] = 0x22;
    *reinterpret_cast<unsigned int*>(dst + 4) = 0xAABBCCDD;

    for (int i = 8; i < 16; ++i)
        dst[i] = static_cast<unsigned char>(i);
}
```

Add separate variants for:

- repeated writes to the same address;
- sparse writes;
- reads mixed with writes;
- 1-, 2-, 4-, and 8-byte stores;
- an intentional write one byte before the buffer; and
- an intentional write one byte after the buffer.

This program provides ground truth for completeness, address, size, value,
and ordering measurements. Compile this control at `-O0` and retain the
disassembly. The source-level store sequence must not be assumed to equal the
machine-level sequence without checking the generated instructions; a
multi-byte store may also be split into smaller stores.

### 4.2 Opaque-library test

Use zlib without modifying its source:

```cpp
uLong capacity = compressBound(input_size);
unsigned char* compressed = allocate_guarded_buffer(capacity);
uLong output_size = capacity;

int result = compress(compressed, &output_size,
                      input, input_size);
```

Check independently that:

- `result == Z_OK`;
- the output prefix of length `output_size` is valid;
- the bytes after `output_size` are unchanged; and
- the guard bytes before and after the destination are unchanged.

Run with inputs that are:

- empty;
- short and repetitive;
- long and repetitive; and
- long and difficult to compress.

Also vary the compression level with `compress2()`.

## 5. Buffer-layout matrix

Repeat the synthetic and zlib tests using:

| Layout | Purpose |
| --- | --- |
| 16-byte buffer | Tests small-buffer behavior |
| One-page buffer | Exposes page-level monitoring limitations |
| Multi-page buffer | Tests coverage across pages |
| Destination crossing a page boundary | Tests range/page handling |
| Guarded destination | Tests out-of-bounds detection |
| Aligned destination | Baseline |
| Unaligned destination | Tests multi-byte access handling |

The same logical test must use the same layout for every tool.

## 6. Tool procedures

### 6.1 TracerPIN

Compile the caller with debug information. The third-party library does not
need to be recompiled:

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer study.cpp -lz -o study
Tracer -fname main -vname compressed -excl 0 -o tracerpin.log -- ./study
```

Use `-td 1` when thread ownership information is part of the experiment.
Record the exact TracerPIN version, PIN version, compiler, and command line.

### 6.2 Frida

Intercept `compress()` and take the destination from its first argument. Take
the capacity from the second argument and enable `MemoryAccessMonitor` for
that range.

Record:

- callback count;
- page index;
- operation type;
- accessed address;
- instruction address;
- thread ID; and
- whether monitoring was re-armed.

Run two modes:

1. no re-arming, representing the normal low-effort API; and
2. re-arming after each callback, clearly labelled as an experimental mode
   because it is not guaranteed to observe every access.

Do not describe `MemoryAccessMonitor` output as an exact write trace. It
reports the first access to each monitored page.

### 6.3 Valgrind Lackey

Run:

```bash
valgrind --tool=lackey --trace-mem=yes ./study 2> lackey.log
```

Record the complete raw trace before filtering. Then filter the trace to the
known destination address range and retain reads, writes, addresses, and
access sizes.

Report both raw and filtered sizes. This is important because the filtering
work and whole-process trace volume are part of the practical cost of the
approach.

### 6.4 DynamoRIO

Run `drmemtrace` over the same executable and input. Use its trace-analysis
client or a small custom client to retain only data references intersecting
the destination range.

Record:

- data-reference address;
- access size;
- instruction address;
- read/write type;
- thread ID; and
- raw and filtered trace sizes.

The custom filtering client must be included in the reported setup effort.

## 7. Measurements

### Correctness

For the synthetic control, compare each tool against the known event list:

- true positives;
- missed accesses;
- false positives;
- address accuracy;
- access-size accuracy;
- value accuracy; and
- ordering accuracy.

Useful summary measures are:

```text
access recall       = correctly observed accesses / expected accesses
access precision    = correctly observed accesses / reported accesses
order agreement     = correctly ordered event pairs / expected ordered pairs
```

For Frida's normal `MemoryAccessMonitor` mode, sequence recall and order
agreement should be reported as not applicable rather than treated as zero.
That mode provides page events, not memory-operation events.

### Buffer safety

For every run, report whether:

- all expected destination bytes were observed as written;
- any guard byte was modified;
- any reported access falls outside the intended range; and
- the program produced the expected output.

### Cost

Measure:

- setup time;
- required source changes;
- required library changes;
- command/script size;
- elapsed runtime;
- peak resident memory;
- raw log size; and
- filtered log size.

Run each configuration at least five times after one warm-up run. Report the
median and variation. Use the same machine, CPU-affinity policy, compiler,
optimization level, input, and library version for all tools.

## 8. Expected comparison

The expected qualitative result is:

| Tool | Expected strength | Expected limitation |
| --- | --- | --- |
| Frida monitor | Fast, simple access/page detection | Cannot guarantee complete ordered writes |
| Valgrind Lackey | Detailed general memory trace | Very large output and high overhead |
| DynamoRIO | Detailed memory references with thread and size metadata | Requires filtering/client work and trace analysis |
| TracerPIN | Direct source-variable filtering and values | PIN/x86 environment and DWARF requirements |

The synthetic control must validate whether these expectations are true. The
zlib experiment then evaluates the tools when the internal implementation is
unknown.

## 9. Deliverables

The study should produce:

1. source for the synthetic and zlib test programs;
2. Frida, filtering, and analysis scripts;
3. exact command lines and environment versions;
4. raw and filtered traces for representative runs;
5. a correctness table for the synthetic control;
6. an overhead and trace-volume table; and
7. a qualitative analysis of setup friction and information recovered.

## 10. Scope limitation

This study compares user-space memory instrumentation. It does not claim to
measure cache behavior, physical memory traffic, DMA, kernel accesses, or
writes performed by hardware devices. It also does not treat final output
contents as evidence of the internal write order.

## 11. Initial execution status

The first representative run has been completed for the known-write control
and the zlib workload. Results are recorded in
[`case6_experiment/results.md`](case6_experiment/results.md). The initial run
does not yet satisfy the final statistical protocol: five repetitions,
warm-up handling, timing/RSS measurements, and per-tool guard tests remain
follow-up work.
