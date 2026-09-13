# TracerPIN — Use Cases With Friction Analysis

For each use case: the C++ scenario, how existing tools handle it (and why
it hurts), and how TracerPIN compares.

---

## 1. Multi-Threaded Write-Order Forensics

**Problem:** Two threads write to the same variable and you want the exact
interleaving — which thread read what value, then wrote what, and in what
order — to reconstruct why the final state is wrong.

### C++ Example

```cpp
#include <thread>

int* counter;

void increment(int n) {
    for (int i = 0; i < n; i++) {
        int tmp = *counter;   // read
        *counter = tmp + 1;   // write
    }
}

int main() {
    counter = new int(0);
    std::thread t1(increment, 5);
    std::thread t2(increment, 5);
    t1.join();
    t2.join();
    // expected 10, often less
    delete counter;
}
```

### Without TracerPIN — using `rr` (record and replay)

**Steps:**
1. Requires Linux x86-64. Must set:
   ```bash
   sudo sysctl kernel.perf_event_paranoid=1
   ```
2. Record the execution:
   ```bash
   rr record ./compiled
   ```
3. Open the replay:
   ```bash
   rr replay
   ```
   This drops you into a GDB session.
4. Find the variable address:
   ```gdb
   (rr) break main
   (rr) continue
   (rr) p counter
   $1 = (int *) 0x61900000ef80
   ```
5. Set a watchpoint:
   ```gdb
   (rr) awatch *0x61900000ef80
   ```
6. To get a log instead of interactive stops, write a GDB commands block:
   ```gdb
   (rr) commands
   > silent
   > printf "val=%d pc=%p\n", *0x61900000ef80, $pc
   > continue
   > end
   (rr) continue
   ```
   Or a Python script passed via `-x watchlog.py`:
   ```python
   class WatchLogger(gdb.Breakpoint):
       def stop(self):
           val = gdb.parse_and_eval("*0x61900000ef80")
           pc  = gdb.selected_frame().pc()
           print(f"ACCESS val={val} pc={pc:#x}")
           return False
   gdb.execute("break main")
   gdb.execute("run")
   WatchLogger("*0x61900000ef80", gdb.BP_WATCHPOINT, gdb.WP_ACCESS)
   gdb.execute("continue")
   ```

**Why it hurts:**
- Linux x86-64 only. Does not work on macOS.
- Requires a kernel permission change (`perf_event_paranoid`).
- Workflow is interactive first — getting a clean text log requires writing
  a GDB Python script.
- x86 has only 4 hardware watchpoints. Watching more than 4 variables falls
  back to software watchpoints, which are orders of magnitude slower.
- The trace gives you values and `$pc` but no thread ID without extra work.

### With TracerPIN

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer -O0 program.cpp -o compiled -lpthread
Tracer -fname main -vname counter -td 1 -o trace.log -- ./compiled
```

The log shows thread-tagged reads and writes in chronological order:

```
[R][0][0]0x61900000ef80  0x00000003   // thread 0 reads 3
[R][1][0]0x61900000ef80  0x00000003   // thread 1 also reads 3 — stale
[W][0][0]0x61900000ef80  0x00000004   // thread 0 writes 4
[W][1][0]0x61900000ef80  0x00000004   // thread 1 writes 4 — lost update
```

Format: `[OperatorThread][OwnerThread]`. No GDB, no kernel config, no scripting.

---

## 2. Key / Secret Zeroing Verification

**Problem:** `memset(key, 0, n)` before `free(key)` is a dead store: the
compiler can legally remove it at `-O2` since the memory is about to be freed.
At `-O2`, GCC and Clang both apply dead store elimination. The key material
remains in the freed heap page until the allocator reuses it.

Note: compiling with `-g` does **not** prevent this. Debug info and
optimization level are independent.

### C++ Example

```cpp
#include <string.h>
#include <stdlib.h>

void process_key(const char* input) {
    char* key = (char*)malloc(32);
    memcpy(key, input, 32);
    // ... crypto operations on key ...
    memset(key, 0, 32);  // compiler may silently remove this at -O2
    free(key);
}

int main() {
    process_key("mysecretkey1234567890123456789012");
}
```

### Without TracerPIN — disassembly

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer -O2 program.cpp -o compiled
objdump -d compiled | grep -A 60 '<_Z11process_key'
```

You must read x86-64 assembly and look for the zeroing instruction. If
`memset` was preserved it appears as `rep stosb` or a sequence of `xor`/`mov`
plus a loop. If it was elided, those instructions are simply absent.

```asm
# Zeroing preserved (good):
lea    rdi,[rbp-0x20]
xor    eax,eax
mov    ecx,0x20
rep    stosb              ← zero-write is here

# Zeroing elided (bad):
mov    rdi,rbp
call   free@plt           ← jumps straight to free, no zeroing
```

**Why it hurts:**
- Requires reading compiler-generated assembly — non-trivial for developers
  unfamiliar with x86-64.
- The function may be inlined or split across multiple compilation units.
- At high optimization levels the function body is reordered, making the
  assembly harder to follow.
- Needs to be re-checked every time the code or compiler version changes.

### With TracerPIN

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer -O2 program.cpp -o compiled
Tracer -fname process_key -vname key -o trace.log -- ./compiled
```

If the zeroing was elided, the last writes visible in the trace are the
crypto writes, not zero values. If it was preserved, you see:

```
[W]0x...  0x0000c0ffee...   // crypto operation
[W]0x...  0x00000000        // zeroing write ← still here
[W]0x...  0x00000000
...
```

No assembly knowledge required. Works on the actual production binary at `-O2`.

---

## 3. In-Place Algorithm Access Order

**Problem:** In-place algorithms (matrix transpose, FFT, in-place sort) are
correct only if no element is read after it has been incorrectly overwritten.
You want to verify the empirical R/W interleaving matches the expected pattern.

### C++ Example

```cpp
#include <algorithm>

// In-place transpose of an n×n matrix stored row-major in a 1D array.
// Each off-diagonal element is swapped exactly once (i < j).
// A bug: if the loop condition is wrong (j = i instead of j = i+1),
// every pair is swapped twice — the matrix appears unchanged.

void transpose(int* matrix, int n) {
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)  // correct: j starts after i
            std::swap(matrix[i*n + j], matrix[j*n + i]);
}

void transpose_buggy(int* matrix, int n) {
    for (int i = 0; i < n; i++)
        for (int j = i; j < n; j++)  // bug: j = i swaps diagonal + re-swaps pairs
            std::swap(matrix[i*n + j], matrix[j*n + i]);
}

int main() {
    int mat[16];
    for (int i = 0; i < 16; i++) mat[i] = i;
    transpose(mat, 4);
}
```

### Without TracerPIN — Valgrind lackey

```bash
valgrind --tool=lackey --trace-mem=yes ./compiled 2>full_trace.txt
```

Output format — every single memory access in the entire process:
```
I 0023C790,2
L BE801950,4     # data load (read)
S BE80199C,4     # data store (write)
M 0025747C,1     # modify (read + write)
```

To filter down to your variable's address range:
1. First, find the variable's address. Add a temporary print:
   ```cpp
   printf("mat base: %p\n", (void*)mat);
   ```
   Run once under lackey to get the address (it shifts under Valgrind).

2. Then filter with a script:
   ```python
   BASE = 0xBE801950   # address from step 1
   SIZE = 64           # 16 ints * 4 bytes
   with open("full_trace.txt") as f:
       for line in f:
           parts = line.split()
           if len(parts) != 2: continue
           addr, _ = parts[1].split(',')
           if BASE <= int(addr, 16) < BASE + SIZE:
               print(line.strip())
   ```

**Why it hurts:**
- A trivial program generates millions of trace lines. A program with any
  library calls generates hundreds of millions. The file can be gigabytes.
- The address under Valgrind differs from native execution (ASLR suppression,
  layout differences), so you must determine it from within the same Valgrind
  run, requiring a code change.
- No thread label on each access line.
- You write and maintain the filter script yourself.

### With TracerPIN

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer program.cpp -o compiled
Tracer -fname main -vname mat -vs 64 -o trace.log -- ./compiled
```

Only accesses to `mat` are logged. For the correct transpose (`j = i+1`),
each off-diagonal pair appears as one R + one W + one R + one W
(the two reads and two writes of a swap), and each pair of addresses
appears exactly once. For the buggy transpose, the same address pair
appears twice — the second swap undoes the first.

---

## 4. DP Traversal Order on Pre-Initialized Tables

**Problem:** A dynamic programming algorithm reads previously-computed cells.
If the traversal direction is wrong, it reads a cell before the algorithm has
written it. If the table was pre-initialized with `memset(dp, 0, ...)`,
those reads return 0 — valid memory, no Valgrind or ASan complaint — but the
result is silently wrong.

No standard tool detects logically premature reads in a pre-initialized table.

### C++ Example

```cpp
#include <string.h>

const int N = 8;
int dp[N];

// dp[i] = dp[i-1] + dp[i-2], must traverse left-to-right
void fib_dp_correct() {
    memset(dp, 0, sizeof(dp));
    dp[0] = 1; dp[1] = 1;
    for (int i = 2; i < N; i++)
        dp[i] = dp[i-1] + dp[i-2]; // reads already-written cells
}

// Bug: traverses right-to-left, reads cells not yet computed
void fib_dp_buggy() {
    memset(dp, 0, sizeof(dp));
    dp[0] = 1; dp[1] = 1;
    for (int i = N-1; i >= 2; i--)
        dp[i] = dp[i-1] + dp[i-2]; // reads 0 (memset value), not computed values
}

int main() { fib_dp_buggy(); }
```

### Without TracerPIN

**Option A — custom shadow array (requires source modification):**
```cpp
bool written[N] = {false};

void fib_dp_safe() {
    memset(dp, 0, sizeof(dp));
    dp[0] = 1; written[0] = true;
    dp[1] = 1; written[1] = true;
    for (int i = N-1; i >= 2; i--) {
        assert(written[i-1] && "reading uncomputed cell!");
        assert(written[i-2] && "reading uncomputed cell!");
        dp[i] = dp[i-1] + dp[i-2];
        written[i] = true;
    }
}
```
Requires modifying every DP function. Doesn't scale to 2D tables without
significant boilerplate.

**Option B — Valgrind lackey + filter + post-process:**
Same friction as use case 3, plus you must write post-processing logic that
verifies every [R] at address X was preceded by a [W] at address X.

**Option C — custom PIN tool:**
Write a C++ Pintool that maintains a set of written addresses and checks each
read against it. Requires learning the PIN API, compiling the tool, and
maintaining it.

**Why it hurts:** every option requires either modifying the source or writing
a non-trivial instrumentation program from scratch.

### With TracerPIN

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer program.cpp -o compiled
Tracer -fname fib_dp_buggy -vname dp -vs 32 -o trace.log -- ./compiled
```

Post-process the trace with a short script:
```python
written = set()
with open("trace.log") as f:
    for line in f:
        parts = line.split()
        op, addr = parts[0], parts[1]
        if op == "[W]":
            written.add(addr)
        elif op == "[R]" and addr not in written:
            print(f"PREMATURE READ at {addr}")
```

For the correct traversal: no premature reads.
For the buggy traversal: every `dp[i]` for `i >= 2` is flagged as a premature read.

TracerPIN provides the raw sequence; the post-processing is a trivial script
rather than a custom instrumentation framework.

---

## 5. ML / Matrix Output Completeness

**Problem:** You implement a matrix operation (multiply, convolution,
activation) from scratch. A loop-bounds bug silently leaves some output
elements unwritten. The result is wrong but no tool flags it — the output
buffer is valid allocated memory, it just was never written by the algorithm.

No standard tool verifies "every element of this output buffer was written
exactly once."

### C++ Example

```cpp
#include <stdlib.h>

void matmul(float* A, float* B, float* C, int n) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            C[i*n + j] = 0.0f;
            for (int k = 0; k < n; k++)
                C[i*n + j] += A[i*n + k] * B[k*n + j];
        }
}

// Bug: off-by-one — last column of C is never written
void matmul_buggy(float* A, float* B, float* C, int n) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n - 1; j++) {  // should be j < n
            C[i*n + j] = 0.0f;
            for (int k = 0; k < n; k++)
                C[i*n + j] += A[i*n + k] * B[k*n + j];
        }
}

int main() {
    int n = 4;
    float* A = (float*)malloc(n*n*sizeof(float));
    float* B = (float*)malloc(n*n*sizeof(float));
    float* C = (float*)calloc(n*n, sizeof(float));
    // fill A, B ...
    matmul_buggy(A, B, C, n);
    free(A); free(B); free(C);
}
```

### Without TracerPIN

**Option A — add a companion bitset (source modification):**
```cpp
bool was_written[N*N] = {false};

void matmul_checked(float* A, float* B, float* C, int n) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n - 1; j++) {
            C[i*n + j] = 0.0f;
            was_written[i*n + j] = true;
            for (int k = 0; k < n; k++)
                C[i*n + j] += A[i*n + k] * B[k*n + j];
        }
    for (int i = 0; i < n*n; i++)
        assert(was_written[i] && "output element never written");
}
```
Requires modifying the function under test and adding boilerplate for every
matrix operation you want to verify.

**Option B — Valgrind lackey + filter:**
Same friction as use case 3. After filtering to the C buffer's address range,
count distinct write addresses and compare to `n*n`.

**Why it hurts:** both options require either source changes or filtering
through gigabytes of trace output followed by custom analysis.

### With TracerPIN

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer program.cpp -o compiled
Tracer -fname main -vname C -o trace.log -- ./compiled
```

Post-process:
```python
from collections import Counter

write_counts = Counter()
with open("trace.log") as f:
    for line in f:
        parts = line.split()
        if parts[0] == "[W]":
            write_counts[parts[1]] += 1

n = 4
expected = n * n
print(f"written: {len(write_counts)}/{expected}")

doubles = {a: c for a, c in write_counts.items() if c > 1}
if doubles:
    print("double-written addresses:", doubles)
```

Output for the buggy version:
```
written: 12/16     ← last column (4 elements) was never written
```

No source modification. Works on any function and any output buffer.

---

## 6. Third-Party Library Behavior on Your Buffer

**Problem:** You pass a buffer to a third-party function (`zlib`, an image
decoder, a compression library). You want to know exactly which memory-write
operations it performs on that buffer, in what order, and whether it writes
outside the range you allocated — without reading its source or decompiling
it.

### C++ Example

```cpp
#include <zlib.h>
#include <stdlib.h>
#include <string.h>

int main() {
    const char* input = "Hello World. This is a test string for zlib.";
    uLong src_len = strlen(input) + 1;

    uLong dst_len = compressBound(src_len);
    unsigned char* compressed = (unsigned char*)malloc(dst_len);

    // What does zlib write into 'compressed'? In what order?
    // How many bytes? Are there header bytes before the payload?
    compress(compressed, &dst_len, (const unsigned char*)input, src_len);

    free(compressed);
    return 0;
}
```

### Without TracerPIN — Frida

Frida does not always require a separate allocation-discovery run. Because
`compress()` receives the destination as its first argument, a script can
intercept the call and monitor that argument directly:

```javascript
const compress = Module.getGlobalExportByName("compress");

Interceptor.attach(compress, {
    onEnter(args) {
        this.destination = args[0];
        this.capacity = args[1].readULong();
        MemoryAccessMonitor.enable(
            { base: this.destination, size: this.capacity },
            { onAccess(details) {
                console.log(details.operation, details.address,
                            details.from, details.threadId);
            }});
    },
    onLeave() { MemoryAccessMonitor.disable(); }
});
```

This is a reasonable low-effort test for whether the destination is touched.
However, Frida's `MemoryAccessMonitor` reports the first access to each
contained memory page, not every subsequent access. A small destination that
fits in one page therefore produces at most one callback. Re-arming the
monitor after each callback can collect more events, but introduces a race and
still does not provide a guaranteed instruction-level sequence. Frida's
`Stalker` can trace instructions, but obtaining exact memory writes then
requires a custom instruction transformer that decodes stores and computes
their effective addresses.

**What this baseline can establish:** which monitored pages were accessed,
which operation first touched each page, the instruction address, and the
thread. It does not establish the complete write sequence or record the values
stored in the destination.

### With TracerPIN

Compile your own code (not zlib) with debug flags. zlib does not need them.

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer program.cpp -lz -o compiled
Tracer -fname main -vname compressed -excl 0 -o trace.log -- ./compiled
```

`-excl 0` disables the filter that excludes library code, so writes made
from inside zlib to your buffer are recorded.

The trace shows every instrumented write operation zlib makes to your buffer,
in order, with its address, access size, and value:
```
[W]0x...  0x0000789c          // zlib header (one 2-byte store, for example)
[W]0x...  0x0000cb48          // compressed data (store size is tool-dependent)
...
```

The trace records memory instructions, so a multi-byte store is one trace
entry whose size identifies how many bytes it touched; it is not necessarily
one entry per byte. No source modification or monitoring script is required.

### Case-study design

This use case can be evaluated as a black-box buffer-observability study. The
library implementation is deliberately treated as unknown to the tracer.
The experiment asks whether a tool can recover the write footprint and write
sequence of an opaque callee while preserving the caller's normal execution.

The detailed experimental protocol is in
[`case6_comparison_plan.md`](case6_comparison_plan.md).

La comparación detallada de herramientas, extensiones necesarias y la
evaluación de TracerPIN está disponible en
[`case6_comparacion_es.md`](case6_comparacion_es.md).

#### Research question

Can TracerPIN identify all writes made by a third-party library to a caller-
owned buffer, including the first write, the final write, the number of bytes
written, and the temporal order of those writes?

#### Experimental variants

Use one caller and vary only the library operation or destination layout:

1. `compress()` with a buffer substantially larger than the compressed result.
2. `compress2()` with compression levels `Z_BEST_SPEED` and `Z_BEST_COMPRESSION`.
3. A guard-buffer variant that places sentinel bytes immediately before and
   after the destination. The sentinels are checked after the call to detect
   an out-of-bounds write.

The first two variants test whether the trace changes with the library's
algorithmic path. The guard-buffer variant tests spatial completeness. Run
each variant several times with the same input and with inputs of different
lengths (empty, short, incompressible, and highly repetitive).

#### Ground truth and measurements

The caller knows `dst_len` returned by zlib, so it supplies an independent
post-call check: the destination prefix must contain the compressed output,
the bytes after `dst_len` must retain their sentinel value, and the return
code must be `Z_OK`. From the TracerPIN log, measure:

* the minimum and maximum traced destination address;
* the union of bytes touched, expanding each entry by its recorded access
  size;
* the number of write entries and the total number of bytes written;
* the first and last write offsets and the sequence of write offsets; and
* whether any write falls outside the destination range.

The expected result is not that zlib writes one byte at a time. The expected
result is that every write instruction touching the destination is represented
in the trace, and that the union of those writes agrees with the independently
checked output and guard regions.

#### Comparison protocol

Compare tools on the same executable, input corpus, library version, and
machine. Do not treat a page event as equivalent to a memory-operation event;
the comparison has several distinct dimensions:

| Dimension | Frida `MemoryAccessMonitor` | Valgrind Lackey | DynamoRIO `drmemtrace` | TracerPIN |
| --- | --- | --- | --- | --- |
| Buffer discovery | Function argument in the script | Manual filtering or custom tool | Manual filtering or custom client | Caller variable via DWARF |
| Spatial coverage | First access per page | Individual accesses, approximately | Individual data references | Filtered individual reads/writes |
| Ordered sequence | No complete sequence | Yes, after filtering | Yes | Yes |
| Stored values | Not provided by the monitor | Requires extra instrumentation | Requires extra instrumentation | Included in the trace |
| Library code | Interceptor can include it | Included, then filtered | Included, then filtered | Requires `-excl 0` |
| Main cost | JavaScript setup and page granularity | Very large output and high overhead | Trace storage and analysis | PIN/platform and DWARF requirements |

Also include a simple API-wrapper baseline. A wrapper around `compress()` logs
the pointer, capacity, returned length, status, and before/after buffer
contents. It is useful because it represents the easiest practical approach,
but it cannot reveal the internal write order or intermediate values.

For each tool and variant, report:

* setup time and required source/library changes;
* whether all destination pages and guard regions were detected;
* number of events and whether the event sequence is complete;
* whether addresses, access sizes, thread IDs, and stored values are available;
* trace/log size, elapsed time, and peak memory use; and
* whether the compressed output and sentinel checks still pass.

Use a small synthetic library with deliberately known stores as a correctness
control. Then repeat the experiment with zlib as the opaque real-world case.
For the synthetic control, compare each tool's output with the known store
sequence. For zlib, compare spatial coverage against the returned output
length and guard bytes; exact intermediate write order is an observation, not
an independently known ground truth.

#### Reproducible command

```bash
g++ -g -gdwarf-4 -fno-omit-frame-pointer study.cpp -lz -o study
Tracer -fname main -vname compressed -excl 0 -td 1 -o trace.log -- ./study
```

The `-excl 0` setting is essential: the writes occur inside zlib, outside the
main executable. The `-td 1` setting is useful when the study also records
which thread owns the buffer and which thread performs each access. For the
basic single-threaded experiment, it can be omitted.
