TracerPIN
====================

Why use this tool?
----------------------
To trace the actual CPU loads and stores performed on a variable in a program execution. **Mainly for static or dynamic primitive types, or arrays of primitive types.**

Motivation
----------

**The development of this tool is designed for tracing variables of high volume in number crunching scenarios.
For instance a large matrix that represents an image.**

*You could also use it for smaller variables* or to trace all memory operations of a program, but it's not the primary use case.

Quick Start
-----------

Trace variables of:
* **Arrays of primitive types**
* Primitive types

Either dynamic *(malloced)* or static *(local or global)*.

**Example:** You wrote a complex number-crunching routine and allocated a big matrix (or tensor, buffer, etc.) and you want to know exactly how that data structure is really touched by the CPU – the actual sequence of loads and stores performed on the underlying memory pages while your program runs.

1. **Compile your program with debug information:**
   ```bash
   g++ -g -gdwarf-4 -fno-omit-frame-pointer your_program.cpp -o your_program
   ```

2. **Run TracerPIN to trace a variable:**
   ```bash
   Tracer -fname my_function -vname matrix -o my_log_file.log -- ./your_program -its args
   ```

   For static variables, also specify the size:
   ```bash
   Tracer -fname myFunction -vname myArray -vs 40 -o trace.log -- ./your_program -its args
   ```

This will record all the memory operations made to the region that holds the variable and save them to the specified file:
- Every write that initializes the pointer array
- Every read/write when the matrix (or array) is filled or processed
- Exactly which addresses and in which order they are accessed

The result is a clean, chronological log of real memory traffic:

```smalltalk
[W]0x00007fffffffe0a0 0x000055555556b320 // write on matrix
[W]0x000055555556b320 0x000055555556b4b0
[W]0x000055555556b328 0x000055555556b4d0
[W]0x000055555556b330 0x000055555556b4f0
[R]0x000055555556b320 0x000055555556b4b0 // matrix read
...
```

See the [Examples](#examples-for-tracing-variables) section for more detailed use cases.

### Not expected use case
* Tracing of **std::vectors** 
* Tracing of structs with pointer fields

The code could be adapted to do so.


What is this tool?
------------------

TracerPIN is an Intel PIN tool for generating execution traces of a running process.

**This tool is an extension of an existing tool** [(credits)](#credits), focused on the [motivation](#motivation).

Support is limited to platforms supported by Intel PIN and TracerPIN has only been tested under
X86 and X86_64.


Prerequisites
-------------

Before installing TracerPIN, ensure you have the following:

#### System Packages

For x86 and x86_64 support, install:

```bash
sudo apt-get install --no-install-recommends wget make g++
sudo apt-get install --no-install-recommends libstdc++-4.9-dev libssl-dev
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install --no-install-recommends gcc-multilib g++-multilib
sudo apt-get install --no-install-recommends libstdc++-4.9-dev:i386 libssl-dev:i386
```

#### Intel PIN Framework

TracerPIN requires the [Intel PIN framework](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html) (version 3.30, kit 98830).

You can download it manually or use:

```bash
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.30-98830-g1d7b601b3-gcc-linux.tar.gz
tar xzf pin-3.30-98830-g1d7b601b3-gcc-linux.tar.gz
mv pin-3.30-98830-g1d7b601b3-gcc-linux /opt
export PIN_ROOT=/opt/pin-3.30-98830-g1d7b601b3-gcc-linux
echo -e "\nexport PIN_ROOT=/opt/pin-3.30-98830-g1d7b601b3-gcc-linux" >> ~/.bashrc
```

> Make sure you have read/write access to the PIN installation directory.

#### dwgrep Tool

Install `dwgrep` from the [GitHub Repo](https://github.com/pmachata/dwgrep) following their [installation instructions](https://pmachata.github.io/dwgrep/#installation).

You will need *CMake* to compile the tool, install via their [official website](https://cmake.org/download/) or:
```bash
sudo apt install cmake
```

To verify `dwgrep` installation, run the following commands:

```bash
cat > hello.c <<'EOF'
#include <stdio.h>
int main() { printf("Hello DWARF!\\n"); return 0; }
EOF
```

```bash
gcc -g -gdwarf-4 -fno-omit-frame-pointer hello.c -o hello
```

```bash
dwgrep hello -e 'entry ?DW_TAG_compile_unit'
```

You should get an output like the following:

```bash
[b]	compile_unit
	producer	"GNU C23 15.2.1 20250813 -mtune=generic -march=x86-64 -g -gdwarf-4 -fno-omit-frame-pointer"
	language	C99
	name	"hello.c"
	comp_dir	"/home/you"
	low_pc	0x1139
	high_pc	31
	stmt_list	0
```

Clean up the test files:
```bash
rm hello*
```

If verification fails, install additional dependencies:

```bash
sudo apt-get install libdw-dev libelf-dev liblzma-dev libzstd-dev bison
```

You may also need to update `LD_LIBRARY_PATH` to include the path to *libzwerg* (dependency of `dwgrep`), usually `/usr/local/lib64`:

```bash
export LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH
```

Installation
------------

Once prerequisites are installed, compile and install TracerPIN:

```bash
make
sudo make install
```

The `Tracer` binary and the instrumentation libraries (`obj-ia32/`, `obj-intel64/`) are installed under `$(PREFIX)/bin`, which defaults to **`/usr/local/bin`**. Ensure that directory is in your `PATH`. To install elsewhere, run `make install PREFIX=/your/path` (e.g. `PREFIX=$HOME/.local`).

> Ensure `PIN_ROOT` is set in your environment before running `make`.

Usage
-----

Calling the tool without argument will provide some help:

```bash
Tracer
```

### Trace format

Here's the basic command line you would use to trace the `ls` program and generate a human readable trace 
file called `ls.log`.

```bash
Tracer -o ls.log -- ls
```

or to accept the default filename, just do

```bash
Tracer ls
```

So the pattern for using the tool would be 
```
Tracer [options] -o <log_file> -- <executable> [executable_args]

```


The text format is relatively easy to read. Each line begins with a tag indicating the information 
type:

* `[W]` or `[R]` for write or read instructions
* `[B]` Basic block, if `-b 1`
* `[C]` Function call, if `-c 1` or `-C 1`
* `[I]` Instruction execution, if `-i 1`
* With the debug flag `-d 1`
    * `[*]` Arguments
    * `[-]` Information on base image and libraries
    * `[!]` Information on filtered elements
    * `[T]` Thread event
    * `[DEBUG]` for debug logs added with the Aux function `DebugLog()`

> **Note:** Each memory log line contains two hexadecimal values: the first represents the memory address being accessed, and the second represents the value read from or written to that address.


### Main Usage

Dynamic local variable in a function
```bash
Tracer -fname myFunc -vname myVar -o my_log_file.log -- ./compiled
```
---

Static local variable in a function with known size
```bash
Tracer -fname myFunc -vname myVar -vs 10 -o my_log_file.log -- ./compiled
```

#### Important Notes

> **Buffering behavior:** For optimization purposes, the tool doesn't respect order for logs other than memory write and read logs, as they are buffered. If you include `-c`, `-b`, `-i`, or `-d` options, you'll get either mixed traces or the traces generated by those options followed by the memory R/W's at the end. 

### Main Options

More details about options are listed when running `Tracer` command in the *CLI*, but here's a summarized list of options and their use *(in order of importance)*:


| Option | Description | Default value |
| ------ | ----------- | ------------- |
| `-o <path_to_file>` | Define where the log is saved | *trace-full-info.txt* |
| `-vname <var_name>` | [(*)](#clarification) Name of variable to be traced. Use with `-fname` | "" |
| `-fname <func_name>` |[(*)](#clarification) Name of function to search for `<var_name>`. Use with `-vname` | "" |
| `-vs n` | [(*)](#clarification) Size of variable in bytes. To trace **static** variables | 0 |
| `-td 0/1` | Discriminate on memory logs. (`[Owner][Accessing]`) | 0 |
| `-recursive 0/1` | Recursively trace malloced memory.  i.e. tracing a dynamic var that gets written other pointers to the heap (i.e. an `**int`) . Only used with `-fname -vname` | 1 |
| `-excl 0/1` | Exclude instrumentation outside main image | 1 |
| `-d 0/1` | Turn on debug logs. You can add your own with the function `DebugLog`, see examples in the code | 0 |
| `-file 0/1` | Enable file output, if 0 will not open log file | 1 |

<a id="clarification"></a>
> (*): These options require your executable to be compiled with debug information (e.g., `-g -gdwarf-4`). Without this, the tool cannot resolve variable or function names and tracing will not be accurate or may not work at all.

### Important remarks
If you wish to trace a specific variable you must assure that the executable is compiled with the following parameters (for `clang++/g++/..`):

* `-g` to include debugging information
* `-gdwarf-4` given that the tool reads based on this debug format, to use the DWARF 4 standard
* `-fno-omit-frame-pointer` to keep the stack frame and maintain consistent behaviour for allocation of variable (pointers)

### About static variables
Debug data doesn't provide information about the size of static variables, for example a fixed array of `int`. That's why when trying to trace a static array you need to indicate the size of the variable with the `-vs` option. This limitation means that variable-length arrays (VLAs) cannot be traced: `int myArray[variable]` consistently

If the variable is simply a primitive type, you can check the byte size with the next command:

```
dwgrep <your_executable> -e '(
|D|
let F := D entry ?DW_TAG_subprogram (@DW_AT_name == <your_func_name>); 
let V := F child ?TAG_variable (@DW_AT_name == <your_var_name>); 

V @DW_AT_type @DW_AT_byte_size
)'
```

### Filtering information

```txt
If no variable is specified (-vname / -fname), the tool logs all memory accesses (subject to -f / -excl)
```

If you trace a large binary you might notice the trace size increase very fast and you might want 
to only trace specific address ranges or binaries. TracerPIN accepts several command line options
to filter the address range.

Option `-f` is used to limit tracing to a given range.

By default (`-f 1`) it's tracing all but system libraries.
It's possible to force to trace them too: `-f 0` or to trace only the main executable: `-f 2` or to
provide a range of addresses to trace: `-f 0x400000-0x410000`.
Option `-f` is about what to instrument when BBLs are getting parsed but it's also possible to give
indications when to instrument, e.g. when you want to capture only a specific iteration of a loop.
To do so, use option `-F 0x400000:0x410000`. This time the addresses serve as a start and stop indicators,
not as an address range, and it's possible to target a specific iteration with the option `-n`,
while by default all iterations will be recorded.

Examples for tracing variables
------------------------------
In this section we'll display several examples focusing on the trace of a specific variable, be it static or dynamic.

Refer to the [examples.cpp](examples.cpp) file to run the examples. All the snippets shown below show the code partially.

Compile the example
```bash
g++ -fno-omit-frame-pointer examples.cpp -gdwarf-4 -g -o compiled
```

### Static Variables

#### Global variable *(Ex 0)*

> We need the `-vname` and `-vs` only; omit `-fname`

```cpp
int globalArray[4] = {0};

int main() {
  // Ex 0
  for(int i = 0; i < 4; i++)
    globalArray[i] = 15;
}
```

You would trace the variable `globalArray` with:

```bash
Tracer -vname globalArray -vs 16 -o my_log_file.log -- ./compiled
```

```smalltalk
[W]0x0000555555558080 0x0000000f
[W]0x0000555555558084 0x0000000f
[W]0x0000555555558088 0x0000000f
[W]0x000055555555808c 0x0000000f
```

#### Primitive type *(Ex 1)*

> We need the `-fname`, `-vname` and `-vs`

```cpp
int primitiveType(int a) {
  int myVar = 10;
  myVar = a + 2;

  return myVar;
}

int main() {
  int d = primitiveType(2);
}
```

You would trace the variable `myVar` with:

```bash
Tracer -fname primitiveType -vname myVar -vs 4 -o my_log_file.log -- ./compiled
```

and with `a=2` we would get:

```smalltalk
[W]0x00007fffffffe00c 0x0000000a
[W]0x00007fffffffe00c 0x00000004
[R]0x00007fffffffe00c 0x00000004
```

#### Array of primitive type *(Ex 2)*

```cpp
void fixedArray() {
  int myTenPositionVector[10];

  for (int i = 0; i < 10; i++) {
    myTenPositionVector[i] = i;
  }

  int a = myTenPositionVector[3]; // [R] 4th element with value 3
}

int main() {
  fixedArray();
}
```
You would run (considering `int` occupies 4 bytes):
```bash
Tracer -fname fixedArray -vname myTenPositionVector -vs 40 -o my_log_file.log -- ./compiled
```

and get:
```smalltalk
[W]0x00007fffffffe000 0x00000000
[W]0x00007fffffffe004 0x00000001
[W]0x00007fffffffe008 0x00000002
[W]0x00007fffffffe00c 0x00000003
[W]0x00007fffffffe010 0x00000004
[W]0x00007fffffffe014 0x00000005
[W]0x00007fffffffe018 0x00000006
[W]0x00007fffffffe01c 0x00000007
[W]0x00007fffffffe020 0x00000008
[W]0x00007fffffffe024 0x00000009
[R]0x00007fffffffe00c 0x00000003 // read 4th position
```

#### Other cases
If you know the byte size of another variable that isn't a primitive type (or pointer to) but the size is fixed, you could indicate the size with the `-vs` parameter, i.e. a struct that lives on the stack.

### Dynamic Variables
> In this case we just need the `-fname` and `-vname`

Here we have more potential cases, because we trace the memory requested by the executable with `malloc`.

#### Important note !!

There's a particular case you ought to look out for, if using `-fname f -vname v`:

when reaching the function `f`, the moment the program does the first write on the variable `v`, then the region of memory will **always be traced** regardless of where it is being written until the pointer is freed.
Even if the write is made outside the function `f`.

So, if your program passes the memory pointer of `v` to different functions and threads the best option is to indicate by parameter the function that originally called `malloc`. 

For better understanding, here's an example:
```cpp
void indirection(int* pointer, int size) {
	int* copy = pointer;
	// write to copy
}

void indirection2(int* pointer, int size) {
	int* copy = pointer;
	// write to copy
}

int main() {
	int* var = malloc(...); // Point 1
	var[i] = ...;
	indirection(var, ...); // Point 2
	indirection2(var, ...); // Point 3
}
```

If you indicate to the tool to trace 

* `-fname main -vname var` you would get all the writes and reads from *Point 1* and onwards / or until freed
* `-fname indirection -vname copy` you would get the write and reads from *Point 2* and onwards / or until freed
* `-fname indirection2 -vname copy` you would get the write and reads from *Point 3* and onwards / or until freed

This is because the instrumentation logic is modeled to start tracing from the function that asked for the memory (in this case **main**).


#### Malloc and write *(Ex 3 & 4)*

```cpp
void mallocAndWriteArray() {
  int totalSize = 5;
  int *otherArr = (int *)malloc(totalSize * sizeof(int));

  for (int i = 0; i < totalSize; i++) {
    otherArr[i] = i + 1;
  }

  int a = otherArr[3];

  free(otherArr);
}

int main() {
  mallocAndWriteArray();
  // Ex 4 it's the same but with variable named arr and declared in main
}
```

```bash
Tracer -fname mallocAndWriteArray -vname otherArr -o my_log_file.log -- ./compiled
```

```smalltalk
[W]0x00007fffffffe028 0x000055555556b320
[W]0x000055555556b320 0x00000001
[W]0x000055555556b324 0x00000002
[W]0x000055555556b328 0x00000003
[W]0x000055555556b32c 0x00000004
[W]0x000055555556b330 0x00000005
[R]0x000055555556b32c 0x00000004
```

Notice here that we also get the pointer returned by `malloc`

#### Write to the pointer of memory outside of the function where it's declared *(Ex 5)*

```cpp
void indirection(int* myArr, int size) {
  for (int i = 0; i < size; i++) {
    myArr[i] = i;
  }
}

int main() {
  int otherTotalSize = 3;
  int *otherArr = (int *)malloc(otherTotalSize * sizeof(int));
  for (int i = 0; i < otherTotalSize; i++) {
    otherArr[i] = i;
  }
  indirection(otherArr, otherTotalSize);
  free(otherArr);
}
```
the memory region will be traced wherever it is written. Here we'll trace the writes inside `main` and the ones in the `indirection` function.

```bash
Tracer -fname main -vname otherArr -o my_log_file.log -- ./compiled
```

```smalltalk
[W]0x00007fffffffe090 0x000055555556b320
[W]0x000055555556b320 0x00000000
[W]0x000055555556b324 0x00000001
[W]0x000055555556b328 0x00000002
[W]0x000055555556b320 0x00000000 // from indirection
[W]0x000055555556b324 0x00000001
[W]0x000055555556b328 0x00000002
```

#### Write outside of function and other thread *(Ex 6)*

In this case the option `-td 1` would come in handy to distinguish which thread is writing the memory region.

```cpp
void indirection(int* myArrPointer, int size) {
  for (int i = 0; i < size; i++) {
    myArrPointer[i] = i;
  }
}

int main() {
  int anotherSize = 3;
  int *anotherArray = (int *)malloc(anotherSize * sizeof(int));
  indirection(anotherArray, anotherSize);
  std::thread t(indirection, anotherArray, anotherSize);

  t.join();

  free(anotherArray);
}
```
this would trace the writes in `main` and the ones by thread `t`:

```bash
Tracer -fname main -vname anotherArray -o my_log_file.log -td 1 -- ./compiled
```

```smalltalk
[W][0][0]0x00007fffffffe078 0x000055555556b320
[W][0][0]0x000055555556b320 0x00000000
[W][0][0]0x000055555556b324 0x00000001
[W][0][0]0x000055555556b328 0x00000002
[W][1][0]0x000055555556b320 0x00000000
[W][1][0]0x000055555556b324 0x00000001
[W][1][0]0x000055555556b328 0x00000002
```
Having `[OperatorThreadID][OwnerThreadID]` (`[0]` is main, `[1]` is **t**)
i.e. `OwnerThreadID` is the thread that instantiated the memory, and the operator the one who is reading or writing on that memory.

#### Write outside of the main image *(Ex 7)*
This would be for example using the `std::strcpy` function:

```cpp
int main() {
  char* hello = (char *)malloc(20 * sizeof(char));
  std::strcpy(hello, "Hello");

  char a = hello[1]; // [R]

  free(hello);
}
```

```bash
Tracer -fname main -vname hello -o my_log_file.log -- ./compiled
```


```smalltalk
[W]0x00007fffffffde18 0x000055555556b320
[W]0x000055555556b320 0x6c6c6548
[W]0x000055555556b324 0x006f
[R]0x000055555556b321 0x65
```

Being: 

```
6c6c6548 = lleH
006f = \0o
```

#### Array with more dimensions *(extendable to n) (Ex 8)*

```cpp
int main() {
  int rows = 3, cols = 4;

  int** matrix = (int **)malloc(rows * sizeof(int *));

  for (int i = 0; i < rows; ++i){
    matrix[i] = (int *)malloc(cols * sizeof(int));
    // each write in matrix[i] will add the 
    // region of memory to the list of "regions of interest"
  }

  for (int i = 0; i < rows; ++i){
    matrix[i][0] = i; // Reads m[i] for each write --> [R] and [W]
  }

  for (int i = 0; i < rows; ++i){
    matrix[i][2] = i;
  }

  free(matrix);
}
```

```bash
Tracer -fname main -vname matrix -o my_log_file.log -- ./compiled
```
lets alias `matrix` to `m` for easier comments

```smalltalk
[W]0x00007fffffffe0a0 0x000055555556b320 // write on m
[W]0x000055555556b320 0x000055555556b4b0 // m[0]
[W]0x000055555556b328 0x000055555556b4d0 // m[1]
[W]0x000055555556b330 0x000055555556b4f0 // m[2]
[R]0x000055555556b320 0x000055555556b4b0 // read m[0] to write col 0
[W]0x000055555556b4b0 0x00000000 // write m[0][0]
[R]0x000055555556b328 0x000055555556b4d0 // read m[1] to write col 0
[W]0x000055555556b4d0 0x00000001 // ...
[R]0x000055555556b330 0x000055555556b4f0
[W]0x000055555556b4f0 0x00000002
[R]0x000055555556b320 0x000055555556b4b0
[W]0x000055555556b4b8 0x00000000
[R]0x000055555556b328 0x000055555556b4d0
[W]0x000055555556b4d8 0x00000001
[R]0x000055555556b330 0x000055555556b4f0
[W]0x000055555556b4f8 0x00000002
```

Original Tool options
---
| Option | Description | Default value |
| ------ | ----------- | ------------- |
| `-i 0/1` | Log all instructions | 0 |
| `-m 0/1` | Log all memory access | 1 |
| `-b 0/1` | Log all basic blocks [(PIN BBL definition)](https://software.intel.com/sites/landingpage/pintool/docs/98484/Pin/html/index.html) | 0 |
| `-c 0/1` | Log all calls | 0 |
| `-C 0/1` | Log all calls with their first three args | 0 |
| `-f 0/1/2` | (0) no filter (1) filter system libraries (2) filter all but main exec | 1 |
| `-F 0/(0x12..:0x588..)` | Use addresses as start:stop live filter | 0 |
| `-n 0/n` | Filter *n* occurrences, only with `-F` | 0 |
| `-q 0/1` | Be quiet under normal conditions | 0 |

Troubleshooting
---------------

#### Common issues

* **No or wrong trace when tracing a variable** — Ensure the executable was built with debug info: `-g -gdwarf-4 -fno-omit-frame-pointer`. Check that `-fname` and `-vname` match the function and variable (for **global** variables use `-vname` and `-vs` only; omit `-fname`). For static arrays or fixed-size variables, set `-vs` to the size in bytes.

#### PIN on IA32 (Debian Stretch, kernel > 4.3)

We noticed the following problem using PIN on IA32 binaries on Debian Stretch under a Linux kernel > 4.3:

```
A: Source/pin/vm_ia32_l/jit_region_ia32_linux.cpp: XlateSysCall: 33: Sysenter is supported on IA32 only and the expected location is inside Linux Gate

################################################################################
## STACK TRACE
################################################################################
etc
```

Strangely enough, running a Debian Jessie in a Docker with the same kernel > 4.3 works fine.  
So till the root cause of this issue is found, please either make sure to run a kernel <= 4.3 or to run from a Docker image with Debian Jessie.

Credits
-------

Based on code written by
* [Original TracerPIN](https://github.com/SideChannelMarvels/Tracer/tree/valgrind-3.23.0/TracerPIN) repo by **doegox**
* Arnaud Maillet for his [NSC2013 challenge writeup](http://kutioo.blogspot.be/2013/05/nosuchcon-2013-challenge-write-up-and.html)
* tracesurfer for [SSTIC2010](https://code.google.com/p/tartetatintools/)
* Carlos G. Prado for his [Brucon workshop](http://brundlelab.wordpress.com/2013/09/30/brucon-2013-workshop-slides/)
* source/tools/SimpleExamples/trace.cpp by Intel
