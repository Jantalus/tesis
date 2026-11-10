#ifndef TRACERPIN_TRACE_ENTRY_H
#define TRACERPIN_TRACE_ENTRY_H

#include "pin.H"

#include <cstddef>

constexpr size_t kMaxMemoryDumpBytes = 256;
constexpr size_t kMaxBufferEntries = 1'000'000;

struct MemoryTraceEntry {
  THREADID threadOwner;
  THREADID threadWriter;
  ADDRINT address;
  INT32 size;
  UINT8 memdump[kMaxMemoryDumpBytes];
  CHAR operation;
};

#endif
