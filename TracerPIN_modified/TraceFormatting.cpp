#include "TraceFormatting.h"

#include <cstdint>

std::string FormatTraceEntry(const MemoryTraceEntry &entry,
                             bool includeThreadOwnership) {
  std::string result;
  result.reserve(64);

  static const char hex[] = "0123456789abcdef";

  result += '[';
  result += entry.operation;
  result += ']';

  if (includeThreadOwnership) {
    result += '[';
    result += std::to_string(entry.threadWriter);
    result += "][";
    result += std::to_string(entry.threadOwner);
    result += ']';
  }

  result += "0x";
  char addressBuffer[17];
  addressBuffer[16] = '\0';
  uintptr_t address = reinterpret_cast<uintptr_t>(entry.address);
  for (int i = 15; i >= 0; --i) {
    addressBuffer[i] = hex[address & 0xF];
    address >>= 4;
  }
  result += addressBuffer;
  result += ' ';

  switch (entry.size) {
  case 1: {
    result += "0x";
    const UINT8 value = entry.memdump[0];
    result += hex[(value >> 4) & 0xF];
    result += hex[value & 0xF];
    break;
  }
  case 2: {
    result += "0x";
    const UINT16 value = *reinterpret_cast<const UINT16 *>(entry.memdump);
    for (int i = 3; i >= 0; --i) {
      result += hex[(value >> (i * 4)) & 0xF];
    }
    break;
  }
  case 4: {
    result += "0x";
    const UINT32 value = *reinterpret_cast<const UINT32 *>(entry.memdump);
    for (int i = 7; i >= 0; --i) {
      result += hex[(value >> (i * 4)) & 0xF];
    }
    break;
  }
  case 8: {
    result += "0x";
    const UINT64 value = *reinterpret_cast<const UINT64 *>(entry.memdump);
    for (int i = 15; i >= 0; --i) {
      result += hex[(value >> (i * 4)) & 0xF];
    }
    break;
  }
  default:
    for (INT32 i = 0; i < entry.size; ++i) {
      result += ' ';
      const UINT8 value = entry.memdump[i];
      result += hex[(value >> 4) & 0xF];
      result += hex[value & 0xF];
    }
    break;
  }

  result += '\n';
  return result;
}
