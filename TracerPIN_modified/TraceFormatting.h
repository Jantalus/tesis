#ifndef TRACERPIN_TRACE_FORMATTING_H
#define TRACERPIN_TRACE_FORMATTING_H

#include "TraceEntry.h"

#include <string>

std::string FormatTraceEntry(const MemoryTraceEntry &entry,
                             bool includeThreadOwnership);

#endif
