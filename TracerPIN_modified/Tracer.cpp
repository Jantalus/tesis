/* ===================================================================== */
/* TracerPIN is an execution tracing module for Intel PIN tools          */
/* Copyright (C) 2020                                                    */
/* Original author:   Phil Teuwen <phil@teuwen.org>                      */
/* Contributors:      Charles Hubain <me@haxelion.eu>                    */
/*                    Joppe Bos <joppe_bos@hotmail.com>                  */
/*                    Wil Michiels <w.p.a.j.michiels@tue.nl>             */
/*                    Keegan Saunders <keegan@sdf.org>                   */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* any later version.                                                    */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/* ===================================================================== */
#include "pin.H"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>

#include "DwarfQueries.h"
#include "TraceEntry.h"
#include "TraceFormatting.h"
#include "TracerOptions.h"

// For string split of lowpc,higpc
#include <vector>

#ifndef GIT_DESC
#define GIT_DESC "(unknown version)"
#endif // GIT_DESC
/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif


// Force each thread's data to be in its own data cache line so that
// multiple threads do not contend for the same data cache line.
// This avoids the false sharing problem.
// #define PADSIZE 56 // 64 byte line size: 64-8

struct ThreadData
{
    std::map<ADDRINT, ADDRINT> allocationSizes;
};
// Initialized once in main()
static TLS_KEY tlsKey = INVALID_TLS_KEY;

// using namespace std;
/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

// Global flag to control file output
bool enableFileOutput = true;

// Helper function to check if we should write to file
inline bool ShouldWriteToFile()
{
    return enableFileOutput;
}

// Memory trace buffer structure and global buffer
MemoryTraceEntry traceBuffer1[kMaxBufferEntries];
MemoryTraceEntry traceBuffer2[kMaxBufferEntries];

// Buffer management structure
struct BufferInfo
{
    MemoryTraceEntry *buffer;
    size_t index;
    bool inUse;  // true if being written to file
    PIN_LOCK lock;
    
    explicit BufferInfo(MemoryTraceEntry *buf)
        : buffer(buf), index(0), inUse(false)
    {
        PIN_InitLock(&lock);
    }
};

BufferInfo buffer1(traceBuffer1);
BufferInfo buffer2(traceBuffer2);
BufferInfo* currentBuffer = &buffer1;
BufferInfo* writeBuffer = nullptr;

// Lock for file writing operations
PIN_LOCK fileWriteLock;


// Debug logging helper function
void DebugLog(const std::string &message)
{
    if (KnobDebugLogs.Value() && ShouldWriteToFile()) {
        TraceFile << "[DEBUG] " << message << std::endl;
    }
}

// Debug logging helper function with formatting support
template <typename... Args>
void DebugLog(const std::string &format, Args... args)
{
    if (KnobDebugLogs.Value() && ShouldWriteToFile()) {
        TraceFile << "[DEBUG] ";
        // Simple formatting - you could use a more sophisticated approach
        TraceFile << format;
        ((TraceFile << args), ...);
        TraceFile << std::endl;
    }
}


// Structure to pass buffer information to write thread
struct WriteBufferArgs {
    BufferInfo* bufferInfo;
    size_t bufferSize;
};

// Thread function to write buffer to file
void WriteBufferToFile(void* arg)
{
    // Extract buffer info from argument
    WriteBufferArgs* args = static_cast<WriteBufferArgs*>(arg);
    BufferInfo* bufferInfo = args->bufferInfo;
    size_t bufferSize = args->bufferSize;
    
    PIN_GetLock(&fileWriteLock, 0);
    
    // Bulk write optimization - build all data in memory first
    std::stringstream bulkData; 
    for (size_t i = 0; i < bufferSize; i++) {
        const MemoryTraceEntry& entry = bufferInfo->buffer[i];
        bulkData << FormatTraceEntry(entry, KnobDiscriminateThread.Value());
    }
    
    // Single file write operation
    TraceFile << bulkData.str();
    
    PIN_ReleaseLock(&fileWriteLock);
    
    // Mark buffer as available again
    PIN_GetLock(&bufferInfo->lock, 0);
    bufferInfo->inUse = false;
    bufferInfo->index = 0;  // Reset index for next use
    PIN_ReleaseLock(&bufferInfo->lock);
    
    // Clean up the argument structure
    delete args;
}



/*
std::stringstream value;
std::string strvalue;
*/
PIN_LOCK _lock;
struct moduledata_t
{
    BOOL excluded;
    ADDRINT begin;
    ADDRINT end;
};

typedef std::map<std::string, moduledata_t> modmap_t;

std::string variable_name;
std::string function_name;
UINT64 variable_size;
// std::string function_dwarf_id;

modmap_t mod_data;
ADDRINT main_begin;
ADDRINT main_end;

// Extras
PROTO proto_malloc;

ADDRINT func_offset = 0;
ADDRINT func_totalbytes = 0;

bool isGnuCompiled = false;

INT64 global_var_offset = 0;
bool filter_global_var = false;

INT64 var_offset = 0;
UINT64 var_byte_size = 0;
bool filter_local_var = false;

struct VariableMemoryLocation
{
    ADDRINT startAddress;
    ADDRINT endAddress;
    ADDRINT allocationBase;
    THREADID ownerThread;

    VariableMemoryLocation(ADDRINT start, ADDRINT end, THREADID tid,
                           ADDRINT allocation = 0)
        : startAddress(start), endAddress(end),
          allocationBase(allocation == 0 ? start : allocation),
          ownerThread(tid) {}
};

// Find the active malloc allocation containing pointer.  Allocations are
// keyed by their base address and cannot overlap while active, so checking
// the predecessor of upper_bound() is sufficient and costs O(log M).
static bool FindContainingAllocation(
    const std::map<ADDRINT, ADDRINT> *allocations,
    ADDRINT pointer,
    ADDRINT *allocationBase,
    ADDRINT *allocationSize)
{
    auto it = allocations->upper_bound(pointer);
    if (it == allocations->begin()) {
        return false;
    }

    --it;
    const ADDRINT base = it->first;
    const ADDRINT size = it->second;
    if (pointer < base || pointer - base >= size) {
        return false;
    }

    *allocationBase = base;
    *allocationSize = size;
    return true;
}

PIN_LOCK _lockvarreg;
std::vector<VariableMemoryLocation> varRegions;

void LogVariableRegions(const std::vector<VariableMemoryLocation> &regions)
{
    if (!ShouldWriteToFile() || !KnobDebugLogs.Value()) return;
    
    TraceFile << regions.size() << " elements" << "[";
    for (const auto &varRegion : regions)
    {
        TraceFile << "<0x" << varRegion.startAddress << ", 0x" << varRegion.endAddress << "> ";
    }

    TraceFile << "]" << std::endl;
}

///////////////

bool main_reached = false;
INT64 logfilter = 1;
bool logfilterlive = false;
ADDRINT filter_begin = 0;
ADDRINT filter_end = 0;
ADDRINT filter_live_start = 0;
ADDRINT filter_live_stop = 0;
INT32 filter_live_n = 0;
INT32 filter_live_i = 0;
bool filter_live_reached = false;
long long bigcounter = 0; // Ready for 4 billions of instructions
enum InfoTypeType
{
    T,
    C,
    B,
    R,
    I,
    W
};
InfoTypeType InfoType = T;
std::string TraceName;

/* ============================================================================= */
/* Intel PIN (3.7) is missing implementations of many C functions, we implement  */
/* them here. THESE ARE NOT UNIVERSALLY COMPATIBLE, DO NOT USE OUTSIDE TracerPIN */
/* ============================================================================= */

extern "C" int stat(const char *name, struct stat *buf)
{
    return syscall(SYS_stat, name, buf);
}

extern "C" int fchmod(int fd, mode_t mode)
{
    return syscall(SYS_fchmod, fd, mode);
}

extern "C" int fchown(int fd, uid_t uid, gid_t gid)
{
    return syscall(SYS_fchown, fd, uid, gid);
}

extern "C" uid_t geteuid(void)
{
    return syscall(SYS_geteuid);
}

extern "C" int fstat(int fd, struct stat *st)
{
    if (fd < 0)
    {
        return -EBADF;
    }
    return syscall(SYS_fstat, fd, st);
}

extern "C" int lstat(const char *path, struct stat *buf)
{
    return syscall(SYS_lstat, path, buf);
}

extern "C" int utimes(const char *path, const struct timeval times[2])
{
    return syscall(SYS_utimes, path, times);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    std::cerr << "Tracer with memory R/W and disass" << std::endl;
    std::cerr << "Result by default in trace-full-info.txt" << std::endl;
    std::cerr << "Only tested in x86, x86_64" << std::endl
              << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary();

    std::cerr << std::endl;

    return -1;
}

/* ===================================================================== */
/* TracerMod Helper funcs                                                      */
/* ===================================================================== */

bool IsWithinMainExec(ADDRINT addr)
{
    DebugLog("Address within main exec 0x", addr);

    return (main_begin <= addr && addr <= main_end);
}

bool IsWithinDwarfFunction(ADDRINT addr) {
    return (addr >= (main_begin + func_offset)) && (addr < (main_begin + func_offset + func_totalbytes));
}

/* ===================================================================== */
/* Helper Functions                                                      */
/* ===================================================================== */

BOOL ExcludedAddress(ADDRINT ip)
{
    switch (logfilter)
    {
    case 1:
        if (!main_reached)
        {
            // Filter loader before main
            if ((ip < main_begin) || (ip > main_end))
                return TRUE;
            else
                main_reached = true;
        }
        if ((ip >= main_begin) && (ip <= main_end))
            return FALSE;
        for (modmap_t::iterator it = mod_data.begin(); it != mod_data.end(); ++it)
        {
            if (it->second.excluded == FALSE)
                continue;
            /* Is the EIP value within the range of any excluded module? */
            if (ip >= it->second.begin && ip <= it->second.end)
                return TRUE;
        }
        break;
    case 2:
    {
        PIN_LockClient();
        IMG im = IMG_FindByAddress(ip);
        PIN_UnlockClient();
        if (!IMG_Valid(im) || !IMG_IsMainExecutable(im))
            return TRUE;
        break;
    }
    case 3:
        return ((ip < filter_begin) || (ip > filter_end));
        break;
    default:
        break;
    }

    return FALSE;
}

BOOL ExcludedAddressLive(ADDRINT ip)
{
    // Always test for (logfilterlive) before calling this function!

    //    cerr << hex << ip << "<>" << filter_live_start << dec << std::endl;
    if (ip == filter_live_start)
    {
        filter_live_i++;
        if ((filter_live_n == 0) || (filter_live_i == filter_live_n))
            filter_live_reached = true;
        //        cerr << "BEGIN " << filter_live_i << " @" << hex << filter_live_start << dec << " -> " << filter_live_reached << std::endl;
    }
    if (ip == filter_live_stop)
    {
        filter_live_reached = false;
        //        cerr << "END   " << filter_live_i << " @" << hex << filter_live_stop << dec << " -> " << filter_live_reached << std::endl;
    }
    return !filter_live_reached;
}

/* ===================================================================== */
/* Helper Functions for Instruction_cb                                   */
/* ===================================================================== */

VOID LogInstruction(ADDRINT ip, std::string *disass, INT32 size)
{
    UINT8 v[32];
    // test on logfilterlive here to avoid calls when not using live filtering
    if (logfilterlive && ExcludedAddressLive(ip))
        return;
    if (static_cast<size_t>(size) > sizeof(v))
    {
        std::cerr << "[!] Instruction size > 32 at " << std::dec << bigcounter << std::hex << (void *)ip << " " << *disass << std::endl;
        return;
    }
    PIN_GetLock(&_lock, ip);
    if (InfoType >= I)
        bigcounter++;
    InfoType = I;
    PIN_SafeCopy(v, (void *)ip, size);
    if (ShouldWriteToFile()) {
        TraceFile << "[I]" << std::setw(10) << std::dec << bigcounter << std::hex << std::setw(16) << (void *)ip << "    " << std::setw(40) << std::left << *disass << std::right;
        TraceFile << std::setfill('0');
        for (INT32 i = 0; i < size; i++)
        {
            TraceFile << " " << std::setfill('0') << std::setw(2) << static_cast<UINT32>(v[i]);
        }
        TraceFile << std::setfill(' ');
        TraceFile << std::endl;
    }

    // To get context, see https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__CONTEXT__API.html
    PIN_ReleaseLock(&_lock);
}

// The caller must hold the trace lock while appending to the active buffer.
void AppendMemoryTrace(THREADID threadOwner,
                       THREADID threadWriter,
                       ADDRINT address,
                       INT32 size,
                       const UINT8 *memdump,
                       CHAR operation,
                       bool isPrefetch)
{
    // This is used with the log already acquired
    if (isPrefetch || !ShouldWriteToFile()) {
        return;
    }
    
    // Add entry to current buffer
    currentBuffer->buffer[currentBuffer->index].threadOwner = threadOwner;
    currentBuffer->buffer[currentBuffer->index].threadWriter = threadWriter;
    currentBuffer->buffer[currentBuffer->index].address = address;
    currentBuffer->buffer[currentBuffer->index].size = size;
    currentBuffer->buffer[currentBuffer->index].operation = operation;
    
    // Copy memdump data
    for (INT32 i = 0; i < size && i < static_cast<INT32>(kMaxMemoryDumpBytes); i++) {
        currentBuffer->buffer[currentBuffer->index].memdump[i] = memdump[i];
    }
    
    currentBuffer->index++;
    
    // Flush buffer when full
    if (currentBuffer->index >= kMaxBufferEntries) {
        // Mark current buffer as in use for writing
        PIN_GetLock(&currentBuffer->lock, 0);
        currentBuffer->inUse = true;
        PIN_ReleaseLock(&currentBuffer->lock);
        
        writeBuffer = currentBuffer;
        
        // Try to switch to the other buffer
        BufferInfo* newBuffer = (currentBuffer == &buffer1) ? &buffer2 : &buffer1;
        
        // Check if the target buffer is available
        PIN_GetLock(&newBuffer->lock, 0);
        if (newBuffer->inUse) {
            // Target buffer is still being written, we need to wait
            // For now, we'll block until it's available
            // In a more sophisticated implementation, we could use a condition variable
            PIN_ReleaseLock(&newBuffer->lock);
            
            // Wait for the buffer to become available
            while (true) {
                PIN_GetLock(&newBuffer->lock, 0);
                if (!newBuffer->inUse) {
                    PIN_ReleaseLock(&newBuffer->lock);
                    break;
                }
                PIN_ReleaseLock(&newBuffer->lock);
                // Small delay to avoid busy waiting
                PIN_Sleep(1); // Sleep for 1 millisecond
            }
        }
        
        // Now switch to the available buffer
        currentBuffer = newBuffer;
        currentBuffer->index = 0;
        PIN_ReleaseLock(&newBuffer->lock);
        
        // Spawn thread to write the full buffer to file
        WriteBufferArgs *args = new WriteBufferArgs{writeBuffer, kMaxBufferEntries};
        PIN_SpawnInternalThread(WriteBufferToFile, args, 0, PIN_THREAD_UID(NULL));
    }
}

ADDRINT CalculateVariableAddress(ADDRINT rbpValue)
{
    ADDRINT offsetFromCFA = 0;
    if (isGnuCompiled) {
        #if defined(TARGET_IA32E)
        offsetFromCFA = ADDRINT(16); // Usual offset for x86_64 is 16B
        #elif defined(TARGET_IA32)
        offsetFromCFA = ADDRINT(8); // Usual offset for x86 is 8B
        #endif
    }

    ADDRINT trueOffset = var_offset - offsetFromCFA;

    return rbpValue - trueOffset;
}

#if defined(TARGET_IA32E)
static VOID RecordMem(const ADDRINT regRBP, THREADID tid, ADDRINT ip, CHAR r, ADDRINT addr, INT32 size, BOOL isPrefetch, ADDRINT prefetchRBP)
//static VOID RecordMem(THREADID tid, ADDRINT ip, CHAR r, ADDRINT addr, INT32 size, BOOL isPrefetch)
{
    THREADID threadOwnerOfX = 0;
    bool found = false;

    // SECTION 1: Local Variable Filtering
    if (filter_local_var) {
        if (func_offset == 0) {
            std::cerr << "Offset function 0, but filter_local_var true" << std::endl;
        }


        // Used for the dynamic case and static case
        ThreadData *threadData = static_cast<ThreadData *>(PIN_GetThreadData(tlsKey, tid));
        ADDRINT rbpValue = 0;
        if (regRBP != 0) {
            rbpValue = regRBP;
        } else {
            rbpValue = prefetchRBP;
        }

        
        if (var_byte_size == 0) {
            // DYNAMIC VARIABLE
            std::map<ADDRINT, ADDRINT> &allocationSizes = threadData->allocationSizes;
            if (IsWithinDwarfFunction(ip)) {
                ADDRINT varInStack = CalculateVariableAddress(rbpValue);


                DebugLog("W on 0x", std::hex, addr, " R: 0x", rbpValue, " R - Of 0x", varInStack, std::dec);

                if (addr == varInStack) {
 
                    DebugLog("Writing on var in stack" );

                    // Operating on x (var by DwarfID)
                    if (r == 'R') { // If reading the pointer, not the heap allocated memory: skip
                        return;
                    }

                    ADDRINT heapAllocatedPointer = 0;

                    PIN_SafeCopy(&heapAllocatedPointer, (void *)varInStack, sizeof(heapAllocatedPointer));

                    ADDRINT allocationBase = 0;
                    ADDRINT allocationSize = 0;
                    bool allocationFound = false;

                    auto it = allocationSizes.find(heapAllocatedPointer);
                    if (it != allocationSizes.end()) {
                        allocationBase = it->first;
                        allocationSize = it->second;
                        allocationFound = true;
                    } else if (KnobTrackInteriorPointers.Value()) {
                        allocationFound = FindContainingAllocation(
                            &allocationSizes, heapAllocatedPointer,
                            &allocationBase, &allocationSize);
                    }

                    // Validate if pointer is from malloc
                    if (!allocationFound) {
                        DebugLog("Pointer 0x", std::hex, heapAllocatedPointer, " not in map", std::dec);
                        // Not found -> Not tracing
                        return;
                    }

                    // By default preserve the old semantics and trace the
                    // complete allocation.  For an interior pointer, an
                    // explicit size restricts the tracked region to the
                    // logical section represented by the pointer.
                    ADDRINT regionStart = allocationBase;
                    ADDRINT regionSize = allocationSize;
                    if (allocationBase != heapAllocatedPointer &&
                        KnobInteriorPointerSize.Value() != 0) {
                        const ADDRINT offset = heapAllocatedPointer - allocationBase;
                        const ADDRINT requestedSize =
                            static_cast<ADDRINT>(KnobInteriorPointerSize.Value());
                        if (offset > allocationSize ||
                            requestedSize > allocationSize - offset) {
                            DebugLog("Interior pointer region exceeds allocation");
                            return;
                        }
                        regionStart = heapAllocatedPointer;
                        regionSize = requestedSize;
                    }

                    // Append to areas of memory to be traced
                    // we save the <regionOfMemoryOfX>, ThreadThatCreatedX
                    PIN_GetLock(&_lockvarreg, 0);
                    varRegions.emplace_back(regionStart,
                                            (regionStart + regionSize),
                                            tid, allocationBase);
                    PIN_ReleaseLock(&_lockvarreg);
                    // Region of memory saved

                    DebugLog("VarRegions ADD x region");
                    LogVariableRegions(varRegions);

                    // Proceed to trace the pointer (to the heap) written
                }
            }
            // Are you reading or writing another instantiaton of x (var by DwarfID) ?

            PIN_GetLock(&_lockvarreg, 0);
            for (const auto &memoryRegion : varRegions) {
                if (memoryRegion.startAddress <= addr && addr < memoryRegion.endAddress) {
                    // Reading or writing some memory of an instantiation of x
                    // Save the owner threadId
                    threadOwnerOfX = memoryRegion.ownerThread;
                    found = true;

                    // Also, the address could have been allocated previously
                    // recursively adding it to the varRegions list.
                    // But only when we are writing our memory region of interest, when reading we don't care

                    if (KnobEnableRecursiveAllocTracking.Value()) {
                        if (r == 'W') {
                            ADDRINT writingBytes = 0;

                            PIN_SafeCopy(&writingBytes, (void *)addr, sizeof(writingBytes));

                            auto it = allocationSizes.find(writingBytes);

                            // Validate if it is a malloced pointer
                            if (it == allocationSizes.end())
                            {
                                // Not found -> not malloced memory
                                DebugLog("Pointer 0x", std::hex, addr, " not in map", std::dec);
                            }
                            else {
                                // pointer is from malloc call
                                ADDRINT varSizeInBytes = it->second;
                                varRegions.emplace_back(writingBytes, (writingBytes + varSizeInBytes), tid);

                                DebugLog("indirect add char - VarRegions ADD x region");
                                LogVariableRegions(varRegions);
                            }
                        }
                    }

                    break;
                }
            }
            PIN_ReleaseLock(&_lockvarreg);

            if (!found) {
                /*
                ADDRINT sixteenBytes = ADDRINT(16);
                ADDRINT trueOffset = var_offset - sixteenBytes;
                ADDRINT varInStack = rbpValue - trueOffset;
                */

                ADDRINT varInStack = CalculateVariableAddress(rbpValue);

                if (!(IsWithinDwarfFunction(ip) && addr == varInStack)) {
                    return;
                } else {
                    found = true; // CAMBIAR CACA, pero funciona
                }
            }
        } else {
            // STATIC Variables
            // We already now all writes to variable occur in the function, so return if not in f
            if (!IsWithinDwarfFunction(ip)) {
                DebugLog("Excluding address out of func 0x", std::hex, ip, std::dec);
                return;
            }

            DebugLog("Address 0x", std::hex, ip, " in func address range", std::dec);

            ADDRINT varLowADDR = CalculateVariableAddress(rbpValue);
            ADDRINT varHighADDR = varLowADDR + var_byte_size;

            if (varLowADDR > addr || varHighADDR <= addr) {
                return;
            }

            DebugLog("RBP VALUE: ", std::hex, rbpValue, std::dec);
            DebugLog("memory instruction over var of interest with varLowADDR 0x", std::hex, varLowADDR, " and varHighADDR 0x", std::hex, varHighADDR, std::dec);
        }
    } else if(filter_global_var) {
        ADDRINT globalVarLowADDR = main_begin + global_var_offset;
        ADDRINT globalVarHihghADDR = globalVarLowADDR + var_byte_size;

        if (globalVarLowADDR> addr || globalVarHihghADDR <= addr) {
            return;
        }
    }

    // SECTION 3: Live Filtering
    // test on logfilterlive here to avoid calls when not using live filtering
    else {
        if (logfilterlive && ExcludedAddressLive(ip)) {
            return;
        }
    }

    // SECTION 4: Memory Operations
    UINT8 memdump[256];

    PIN_GetLock(&_lock, ip);
    if ((size_t)size > sizeof(memdump))
    {
        std::cerr << "[!] Memory size > " << sizeof(memdump) << " at " << std::dec << bigcounter << std::hex << (void *)ip << " " << (void *)addr << std::endl;
        PIN_ReleaseLock(&_lock);
        return;
    }
    PIN_SafeCopy(memdump, (void *)addr, size);
    switch (r)
    {
    case 'R':
        if (InfoType >= R)
            bigcounter++;
        InfoType = R;
        break;
    case 'W':
        if (InfoType >= W)
            bigcounter++;
        InfoType = W;
        break;
    }

    // SECTION 5: Logging
    AppendMemoryTrace(threadOwnerOfX, tid, addr, size, memdump, r, isPrefetch);
    PIN_ReleaseLock(&_lock);
}

static ADDRINT WriteAddr;
static INT32 WriteSize;
//static CONTEXT *RegContext;
static ADDRINT PredicatedRBPValue;

//static VOID RecordWriteAddrSize(ADDRINT addr, INT32 size)
static VOID RecordWriteAddrSize(ADDRINT addr, INT32 size, ADDRINT prefetchRBPValue)
{
    WriteAddr = addr;
    WriteSize = size;
    PredicatedRBPValue = prefetchRBPValue;
}

//static VOID RecordMemWrite(THREADID tid, ADDRINT ip)
static VOID RecordMemWrite(THREADID tid, ADDRINT ip)
{
    RecordMem(0, tid, ip, 'W', WriteAddr, WriteSize, false, PredicatedRBPValue);
    //RecordMem(tid, ip, 'W', WriteAddr, WriteSize, false);
}
#endif
/* ================================================================================= */
/* This is called for each instruction                                               */
/* ================================================================================= */
VOID Instruction_cb(INS ins, VOID *v) {
    ADDRINT ceip = INS_Address(ins);

    // Either by -f -F filters, or by -fdid function lowpc and highpc address
    // excluding ip addresses outside of my function of interest
    if (ExcludedAddress(ceip) && KnobExcludeAddressesOutsideMain.Value()) {
        return;
    }

#if defined(TARGET_IA32E)
    if (KnobLogMem.Value()) {

        if (INS_IsMemoryRead(ins)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_REG_VALUE, REG_RBP,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_BOOL, INS_IsPrefetch(ins),
                IARG_ADDRINT, 0,
                IARG_END);
        }

        if (INS_HasMemoryRead2(ins)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_REG_VALUE, REG_RBP,
                IARG_THREAD_ID,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_BOOL, INS_IsPrefetch(ins),
                IARG_ADDRINT, 0,
                IARG_END);
        }

        // instruments stores using a predicated call, i.e.
        // the call happens iff the store will be actually executed
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_REG_VALUE, REG_RBP,
                IARG_END);

            if (INS_HasFallThrough(ins)) {
                INS_InsertCall(
                    ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_END);
            }
            if (INS_IsControlFlow(ins)) {
                INS_InsertCall(
                    ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_END);
            }
        }
    }
#endif

    if (KnobLogIns.Value()) {
        std::string *disass = new std::string(INS_Disassemble(ins));
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)LogInstruction,
            IARG_INST_PTR,
            IARG_PTR, disass,
            IARG_UINT32, INS_Size(ins),
            IARG_END);
    }
}

/* ===================================================================== */
/* Routine tracing functions                                             */
/* ===================================================================== */

void FreeBefore(THREADID tid, ADDRINT pointerToFree, ADDRINT returnPointer)
{
    if (!IsWithinMainExec(returnPointer)) {
        return;
    }

    ThreadData *threadData = static_cast<ThreadData *>(PIN_GetThreadData(tlsKey, tid));
    int i = 0;
    // Remove from local thread malloc pointers
    for (auto it = threadData->allocationSizes.begin(); it != threadData->allocationSizes.end(); ++it) {

        DebugLog("Thread FREE", tid, "- MapElement", i, "of map is:", it->second);

        if ((it->first) == pointerToFree)
        {
            const ADDRINT allocationSize = it->second;
            threadData->allocationSizes.erase(it);
            DebugLog("Thread ", tid, " freed ", std::hex, pointerToFree,
                     " with 0x", std::hex, allocationSize, " bytes", std::dec);
            break;
        }
        i++;
    }

    DebugLog("VarRegions before freeing");
    LogVariableRegions(varRegions);

    // Remove from global sections of memory
    PIN_GetLock(&_lockvarreg, 0);
    for (auto it = varRegions.begin(); it != varRegions.end();) {
        if (it->allocationBase == pointerToFree) {
            it = varRegions.erase(it);
        } else {
            ++it;
        }
    }
    PIN_ReleaseLock(&_lockvarreg);

    DebugLog("VarRegions after freeing");
    LogVariableRegions(varRegions);
}

// Wrapper for malloc
VOID *MallocWrapper(THREADID threadid,
                    size_t size,
                    AFUNPTR originalMalloc,
                    const char *imgName,
                    ADDRINT retIp,
                    CONTEXT *ctxt)
{
    // Prepare return value and argument for malloc
    VOID* ptr = nullptr; // Return value (first argument)
    size_t arg_size = size; // Argument to malloc

    // Call original malloc using PIN_CallApplicationFunction
    PIN_CallApplicationFunction(ctxt, threadid, CALLINGSTD_DEFAULT, originalMalloc, nullptr,
                                PIN_PARG(VOID*), &ptr, // Return value
                                PIN_PARG(size_t), arg_size, // Argument: size
                                PIN_PARG_END());


    DebugLog("[TID:", threadid, "][Malloc Wrapper] asked for ", std::dec, size, " and got pointer 0x", std::hex, ptr);

    // Consolidated logic: directly insert the malloc pointer and size into the thread data
    if (IsWithinMainExec(retIp)) {
        ThreadData *threadData = static_cast<ThreadData *>(PIN_GetThreadData(tlsKey, threadid));
        threadData->allocationSizes.insert({(ADDRINT)ptr, size});

        DebugLog("Saved: <0x", (ADDRINT)ptr, ",", size, "> on malloc map");
    }

    return ptr;
}

/* ================================================================================= */
/* This is called every time a MODULE (dll, etc.) is LOADED                          */
/* ================================================================================= */
void ImageLoad_cb(IMG Img, void *v)
{
    std::string imageName = IMG_Name(Img);
    ADDRINT lowAddress = IMG_LowAddress(Img);
    ADDRINT highAddress = IMG_HighAddress(Img);
    bool filtered = false;

    // Instrument malloc routine, for tracking dynamic variables
    RTN mallocRtn = RTN_FindByName(Img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        // Define prototype for malloc (void* malloc(size_t))
        proto_malloc = PROTO_Allocate(PIN_PARG(VOID*), CALLINGSTD_DEFAULT,
                                           MALLOC,
                                           PIN_PARG(size_t), PIN_PARG_END());

        // Replace malloc with wrapper
        AFUNPTR origMalloc = RTN_ReplaceSignature(mallocRtn, AFUNPTR(MallocWrapper),
                             IARG_PROTOTYPE, proto_malloc,
                             IARG_THREAD_ID,
                             IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // size argument
                             IARG_ORIG_FUNCPTR,                 // Original function pointer
                             IARG_PTR, IMG_Name(Img).c_str(),  // Image name
                             IARG_RETURN_IP,                   // Return address
                             IARG_CONST_CONTEXT,                     // Pass context for PIN_CallApplicationFunction
                             IARG_END);
        
        if (origMalloc == NULL) {
            TraceFile << "Failed to replace malloc" << std::endl;
        }
    }

    // Find the free() function.
    RTN freeRtn = RTN_FindByName(Img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                       IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP,
                       IARG_END);
        RTN_Close(freeRtn);
    }

    PIN_GetLock(&_lock, 0);
    if (IMG_IsMainExecutable(Img))
    {

        if (ShouldWriteToFile()) {
            /*
            TraceFile << "[-] List of Symbols with address of Main Image" << std::endl;
            TraceFile << "[--------------------]" << std::endl;
            for( SYM sym= IMG_RegsymHead(Img); SYM_Valid(sym); sym = SYM_Next(sym) ) {
                TraceFile << "[-] Symbol name:  " << SYM_Name(sym);
                TraceFile << "|| Symbol Address: 0x" << std::hex << SYM_Address(sym) << std::endl;
            }

            TraceFile << "[-] Analysing main image: " << imageName << std::endl;
            TraceFile << "[-] Image base: 0x" << std::hex << lowAddress  << std::endl;
            TraceFile << "[-] Image end:  0x" << std::hex << highAddress << std::endl;
            TraceFile << "[-] Number of consecutive regions: " << std::dec << numRegions  << std::endl;
            */
            if (logfilter == 2) {
                TraceFile << "[!] Filter all addresses out of that range" << std::endl;
            }
        }

        main_begin = lowAddress;
        main_end = highAddress;

        DebugLog("< main_begin, main_end >: 0x", std::hex, main_begin, ", 0x", main_end, std::dec);
    }
    else
    {
        if ((logfilter == 1) &&
            ((imageName.compare(0, 10, "C:\\WINDOWS") == 0) ||
             (imageName.compare(0, 4, "/lib") == 0) ||
             (imageName.compare(0, 8, "/usr/lib") == 0)))
        {
            filtered = true;
            // Not interested on code within these modules
            mod_data[imageName].excluded = TRUE;
            mod_data[imageName].begin = lowAddress;
            mod_data[imageName].end = highAddress;
        }

        DebugLog("[-] Loaded module: ", imageName);
        if (filtered) DebugLog("[!] Filtered ", imageName);
        DebugLog("[-] Module base: 0x", std::hex, lowAddress, " and end: 0x", std::hex, highAddress, std::dec);

    }
    PIN_ReleaseLock(&_lock);
}

/* ===================================================================== */
/* Helper Functions for Trace_cb                                         */
/* ===================================================================== */

void LogBasicBlock(ADDRINT addr, UINT32 size)
{
    PIN_GetLock(&_lock, addr);
    if (InfoType >= B)
        bigcounter++;
    InfoType = B;
    if (ShouldWriteToFile()) {
        TraceFile << "[B]" << std::setw(10) << std::dec << bigcounter << std::hex << std::setw(16) << (void *)addr << " loc_" << std::hex << addr << ":";
        TraceFile << " // size=" << std::dec << size;
        TraceFile << " thread=" << "0x" << std::hex << PIN_ThreadUid() << std::endl;
    }
    PIN_ReleaseLock(&_lock);
}

void LogCallAndArgs(ADDRINT ip, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
    std::string nameFunc = "";
    std::string nameArg0 = "";
    std::string nameArg1 = "";
    std::string nameArg2 = "";

    nameFunc = RTN_FindNameByAddress(ip);
    if (KnobLogCallArgs.Value())
    {
        nameArg0 = RTN_FindNameByAddress(arg0);
        nameArg1 = RTN_FindNameByAddress(arg1);
        nameArg2 = RTN_FindNameByAddress(arg2);
    }

    PIN_GetLock(&_lock, ip);
    if (InfoType >= C)
        bigcounter++;
    InfoType = C;
    if (ShouldWriteToFile()) {
        TraceFile << "[C]" << std::setw(10) << std::dec << bigcounter << std::hex << " Calling function 0x" << ip << "(" << nameFunc << ")";
        if (KnobLogCallArgs.Value()) {
            TraceFile << " with args: ("
                      << (void *)arg0 << " (" << nameArg0 << " ), "
                      << (void *)arg1 << " (" << nameArg1 << " ), "
                      << (void *)arg2 << " (" << nameArg2 << " )";
        }
        TraceFile << std::endl;
        if (ExcludedAddress(ip)) {
            TraceFile << "[!] Function 0x" << ip << " is filtered, no tracing" << std::endl;
        }
    }
    PIN_ReleaseLock(&_lock);
}

void LogIndirectCallAndArgs(ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
    if (!taken) {
        return;
    }
    LogCallAndArgs(target, arg0, arg1, arg2);
}

/* ================================================================================= */
/* This is called for each Trace. Traces usually begin at the target of a taken      */
/* branch and end with an unconditional branch, including calls and returns.         */
/* Pin guarantees that a trace is only entered at the top,                           */
/* but it may contain multiple exits.                                                */
/* ================================================================================= */
void Trace_cb(TRACE trace, void *v)
{
    /* Iterate through basic blocks */
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS head = BBL_InsHead(bbl);
        if (ExcludedAddress(INS_Address(head))) {
            return;
        }
        /* Instrument function calls? */
        if (KnobLogCall.Value() || KnobLogCallArgs.Value())
        {
            /* ===================================================================================== */
            /* Code to instrument the events at the end of a BBL (execution transfer)                */
            /* Checking for calls, etc.                                                              */
            /* ===================================================================================== */
            INS tail = BBL_InsTail(bbl);

            if (INS_IsCall(tail))
            {
                if (INS_IsDirectControlFlow(tail))
                {
                    const ADDRINT target = INS_DirectControlFlowTargetAddress(tail);

                    INS_InsertPredicatedCall(
                        tail,
                        IPOINT_BEFORE,
                        AFUNPTR(LogCallAndArgs),       // Function to jump to
                        IARG_ADDRINT,                  // "target"'s type
                        target,                        // Who is called?
                        IARG_FUNCARG_ENTRYPOINT_VALUE, // Arg_0 value
                        0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, // Arg_1 value
                        1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, // Arg_2 value
                        2,
                        IARG_END);
                }
                else
                {
                    INS_InsertCall(
                        tail,
                        IPOINT_BEFORE,
                        AFUNPTR(LogIndirectCallAndArgs),
                        IARG_BRANCH_TARGET_ADDR,
                        IARG_BRANCH_TAKEN,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        2,
                        IARG_END);
                }
            }
            else
            {
                /* Other forms of execution transfer */
                RTN rtn = TRACE_Rtn(trace);
                // Trace jmp into DLLs (.idata section that is, imports)
                if (RTN_Valid(rtn) && SEC_Name(RTN_Sec(rtn)) == ".idata")
                {
                    INS_InsertCall(
                        tail,
                        IPOINT_BEFORE,
                        AFUNPTR(LogIndirectCallAndArgs),
                        IARG_BRANCH_TARGET_ADDR,
                        IARG_BRANCH_TAKEN,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        2,
                        IARG_END);
                }
            }
        }
        /* Instrument at basic block level? */
        if (KnobLogBB.Value())
        {
            /* instrument BBL_InsHead to write "loc_XXXXX", like in IDA Pro */
            INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(LogBasicBlock), IARG_ADDRINT, BBL_Address(bbl), IARG_UINT32, BBL_Size(bbl), IARG_END);
        }
    }

}

/* ================================================================================= */
/* Log some information related to thread execution                                  */
/* ================================================================================= */
void ThreadStart_cb(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&_lock, threadIndex + 1);
    ThreadData *allocatedVariables = new ThreadData;
    if (PIN_SetThreadData(tlsKey, allocatedVariables, threadIndex) == FALSE)
    {
        std::cerr << "PIN_SetThreadData allocatedVariables failed" << std::endl;
        PIN_ExitProcess(1);
    }

    if (InfoType >= T)
        bigcounter++;
    InfoType = T;
    DebugLog("[T]", std::setw(10), std::dec, bigcounter, std::hex, "Thread 0x", PIN_ThreadUid(), " started. Flags 0x", std::hex, flags);
    PIN_ReleaseLock(&_lock);
}

void ThreadFinish_cb(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    PIN_GetLock(&_lock, threadIndex + 1);

    DebugLog("[T]", std::setw(10), std::dec, bigcounter, std::hex, " Thread 0x", PIN_ThreadUid(), " finished. Code: ", std::dec, code);

    // free data saved by thread
    ThreadData *tdata = static_cast<ThreadData *>(PIN_GetThreadData(tlsKey, threadIndex));
    delete tdata;

    PIN_ReleaseLock(&_lock);
}

/* ===================================================================== */
/* Fini                                                                  */
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v) {
    if (enableFileOutput) {
        // Wait for any pending write threads to complete
        PIN_GetLock(&fileWriteLock, 0);
        PIN_ReleaseLock(&fileWriteLock);
        
        // Wait for both buffers to be available
        PIN_GetLock(&buffer1.lock, 0);
        PIN_GetLock(&buffer2.lock, 0);
        PIN_ReleaseLock(&buffer1.lock);
        PIN_ReleaseLock(&buffer2.lock);
        
        // Flush any remaining entries in the current buffer using bulk write
        if (currentBuffer->index > 0) {
            std::stringstream bulkData;
            for (size_t i = 0; i < currentBuffer->index; i++) {
                const MemoryTraceEntry& entry = currentBuffer->buffer[i];
                
                bulkData << FormatTraceEntry(entry, KnobDiscriminateThread.Value());
            }
            
            // Single file write operation
            TraceFile << bulkData.str();
        }
        
        // Flush any remaining data
        TraceFile.flush();
        // TraceFile.close();
    }

    PROTO_Free(proto_malloc);
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    // Obtain a Key for TLS (Thread Local Storage)
    tlsKey = PIN_CreateThreadDataKey(NULL);
    if (tlsKey == INVALID_TLS_KEY)
    {
        std::cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit. Needed for dynamic variables tracing" << std::endl;
        PIN_ExitProcess(1);
    }

    // Initialize the file write lock
    PIN_InitLock(&fileWriteLock);

    // Set the file output flag based on knob value
    enableFileOutput = KnobEnableFileOutput.Value();

    TraceName = KnobOutputFile.Value();

    // Only open the file if file output is enabled
    if (enableFileOutput) {
        TraceFile.open(TraceName.c_str());
        if (TraceFile.fail()) {
            std::cerr << "[!] Something went wrong opening the log file..." << std::endl;
            return -1;
        }
        else {
            if (!KnobQuiet.Value()) {
                std::cerr << "[*] Trace file " << TraceName << " opened for writing..." << std::endl
                          << std::endl;
            }
        }
    } else {
        if (!KnobQuiet.Value()) {
            std::cerr << "[*] Trace file not opened for writing..." << std::endl;
        }
    }

    

    variable_name = KnobVariableName.Value();
    function_name = KnobFunctionName.Value();

    

    filter_global_var = (function_name.empty() && !variable_name.empty());

    filter_local_var = (!function_name.empty() && !variable_name.empty());

    #if !defined(TARGET_IA32E)
    if (!variable_name.empty()) {
        std::cerr << "Architecture not x86. Can't find RBP to track variable" << std::endl;
    }
    #endif

    if (filter_local_var) {
        var_byte_size = KnobVarByteSize.Value();

        DebugLog("Using Function name: ", function_name);
        DebugLog("Using Variable name: ", variable_name, " with size ", std::dec, var_byte_size);

        //std::string command = "/home//Desktop/tesis/prueba/tool " + function_name + " " + variable_name + " " + std::string(argv[argc - 1]);
        std::string command = BuildDwgrepLocalVariableQuery(argv[argc - 1], function_name, variable_name);
        std::string lowpc_highpc_varoffset = ExecuteCommand(command);

        if (lowpc_highpc_varoffset == "") {
            std::cerr << "ERR: failed getting data from debug section" << std::endl;
        }

        DebugLog("Command ran: ", command);
        DebugLog("Output from tool: ", lowpc_highpc_varoffset);

        std::vector<std::string> debug_info = SplitString(lowpc_highpc_varoffset, ',');
        if (debug_info.size() != 3)
        {
            std::cerr << "ERR: do not have 3 numbers as the result of getting the debug info" << std::endl;
        }

        // PIN Forces to compile without try catch, so if no numbers are returned kaboom
        func_offset = std::stoi(debug_info[0]);
        func_totalbytes = std::stoi(debug_info[1]);

        if (func_offset == 0 || func_totalbytes == 0)
        {
            std::cerr << "Error getting func offset" << std::endl;
            return 1; // Exit with an error code
        }

        var_offset = std::stoi(debug_info[2].substr(1, debug_info[2].length()));

        if (var_offset == 0)
        {
            std::cerr << "Error getting var offset" << std::endl;
            return 1; // Exit with an error code
        }

        DebugLog("Func offset: 0x", std::hex, std::uppercase, func_offset);
        DebugLog("Var offset: 0x", var_offset, " Var offset - ADDRINT(16): 0x", var_offset - ADDRINT(16), std::dec);

        // Important to calculate CFA, for clang++ CFA = RBP, for g++ CFA = RBP + 16
        command = BuildDwgrepProducerQuery(argv[argc - 1]);
        std::string producer = ExecuteCommand(command);
        isGnuCompiled = IsGnuCompiler(producer);
    } else if (filter_global_var) {
        var_byte_size = KnobVarByteSize.Value();
        DebugLog("Using Variable name: ", variable_name, " with size ", std::dec, var_byte_size);

        std::string command = BuildDwgrepGlobalVariableQuery(argv[argc - 1], variable_name);

        DebugLog("Command ran: ", command);

        std::string globalVarOffsetString = ExecuteCommand(command);

        if (globalVarOffsetString == "") {
            std::cerr << "Variable is not global" << std::endl;
            return 1;
        }

        global_var_offset = std::stoi(globalVarOffsetString);
    }

    char *endptr;
    const char *tmpfilter = KnobLogFilter.Value().c_str();
    logfilter = strtoull(tmpfilter, &endptr, 16);
    if (endptr == tmpfilter)
    {
        std::cerr << "ERR: Failed parsing option -f" << std::endl;
        return 1;
    }
    if ((endptr[0] == '\0') && (logfilter > 2))
    {
        std::cerr << "ERR: Failed parsing option -f" << std::endl;
        return 1;
    }
    if (logfilter > 2)
    {
        filter_begin = logfilter;
        logfilter = 3;
        char *endptr2;
        if (endptr[0] != '-')
        {
            std::cerr << "ERR: Failed parsing option -f" << std::endl;
            return 1;
        }
        filter_end = strtoull(endptr + 1, &endptr2, 16);
        if (endptr2 == endptr + 1)
        {
            std::cerr << "ERR: Failed parsing option -f" << std::endl;
            return 1;
        }
        if (endptr2[0] != '\0')
        {
            std::cerr << "ERR: Failed parsing option -f" << std::endl;
            return 1;
        }
        if (filter_end <= filter_begin)
        {
            std::cerr << "ERR: Failed parsing option -f" << std::endl;
            return 1;
        }
    }

    const char *tmpfilterlive = KnobLogFilterLive.Value().c_str();
    INT64 tmpval = strtoull(tmpfilterlive, &endptr, 16);
    if (tmpval != 0)
        logfilterlive = true;
    if (endptr == tmpfilterlive)
    {
        std::cerr << "ERR: Failed parsing option -F" << std::endl;
        return 1;
    }
    if ((endptr[0] == '\0') && (logfilterlive))
    {
        std::cerr << "ERR: Failed parsing option -F" << std::endl;
        return 1;
    }
    if (tmpval > 0)
    {
        filter_live_start = tmpval;
        char *endptr2;
        if (endptr[0] != ':')
        {
            std::cerr << "ERR: Failed parsing option -F" << std::endl;
            return 1;
        }
        filter_live_stop = strtoull(endptr + 1, &endptr2, 16);
        if (endptr2 == endptr + 1)
        {
            std::cerr << "ERR: Failed parsing option -F" << std::endl;
            return 1;
        }
        if (endptr2[0] != '\0')
        {
            std::cerr << "ERR: Failed parsing option -F" << std::endl;
            return 1;
        }
    }
    filter_live_n = KnobLogFilterLiveN.Value();

    DebugLog("#");
    DebugLog("# Instruction Trace Generated By Matias Giampaolo, inspired by Roswell TracerPin " GIT_DESC);
    DebugLog("#");
    DebugLog("[*] Arguments:");
    for (int nArg = 0; nArg < argc; nArg++)
        DebugLog("[*]", std::setw(5), nArg, ": ", argv[nArg]);
    DebugLog("", std::dec);

        IMG_AddInstrumentFunction(ImageLoad_cb, 0);
    PIN_AddThreadStartFunction(ThreadStart_cb, 0);
    PIN_AddThreadFiniFunction(ThreadFinish_cb, 0);
    TRACE_AddInstrumentFunction(Trace_cb, 0);
    INS_AddInstrumentFunction(Instruction_cb, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
