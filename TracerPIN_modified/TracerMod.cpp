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
#include <array>  // for std::array
#include <chrono> // for high resolution timing
#include <string> // for string operations
#include <cctype> // used to validate string inputs
#include <thread> // for thread functionality

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


// Keep strings alive for the lifetime of the run
static std::vector<std::string> g_ImageNames;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                                 "o", "trace-full-info.txt", "specify trace file name");
KNOB<BOOL> KnobLogIns(KNOB_MODE_WRITEONCE, "pintool",
                      "i", "0", "log all instructions");
KNOB<BOOL> KnobLogMem(KNOB_MODE_WRITEONCE, "pintool",
                      "m", "1", "log all memory accesses");
KNOB<BOOL> KnobLogBB(KNOB_MODE_WRITEONCE, "pintool",
                     "b", "0", "log all basic blocks");
KNOB<BOOL> KnobLogCall(KNOB_MODE_WRITEONCE, "pintool",
                       "c", "0", "log all calls");
KNOB<BOOL> KnobLogCallArgs(KNOB_MODE_WRITEONCE, "pintool",
                           "C", "0", "log all calls with their first three args");
KNOB<std::string> KnobLogFilter(KNOB_MODE_WRITEONCE, "pintool",
                                "f", "1", "(0) no filter (1) filter system libraries (2) filter all but main exec (0x400000-0x410000) trace only specified address range");
KNOB<std::string> KnobLogFilterLive(KNOB_MODE_WRITEONCE, "pintool",
                                    "F", "0", "(0) no live filter (0x400000:0x410000) use addresses as start:stop live filter");
KNOB<INT> KnobLogFilterLiveN(KNOB_MODE_WRITEONCE, "pintool",
                             "n", "0", "which occurence to log, 0=all (only for -F start:stop filter)");
// KNOB<std::string> KnobLogType(KNOB_MODE_WRITEONCE, "pintool",
                              // "t", "human", "log type: human/sqlite");
KNOB<BOOL> KnobQuiet(KNOB_MODE_WRITEONCE, "pintool",
                     "q", "0", "be quiet under normal conditions");
KNOB<std::string> KnobVariableDwarfDIE_ID(KNOB_MODE_WRITEONCE, "pintool",
                                          "vdid", "0", "Variable DWARF DIE ID, obtained from de debug_info section. Recommended to use readelf -wi <executable> \n Default (0) means no use of this filter. Use with <PONER ACA SIZE IN BYTES Y FUNC OPT>");
KNOB<std::string> KnobVariableName(KNOB_MODE_WRITEONCE, "pintool",
                                   "vname", "", "Variable name, will be used to lookup in the dwarf debug data. \n Default (0) means no use of this filter. Use with <PONER ACA SIZE IN BYTES Y FUNC OPT>");
KNOB<UINT64> KnobVarByteSize(KNOB_MODE_WRITEONCE, "pintool",
                             "vs", "0", "Variable to trace size in Bytes. Used with -vdid option");
KNOB<std::string> KnobFunctionDwarfDIE_ID(KNOB_MODE_WRITEONCE, "pintool",
                                          "fdid", "0", "Function DWARF DIE ID, obtained from de debug_info section. Recommended to use readelf -wi <executable> \n Default (0) means no use of this filter. Use with <PONER ACA SIZE IN BYTES Y FUNC OPT>");
KNOB<std::string> KnobFunctionName(KNOB_MODE_WRITEONCE, "pintool",
                                   "fname", "", "Function  name, will be used to lookup in the dwarf debug data. \n Default (0) means no use of this filter. Use with <PONER ACA SIZE IN BYTES Y FUNC OPT>");
KNOB<BOOL> KnobDiscriminateThread(KNOB_MODE_WRITEONCE, "pintool",
                                  "td", "0", "Discriminate which thread read/writes the variable and who owns it");
KNOB<BOOL> KnobExcludeAddressesOutsideMain(KNOB_MODE_WRITEONCE, "pintool",
                                           "excl", "1", "Exclude instructions to instrment outside main executable, ex: libc");
KNOB<BOOL> KnobDebugLogs(KNOB_MODE_WRITEONCE, "pintool",
                         "d", "0", "Add debug logs for reading RBP, and knowing when addresses are filtered because of func, or because of not var of interest");
KNOB<BOOL> KnobEnableFileOutput(KNOB_MODE_WRITEONCE, "pintool",
                                "file", "1", "enable/disable file output (1=enable, 0=disable)");
KNOB<BOOL> KnobEnableRecursiveAllocTracking(KNOB_MODE_WRITEONCE, "pintool",
                                "recursive", "1", "enable/disable recursive tracking of malloced pointers (1=enable, 0=disable)");


// Force each thread's data to be in its own data cache line so that
// multiple threads do not contend for the same data cache line.
// This avoids the false sharing problem.
// #define PADSIZE 56 // 64 byte line size: 64-8

class threadData_t
{
public:
    ADDRINT sizeAsked;
    // UINT8 _pad[PADSIZE];
    std::map<ADDRINT, ADDRINT> *sizeByPointer;

    threadData_t()
    {
        sizeByPointer = new std::map<ADDRINT, ADDRINT>;
    }

    ~threadData_t()
    {
        free(sizeByPointer);
    }
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
// Memory trace buffer structure and global buffer
struct MemoryTraceEntry
{
    THREADID threadOwner;
    THREADID threadWriter;
    ADDRINT address;
    INT32 size;
    UINT8 memdump[256];
    CHAR operation; // 'R' for read, 'W' for write
};

const size_t MAX_BUFFER_ENTRIES = 1'000'000; // Fixed size for buffer
MemoryTraceEntry traceBuffer1[MAX_BUFFER_ENTRIES];
MemoryTraceEntry traceBuffer2[MAX_BUFFER_ENTRIES];

// Buffer management structure
struct BufferInfo {
    MemoryTraceEntry* buffer;
    size_t index;
    bool inUse;  // true if being written to file
    PIN_LOCK lock;
    
    BufferInfo(MemoryTraceEntry* buf) : buffer(buf), index(0), inUse(false) {
        PIN_InitLock(&lock);
    }
};

BufferInfo buffer1(traceBuffer1);
BufferInfo buffer2(traceBuffer2);
BufferInfo* currentBuffer = &buffer1;
BufferInfo* writeBuffer = nullptr;

// Lock for file writing operations
PIN_LOCK fileWriteLock;

// Structure to pass buffer information to write thread
struct WriteBufferArgs {
    BufferInfo* bufferInfo;
    size_t bufferSize;
};

std::string FormatTraceEntry(const MemoryTraceEntry& entry) {
    // Preallocate string with estimated capacity
    std::string result;
    result.reserve(64); // Adjust based on expected output size (e.g., operation, threads, address, memdump)

    // Hex conversion lookup table
    static const char hex[] = "0123456789abcdef";

    // Append operation
    result += '[';
    result += entry.operation;
    result += ']';

    // Append thread info if enabled
    if (KnobDiscriminateThread.Value()) {
        result += '[';
        result += std::to_string(entry.threadWriter);
        result += "][";
        result += std::to_string(entry.threadOwner);
        result += ']';
    }

    // Append address (convert to hex manually for efficiency)
    result += "0x";
    char addr_buf[17]; // Enough for 64-bit address (16 hex digits + null)
    addr_buf[16] = '\0';
    uintptr_t addr = reinterpret_cast<uintptr_t>(entry.address);
    for (int i = 15; i >= 0; --i) {
        addr_buf[i] = hex[addr & 0xF];
        addr >>= 4;
    }
    result += addr_buf;
    result += ' ';

    // Append memdump based on size
    switch (entry.size) {
        case 1: {
            result += "0x";
            UINT8 val = entry.memdump[0];
            result += hex[(val >> 4) & 0xF];
            result += hex[val & 0xF];
            break;
        }
        case 2: {
            result += "0x";
            UINT16 val = *reinterpret_cast<const UINT16*>(entry.memdump);
            for (int i = 3; i >= 0; --i) {
                result += hex[(val >> (i * 4)) & 0xF];
            }
            break;
        }
        case 4: {
            result += "0x";
            UINT32 val = *reinterpret_cast<const UINT32*>(entry.memdump);
            for (int i = 7; i >= 0; --i) {
                result += hex[(val >> (i * 4)) & 0xF];
            }
            break;
        }
        case 8: {
            result += "0x";
            UINT64 val = *reinterpret_cast<const UINT64*>(entry.memdump);
            for (int i = 15; i >= 0; --i) {
                result += hex[(val >> (i * 4)) & 0xF];
            }
            break;
        }
        default: {
            for (INT32 j = 0; j < entry.size; ++j) {
                result += " ";
                UINT8 val = entry.memdump[j];
                result += hex[(val >> 4) & 0xF];
                result += hex[val & 0xF];
            }
            break;
        }
    }

    result += '\n';
    return result;
}

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
        bulkData << FormatTraceEntry(entry);
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

// Helper function to check if we should write to file
inline bool ShouldWriteToFile() {
    return enableFileOutput;
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

std::string variable_dwarf_id;
std::string function_dwarf_id;
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
INT64 var_offset = 0;
UINT64 var_byte_size = 0;
bool filter_by_dwarf = false;

struct VariableMemoryLocation
{
    ADDRINT startAddress;
    ADDRINT endAdress;
    THREADID ownerThread;

    VariableMemoryLocation(ADDRINT start, ADDRINT end, THREADID tid) : startAddress(start), endAdress(end), ownerThread(tid) {}
};

PIN_LOCK _lockvarreg;
std::vector<VariableMemoryLocation> varRegions;

void printVarRegions(std::vector<VariableMemoryLocation> regions)
{
    if (!ShouldWriteToFile()) return;
    
    TraceFile << regions.size() << " elements" << "[";
    for (const auto &varRegion : regions)
    {
        TraceFile << "<0x" << varRegion.startAddress << ", 0x" << varRegion.endAdress << "> ";
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
bool quiet = false;
long long bigcounter = 0; // Ready for 4 billions of instructions
long long currentbbl = 0;
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

enum LogTypeType
{
    HUMAN,
};

LogTypeType LogType = HUMAN;

// Timing utility class
/*
class FunctionTimer
{
private:
    std::ofstream timingFile;
    std::map<std::string, std::chrono::high_resolution_clock::time_point> startTimes;
    std::map<std::string, double> totalTimes;
    std::map<std::string, int> callCounts;
    PIN_LOCK timingLock;

public:
    FunctionTimer()
    {
        // Open timing file on desktop
        std::string homeDir = std::getenv("HOME") ? std::getenv("HOME") : "/home/mgiampaolo";
        std::string timingFilePath = homeDir + "/Desktop/function_timing.txt";
        timingFile.open(timingFilePath.c_str());
        if (timingFile.is_open())
        {
            timingFile << "Function Timing Log - TracerPIN" << std::endl;
            timingFile << "=================================" << std::endl;
            timingFile << std::endl;
        }
    }

    ~FunctionTimer()
    {
        if (timingFile.is_open())
        {
            timingFile.close();
        }
    }

    void startTimer(const std::string &functionName)
    {
        PIN_GetLock(&timingLock, 0);
        startTimes[functionName] = std::chrono::high_resolution_clock::now();
        PIN_ReleaseLock(&timingLock);
    }

    void endTimer(const std::string &functionName)
    {
        PIN_GetLock(&timingLock, 0);
        auto endTime = std::chrono::high_resolution_clock::now();

        if (startTimes.find(functionName) != startTimes.end())
        {
            auto startTime = startTimes[functionName];
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
            double microseconds = duration.count();

            totalTimes[functionName] += microseconds;
            callCounts[functionName]++;

            // Remove the start time to free memory
            startTimes.erase(functionName);
        }

        PIN_ReleaseLock(&timingLock);
    }

    void printSummary()
    {
        if (timingFile.is_open())
        {
            timingFile << "FUNCTION TIMING SUMMARY:" << std::endl;
            timingFile << "========================" << std::endl;
            timingFile << std::endl;

            for (const auto &pair : totalTimes)
            {
                const std::string &funcName = pair.first;
                double totalTimeMicroseconds = pair.second;
                int calls = callCounts[funcName];
                double avgTimeMicroseconds = calls > 0 ? totalTimeMicroseconds / calls : 0;

                // Convert to milliseconds
                double totalTimeMs = totalTimeMicroseconds / 1000.0;
                double avgTimeMs = avgTimeMicroseconds / 1000.0;

                timingFile << funcName << ":" << std::endl;
                timingFile << "  Total calls: " << calls << std::endl;
                timingFile << "  Total time: " << totalTimeMs << " milliseconds" << std::endl;
                timingFile << "  Average time: " << avgTimeMs << " milliseconds" << std::endl;
                timingFile << std::endl;
            }

            // Print grand totals
            double grandTotalTimeMicroseconds = 0;
            int grandTotalCalls = 0;
            for (const auto &pair : totalTimes)
            {
                grandTotalTimeMicroseconds += pair.second;
                grandTotalCalls += callCounts[pair.first];
            }

            // Convert to seconds
            double grandTotalTimeSeconds = grandTotalTimeMicroseconds / 1000000.0;
            double avgTimeSeconds = grandTotalCalls > 0 ? grandTotalTimeSeconds / grandTotalCalls : 0;

            timingFile << "GRAND TOTALS:" << std::endl;
            timingFile << "=============" << std::endl;
            timingFile << "Total function calls: " << grandTotalCalls << std::endl;
            timingFile << "Total execution time: " << grandTotalTimeSeconds << " seconds" << std::endl;
            timingFile << "Average time per call: " << avgTimeSeconds << " seconds" << std::endl;
        }
    }
};

// Global timing instance
static FunctionTimer *g_timer = nullptr;
*/

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
    std::cerr << "Result by default in trace-full-info.txt" << std::endl
              << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary();

    std::cerr << std::endl;

    return -1;
}

/* ===================================================================== */
/* Mati Helper funcs                                                      */
/* ===================================================================== */

bool IsWithinMainExec(ADDRINT addr)
{
    if (KnobDebugLogs.Value())
    {
        TraceFile << "[DEBUG] Address within main exec 0x" << addr << std::endl;
    }

    return (main_begin <= addr && addr <= main_end);
}

bool IsWithinDwarfFunction(ADDRINT addr)
{
    // In case of not passing -did option, this will always return false: address can't be >= addr_main and < at the same time
    return (addr >= (main_begin + func_offset)) && (addr < (main_begin + func_offset + func_totalbytes));
}

std::vector<std::string> splitstring(std::string myString, char delimiter)
{
    std::istringstream stream(myString);
    std::string token;
    std::vector<std::string> result;

    while (std::getline(stream, token, delimiter))
    {
        result.push_back(token);
    }

    return result;
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

BOOL ExcludedAddressForVar(ADDRINT ip)
{

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

VOID printInst(ADDRINT ip, std::string *disass, INT32 size)
{
    UINT8 v[32];
    // test on logfilterlive here to avoid calls when not using live filtering
    if (logfilterlive && ExcludedAddressLive(ip))
        return;
    if ((size_t)size > sizeof(v))
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

// Helper function to format a trace entry to string
std::string FormatTraceEntryOld(const MemoryTraceEntry& entry)
{
    std::stringstream ss;
    ss << "[" << entry.operation << "]";
    if (KnobDiscriminateThread.Value()) {
        ss << "[" << entry.threadWriter << "]";
        ss << "[" << entry.threadOwner << "]";
    }
    
    ss << (void*)entry.address << " " << std::hex;
    
    switch (entry.size) {
        case 1:
            ss << "0x" << std::setfill('0') << std::setw(2) << static_cast<UINT32>(entry.memdump[0]);
            break;
        case 2:
            ss << "0x" << std::setfill('0') << std::setw(4) << *(UINT16*)entry.memdump;
            break;
        case 4:
            ss << "0x" << std::setfill('0') << std::setw(8) << *(UINT32*)entry.memdump;
            break;
        case 8:
            ss << "0x" << std::setfill('0') << std::setw(16) << *(UINT64*)entry.memdump;
            break;
        default:
            for (INT32 j = 0; j < entry.size; j++) {
                ss << " " << std::setfill('0') << std::setw(2) << static_cast<UINT32>(entry.memdump[j]);
            }
            break;
    }
    ss << std::setfill(' ') << std::endl;
    return ss.str();
}


// Aux function to add memory trace entry to buffer and flush when full
void AddToTraceBuffer(THREADID threadOwner, THREADID threadWriter, ADDRINT address, INT32 size, UINT8* memdump, CHAR operation, bool isPrefetch)
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
    for (int i = 0; i < size && i < 256; i++) {
        currentBuffer->buffer[currentBuffer->index].memdump[i] = memdump[i];
    }
    
    currentBuffer->index++;
    
    // Flush buffer when full
    if (currentBuffer->index >= MAX_BUFFER_ENTRIES) {
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
        WriteBufferArgs* args = new WriteBufferArgs{writeBuffer, MAX_BUFFER_ENTRIES};
        PIN_SpawnInternalThread(WriteBufferToFile, args, 0, PIN_THREAD_UID(NULL));
    }
}

ADDRINT calculateVarOffset(ADDRINT rbpValue) {
    ADDRINT offsetFromCFA = 0;
    if (isGnuCompiled) {
        offsetFromCFA = ADDRINT(16);
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

    // SECTION 1: DWARF Filtering
    if (filter_by_dwarf) {
        if (func_offset == 0) {
            std::cerr << "Offset function 0, but filter_by_dwarf true" << std::endl;
        }


        // Used for the dynamic case and static case
        threadData_t *threadData = static_cast<threadData_t *>(PIN_GetThreadData(tlsKey, tid));
        ADDRINT rbpValue = 0;
        if (regRBP != 0) {
            rbpValue = regRBP;
        } else {
            rbpValue = prefetchRBP;
        }

        
        if (var_byte_size == 0) {
            // DYNAMIC VARIABLE
            std::map<ADDRINT, ADDRINT> *sizeByPointer = threadData->sizeByPointer;
            if (IsWithinDwarfFunction(ip)) {
                /*
                ADDRINT sixteenBytes = ADDRINT(16);
                ADDRINT trueOffset = var_offset - sixteenBytes;
                ADDRINT varInStack = rbpValue - trueOffset;
                */
                ADDRINT varInStack = calculateVarOffset(rbpValue);


                if (KnobDebugLogs.Value()) {
                    if (ShouldWriteToFile()) {
                        TraceFile << std::hex;

                        TraceFile << "W on 0x" << addr << " R: 0x" << rbpValue 
                        << " R - Of 0x" << varInStack << std::endl;

                        TraceFile << std::dec;
                    }
                }

                if (addr == varInStack) {
 
                    if (KnobDebugLogs.Value()) {
                        if (ShouldWriteToFile()) {
                            TraceFile << "Writing on var in stack" << std::endl;
                        }
                    }
                    // Operating on x (var by DwarfID)
                    if (r == 'R') { // If reading the pointer, not the heap allocated memory: skip
                        return;
                    }

                    ADDRINT heapAllocatedPointer = 0;

                    PIN_SafeCopy(&heapAllocatedPointer, (void *)varInStack, sizeof(heapAllocatedPointer));

                    auto it = sizeByPointer->find(heapAllocatedPointer);

                    // Validate if pointer is from malloc
                    if (it == sizeByPointer->end())
                    {
                        if (KnobDebugLogs.Value())
                        {
                            if (ShouldWriteToFile()) {
                                TraceFile << "[DEBUG] Pointer 0x" << heapAllocatedPointer << " not in map " << std::endl;
                            }
                        }
                        // Not found -> Not tracing
                        return;
                    }

                    // pointer is from malloc call
                    ADDRINT varSizeInBytes = it->second;

                    // Append to areas of memory to be traced
                    // we save the <regionOfMemoryOfX>, ThreadThatCreatedX
                    PIN_GetLock(&_lockvarreg, 0);
                    varRegions.emplace_back(heapAllocatedPointer, (heapAllocatedPointer + varSizeInBytes), tid);
                    PIN_ReleaseLock(&_lockvarreg);
                    // Region of memory saved

                    if (KnobDebugLogs.Value()) {
                        if (ShouldWriteToFile()) {
                            TraceFile << "[DEBUG] VarRegions ADD x region";
                            printVarRegions(varRegions);
                        }
                    }

                    // Proceed to trace the pointer (to the heap) written
                }
            }
            // Are you reading or writing another instantiaton of x (var by DwarfID) ?

            PIN_GetLock(&_lockvarreg, 0);
            for (const auto &memoryRegion : varRegions) {
                if (memoryRegion.startAddress <= addr && addr < memoryRegion.endAdress) {
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

                            auto it = sizeByPointer->find(writingBytes);

                            // Validate if it is a malloced pointer
                            if (it == sizeByPointer->end())
                            {
                                // Not found -> not malloced memory
                                if (KnobDebugLogs.Value())
                                {
                                    if (ShouldWriteToFile())
                                    {
                                        TraceFile << "[DEBUG] Pointer 0x" << addr << " not in map " << std::endl;
                                    }
                                }
                            }
                            else {
                                // pointer is from malloc call
                                ADDRINT varSizeInBytes = it->second;
                                varRegions.emplace_back(writingBytes, (writingBytes + varSizeInBytes), tid);

                                if (KnobDebugLogs.Value())
                                {
                                    if (ShouldWriteToFile())
                                    {
                                        TraceFile << "[DEBUG] indirect add char - VarRegions ADD x region ";
                                        printVarRegions(varRegions);
                                    }
                                }
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

                ADDRINT varInStack = calculateVarOffset(rbpValue);

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
                if (KnobDebugLogs.Value()) {
                    if (ShouldWriteToFile()) {
                        TraceFile << "[DEBUG] Excluding address out of func 0x" << ip << std::endl;
                    }
                }
                return;
            }

            if (KnobDebugLogs.Value()) {
                if (ShouldWriteToFile()) {
                    TraceFile << "[DEBUG] Address 0x" << ip << " in func address range" << std::endl;
                }
            }

            /*
            ADDRINT sixteenBytes = ADDRINT(16);
            ADDRINT trueOffset = var_offset - sixteenBytes;
            ADDRINT varLowADDR = rbpValue - trueOffset;
            */
            ADDRINT varLowADDR = calculateVarOffset(rbpValue);
            ADDRINT varHighADDR = varLowADDR + var_byte_size;

            if (varLowADDR > addr || varHighADDR <= addr) {
                return;
            }

            if (KnobDebugLogs.Value()) {
                if (ShouldWriteToFile()) {
                    OS_THREAD_ID tid = PIN_GetTid();
                    TraceFile
                        << "[DEBUG] TID:" << tid << " - "
                        << "RBP VALUE: " << rbpValue << std::endl;

                    TraceFile << "[DEBUG] memory instruction over var of interest ";
                    TraceFile << "with varLowADDR " << varLowADDR << "and varHighADDR " << varHighADDR << std::endl;
                }
            }
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
    AddToTraceBuffer(threadOwnerOfX, tid, addr, size, memdump, r, isPrefetch);
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
VOID Instruction_cb(INS ins, VOID *v)
{
    ADDRINT ceip = INS_Address(ins);

    // Either by -f -F filters, or by -fdid function lowpc and highpc address
    // excluding ip addresses outside of my function of interest
    if (ExcludedAddress(ceip) && KnobExcludeAddressesOutsideMain.Value()) {
        return;
    }

#if defined(TARGET_IA32E)
    if (KnobLogMem.Value())
    {

        if (INS_IsMemoryRead(ins))
        {
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

        if (INS_HasMemoryRead2(ins))
        {
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
        if (INS_IsMemoryWrite(ins))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_REG_VALUE, REG_RBP,
                IARG_END);

            if (INS_HasFallThrough(ins))
            {
                INS_InsertCall(
                    ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_END);
            }
            if (INS_IsControlFlow(ins))
            {
                INS_InsertCall(
                    ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_END);
            }
        }
    }
#endif

    if (KnobLogIns.Value())
    { // && !filter_by_dwarf) { TODO: por que filtraba por esto?
        std::string *disass = new std::string(INS_Disassemble(ins));
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)printInst,
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
    if (!IsWithinMainExec(returnPointer))
    {
        return;
    }

    threadData_t *threadData = static_cast<threadData_t *>(PIN_GetThreadData(tlsKey, tid));
    int i = 0;
    // Remove from local thread malloc pointers
    for (std::map<ADDRINT, ADDRINT>::iterator it = threadData->sizeByPointer->begin(); it != threadData->sizeByPointer->end(); it++)
    {

        if (KnobDebugLogs.Value())
        {
            if (ShouldWriteToFile()) {
                TraceFile << "Thread FREE" << tid << "- MapElement " << i << " of map is:" << it->second << std::endl;
            }
        }

        if ((it->first) == pointerToFree)
        {
            threadData->sizeByPointer->erase(it);
            if (KnobDebugLogs.Value())
            {
                if (ShouldWriteToFile()) {
                    TraceFile << "Thread " << tid << " freed " << pointerToFree << " with 0x" << it->second << " bytes" << std::endl;
                }
            }
            break;
        }
        i++;
    }

    if (KnobDebugLogs.Value())
    {
        if (ShouldWriteToFile()) {
            TraceFile << "[DEBUG] VarRegions before freeing";
            printVarRegions(varRegions);
        }
    }
    // Remove from global sections of memory
    PIN_GetLock(&_lockvarreg, 0);
    for (auto it = varRegions.begin(); it != varRegions.end();)
    {
        if (it->startAddress == pointerToFree)
        {
            it = varRegions.erase(it);
        }
        else
        {
            ++it;
        }
    }
    PIN_ReleaseLock(&_lockvarreg);

    if (KnobDebugLogs.Value())
    {
        if (ShouldWriteToFile()) {
            TraceFile << "[DEBUG] VarRegions after freeing";
            printVarRegions(varRegions);
        }
    }
}

void MallocBeforeLog(THREADID tid, size_t size, ADDRINT returnIp, const char* imgName) {
    TraceFile << "[BEFORE] malloc from " << imgName
              << " size=" << size << std::dec << std::endl; 
}

void MallocAfterLog(THREADID tid, VOID* retPtr, ADDRINT returnIp, const char* imgName) {
    TraceFile << "[AFTER] malloc from " << imgName
              << " returned ptr=" << retPtr << std::dec << std::endl;
}

void MallocBefore(THREADID tid, ADDRINT size, ADDRINT returnPointer)
{

    if (!IsWithinMainExec(returnPointer))
    {
        return;
    }

    if (KnobDebugLogs.Value())
    {
        if (ShouldWriteToFile()) {
            TraceFile << "[DEBUG] [TID:" << tid << "][Malloc before] asked for " << size << " bytes of memory" << std::endl;
        }
    }

    threadData_t *threadData = static_cast<threadData_t *>(PIN_GetThreadData(tlsKey, tid));
    threadData->sizeAsked = size;

    // TraceFile << "Thread " << tid << " asked for 0x" << size << " bytes of memory" << std::endl;
}

void MallocAfter(THREADID tid, ADDRINT memPointer, ADDRINT returnPointer)
{
    if (KnobDebugLogs.Value())
    {
        if (ShouldWriteToFile()) {
            TraceFile << "[DEBUG] [TID:" << tid << "][Malloc after] got 0x" << memPointer << std::endl;
        }
    }

    if (!IsWithinMainExec(returnPointer))
    {
        return;
    }

    if (KnobDebugLogs.Value())
    {
        if (ShouldWriteToFile()) {
            TraceFile << "[DEBUG] [TID:" << tid << "][Malloc after] got 0x" << memPointer << std::endl;
        }
    }

    threadData_t *threadData = static_cast<threadData_t *>(PIN_GetThreadData(tlsKey, tid));
    threadData->sizeByPointer->insert({memPointer, threadData->sizeAsked});

    if (KnobDebugLogs.Value())
    {
        if (ShouldWriteToFile()) {
            TraceFile << "Thread " << tid << " got pointer 0x" << memPointer << " with 0x" << threadData->sizeAsked << " bytes of memory" << std::endl;
            TraceFile << "{" << std::endl;
            for (std::map<ADDRINT, ADDRINT>::iterator it = threadData->sizeByPointer->begin(); it != threadData->sizeByPointer->end(); it++) {
                TraceFile << it->first << " : " << it -> second << "," << std::endl;
            }
            TraceFile << "}" << std::endl;
        }
    }
}

// Wrapper for malloc
VOID* MallocWrapper(THREADID threadid, size_t size, AFUNPTR originalMalloc, const char* imgName, ADDRINT retIp, CONTEXT* ctxt) {
    // Prepare return value and argument for malloc
    VOID* ptr = nullptr; // Return value (first argument)
    size_t arg_size = size; // Argument to malloc

    // Call original malloc using PIN_CallApplicationFunction
    PIN_CallApplicationFunction(ctxt, threadid, CALLINGSTD_DEFAULT, originalMalloc, nullptr,
                                PIN_PARG(VOID*), &ptr, // Return value
                                PIN_PARG(size_t), arg_size, // Argument: size
                                PIN_PARG_END());


    if (KnobDebugLogs.Value()) {
        if (ShouldWriteToFile()) {
            TraceFile << "[DEBUG] [TID:" << threadid << "][Malloc Wrapper] asked for " << size << " and got pointer 0x" << ptr << std::endl;
        }
    }

    // Consolidated logic: directly insert the malloc pointer and size into the thread data
    if (IsWithinMainExec(retIp)) {
        threadData_t *threadData = static_cast<threadData_t *>(PIN_GetThreadData(tlsKey, threadid));
        threadData->sizeByPointer->insert({(ADDRINT)ptr, size});

        if (KnobDebugLogs.Value()) {
            if (ShouldWriteToFile()) {
                TraceFile << "Saved: <0x" << (ADDRINT)ptr << "," << size << "> on malloc map" << std::endl;
            }
        }

    }

    return ptr;
}

VOID* MallocWrapper2(CONTEXT* ctxt, AFUNPTR origMalloc, size_t size) {
    TraceFile << "MyMalloc: Allocating " << size << " bytes" << std::endl;
// Call the original malloc function
    VOID* result;
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_DEFAULT, origMalloc, NULL,
                               PIN_PARG(VOID*), &result,
                               PIN_PARG(size_t), size,
                               PIN_PARG_END());

    // Optional: Additional logic after malloc
    TraceFile << "MyMalloc: Returned pointer " << result << std::endl;
    return result;
}


/* ================================================================================= */
/* This is called every time a MODULE (dll, etc.) is LOADED                          */
/* ================================================================================= */
void ImageLoad_cb(IMG Img, void *v)
{
    std::string imageName = IMG_Name(Img);
    ADDRINT lowAddress = IMG_LowAddress(Img);
    ADDRINT highAddress = IMG_HighAddress(Img);
    // UINT32 numRegions = IMG_NumRegions(Img);

    /*
    for (SEC sec = IMG_SecHead(Img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            if (RTN_Name(rtn).find("malloc") != std::string::npos) {
                TraceFile << "In image " << imageName << " Found malloc-like: " << RTN_Name(rtn) << std::endl;
            }
             // Store image name so the C-string stays valid
            //g_ImageNames.emplace_back(IMG_Name(Img));
            //const char *imgNameCStr = g_ImageNames.back().c_str();

            const char *imgNameCStr = IMG_Name(Img).c_str();

            RTN_Open(rtn);

            // BEFORE malloc
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MallocBeforeLog,
                           IARG_THREAD_ID,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // malloc(size)
                           IARG_RETURN_IP,
                           IARG_PTR, imgNameCStr,
                           IARG_END);

            // AFTER malloc
            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfterLog,
                           IARG_THREAD_ID,
                           IARG_FUNCRET_EXITPOINT_VALUE, // return pointer
                           IARG_RETURN_IP,
                           IARG_PTR, imgNameCStr,
                           IARG_END);

            RTN_Close(rtn);
            //std::cout << "Found function: " << RTN_Name(rtn) << " in " << IMG_Name(Img) << std::endl;
        }
    }
*/


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

        //RTN_Close(mallocRtn);

        /*
        RTN_Open(mallocRtn);

        // Instrument malloc() to save the pointer and bytes asked by the thread
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                       IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE, IARG_RETURN_IP,
                       IARG_END);
        // RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
        //                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
        */
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

        if (KnobDebugLogs.Value()) {
            if (ShouldWriteToFile()) {
                TraceFile << "< main_begin, main_end >: " << main_begin << ", " << main_end << std::endl;
            }
        }
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
        if (ShouldWriteToFile() && KnobDebugLogs.Value()) {
            TraceFile << "[-] Loaded module: " << imageName << std::endl;
            if (filtered)
                TraceFile << "[!] Filtered " << imageName << std::endl;
            TraceFile << "[-] Module base: 0x" << std::hex << lowAddress << std::endl;
            TraceFile << "[-] Module end:  0x" << std::hex << highAddress << std::endl;
        }
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
    currentbbl = bigcounter;
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
    threadData_t *allocatedVariables = new threadData_t;
    if (PIN_SetThreadData(tlsKey, allocatedVariables, threadIndex) == FALSE)
    {
        std::cerr << "PIN_SetThreadData allocatedVariables failed" << std::endl;
        PIN_ExitProcess(1);
    }

    if (InfoType >= T)
        bigcounter++;
    InfoType = T;
    if (ShouldWriteToFile() && KnobDebugLogs.Value()) {
        TraceFile << "[T]" << std::setw(10) << std::dec << bigcounter << std::hex << " Thread 0x" << PIN_ThreadUid() << " started. Flags: 0x" << std::hex << flags << std::endl;
    }
    PIN_ReleaseLock(&_lock);
}

void ThreadFinish_cb(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    PIN_GetLock(&_lock, threadIndex + 1);
    if (ShouldWriteToFile() && KnobDebugLogs.Value()) {
        TraceFile << "[T]" << std::setw(10) << std::dec << bigcounter << std::hex << " Thread 0x" << PIN_ThreadUid() << " finished. Code: " << std::dec << code << std::endl;
    }
    // free data saved by thread
    threadData_t *tdata = static_cast<threadData_t *>(PIN_GetThreadData(tlsKey, threadIndex));
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
                
                bulkData << FormatTraceEntry(entry);
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

// Function to execute the command and read the output
std::string executeCommand(const std::string &command)
{
    // Open the process using popen
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

    if (!pipe)
    {
        return "";
    }

    // Read the output of the command
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }

    return result;
}

std::string sanitizeIdentifier(const std::string& input) {
    std::string result;
    
    // Process first character: must be letter or underscore
    if (!input.empty()) {
        if (std::isalpha(input[0]) || input[0] == '_') {
            result += input[0];
        }
    }
    
    // Process remaining characters: keep letters, digits, and underscores
    for (size_t i = 1; i < input.length(); ++i) {
        if (std::isalnum(input[i]) || input[i] == '_') {
            result += input[i];
        }
    }
    
    // If result is empty, return a default valid identifier
    if (result.empty()) {
        return "_";
    }
    
    return result;
}

bool isGnuCompiler(const std::string& producer) {
    return producer.find("GNU C") != std::string::npos;
}

std::string dwgrepGetLowPCHighPCAndOffsetCommand(const std::string& executable,
                                  const std::string& function_name,
                                  const std::string& variable_name) {

    std::string sanitized_f = sanitizeIdentifier(function_name);
    std::string sanitized_v = sanitizeIdentifier(variable_name);


    std::string command = "dwgrep " + executable + " -e '(\n|D|\n" +
                         "let F := D entry ?DW_TAG_subprogram (@DW_AT_name == \"" +
                         sanitized_f + "\"); \n" +
                         "let V := F child ?TAG_variable (@DW_AT_name == \"" +
                         sanitized_v + "\"); \n" +
                         "let Loc := V @DW_AT_location ?(elem label == DW_OP_fbreg) elem value;\n\n" +
                         "F @DW_AT_low_pc F @DW_AT_high_pc \"%d,%d,%( Loc %)\" \n)'";
    return command;
}

std::string dwgrepGetProducer(const std::string& executable) {


    std::string command = "dwgrep " + executable + " -e '(\n|D|\n" +
                         "let F := D entry ?DW_TAG_compile_unit; \n" +
                         "F @DW_AT_producer \"%s\" \n)'";
    return command;
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
        if (TraceFile.fail())
        {
            std::cerr << "[!] Something went wrong opening the log file..." << std::endl;
            return -1;
        }
        else
        {
            if (!KnobQuiet.Value())
            {
                std::cerr << "[*] Trace file " << TraceName << " opened for writing..." << std::endl
                          << std::endl;
            }
        }
    } else {
        if (!KnobQuiet.Value()) {
            std::cerr << "[*] Trace file not opened for writing..." << std::endl;
        }
    }

    variable_dwarf_id = KnobVariableDwarfDIE_ID.Value();
    function_dwarf_id = KnobFunctionDwarfDIE_ID.Value();
    variable_name = KnobVariableName.Value();
    function_name = KnobFunctionName.Value();

    // filter_by_dwarf = (function_dwarf_id > "0" && variable_dwarf_id > "0") || (function_name != "" && variable_name != "");
    //  TODO: make it so that you can either pass the string or the dwarf ids
    filter_by_dwarf = (function_dwarf_id > "0" && variable_dwarf_id > "0") || (function_name != "" && variable_name != "");
    if (filter_by_dwarf)
    {
#if !defined(TARGET_IA32E)
        std::cerr << "TARGET IA32e not defined and can't access register data (particularly RBP) for PIN CONTEXT" << std::endl;
        return 1;
#endif
        var_byte_size = KnobVarByteSize.Value();

        if (KnobDebugLogs.Value())
        {
            if (ShouldWriteToFile()) {
                TraceFile << "Using DWARF Function DIE ID: " << function_dwarf_id << std::endl;
                TraceFile << "Using DWARF Variable DIE ID: " << variable_dwarf_id;
                TraceFile << " with size " << std::dec << var_byte_size << std::endl;

                TraceFile << "Using Function name: " << function_name << std::endl;
                TraceFile << "Using Variable name: " << variable_name;
                TraceFile << " with size " << std::dec << var_byte_size << std::endl;
            }
        }

        //std::string command = "/home//Desktop/tesis/prueba/tool " + function_name + " " + variable_name + " " + std::string(argv[argc - 1]);
        std::string command = dwgrepGetLowPCHighPCAndOffsetCommand( std::string(argv[argc - 1]), function_name, variable_name);
        std::string lowpc_highpc_varoffset = executeCommand(command);

        if (lowpc_highpc_varoffset == "")
        {
            std::cerr << "ERR: failed getting data from debug section" << std::endl;
        }

        if (KnobDebugLogs.Value())
        {
            if (ShouldWriteToFile()) {
                TraceFile << "Command ran: " << command << std::endl;
                TraceFile << "Output from tool: " << lowpc_highpc_varoffset << std::endl;
            }
        }

        std::vector<std::string> debug_info = splitstring(lowpc_highpc_varoffset, ',');
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

        if (KnobDebugLogs.Value()) {
            if (ShouldWriteToFile()) {
                TraceFile << "Func offset: 0x" << std::hex << std::uppercase << func_offset << std::endl;
                TraceFile << "Var offset: 0x" << var_offset << " Var offset - ADDRINT(16): 0x" << var_offset - ADDRINT(16) << std::dec << std::endl;
            }
        }

        // Important to calculate CFA, for clang++ CFA = RBP, for g++ CFA = RBP + 16
        command = dwgrepGetProducer(std::string(argv[argc - 1]));
        std::string producer = executeCommand(command);
        isGnuCompiled = isGnuCompiler(producer);
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

    // TraceName = KnobOutputFile.Value();

    if (ShouldWriteToFile() && KnobDebugLogs.Value()) {
        TraceFile << "#" << std::endl;
        TraceFile << "# Instruction Trace Generated By Roswell TracerPin " GIT_DESC << std::endl;
        TraceFile << "#" << std::endl;
        TraceFile << "[*] Arguments:" << std::endl;
        for (int nArg = 0; nArg < argc; nArg++)
            TraceFile << "[*]" << std::setw(5) << nArg << ": " << argv[nArg] << std::endl;
        TraceFile.unsetf(std::ios::showbase);
    }

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