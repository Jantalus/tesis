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
#include "sqlite3.h"
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <array>     // for std::array

#ifndef GIT_DESC
#define GIT_DESC "(unknown version)"
#endif //GIT_DESC
// using namespace std;
/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;
std::stringstream value;
std::string strvalue;
PIN_LOCK _lock;
struct moduledata_t
{
    BOOL excluded;
    ADDRINT begin;
    ADDRINT end;
};

typedef std::map<std::string, moduledata_t> modmap_t;

std::string variable_dwarf_id;
UINT64 variable_size;
std::string function_dwarf_id;

modmap_t mod_data;
ADDRINT main_begin;
ADDRINT main_end;

// Extras
ADDRINT func_offset = 0;
ADDRINT var_offset = 0;
UINT64 var_byte_size = 0;
bool filter_by_dwarf = false;
// /////////////

bool main_reached=false;
INT64 logfilter=1;
bool logfilterlive=false;
ADDRINT filter_begin=0;
ADDRINT filter_end=0;
ADDRINT filter_live_start=0;
ADDRINT filter_live_stop=0;
INT32 filter_live_n=0;
INT32 filter_live_i=0;
bool filter_live_reached=false;
bool quiet=false;
long long bigcounter=0; // Ready for 4 billions of instructions
long long currentbbl=0;
enum InfoTypeType { T, C, B, R, I, W };
InfoTypeType InfoType=T;
std::string TraceName;
sqlite3 *db;
sqlite3_int64 bbl_id = 0, ins_id = 0;
sqlite3_stmt *info_insert, *bbl_insert, *call_insert, *lib_insert, *ins_insert, *mem_insert, *thread_insert, *thread_update;

enum LogTypeType { HUMAN, SQLITE };
static const char *SETUP_QUERY = 
"CREATE TABLE IF NOT EXISTS info (key TEXT PRIMARY KEY, value TEXT);\n"
"CREATE TABLE IF NOT EXISTS lib (name TEXT, base TEXT, end TEXT);\n"
"CREATE TABLE IF NOT EXISTS bbl (addr TEXT, addr_end TEXT, size INTEGER, thread_id INTEGER);\n"
"CREATE TABLE IF NOT EXISTS call (ins_id INTEGER, addr TEXT, name TEXT);\n"
"CREATE TABLE IF NOT EXISTS ins (bbl_id INTEGER, ip TEXT, dis TEXT, op TEXT);\n"
"CREATE TABLE IF NOT EXISTS mem (ins_id INTEGER, ip TEXT, type TEXT, addr TEXT, addr_end TEXT, size INTEGER, data TEXT, value TEXT);\n"
"CREATE TABLE IF NOT EXISTS thread (thread_id INTEGER, start_bbl_id INTEGER, exit_bbl_id INTEGER);\n";

LogTypeType LogType=HUMAN;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                            "o", "trace-full-info.txt", "specify trace file name");
KNOB<BOOL> KnobLogIns(KNOB_MODE_WRITEONCE, "pintool",
                      "i", "1", "log all instructions");
KNOB<BOOL> KnobLogMem(KNOB_MODE_WRITEONCE, "pintool",
                      "m", "1", "log all memory accesses");
KNOB<BOOL> KnobLogBB(KNOB_MODE_WRITEONCE, "pintool",
                     "b", "1", "log all basic blocks");
KNOB<BOOL> KnobLogCall(KNOB_MODE_WRITEONCE, "pintool",
                       "c", "1", "log all calls");
KNOB<BOOL> KnobLogCallArgs(KNOB_MODE_WRITEONCE, "pintool",
                           "C", "0", "log all calls with their first three args");
KNOB<std::string> KnobLogFilter(KNOB_MODE_WRITEONCE, "pintool",
                        "f", "1", "(0) no filter (1) filter system libraries (2) filter all but main exec (0x400000-0x410000) trace only specified address range");
KNOB<std::string> KnobLogFilterLive(KNOB_MODE_WRITEONCE, "pintool",
                        "F", "0", "(0) no live filter (0x400000:0x410000) use addresses as start:stop live filter");
KNOB<INT> KnobLogFilterLiveN(KNOB_MODE_WRITEONCE, "pintool",
                           "n", "0", "which occurence to log, 0=all (only for -F start:stop filter)");
KNOB<std::string> KnobLogType(KNOB_MODE_WRITEONCE, "pintool",
                         "t", "human", "log type: human/sqlite");
KNOB<BOOL> KnobQuiet(KNOB_MODE_WRITEONCE, "pintool",
                       "q", "0", "be quiet under normal conditions");
KNOB<std::string> KnobVariableDwarfDIE_ID(KNOB_MODE_WRITEONCE, "pintool",
                         "vdid", "0", "Variable DWARF DIE ID, obtained from de debug_info section. Recommended to use readelf -wi <executable> \n Default (0) means no use of this filter. Use with <PONER ACA SIZE IN BYTES Y FUNC OPT>");
KNOB<UINT64> KnobVarByteSize(KNOB_MODE_WRITEONCE, "pintool",
                       "vs", "0", "Variable to trace size in Bytes. Used with -vdid option");
KNOB<std::string> KnobFunctionDwarfDIE_ID(KNOB_MODE_WRITEONCE, "pintool",
                         "fdid", "0", "Function DWARF DIE ID, obtained from de debug_info section. Recommended to use readelf -wi <executable> \n Default (0) means no use of this filter. Use with <PONER ACA SIZE IN BYTES Y FUNC OPT>");

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

extern "C" int lstat(const char * path, struct stat * buf)
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
    std::cerr << "Result by default in trace-full-info.txt" << std::endl << std::endl;

    std::cerr << KNOB_BASE::StringKnobSummary();

    std::cerr << std::endl;

    return -1;
}

/* ===================================================================== */
/* Helper Functions                                                      */
/* ===================================================================== */

BOOL ExcludedAddress(ADDRINT ip)
{
    switch (logfilter)
    {
    case 1:
        if (! main_reached)
        {
	        // Filter loader before main
	        if ((ip < main_begin) || (ip > main_end))
	            return TRUE;
            else
                main_reached=true;
		}
        if ((ip >= main_begin) && (ip <= main_end))
            return FALSE;
        for(modmap_t::iterator it = mod_data.begin(); it != mod_data.end(); ++it)
        {
            if(it->second.excluded == FALSE) continue;
            /* Is the EIP value within the range of any excluded module? */
            if(ip >= it->second.begin && ip <= it->second.end) return TRUE;
        }
        break;
    case 2:
    {
        PIN_LockClient();
        IMG im = IMG_FindByAddress(ip);
        PIN_UnlockClient();
        if (! IMG_Valid(im) || ! IMG_IsMainExecutable(im))
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
    if (ip == filter_live_start) {
        filter_live_i++;
        if ((filter_live_n == 0) || (filter_live_i == filter_live_n)) filter_live_reached=true;
//        cerr << "BEGIN " << filter_live_i << " @" << hex << filter_live_start << dec << " -> " << filter_live_reached << std::endl;
    }
    if (ip == filter_live_stop) {
        filter_live_reached=false;
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
    if (InfoType >= I) bigcounter++;
    InfoType=I;
    PIN_SafeCopy(v, (void *)ip, size);
    switch (LogType) {
        case HUMAN:
            TraceFile << "[I]" << std::setw(10) << std::dec << bigcounter << std::hex << std::setw(16) << (void *)ip << "    " << std::setw(40) << std::left << *disass << std::right;
            TraceFile << std::setfill('0');
            for (INT32 i = 0; i < size; i++)
            {
                TraceFile << " " << std::setfill('0') << std::setw(2) << static_cast<UINT32>(v[i]);
            }
            TraceFile << std::setfill(' ');
            TraceFile << std::endl;
            break;
        case SQLITE:
            sqlite3_reset(ins_insert);
            sqlite3_bind_int64(ins_insert, 1, bbl_id);
            value.str("");
            value.clear();
            value << std::hex << "0x" << std::setfill('0') << std::setw(16) << ip;
            strvalue = value.str();
            sqlite3_bind_text(ins_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins_insert, 3, (*disass).c_str(), -1, SQLITE_TRANSIENT);
            value.str("");
            value.clear();
            value << std::setfill('0') << std::hex;
            for (INT32 i = 0; i < size; i++)
            {
                value << std::setw(2) << static_cast<UINT32>(v[i]);
            }
            strvalue = value.str();
            sqlite3_bind_text(ins_insert, 4, strvalue.c_str(), -1, SQLITE_TRANSIENT);
            if(sqlite3_step(ins_insert) != SQLITE_DONE)
                printf("INS error: %s\n", sqlite3_errmsg(db));
            ins_id = sqlite3_last_insert_rowid(db);
            break;
    }
// To get context, see https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__CONTEXT__API.html
    PIN_ReleaseLock(&_lock);
}

static VOID RecordMemHuman(ADDRINT ip, CHAR r, ADDRINT addr, UINT8* memdump, INT32 size, BOOL isPrefetch)
{
    TraceFile << "[" << r << "]" << std::setw(10) << std::dec << bigcounter << std::hex << std::setw(16) << (void *) ip << "                                                   "
              << " " << std::setw(18) << (void *) addr << " size="
              << std::dec << std::setw(2) << size << " value="
              << std::hex << std::setw(18-2*size);
    if (!isPrefetch)
    {
        switch(size)
        {
        case 0:
            TraceFile << std::setw(1);
            break;

        case 1:
            TraceFile << "0x" << std::setfill('0') << std::setw(2);
            TraceFile << static_cast<UINT32>(*memdump);
            TraceFile << std::setfill(' ');
            break;

        case 2:
            TraceFile << "0x" << std::setfill('0') << std::setw(4);
            TraceFile << *(UINT16*)memdump;
            break;

        case 4:
            TraceFile << "0x" << std::setfill('0') << std::setw(8);
            TraceFile << *(UINT32*)memdump;
            break;

        case 8:
            TraceFile << "0x" << std::setfill('0') << std::setw(16);
            TraceFile << *(UINT64*)memdump;
            break;

        default:
            for (INT32 i = 0; i < size; i++)
            {
                TraceFile << " " << std::setfill('0') << std::setw(2) << static_cast<UINT32>(memdump[i]);
            }
            break;
        }
    }
    TraceFile << std::setfill(' ') << std::endl;
}

static VOID RecordMemSqlite(ADDRINT ip, CHAR r, ADDRINT addr, UINT8* memdump, INT32 size, BOOL isPrefetch)
{
    // Insert read or write
    sqlite3_reset(mem_insert);
    sqlite3_bind_int64(mem_insert, 1, r == 'R' ? (ins_id+1) : ins_id );
    value.str("");
    value.clear();
    value << std::hex << "0x" << std::setfill('0') << std::setw(16) << ip;
    strvalue = value.str();
    sqlite3_bind_text(mem_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
    char mode[2] = {0,0};
    mode[0]=r;
    sqlite3_bind_text(mem_insert, 3, mode, -1, SQLITE_TRANSIENT);
    value.str("");
    value.clear();
    value << std::hex << "0x" << std::setfill('0') << std::setw(16) << addr;
    strvalue = value.str();
    sqlite3_bind_text(mem_insert, 4, strvalue.c_str(), -1, SQLITE_TRANSIENT);
    value.str("");
    value.clear();
    value << std::hex << "0x" << std::setfill('0') << std::setw(16) << addr;
    strvalue = value.str();
    sqlite3_bind_text(mem_insert, 5, strvalue.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(mem_insert, 6, size);
    if (!isPrefetch)
    {
        value.str("");
        value.clear();
        value << std::hex << std::setfill('0');
        for (INT32 i = 0; i < size; i++)
        {
            value << std::setw(2) << static_cast<UINT32>(memdump[i]);
        }
        strvalue = value.str();
        sqlite3_bind_text(mem_insert, 7, strvalue.c_str(), -1, SQLITE_TRANSIENT);
        value.str("");
        value.clear();
        value << std::hex  << "0x" << std::setfill('0');
        switch(size)
        {
        case 0:
            break;
        case 1:
            value << std::setw(2) << static_cast<UINT32>(*memdump);
            break;
        case 2:
            value << std::setw(4) << *(UINT16*)memdump;
            break;
        case 4:
            value << std::setw(8) << *(UINT32*)memdump;
            break;
        case 8:
            value << std::setw(16) << *(UINT64*)memdump;
            break;
        default:
            break;
        }
        strvalue = value.str();
        sqlite3_bind_text(mem_insert, 8, strvalue.c_str(), -1, SQLITE_TRANSIENT);
        if(sqlite3_step(mem_insert) != SQLITE_DONE)
            printf("MEM error: %s\n", sqlite3_errmsg(db));
    }
}

static VOID RecordMem(ADDRINT ip, CHAR r, ADDRINT addr, INT32 size, BOOL isPrefetch)
{
    UINT8 memdump[256];
    // test on logfilterlive here to avoid calls when not using live filtering
    if (logfilterlive && ExcludedAddressLive(ip))
        return;
    PIN_GetLock(&_lock, ip);
    if ((size_t)size > sizeof(memdump))
    {
        std::cerr << "[!] Memory size > " << sizeof(memdump) << " at " << std::dec << bigcounter << std::hex << (void *)ip << " " << (void *)addr << std::endl;
        PIN_ReleaseLock(&_lock);
        return;
    }
    PIN_SafeCopy(memdump, (void *)addr, size);
    switch (r) {
        case 'R':
            if (InfoType >= R) bigcounter++;
            InfoType=R;
            break;
        case 'W':
            if (InfoType >= W) bigcounter++;
            InfoType=W;
            break;
    }
    switch (LogType) {
        case HUMAN:
            RecordMemHuman(ip, r, addr, memdump, size, isPrefetch);
            break;
        case SQLITE:
            RecordMemSqlite(ip, r, addr, memdump, size, isPrefetch);
            break;
    }
    PIN_ReleaseLock(&_lock);
}

static ADDRINT WriteAddr;
static INT32 WriteSize;

static VOID RecordWriteAddrSize(ADDRINT addr, INT32 size)
{
    WriteAddr = addr;
    WriteSize = size;
}


static VOID RecordMemWrite(ADDRINT ip)
{
    RecordMem(ip, 'W', WriteAddr, WriteSize, false);
}

/* ================================================================================= */
/* This is called for each instruction                                               */
/* ================================================================================= */
VOID Instruction_cb(INS ins, VOID *v)
{
    ADDRINT ceip = INS_Address(ins);
    if(ExcludedAddress(ceip))
        return;

    if (KnobLogMem.Value()) {

        if (INS_IsMemoryRead(ins))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_BOOL, INS_IsPrefetch(ins),
                IARG_END);
        }

        if (INS_HasMemoryRead2(ins))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_BOOL, INS_IsPrefetch(ins),
                IARG_END);
        }

        // instruments stores using a predicated call, i.e.
        // the call happens iff the store will be actually executed
        if (INS_IsMemoryWrite(ins))
        {
            // Callback a mi func?
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_END);

            if (INS_HasFallThrough(ins))
            {
                INS_InsertCall(
                    ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite,
                    IARG_INST_PTR,
                    IARG_END);
            }
            if (INS_IsControlFlow(ins))
            {
                INS_InsertCall(
                    ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite,
                    IARG_INST_PTR,
                    IARG_END);
            }

        }
    }
    if (KnobLogIns.Value()) {
        std::string* disass = new std::string(INS_Disassemble(ins));
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)printInst,
            IARG_INST_PTR,
            IARG_PTR, disass,
            IARG_UINT32, INS_Size(ins),
            IARG_END);
    }
}


/* ================================================================================= */
/* This is called every time a MODULE (dll, etc.) is LOADED                          */
/* ================================================================================= */
void ImageLoad_cb(IMG Img, void *v)
{
    std::string imageName = IMG_Name(Img);
    ADDRINT lowAddress = IMG_LowAddress(Img);
    ADDRINT highAddress = IMG_HighAddress(Img);
    UINT32 numRegions = IMG_NumRegions(Img);

    bool filtered = false;
    PIN_GetLock(&_lock, 0);
    if(IMG_IsMainExecutable(Img))
    {
        switch (LogType) {
            case HUMAN:

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
                if (logfilter==2)
                {
                    TraceFile << "[!] Filter all addresses out of that range" << std::endl;
                }
                break;
            case SQLITE:
                sqlite3_reset(lib_insert);
                sqlite3_bind_text(lib_insert, 1, imageName.c_str(), -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                value << std::hex << "0x" << std::setfill('0') << std::setw(16) << lowAddress;
                strvalue = value.str();
                sqlite3_bind_text(lib_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                value << std::hex << "0x" << std::setfill('0') << std::setw(16) << highAddress;
                strvalue = value.str();
                sqlite3_bind_text(lib_insert, 3, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                if(sqlite3_step(lib_insert) != SQLITE_DONE)
                    printf("LIB error: %s\n", sqlite3_errmsg(db));
                break;
        }
        main_begin = lowAddress;
        main_end = highAddress;
    } else {
        if((logfilter == 1) &&
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
        switch (LogType) {
            case HUMAN:
                TraceFile << "[-] Loaded module: " << imageName << std::endl;
                if (filtered)
                    TraceFile << "[!] Filtered " << imageName << std::endl;
                TraceFile << "[-] Module base: 0x" << std::hex << lowAddress  << std::endl;
                TraceFile << "[-] Module end:  0x" << std::hex << highAddress << std::endl;
                break;
            case SQLITE:
                sqlite3_reset(lib_insert);
                sqlite3_bind_text(lib_insert, 1, imageName.c_str(), -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                value << std::hex << "0x" << std::setfill('0') << std::setw(16) << lowAddress;
                strvalue = value.str();
                sqlite3_bind_text(lib_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                value << std::hex << "0x" << std::setfill('0') << std::setw(16) << highAddress;
                strvalue = value.str();
                sqlite3_bind_text(lib_insert, 3, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                if(sqlite3_step(lib_insert) != SQLITE_DONE)
                    printf("LIB error: %s\n", sqlite3_errmsg(db));
                break;
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
    if (InfoType >= B) bigcounter++;
    InfoType=B;
    currentbbl=bigcounter;
    switch (LogType) {
        case HUMAN:
                TraceFile << "[B]" << std::setw(10) << std::dec << bigcounter << std::hex << std::setw(16) << (void *) addr << " loc_" << std::hex << addr << ":";
                TraceFile << " // size=" << std::dec << size;
                TraceFile << " thread=" << "0x" << std::hex << PIN_ThreadUid() << std::endl;
                break;
            case SQLITE:
                sqlite3_reset(bbl_insert);
                value.str("");
                value.clear();
                value << "0x" << std::hex << std::setfill('0') << std::setw(16) << addr;
                strvalue = value.str();
                sqlite3_bind_text(bbl_insert, 1, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                value << std::hex << "0x" << std::setfill('0') << std::setw(16) << addr + size - 1;
                strvalue = value.str();
                sqlite3_bind_text(bbl_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(bbl_insert, 3, size);
                sqlite3_bind_int64(bbl_insert, 4, PIN_ThreadUid());
                if(sqlite3_step(bbl_insert) != SQLITE_DONE)
                    printf("BBL error: %s\n", sqlite3_errmsg(db));
                bbl_id = sqlite3_last_insert_rowid(db);
                break;
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
        if (KnobLogCallArgs.Value()) {
            nameArg0 = RTN_FindNameByAddress(arg0);
            nameArg1 = RTN_FindNameByAddress(arg1);
            nameArg2 = RTN_FindNameByAddress(arg2);
        }

        PIN_GetLock(&_lock, ip);
        if (InfoType >= C) bigcounter++;
        InfoType=C;
        switch (LogType) {
            case HUMAN:
                TraceFile << "[C]" << std::setw(10) << std::dec << bigcounter << std::hex << " Calling function 0x" << ip << "(" << nameFunc << ")";
                if (KnobLogCallArgs.Value()) {
                    TraceFile << " with args: ("
                            << (void *) arg0 << " (" << nameArg0 << " ), "
                            << (void *) arg1 << " (" << nameArg1 << " ), "
                            << (void *) arg2 << " (" << nameArg2 << " )";
                }
                TraceFile << std::endl;
                if (ExcludedAddress(ip))
                {
                    TraceFile << "[!] Function 0x" << ip << " is filtered, no tracing" << std::endl;
                }
                break;
            case SQLITE:
                value.str("");
                value.clear();
                value << "0x" << std::hex << std::setfill('0') << std::setw(16) << ip;
                strvalue = value.str();
                sqlite3_bind_text(call_insert, 1, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(call_insert, 2, nameFunc.c_str(), -1, SQLITE_TRANSIENT);
                if(sqlite3_step(call_insert) != SQLITE_DONE)
                    printf("CALL error: %s\n", sqlite3_errmsg(db));
                break;
        }
        PIN_ReleaseLock(&_lock);
    }

    void LogIndirectCallAndArgs(ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
    {
        if (!taken)
            return;
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
        for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
            INS head = BBL_InsHead(bbl);
            if(ExcludedAddress(INS_Address(head)))
                return;
            /* Instrument function calls? */
            if(KnobLogCall.Value() || KnobLogCallArgs.Value())
            {
                /* ===================================================================================== */
                /* Code to instrument the events at the end of a BBL (execution transfer)                */
                /* Checking for calls, etc.                                                              */
                /* ===================================================================================== */
                INS tail = BBL_InsTail(bbl);

                if(INS_IsCall(tail))
                {
                    if(INS_IsDirectControlFlow(tail))
                    {
                        const ADDRINT target = INS_DirectControlFlowTargetAddress(tail);

                        INS_InsertPredicatedCall(
                            tail,
                            IPOINT_BEFORE,
                            AFUNPTR(LogCallAndArgs),            // Function to jump to
                            IARG_ADDRINT,                       // "target"'s type
                            target,                             // Who is called?
                            IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_0 value
                            0,
                            IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_1 value
                            1,
                            IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_2 value
                            2,
                            IARG_END
                        );
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
                            IARG_END
                        );
                    }
                }
                else
                {
                    /* Other forms of execution transfer */
                    RTN rtn = TRACE_Rtn(trace);
                    // Trace jmp into DLLs (.idata section that is, imports)
                    if(RTN_Valid(rtn) && SEC_Name(RTN_Sec(rtn)) == ".idata")
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
                            IARG_END
                        );
                    }
                }
            }
            /* Instrument at basic block level? */
            if(KnobLogBB.Value())
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
        if (InfoType >= T) bigcounter++;
        InfoType=T;
        switch (LogType) {
            case HUMAN:
                TraceFile << "[T]" << std::setw(10) << std::dec << bigcounter << std::hex << " Thread 0x" << PIN_ThreadUid() << " started. Flags: 0x" << std::hex << flags << std::endl;
                break;
            case SQLITE:
                sqlite3_reset(thread_insert);
                sqlite3_bind_int64(thread_insert, 1, PIN_ThreadUid());
                sqlite3_bind_int64(thread_insert, 2, currentbbl);
                if(sqlite3_step(thread_insert) != SQLITE_DONE)
                    printf("THREAD error: %s\n", sqlite3_errmsg(db));
                break;
        }
        PIN_ReleaseLock(&_lock);
    }


    void ThreadFinish_cb(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
    {
        PIN_GetLock(&_lock, threadIndex + 1);
        switch (LogType) {
            case HUMAN:
                TraceFile << "[T]" << std::setw(10) << std::dec << bigcounter << std::hex << " Thread 0x" << PIN_ThreadUid() << " finished. Code: " << std::dec << code << std::endl;
                break;
            case SQLITE:
                sqlite3_reset(thread_update);
                sqlite3_bind_int64(thread_update, 1, currentbbl);
                sqlite3_bind_int64(thread_update, 2, PIN_ThreadUid());
                if(sqlite3_step(thread_update) != SQLITE_DONE)
                    printf("THREAD error: %s\n", sqlite3_errmsg(db));
                break;
        }
        PIN_ReleaseLock(&_lock);
    }

    /* ===================================================================== */
    /* Fini                                                                  */
    /* ===================================================================== */

    VOID Fini(INT32 code, VOID *v)
    {
        switch (LogType) {
            case HUMAN:
                TraceFile.close();
                break;
            case SQLITE:
                sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
                sqlite3_finalize(info_insert);
                sqlite3_finalize(lib_insert);
                sqlite3_finalize(bbl_insert);
                sqlite3_finalize(ins_insert);
                sqlite3_finalize(mem_insert);
                sqlite3_finalize(call_insert);
                sqlite3_finalize(thread_insert);
                sqlite3_finalize(thread_update);
                if(sqlite3_close(db) != SQLITE_OK)
                {
                    std::cerr << "Failed to close db (wut?): " << sqlite3_errmsg(db) << std::endl;
                }
                break;
        }
    }

// Function to execute the command and read the output
    std::string executeCommand(const std::string &command) {
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

    /* ===================================================================== */
    /* Main                                                                  */
    /* ===================================================================== */

    int  main(int argc, char *argv[])
    {
        PIN_InitSymbols();

        if( PIN_Init(argc,argv) )
        {
            return Usage();
        }

        TraceName = KnobOutputFile.Value();

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

        // TODO: Agregar chequeos de tipos, que sea un numero pelado
        
        std::string var_dwarf_die_id = KnobVariableDwarfDIE_ID.Value();
        std::string func_dwarf_die_id = KnobFunctionDwarfDIE_ID.Value();

        std::string dwarf_txt =  "/home/mgiampaolo/Desktop/tesis/readelf_vector_wi.txt";
        filter_by_dwarf = var_dwarf_die_id > "0" && func_dwarf_die_id > "0";
        if (filter_by_dwarf) {
            var_byte_size = KnobVarByteSize.Value();

            TraceFile << "Using DWARF Function DIE ID: " << func_dwarf_die_id << std::endl;
            TraceFile << "Using DWARF Variable DIE ID: " << var_dwarf_die_id;
            TraceFile << " with size " << std::dec << var_byte_size << std::endl;

            std::string command = "/home/mgiampaolo/Desktop/tesis/prueba/tool fbreg " + var_dwarf_die_id + " " + dwarf_txt;
            std::string fbreg_offset = executeCommand(command);
            if (fbreg_offset == "") {
                std::cerr << "ERR: failed getting fbreg offset" << std::endl;
            }

            command = "/home/mgiampaolo/Desktop/tesis/prueba/tool lowpc " + func_dwarf_die_id +  + " " + dwarf_txt;
            std::string lowpc_addr = executeCommand(command);
            if (lowpc_addr == "") {
                std::cerr << "ERR: failed getting lowpc address" << std::endl;
            }


            TraceFile << "FBREG OFFSET: " << fbreg_offset << std::endl;
            TraceFile << "LOWPC addr: " << lowpc_addr << std::endl;
            // TODO: Catch errores??
            try {
                func_offset = std::stoi(lowpc_addr);
            }
            catch (std::exception &err) {
                std::cerr << "Dwarf ID of function to find should be a number" << std::endl;
                return 1; // Exit with an error code
            }

            try {
                var_offset = std::stoi(fbreg_offset);
            }
            catch (std::exception &err) {
                std::cerr << "Dwarf ID of variable to find should be a number" << std::endl;
                return 1; // Exit with an error code
            }
        }



        char *endptr;
        const char *tmpfilter = KnobLogFilter.Value().c_str();
        logfilter=strtoull(tmpfilter, &endptr, 16);
        if (endptr == tmpfilter) {
            std::cerr << "ERR: Failed parsing option -f" <<std::endl;
            return 1;
        }
        if ((endptr[0] == '\0') && (logfilter > 2)) {
            std::cerr << "ERR: Failed parsing option -f" <<std::endl;
            return 1;
        }
        if (logfilter > 2) {
            filter_begin=logfilter;
            logfilter = 3;
            char *endptr2;
            if (endptr[0] != '-') {
                std::cerr << "ERR: Failed parsing option -f" <<std::endl;
                return 1;
            }
            filter_end=strtoull(endptr+1, &endptr2, 16);
            if (endptr2 == endptr+1) {
                std::cerr << "ERR: Failed parsing option -f" <<std::endl;
                return 1;
            }
            if (endptr2[0] != '\0') {
                std::cerr << "ERR: Failed parsing option -f" <<std::endl;
                return 1;
            }
            if (filter_end <= filter_begin) {
                std::cerr << "ERR: Failed parsing option -f" <<std::endl;
                return 1;
            }
        }

        const char *tmpfilterlive = KnobLogFilterLive.Value().c_str();
        INT64 tmpval=strtoull(tmpfilterlive, &endptr, 16);
        if (tmpval != 0) logfilterlive=true;
        if (endptr == tmpfilterlive) {
            std::cerr << "ERR: Failed parsing option -F" <<std::endl;
            return 1;
        }
        if ((endptr[0] == '\0') && (logfilterlive)) {
            std::cerr << "ERR: Failed parsing option -F" <<std::endl;
            return 1;
        }
        if (tmpval > 0) {
            filter_live_start=tmpval;
            char *endptr2;
            if (endptr[0] != ':') {
                std::cerr << "ERR: Failed parsing option -F" <<std::endl;
                return 1;
            }
            filter_live_stop=strtoull(endptr+1, &endptr2, 16);
            if (endptr2 == endptr+1) {
                std::cerr << "ERR: Failed parsing option -F" <<std::endl;
                return 1;
            }
            if (endptr2[0] != '\0') {
                std::cerr << "ERR: Failed parsing option -F" <<std::endl;
                return 1;
            }
        }
        filter_live_n = KnobLogFilterLiveN.Value();

        // TraceName = KnobOutputFile.Value();

        if (KnobLogType.Value().compare("human") == 0)
        {
            LogType = HUMAN;
        }
        else if (KnobLogType.Value().compare("sqlite") == 0)
        {
            LogType = SQLITE;
            if (TraceName.compare("trace-full-info.txt") == 0)
                TraceName = "trace-full-info.sqlite";
        }
        switch (LogType) {
            case HUMAN:
                //TraceFile.open(TraceName.c_str());
                //if(TraceFile.fail())
                //{
                //    cerr << "[!] Something went wrong opening the log file..." << std::endl;
                //    return -1;
                //} else {
                //    if (! KnobQuiet.Value()) {
                //        cerr << "[*] Trace file " << TraceName << " opened for writing..." << std::endl << std::endl;
                //    }
                //}
                break;
            case SQLITE:
                remove(TraceName.c_str());
                if(sqlite3_open(TraceName.c_str(), &db) != SQLITE_OK)
                {
                    std::cerr << "Could not open database " << TraceName << ":" << sqlite3_errmsg(db) << std::endl;
                    return -1;
                }
                if(sqlite3_exec(db, SETUP_QUERY, NULL, NULL, NULL) != SQLITE_OK)
                {
                    std::cerr << "Could not setup database " << TraceName << ":" << sqlite3_errmsg(db) << std::endl;
                    return -1;
                }
                if (! KnobQuiet.Value()) {
                    std::cerr << "[*] Trace file " << TraceName << " opened for writing..." << std::endl << std::endl;
                }
                sqlite3_prepare_v2(db, "INSERT INTO info (key, value) VALUES (?, ?);", -1, &info_insert, NULL);
                sqlite3_prepare_v2(db, "INSERT INTO lib (name, base, end) VALUES (?, ?, ?);", -1, &lib_insert, NULL);
                sqlite3_prepare_v2(db, "INSERT INTO bbl (addr, addr_end, size, thread_id) VALUES (?, ?, ?, ?);", -1, &bbl_insert, NULL);
                sqlite3_prepare_v2(db, "INSERT INTO call (addr, name) VALUES (?, ?);", -1, &call_insert, NULL);
                sqlite3_prepare_v2(db, "INSERT INTO ins (bbl_id, ip, dis, op) VALUES (?, ?, ?, ?);", -1, &ins_insert, NULL);
                sqlite3_prepare_v2(db, "INSERT INTO mem (ins_id, ip, type, addr, addr_end, size, data, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", -1, &mem_insert, NULL);
                sqlite3_prepare_v2(db, "INSERT INTO thread (thread_id, start_bbl_id) VALUES (?, ?);", -1, &thread_insert, NULL);
                sqlite3_prepare_v2(db, "UPDATE thread SET exit_bbl_id=? WHERE thread_id=?;", -1, &thread_update, NULL);

                sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);

                break;
        }

        switch (LogType) {
            case HUMAN:
                TraceFile << "#" << std::endl;
                TraceFile << "# Instruction Trace Generated By Roswell TracerPin " GIT_DESC << std::endl;
                TraceFile << "#" << std::endl;
                TraceFile << "[*] Arguments:" << std::endl;
                for (int nArg=0; nArg < argc; nArg++)
                    TraceFile << "[*]" << std::setw(5) << nArg << ": " << argv[nArg] << std::endl;
                TraceFile.unsetf(std::ios::showbase);
                break;
            case SQLITE:
                sqlite3_reset(info_insert);
                sqlite3_bind_text(info_insert, 1, "TRACERPIN_VERSION", -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                value << GIT_DESC << " / PIN " << PIN_PRODUCT_VERSION_MAJOR << "." << PIN_PRODUCT_VERSION_MINOR << " build " << PIN_BUILD_NUMBER;
                strvalue = value.str();
                sqlite3_bind_text(info_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                if(sqlite3_step(info_insert) != SQLITE_DONE)
                    printf("INFO error: %s\n", sqlite3_errmsg(db));

                sqlite3_reset(info_insert);
                sqlite3_bind_text(info_insert, 1, "PINPROGRAM", -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                int nArg=0;
                for (; (nArg < argc) && std::string(argv[nArg]) != "--"; nArg++) {
                    if (nArg>0) value << " ";
                    value << argv[nArg];
                }
                strvalue = value.str();
                sqlite3_bind_text(info_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                if(sqlite3_step(info_insert) != SQLITE_DONE)
                    printf("INFO error: %s\n", sqlite3_errmsg(db));

                if (++nArg < argc) {
                    sqlite3_reset(info_insert);
                    sqlite3_bind_text(info_insert, 1, "PROGRAM", -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(info_insert, 2, argv[nArg++], -1, SQLITE_TRANSIENT);
                    if(sqlite3_step(info_insert) != SQLITE_DONE)
                        printf("INFO error: %s\n", sqlite3_errmsg(db));
                }

                sqlite3_reset(info_insert);
                sqlite3_bind_text(info_insert, 1, "ARGS", -1, SQLITE_TRANSIENT);
                value.str("");
                value.clear();
                int nArg_start=nArg;
                for (; (nArg < argc); nArg++) {
                    if (nArg>nArg_start) value << " ";
                    value << argv[nArg];
                }
                strvalue = value.str();
                sqlite3_bind_text(info_insert, 2, strvalue.c_str(), -1, SQLITE_TRANSIENT);
                if(sqlite3_step(info_insert) != SQLITE_DONE)
                printf("INFO error: %s\n", sqlite3_errmsg(db));
            break;
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