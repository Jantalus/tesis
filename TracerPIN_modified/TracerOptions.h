#ifndef TRACERPIN_OPTIONS_H
#define TRACERPIN_OPTIONS_H

#include "pin.H"

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o",
                                 "trace-full-info.txt",
                                 "specify trace file name");
KNOB<BOOL> KnobLogIns(KNOB_MODE_WRITEONCE, "pintool", "i", "0",
                      "log all instructions");
KNOB<BOOL> KnobLogMem(KNOB_MODE_WRITEONCE, "pintool", "m", "1",
                      "log all memory accesses");
KNOB<BOOL> KnobLogBB(KNOB_MODE_WRITEONCE, "pintool", "b", "0",
                     "log all basic blocks");
KNOB<BOOL> KnobLogCall(KNOB_MODE_WRITEONCE, "pintool", "c", "0",
                       "log all calls");
KNOB<BOOL> KnobLogCallArgs(KNOB_MODE_WRITEONCE, "pintool", "C", "0",
                           "log all calls with their first three args");
KNOB<std::string> KnobLogFilter(
    KNOB_MODE_WRITEONCE, "pintool", "f", "1",
    "(0) no filter (1) filter system libraries (2) filter all but main exec "
    "(0x400000-0x410000) trace only specified address range");
KNOB<std::string> KnobLogFilterLive(KNOB_MODE_WRITEONCE, "pintool", "F", "0",
                                    "(0) no live filter (0x400000:0x410000) "
                                    "use addresses as start:stop live filter");
KNOB<INT> KnobLogFilterLiveN(
    KNOB_MODE_WRITEONCE, "pintool", "n", "0",
    "which occurence to log, 0=all (only for -F start:stop filter)");
KNOB<BOOL> KnobQuiet(KNOB_MODE_WRITEONCE, "pintool", "q", "0",
                     "be quiet under normal conditions");
KNOB<std::string>
    KnobVariableName(KNOB_MODE_WRITEONCE, "pintool", "vname", "",
                     "Variable name, will be used to search the children nodes "
                     "of the function in the debug data. \n Default ('') means "
                     "no use of this filter. Use with -fname");
KNOB<UINT64>
    KnobVarByteSize(KNOB_MODE_WRITEONCE, "pintool", "vs", "0",
                    "Variable to trace size in Bytes. Use with -fname -vname, "
                    "the pressence of a value here assumes an static variable");
KNOB<std::string> KnobFunctionName(
    KNOB_MODE_WRITEONCE, "pintool", "fname", "",
    "Function  name, will be used to search in the debug data.\n Default ('') "
    "means no use of this filter. Use with -vname");
KNOB<BOOL>
    KnobDiscriminateThread(KNOB_MODE_WRITEONCE, "pintool", "td", "0",
                           "Discriminate which thread read/writes the variable "
                           "and who owns it.\n[Owner][Accessing]");
KNOB<BOOL> KnobExcludeAddressesOutsideMain(
    KNOB_MODE_WRITEONCE, "pintool", "excl", "1",
    "Exclude instructions to instrment outside main executable, ex: "
    "libc.\nThis can lead to lose of traces if the variable pointer is written "
    "outside the main image.");
KNOB<BOOL>
    KnobDebugLogs(KNOB_MODE_WRITEONCE, "pintool", "d", "0",
                  "Debug logs, not very useful unless you add your own.");
KNOB<BOOL>
    KnobEnableFileOutput(KNOB_MODE_WRITEONCE, "pintool", "file", "1",
                         "enable/disable file output (1=enable, 0=disable)");
KNOB<BOOL> KnobEnableRecursiveAllocTracking(
    KNOB_MODE_WRITEONCE, "pintool", "recursive", "1",
    "enable/disable recursive tracking of malloced pointers (1=enable, "
    "0=disable).\nThis means that when writing a malloced pointer to an "
    "already traced section of memory, it will be added to the regions of "
    "interest.");
KNOB<BOOL> KnobTrackInteriorPointers(
    KNOB_MODE_WRITEONCE, "pintool", "interior", "0",
    "enable/disable tracking pointers that point inside an active malloc "
    "allocation (1=enable, 0=disable)");
KNOB<UINT64>
    KnobInteriorPointerSize(KNOB_MODE_WRITEONCE, "pintool", "interior-size",
                            "0",
                            "logical size in bytes of an interior-pointer "
                            "region; 0 tracks the containing allocation");

#endif
