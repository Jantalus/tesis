#ifndef TRACERPIN_DWARF_QUERIES_H
#define TRACERPIN_DWARF_QUERIES_H

#include <string>
#include <vector>

std::string ExecuteCommand(const std::string &command);
std::vector<std::string> SplitString(const std::string &input, char delimiter);
bool IsGnuCompiler(const std::string &producer);

std::string BuildDwgrepGlobalVariableQuery(const std::string &executable,
                                           const std::string &variableName);
std::string BuildDwgrepLocalVariableQuery(const std::string &executable,
                                          const std::string &functionName,
                                          const std::string &variableName);
std::string BuildDwgrepProducerQuery(const std::string &executable);

#endif
