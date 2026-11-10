#include "DwarfQueries.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <memory>
#include <sstream>

namespace {

std::string SanitizeIdentifier(const std::string &input) {
  std::string result;

  if (!input.empty() && (std::isalpha(input[0]) || input[0] == '_')) {
    result += input[0];
  }

  for (size_t i = 1; i < input.length(); ++i) {
    if (std::isalnum(input[i]) || input[i] == '_') {
      result += input[i];
    }
  }

  return result.empty() ? "_" : result;
}

} // namespace

std::string ExecuteCommand(const std::string &command) {
  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"),
                                                pclose);

  if (!pipe) {
    return {};
  }

  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }

  return result;
}

std::vector<std::string> SplitString(const std::string &input, char delimiter) {
  std::istringstream stream(input);
  std::string token;
  std::vector<std::string> result;

  while (std::getline(stream, token, delimiter)) {
    result.push_back(token);
  }

  return result;
}

bool IsGnuCompiler(const std::string &producer) {
  return producer.find("GNU C") != std::string::npos;
}

std::string BuildDwgrepGlobalVariableQuery(const std::string &executable,
                                           const std::string &variableName) {
  const std::string variable = SanitizeIdentifier(variableName);
  return "dwgrep " + executable +
         " -e '(|D| let V := D entry ?DW_TAG_variable (@DW_AT_name == \"" +
         variable +
         "\");let Loc := V @DW_AT_location ?(elem label == DW_OP_addr) elem "
         "value;Loc \"%d\")'";
}

std::string BuildDwgrepLocalVariableQuery(const std::string &executable,
                                          const std::string &functionName,
                                          const std::string &variableName) {
  const std::string function = SanitizeIdentifier(functionName);
  const std::string variable = SanitizeIdentifier(variableName);

  return "dwgrep " + executable + " -e '(\n|D|\n" +
         "let F := D entry ?DW_TAG_subprogram (@DW_AT_name == \"" + function +
         "\"); \n" + "let V := F child ?TAG_variable (@DW_AT_name == \"" +
         variable + "\"); \n" +
         "let Loc := V @DW_AT_location ?(elem label == DW_OP_fbreg) elem "
         "value;\n\n" +
         "F @DW_AT_low_pc F @DW_AT_high_pc \"%d,%d,%( Loc %)\" \n)'";
}

std::string BuildDwgrepProducerQuery(const std::string &executable) {
  return "dwgrep " + executable + " -e '(\n|D|\n" +
         "let F := D entry ?DW_TAG_compile_unit; \n" +
         "F @DW_AT_producer \"%s\" \n)'";
}
