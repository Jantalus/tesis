#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <array>
#include <cstdio>
#include <cstring>
#include <cstdlib> // For std::stoll
#include <cinttypes> // For printing int64_t

std::string tmpTxtDwarfFilePath = ""; // At first nothing

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

int64_t get_fbreg_value(std::string id_to_find) {
    std::ifstream file(tmpTxtDwarfFilePath);
    if (!file.is_open()) {
        std::cerr << "Error opening file with path: '" << tmpTxtDwarfFilePath << "'" << std::endl;
        throw std::runtime_error("error opening file");
    }

    std::string line;
    bool found = false;
    std::regex fbreg_pattern(R"(.*DW_OP_fbreg:\s*(-?\d+).*)"); // Regex to match DW_OP_fbreg value
    int64_t fbreg_value = -1;

    // Read the file line by line
    while (std::getline(file, line)) {
        // Check if this line contains the ID we're looking for
        if (line.find("<" + id_to_find + ">") != std::string::npos) {
            found = true;
        }

        // If the ID was found, look for the DW_AT_location field and the DW_OP_fbreg value
        if (found && line.find("DW_AT_location") != std::string::npos) {
            // Check if the line contains the DW_OP_fbreg operator
            std::smatch match;
            if (std::regex_match(line, match, fbreg_pattern)) {
                fbreg_value = std::stoll(match[1]);
                // std::cout << "DW_OP_fbreg value for ID " << id_to_find << ": " << fbreg_value << std::endl;
                break; // Exit after finding the value
            } else {
                throw std::runtime_error("fbreg offset value not found");
            }
        }
    }

    if (!found) {
        std::cerr << "ID " << id_to_find << " not found in the file." << std::endl;
    }

    file.close();

    return fbreg_value;
}

std::string get_dwarf_id(const std::string& name_to_find, int lines_above) {
    std::ifstream file(tmpTxtDwarfFilePath);
    if (!file.is_open()) {
        std::cerr << "Error opening file with path: '" << tmpTxtDwarfFilePath << "'" << std::endl;
        throw std::runtime_error("error opening file");
    }

    std::string line;
    bool found = false;
    std::regex name_pattern(R"(.*DW_AT_name.*:\s)" + name_to_find + R"(\b.*)");
    //(R"(.*DW_OP_fbreg:\s*(-?\d+).*)"); // Regex to match DW_OP_fbreg value
    std::regex id_pattern(R"(.*<[0-9a-f]+><([0-9a-f]+)>:.*)");
    std::deque<std::string> line_buffer; // Stores recent lines to look back
    std::string dwarf_id;

    // Read the file line by line
    while (std::getline(file, line)) {
        // Maintain a buffer of size lines_above + 1
        line_buffer.push_back(line);
        if (static_cast<int>(line_buffer.size()) > lines_above + 1) {
            line_buffer.pop_front();
        }

        // Check if this line contains the DW_AT_name we're looking for
        if (std::regex_match(line, name_pattern)) {
            found = true;
            // Check if we have enough lines in the buffer
            if (static_cast<int>(line_buffer.size()) >= lines_above) {
                // Get the line that is 'lines_above' lines before the current one
                std::string target_line = line_buffer[0];
                std::smatch match;
                if (std::regex_match(target_line, match, id_pattern)) {
                    dwarf_id = match[1];
                    break; // Exit after finding the ID
                } else {
                    throw std::runtime_error("ID not found in the expected line above DW_AT_name");
                }
            } else {
                throw std::runtime_error("Not enough lines above DW_AT_name to find ID");
            }
        }
    }

    file.close();

    if (!found) {
        std::cerr << "Name '" << name_to_find << "' not found in the file." << std::endl;
        throw std::runtime_error("name not found");
    }

    return dwarf_id;
}

std::tuple<int64_t,int64_t>  get_func_high_and_low_pc(std::string id_to_find) {
    std::ifstream file(tmpTxtDwarfFilePath);
    if (!file.is_open()) {
        std::cerr << "Error opening file with path: '" << tmpTxtDwarfFilePath << "'" << std::endl;
        return std::make_tuple(1,1);
    }

    std::string line;
    bool found = false;
    // "$"
    std::regex lowpc_regex(R"(.*DW_AT_low_pc\s*:\s*0x([A-Fa-f0-9]+).*)"); // Regex to match X_pc_value (ex: 0x12fe)
    std::regex highpc_regex(R"(.*DW_AT_high_pc\s*:\s*0x([A-Fa-f0-9]+).*)");
    int64_t lowpc_value = -1;
    int64_t highpc_value = -1;

    // Read the file line by line
    while (std::getline(file, line)) {
        // Check if this line contains the ID we're looking for
        if (line.find("<" + id_to_find + ">") != std::string::npos) {
            found = true;
        }

        // If the ID was found, look for the DW_AT_location field and the DW_OP_fbreg value
        if (found) {
            if (line.find("DW_AT_low_pc") != std::string::npos) {
                std::smatch match;
                if (std::regex_match(line, match, lowpc_regex)) {
                    lowpc_value = std::stoll(match[1], nullptr, 16);
                    // std::cout << "HEX lowpc value for ID " << id_to_find << ": " << lowpc_value << std::endl;
                }
                else {
                    throw std::runtime_error("func low PC value not found");
                }
            }
            if (line.find("DW_AT_high_pc") != std::string::npos) {
                std::smatch match;
                if (std::regex_match(line, match, highpc_regex)) {
                    highpc_value = std::stoll(match[1], nullptr, 16);
                    // std::cout << "HEX lowpc value for ID " << id_to_find << ": " << lowpc_value << std::endl;
                }
                else {
                    throw std::runtime_error("func high PC value not found");
                }
            }
            if (lowpc_value != -1 && highpc_value != -1) {
                break; // Optional: Stop searching once both values are found
            }
        }
    }

    if (!found) {
        std::cerr << "ID " << id_to_find << " not found in the file." << std::endl;
    }

    file.close();

    return std::make_tuple(lowpc_value, highpc_value);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <function name> <variable name> <path_to_executable>" << std::endl;
        std::cerr << "Output: f_lowpc,f_highpc,x_offset" << std::endl;
        return 1; // Exit with an error code
    }
    try {
        // create tmp file, save the path
        tmpTxtDwarfFilePath = executeCommand("mktemp -t dwarf_data_XXXX.txt");
        // output contains \n at the end
        tmpTxtDwarfFilePath.erase(tmpTxtDwarfFilePath.length()-1, 2);
        // write the dwarf info into that file
        executeCommand("readelf -wi " + std::string(argv[argc-1]) + " > " + tmpTxtDwarfFilePath);

        // read the offset and f low/high pc
        std::string function_dwarf_id = get_dwarf_id(argv[1], 2);
        std::string var_dwarf_id = get_dwarf_id(argv[2], 1);

        std::tuple<int64_t,int64_t> highAndLowPc = get_func_high_and_low_pc(function_dwarf_id);
        int64_t x_offset = get_fbreg_value(var_dwarf_id);

        // delete tmp file
        if (std::remove(tmpTxtDwarfFilePath.c_str()) != 0) {
            std::cerr << "Error deleting temp file: " << std::strerror(errno) << std::endl;
        }
        /*
        else {
            std::cout << "Temporary file " << tmpTxtDwarfFilePath << " deleted successfully" << std::endl;
        }
        */

        std::cout << std::get<0>(highAndLowPc) << "," << std::get<1>(highAndLowPc) << "," << x_offset << std::endl;
    }
    catch (const std::exception &err) {
        std::cerr << "Error executing: " << err.what() << std::endl;
        return 1; // Exit with an error code
    }

    return 0;
}
