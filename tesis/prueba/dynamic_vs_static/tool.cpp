#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <cstdlib> // For std::stoll
#include <cinttypes> // For printing int64_t


int64_t get_fbreg_value(std::string id_to_find, std::string path_to_dwarfinfo) {
    std::ifstream file(path_to_dwarfinfo);
    if (!file.is_open()) {
        std::cerr << "Error opening file with path: '" << path_to_dwarfinfo << "'" << std::endl;
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

int64_t get_func_lowpc(std::string id_to_find, std::string path_to_dwarfinfo) {
    std::ifstream file(path_to_dwarfinfo);
    if (!file.is_open()) {
        std::cerr << "Error opening file with path: '" << path_to_dwarfinfo << "'" << std::endl;
        return 1;
    }

    std::string line;
    bool found = false;
    std::regex fbreg_pattern(R"(.*DW_AT_low_pc\s*:\s*0x(\d+).*)"); // Regex to match DW_OP_fbreg value
    int64_t lowpc_value = -1;

    // Read the file line by line
    while (std::getline(file, line)) {
        // Check if this line contains the ID we're looking for
        if (line.find("<" + id_to_find + ">") != std::string::npos) {
            found = true;
        }

        // If the ID was found, look for the DW_AT_location field and the DW_OP_fbreg value
        if (found && line.find("DW_AT_low_pc") != std::string::npos) {
            // Check if the line contains the DW_OP_fbreg operator
            std::smatch match;
            if (std::regex_match(line, match, fbreg_pattern)) {
                lowpc_value = std::stoll(match[1]);
                // std::cout << "HEX lowpc value for ID " << id_to_find << ": " << lowpc_value << std::endl;
                break;
            } else {
                throw std::runtime_error("func low PC value not found");
            }
        }
    }

    if (!found) {
        std::cerr << "ID " << id_to_find << " not found in the file." << std::endl;
    }

    file.close();

    return lowpc_value;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " fbreg|lowpc <id_to_find> <path_to_dwarfinfo>" << std::endl;
        return 1; // Exit with an error code
    }

    std::string firstArg = argv[1];
    if (firstArg != "fbreg" && firstArg != "lowpc") {
        std::cerr << "First param should be: fbreg|lowpc. And actual is " << argv[1] << std::endl;
        return 1; // Exit with an error code
    }
    try {
        std::string dwarf_id = argv[2];
        std::stoi(dwarf_id);
    } catch(std::exception &err) {
        std::cerr << "Dwarf ID to find should be a number" << std::endl;
        return 1; // Exit with an error code
    }


    std::string id_to_find = argv[2];  // The ID to find
    std::string path_to_dwarfinfo = argv[3];  // Path to the DWARF info file

    // Get the DW_OP_fbreg value
    try {
        if (firstArg == "fbreg"){
            int64_t fbreg_value = get_fbreg_value(id_to_find, path_to_dwarfinfo);
            std::cout << fbreg_value << std::endl;
        }
        else {
            int64_t lowpc_value = get_func_lowpc(id_to_find, path_to_dwarfinfo);
            std::cout << lowpc_value << std::endl;
        }
    }
    catch (std::exception &err) {
        std::cerr << "Dwarf ID to find should be a number" << std::endl;
        return 1; // Exit with an error code
    }

    return 0;
}
