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
        return 1;
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
                int64_t fbreg_value = std::stoll(match[1]);
                std::cout << "DW_OP_fbreg value for ID " << id_to_find << ": " << fbreg_value << std::endl;
                break; // Exit after finding the value
            } else {
              std::cout << "CACA MALO FEO" << std::endl;
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
                std::cout << "HEX lowpc value for ID " << id_to_find << ": " << lowpc_value << std::endl;

                break; // Exit after finding the value
            } else {
              std::cout << "CACA MALO FEO" << std::endl;
            }
        }
    }

    if (!found) {
        std::cerr << "ID " << id_to_find << " not found in the file." << std::endl;
    }

    file.close();

    return lowpc_value;
}

int main() {
    // Open the file
    get_fbreg_value("497", "/home/mgiampaolo/Desktop/tesis/readelf_vector_wi.txt");
    //get_fbreg_value2("497", "/home/mgiampaolo/Desktop/tesis/readelf_vector_wi.txt", R"(.*DW_OP_fbreg:\s*(-?\d+).*)");
    //     <47b>   DW_AT_location    : 3 byte block: 91 9c 7f 	(DW_OP_fbreg: -100)

    get_func_lowpc("451", "/home/mgiampaolo/Desktop/tesis/readelf_vector_wi.txt");
    //      <45d>   DW_AT_low_pc      : 0x1179
    // R"(.*DW_AT_low_pc\s*:\s*0(x\d+).*)"

    return 0;
}