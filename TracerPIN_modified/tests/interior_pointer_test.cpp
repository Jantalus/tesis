#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" void exact_case() {
    unsigned char *buffer = static_cast<unsigned char *>(std::malloc(16));
    for (int i = 0; i < 4; ++i) {
        buffer[i] = static_cast<unsigned char>(0x10 + i);
    }
    std::printf("exact=%u\n", static_cast<unsigned>(buffer[3]));
    std::free(buffer);
}

extern "C" void interior_case() {
    unsigned char *allocation = static_cast<unsigned char *>(std::malloc(32));
    unsigned char *section = allocation + 8;
    for (int i = 0; i < 4; ++i) {
        section[i] = static_cast<unsigned char>(0xa0 + i);
    }
    std::printf("interior=%u\n", static_cast<unsigned>(section[3]));
    std::free(allocation);
}

extern "C" void oversize_case() {
    unsigned char *allocation = static_cast<unsigned char *>(std::malloc(16));
    unsigned char *section = allocation + 12;
    section[0] = 0xee;
    std::printf("oversize=%u\n", static_cast<unsigned>(section[0]));
    std::free(allocation);
}

int main(int argc, char **argv) {
    if (argc != 1) {
        return 2;
    }
    const char *program = std::strrchr(argv[0], '/');
    program = program == nullptr ? argv[0] : program + 1;
    if (std::strcmp(program, "exact") == 0) {
        exact_case();
    } else if (std::strcmp(program, "interior") == 0) {
        interior_case();
    } else if (std::strcmp(program, "oversize") == 0) {
        oversize_case();
    } else {
        return 2;
    }
    return 0;
}
