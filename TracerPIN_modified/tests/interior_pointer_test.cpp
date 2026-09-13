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
    if (argc != 2) {
        return 2;
    }
    if (std::strcmp(argv[1], "exact") == 0) {
        exact_case();
    } else if (std::strcmp(argv[1], "interior") == 0) {
        interior_case();
    } else if (std::strcmp(argv[1], "oversize") == 0) {
        oversize_case();
    } else {
        return 2;
    }
    return 0;
}
