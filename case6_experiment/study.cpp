#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {
constexpr std::size_t kGuard = 32;
constexpr unsigned char kGuardByte = 0xCD;

struct Buffer {
    unsigned char* allocation;
    unsigned char* compressed;
    std::size_t capacity;
    bool direct;
};

Buffer make_buffer(std::size_t capacity, bool unaligned, bool direct) {
    const std::size_t extra = unaligned ? 1 : 0;
    if (direct) {
        auto* allocation = static_cast<unsigned char*>(
            std::malloc(capacity + kGuard));
        if (!allocation) {
            std::perror("malloc");
            std::exit(2);
        }
        std::memset(allocation + capacity, kGuardByte, kGuard);
        return {allocation, allocation, capacity, true};
    }
    auto* allocation = static_cast<unsigned char*>(
        std::malloc(kGuard + extra + capacity + kGuard));
    if (!allocation) {
        std::perror("malloc");
        std::exit(2);
    }
    std::memset(allocation, kGuardByte, kGuard + extra + capacity + kGuard);
    return {allocation, allocation + kGuard + extra, capacity, false};
}

bool changed(const unsigned char* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i)
        if (p[i] != kGuardByte)
            return true;
    return false;
}

std::uint64_t checksum(const unsigned char* p, std::size_t n) {
    std::uint64_t result = 1469598103934665603ULL;
    for (std::size_t i = 0; i < n; ++i) {
        result ^= p[i];
        result *= 1099511628211ULL;
    }
    return result;
}

extern "C" __attribute__((noinline)) void known_writes(unsigned char* dst) {
    dst[0] = 0x11;
    dst[1] = 0x22;
    auto* word = reinterpret_cast<std::uint32_t*>(dst + 4);
    *word = 0xAABBCCDD;
    for (int i = 8; i < 16; ++i)
        dst[i] = static_cast<unsigned char>(i);
    dst[8] = 0x99;
}

__attribute__((noinline)) int run_known(std::size_t capacity, bool unaligned,
                                        bool bad_write, bool direct) {
    Buffer buffer = make_buffer(capacity, unaligned, direct);
    unsigned char* compressed = buffer.compressed;

    known_writes(compressed);
    if (bad_write) {
        compressed[-1] = 0xEE;
        compressed[capacity] = 0xEF;
    }

    std::printf("mode=known capacity=%zu address=%p before=%d after=%d "
                "checksum=%016llx\n",
                capacity, static_cast<void*>(compressed),
                direct ? 0 : changed(buffer.compressed - kGuard, kGuard),
                changed(buffer.compressed + capacity, kGuard),
                static_cast<unsigned long long>(checksum(compressed, 16)));
    std::free(buffer.allocation);
    return 0;
}

__attribute__((noinline)) int run_zlib(std::size_t input_size,
                                       std::size_t capacity, bool unaligned,
                                       int level, bool direct) {
    std::vector<unsigned char> input(input_size);
    for (std::size_t i = 0; i < input.size(); ++i)
        input[i] = static_cast<unsigned char>((i * 31 + (i / 17)) & 0xff);

    Buffer buffer = make_buffer(capacity, unaligned, direct);
    unsigned char* compressed = buffer.compressed;
    uLong output_size = static_cast<uLong>(capacity);
    const int result = compress2(compressed, &output_size, input.data(),
                                 static_cast<uLong>(input.size()), level);

    std::printf("mode=zlib input=%zu capacity=%zu output=%lu result=%d "
                "address=%p before=%d after=%d checksum=%016llx\n",
                input_size, capacity, static_cast<unsigned long>(output_size),
                result, static_cast<void*>(compressed),
                direct ? 0 : changed(buffer.compressed - kGuard, kGuard),
                changed(buffer.compressed + capacity, kGuard),
                static_cast<unsigned long long>(checksum(compressed, output_size)));
    std::free(buffer.allocation);
    return result == Z_OK ? 0 : 1;
}
}

int main(int argc, char** argv) {
    const char* environment_mode = std::getenv("STUDY_MODE");
    const std::string mode = argc > 1 ? argv[1] :
        (environment_mode ? environment_mode : "zlib");
    const std::size_t input_size = argc > 2 ? std::strtoull(argv[2], nullptr, 10) :
        (std::getenv("STUDY_INPUT") ? std::strtoull(std::getenv("STUDY_INPUT"), nullptr, 10) : 4096);
    const std::size_t capacity = argc > 3 ? std::strtoull(argv[3], nullptr, 10) :
        (std::getenv("STUDY_CAPACITY") ? std::strtoull(std::getenv("STUDY_CAPACITY"), nullptr, 10) : 8192);
    const bool unaligned = argc > 4 ? std::strcmp(argv[4], "unaligned") == 0 :
        std::getenv("STUDY_UNALIGNED") != nullptr;
    const bool bad_write = (argc > 5 && std::strcmp(argv[5], "bad") == 0) ||
        std::getenv("STUDY_BAD") != nullptr;
    const bool direct = std::getenv("STUDY_DIRECT") != nullptr;

    if (mode == "known")
        return run_known(capacity, unaligned, bad_write, direct);
    if (mode == "zlib")
        return run_zlib(input_size, capacity, unaligned, Z_DEFAULT_COMPRESSION,
                        direct);
    std::fprintf(stderr, "unknown mode: %s\n", mode.c_str());
    return 2;
}
