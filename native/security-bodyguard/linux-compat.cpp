// Linux replacements for the small Darwin libc boundary used by the converted core.
// This file does not implement or bypass Apple's application-signature checks.
#include "linux-platform.h"
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <sys/random.h>
#include <unistd.h>

extern "C" {
__attribute__((visibility("hidden"))) uintptr_t __stack_chk_guard;

static bool random_bytes(void *output, size_t length) {
    auto *data = static_cast<unsigned char *>(output);
    while (length) {
        ssize_t count = getrandom(data, length, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        data += count;
        length -= count;
    }
    return true;
}

// The retained machine code expects a process-global Darwin stack guard.
// Keep its guard checks active, seeded from Linux's CSPRNG.
__attribute__((constructor)) static void initialize_guard() {
    if (!random_bytes(&__stack_chk_guard, sizeof(__stack_chk_guard)))
        std::abort();
}

int _NSGetExecutablePath(char *output, uint32_t *capacity) {
    char path[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length < 0)
        return -1;
    path[length] = '\0';
    if (*capacity <= static_cast<uint32_t>(length)) {
        *capacity = length + 1;
        return -1;
    }
    std::memcpy(output, path, length + 1);
    return 0;
}

char *getCppRandomString(int length) {
    if (length < 0 || length > 4096)
        return nullptr;
    auto *result = static_cast<char *>(std::calloc(length + 1, 1));
    if (!result)
        return nullptr;
    constexpr char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int index = 0; index < length;) {
        unsigned char byte;
        if (!random_bytes(&byte, 1)) {
            std::free(result);
            return nullptr;
        }
        if (byte < 248)
            result[index++] = alphabet[byte % 62];
    }
    return result;
}

unsigned getCppRandomNumber() {
    unsigned value;
    do {
        if (!random_bytes(&value, sizeof(value)))
            std::abort();
        value &= 0x7fffffff;
    } while (!value);
    return value;
}

// glibc versions before 2.36 do not provide the SDK's arc4random entry point.
uint32_t arc4random() noexcept {
    uint32_t value;
    if (!random_bytes(&value, sizeof(value)))
        std::abort();
    return value;
}

int readDataCollectionInfo(int index, char **output, size_t *length) {
    int error = tb_linux_collection(index, output, length);
    return error == 0 && *length != 0;
}

// The shipped Mac implementation has no mapping for the VM field (ID 56).
// Preserve its unavailable result rather than asserting a physical machine.
int vmWihtouWMI(char **output, size_t *length) {
    return readDataCollectionInfo(56, output, length);
}
}
