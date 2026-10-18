// A native Linux process isolates the retained SDK C++ ABI and converted objects
// from Electron. One bounded JSON request per process; no network operations.
#include <array>
#include <cstring>
#include <glib.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

using nlohmann::json;
extern "C" {
void encrypt_ctor(void *) asm("_ZN14CStaticEncryptC1Ev");
void encrypt_dtor(void *) asm("_ZN14CStaticEncryptD1Ev");
signed char
encrypt_decrypt(void *, char *, unsigned, unsigned char *, unsigned, signed char, unsigned char *,
                unsigned &, signed char, signed char,
                unsigned &) asm("_ZN14CStaticEncrypt14EncryptDecryptEPcjPhjaS1_RjaaS2_");
void sign_ctor(void *) asm("_ZN11CCommonSignC1Ev");
void sign_dtor(void *) asm("_ZN11CCommonSignD1Ev");
signed char url_sign(void *, char *, char *, unsigned, char *, unsigned &,
                     unsigned &) asm("_ZN11CCommonSign4SignEPcS0_jS0_RjS1_");
int algorithm_md5_ext(const void *, unsigned, void *, unsigned);
int algorithm_sha1_ext(const void *, unsigned, void *, unsigned);
int algorithm_base64_encode_ext(const void *, unsigned, void *, unsigned);
char *getMiniWua(const char *token, const char *data);

struct SdkByte {
    unsigned char *data;
    int size;
    int capacity;
};

SdkByte *g_newByteBuffer(const void *, int);
void g_freeByte(SdkByte *);
SdkByte *AlgorithmHelperRandomAesDecrypt(SdkByte *);
}

static std::string wire(const void *bytes, size_t length) {
    gchar *encoded = g_base64_encode(static_cast<const guchar *>(bytes), length);
    std::string result(encoded);
    g_free(encoded);
    return result;
}

static json test_algorithms() {
    unsigned char md5[16]{}, sha1[20]{};
    char base64[5] = {};
    bool passed = algorithm_md5_ext("abc", 3, md5, sizeof(md5)) == 16 &&
                  algorithm_sha1_ext("abc", 3, sha1, sizeof(sha1)) == 20 &&
                  algorithm_base64_encode_ext("abc", 3, base64, 4) == 4;
    return {{"success", passed},
            {"md5Wire", wire(md5, sizeof(md5))},
            {"sha1Wire", wire(sha1, sizeof(sha1))},
            {"base64", base64}};
}

static json mini_wua(const json &request, const std::string &input, bool self_test) {
    std::string token = request.value("token", "");
    if (token.empty() || token.size() > 4096 || token.find('\0') != std::string::npos ||
        input.find('\0') != std::string::npos || input.size() > 16384)
        throw std::invalid_argument("invalid MiniWua token or data");
    char *output = getMiniWua(token.c_str(), input.c_str());
    if (!output)
        return {{"success", false}, {"errorCode", -1}};
    std::string result(output);
    std::free(output);
    if (self_test) {
        SdkByte *encoded = g_newByteBuffer(result.data(), result.size());
        SdkByte *decoded = AlgorithmHelperRandomAesDecrypt(encoded);
        bool valid = decoded && decoded->size >= 168 + static_cast<int>(token.size());
        if (valid) {
            auto *bytes = decoded->data;
            valid = bytes[0] == 0xbd && bytes[1] == 0xeb && bytes[2] == 0 && bytes[3] == 1;
            for (int i = 12; i < decoded->size; ++i)
                bytes[i] ^= bytes[4 + (i - 12) % 4] ^ bytes[8 + (i - 12) % 4];
            valid = valid && bytes[12] == 0 && bytes[13] == 19;
            // Field ID 184 occupies index 4; it must report failed Apple
            // validation, not a synthesized Apple trust success.
            valid = valid && bytes[14 + 4 * 8 + 7] == 1;
            unsigned length = (bytes[166] << 8) | bytes[167];
            valid = valid && length == token.size() &&
                    decoded->size >= 170 + static_cast<int>(length) &&
                    std::memcmp(bytes + 168, token.data(), length) == 0 &&
                    bytes[168 + length] == 0 && bytes[169 + length] == 0;
        }
        g_freeByte(encoded);
        g_freeByte(decoded);
        return {{"success", valid}, {"errorCode", valid ? 0 : -1}};
    }
    return {
        {"success", true}, {"errorCode", 0}, {"outputWire", wire(result.data(), result.size())}};
}

static json crypt(const json &request, std::string input, bool encrypt) {
    const int method = request.value("method", 1);
    if (method != 1 && method != 2)
        throw std::invalid_argument("method must be 1 or 2");
    if (input.empty())
        throw std::invalid_argument("input must not be empty");
    bool input_base64 = request.value("inputBase64", !encrypt);
    if (encrypt && input.size() > (input_base64 ? 349528u : 262144u))
        throw std::invalid_argument("encryption input exceeds 256 KiB");
    // This identifier comes from SecurityManager::StaticEncrypt/StaticDecrypt
    // in the vendor addon. Key material stays in the unmodified SDK resources.
    char identifier[] = "tbpcdesktop_encryption_mac";
    // Original layout: vptr/map (32 bytes) plus Darwin pthread_mutex_t (64).
    alignas(16) std::array<unsigned char, 96> context{};
    encrypt_ctor(context.data());
    std::vector<unsigned char> output(input.size() * 4 + 1024, 0);
    unsigned length = output.size(), error = 0;
    signed char success = encrypt_decrypt(context.data(), identifier, method,
                                          reinterpret_cast<unsigned char *>(input.data()),
                                          input.size(), input_base64, output.data(), length,
                                          request.value("outputBase64", encrypt), encrypt, error);
    encrypt_dtor(context.data());
    if (length > output.size())
        throw std::runtime_error("invalid SDK output length");
    return {{"success", success != 0},
            {"errorCode", error},
            {"outputWire", success ? wire(output.data(), length) : ""}};
}

static json sign(const json &request, const std::string &input) {
    const int method = request.value("method", 1);
    if (method < 1 || method > 3 || input.empty() || input.size() > 16384 ||
        input.find('\0') != std::string::npos)
        throw std::invalid_argument("invalid URL-sign input or method");
    std::string appkey = request.value("appkey", "35118605");
    if (appkey.empty() || appkey.size() > 128 || appkey.find('\0') != std::string::npos)
        throw std::invalid_argument("invalid appkey");
    // Original layout has two 64-byte Darwin mutex slots, the second at
    // offset 0x60. Linux's smaller mutex fits inside each retained slot.
    alignas(16) std::array<unsigned char, 160> context{};
    sign_ctor(context.data());
    std::vector<char> output(input.size() + 1024, 0);
    std::memcpy(output.data(), input.data(), input.size());
    unsigned length = output.size(), error = 0;
    signed char success =
        url_sign(context.data(), appkey.data(), nullptr, method, output.data(), length, error);
    sign_dtor(context.data());
    if (length > output.size())
        throw std::runtime_error("invalid SDK output length");
    return {{"success", success != 0},
            {"errorCode", error},
            {"outputWire", success ? wire(output.data(), length) : ""}};
}

static json execute(const json &request) {
    const std::string operation = request.at("operation").get<std::string>();
    if (operation == "selfTest")
        return test_algorithms();

    const std::string encoded = request.value("inputWire", "");
    gsize size = 0;
    guchar *decoded = g_base64_decode(encoded.c_str(), &size);
    std::string input(reinterpret_cast<char *>(decoded), size);
    g_free(decoded);

    if (input.size() > 524288)
        throw std::invalid_argument("input exceeds 512 KiB");

    if (operation == "miniWua" || operation == "miniWuaSelfTest")
        return mini_wua(request, input, operation == "miniWuaSelfTest");
    if (operation == "staticEncrypt" || operation == "staticDecrypt")
        return crypt(request, input, operation == "staticEncrypt");
    if (operation == "urlSign")
        return sign(request, input);

    throw std::invalid_argument("unsupported core operation");
}

int main() {
    // The SDK conversion strips Darwin exception metadata. A process crash or
    // allocation exception must be treated as failure by the parent addon.
    try {
        std::string input;
        char character;
        while (std::cin.get(character) && character != '\n') {
            if (input.size() >= 1048576)
                throw std::invalid_argument("request exceeds 1 MiB");
            input += character;
        }
        std::cout << execute(json::parse(input)).dump() << '\n';
        return 0;
    } catch (const std::exception &error) {
        std::cout << json({{"success", false}, {"error", error.what()}}).dump() << '\n';
        return 1;
    }
}
