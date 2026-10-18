#include "security-linux.h"
#include "helper-process.hpp"
#include "linux-platform.h"
#include "secret-call.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <thread>

using taobao_port::json;
using taobao_port::SecretCall;

struct tb_security_context {
    std::mutex mutex;
    std::string storage_namespace;
    std::string token;
    bool initialized = false;
};

namespace {
const SecretSchema UMID_SCHEMA = {"org.taobao.desktop.LinuxUMID",
                                  SECRET_SCHEMA_NONE,
                                  {{"application", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                   {"namespace", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                   {"kind", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                   {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}},
                                  0,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr};

class IdentityLock {
    int descriptor_ = -1;

  public:
    explicit IdentityLock(const std::string &name) {
        const char *runtime = std::getenv("XDG_RUNTIME_DIR");
        std::string directory = runtime && *runtime
                                    ? std::string(runtime) + "/taobao-security"
                                    : "/tmp/taobao-security-" + std::to_string(getuid());
        if (mkdir(directory.c_str(), 0700) && errno != EEXIST)
            throw std::runtime_error("cannot create UMID lock directory");
        int parent = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat attributes{};
        if (parent < 0 || fstat(parent, &attributes) || attributes.st_uid != getuid() ||
            attributes.st_mode & 0077) {
            if (parent >= 0)
                close(parent);
            throw std::runtime_error("unsafe UMID lock directory");
        }
        gchar *hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, name.c_str(), name.size());
        descriptor_ = openat(parent, hash, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        g_free(hash);
        close(parent);
        if (descriptor_ < 0)
            throw std::runtime_error("cannot open UMID lock");
        if (fstat(descriptor_, &attributes) || !S_ISREG(attributes.st_mode) ||
            attributes.st_uid != getuid() || attributes.st_mode & 0077) {
            close(descriptor_);
            descriptor_ = -1;
            throw std::runtime_error("unsafe UMID lock file");
        }
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
        while (flock(descriptor_, LOCK_EX | LOCK_NB)) {
            if ((errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK) ||
                std::chrono::steady_clock::now() >= deadline) {
                close(descriptor_);
                descriptor_ = -1;
                throw std::runtime_error("UMID identity lock unavailable");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    ~IdentityLock() {
        if (descriptor_ >= 0)
            close(descriptor_);
    }
};

std::string wire(const std::string &input) {
    gchar *value = g_base64_encode(reinterpret_cast<const guchar *>(input.data()), input.size());
    std::string result(value);
    g_free(value);
    return result;
}

std::string unwire(const json &response) {
    std::string encoded = response.at("outputWire").get<std::string>();
    gsize length = 0;
    guchar *value = g_base64_decode(encoded.c_str(), &length);
    std::string result(reinterpret_cast<char *>(value), length);
    g_free(value);
    return result;
}

bool valid_token(const std::string &token) {
    return token.size() == 32 && std::all_of(token.begin(), token.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
           });
}

std::string load_local_umid(const std::string &name) {
    IdentityLock lock(name);
    SecretCall call;
    gchar *stored = secret_password_lookup_sync(&UMID_SCHEMA, call, &call.error, "application",
                                                "taobao-linux-native", "namespace", name.c_str(),
                                                "kind", "local-fallback-v1", nullptr);
    call.check();
    if (stored) {
        std::string result(stored);
        secret_password_free(stored);
        if (!valid_token(result))
            throw std::runtime_error(
                "invalid persisted local UMID; refusing to silently replace identity");
        return result;
    }
    // Local.o::getRandomUUID falls back to a persisted 32-character alphanumeric
    // string. This is that LOCAL fallback, not a server-issued UMID or login token.
    constexpr char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string token;
    while (token.size() < 32) {
        unsigned char byte;
        ssize_t count = getrandom(&byte, 1, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count != 1)
            throw std::runtime_error("Linux random source failed");
        if (byte < 248)
            token += alphabet[byte % 62];
    }
    bool saved = secret_password_store_sync(
        &UMID_SCHEMA, SECRET_COLLECTION_DEFAULT, "Taobao Linux local device identity",
        token.c_str(), call, &call.error, "application", "taobao-linux-native", "namespace",
        name.c_str(), "kind", "local-fallback-v1", nullptr);
    call.check();
    if (!saved)
        throw std::runtime_error("cannot persist local UMID");
    return token;
}

json status(const tb_security_context &context) {
    return {{"initialized", context.initialized},
            {"platform", "linux"},
            {"umidSource", context.token.empty() ? "uninitialized" : "local-fallback"},
            {"serverEnrolled", false},
            {"serverAcceptance", "unverified"},
            {"appleTrustAnchor", false},
            {"appleTeamId", nullptr},
            {"networkEnrollmentImplemented", false}};
}

std::string parameter(const json &input, const char *key, size_t limit) {
    if (!input.contains(key) || !input[key].is_string())
        throw std::invalid_argument(std::string("missing string: ") + key);
    auto value = input[key].get<std::string>();
    if (value.empty() || value.size() > limit || value.find('\0') != std::string::npos ||
        value.find('\r') != std::string::npos || value.find('\n') != std::string::npos)
        throw std::invalid_argument(std::string("invalid parameter: ") + key);
    return value;
}

json factors(tb_security_context &context, const json &input) {
    if (!context.initialized)
        throw std::runtime_error("security library not initialized");
    std::string api = parameter(input, "api", 2048);
    std::string md5 = parameter(input, "urlmd5", 32);
    std::string timestamp = parameter(input, "timestamp", 20);
    if (md5.size() != 32 ||
        !std::all_of(md5.begin(), md5.end(), [](unsigned char c) { return std::isxdigit(c); }) ||
        !std::all_of(timestamp.begin(), timestamp.end(),
                     [](unsigned char c) { return c >= '0' && c <= '9'; }))
        throw std::invalid_argument("invalid URL digest or timestamp");
    const std::string appkey = "35118605", version = "1.0";
    const std::string data =
        "&&&" + appkey + "&" + md5 + "&" + timestamp + "&" + api + "&" + version + "&&&&&&&&&&&&&&";
    json signed_result =
        taobao_port::run_core({{"operation", "urlSign"}, {"method", 1}, {"inputWire", wire(data)}});
    if (!signed_result.value("success", false))
        return {{"success", false},
                {"errorCode", signed_result.value("errorCode", -1)},
                {"result", ""},
                {"status", status(context)}};
    json mini = taobao_port::run_core(
        {{"operation", "miniWua"}, {"inputWire", wire(data)}, {"token", context.token}});
    if (!mini.value("success", false))
        return {{"success", false},
                {"errorCode", mini.value("errorCode", -1)},
                {"result", ""},
                {"status", status(context)}};
    json headers = {{"pctb-x-sign", unwire(signed_result)},
                    {"pctb-x-umt", context.token},
                    {"pctb-x-mini-wua", unwire(mini)},
                    {"pctb-x-urlmd5", md5},
                    {"pctb-x-t", timestamp},
                    {"pctb-x-pv", "6.1"},
                    {"pctb-x-api", api},
                    {"pctb-x-apiver", version},
                    {"pctb-x-appkey", appkey},
                    {"x-bx-env", "web"}};
    return {{"success", true},
            {"errorCode", 0},
            {"result", headers.dump()},
            {"status", status(context)}};
}
} // namespace

extern "C" unsigned tb_security_abi_version() {
    return 1;
}

extern "C" tb_security_context *tb_security_create(const char *name) {
    if (!name || !*name || std::strlen(name) > 128)
        return nullptr;
    try {
        auto context = std::make_unique<tb_security_context>();
        context->storage_namespace = name;
        return context.release();
    } catch (...) {
        return nullptr;
    }
}

extern "C" void tb_security_destroy(tb_security_context *context) {
    delete context;
}

extern "C" void tb_security_free(void *memory) {
    std::free(memory);
}

extern "C" int tb_security_request(tb_security_context *context, const char *text,
                                   char **response) {
    if (!response)
        return -1;
    *response = nullptr;
    if (!context || !text)
        return -1;
    try {
        if (strnlen(text, 1048577) > 1048576)
            throw std::invalid_argument("request exceeds 1 MiB");
        std::lock_guard<std::mutex> lock(context->mutex);
        auto request = json::parse(text);
        auto operation = request.at("operation").get<std::string>();
        json result;
        if (operation == "initialize") {
            context->initialized = false;
            context->token.clear();
            // No network calls occur here. Self-tests prove local computation,
            // not enrollment or authentication by the Taobao service.
            auto test = taobao_port::run_core({{"operation", "miniWuaSelfTest"},
                                               {"token", "0123456789ABCDEFGHIJKLMNOPQRSTUV"},
                                               {"inputWire", wire("offline-initialization")}});
            if (!test.value("success", false))
                throw std::runtime_error("MiniWua conformance self-test failed");
            context->token = load_local_umid(context->storage_namespace);
            context->initialized = true;
            result = {{"success", true}, {"status", status(*context)}};
        } else if (operation == "cleanup") {
            context->initialized = false;
            context->token.clear();
            result = {{"success", true}, {"status", status(*context)}};
        } else if (operation == "status")
            result = {{"success", true}, {"status", status(*context)}};
        else if (operation == "getSecurityFactors")
            result = factors(*context, request.at("parameters"));
        else if (operation == "platformInfo") {
            char *snapshot = tb_linux_platform_snapshot();
            if (!snapshot)
                throw std::runtime_error("Linux platform collection failed");
            std::unique_ptr<char, decltype(&tb_linux_platform_free)> owned(snapshot,
                                                                           tb_linux_platform_free);
            result = {{"success", true}, {"platformInfo", json::parse(snapshot)}};
        } else
            throw std::invalid_argument("unsupported native library operation");
        *response = strdup(result.dump().c_str());
        return *response ? 0 : -1;
    } catch (const std::exception &error) {
        try {
            *response =
                strdup(json({{"success", false}, {"errorCode", -1}, {"error", error.what()}})
                           .dump()
                           .c_str());
        } catch (...) {
            *response = nullptr;
        }
        return -1;
    } catch (...) {
        return -1;
    }
}
