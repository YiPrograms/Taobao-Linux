#include "helper-process.hpp"
#include "secret-call.hpp"
#include "security-linux.h"
#include <libsecret/secret.h>
#include <memory>
#include <napi.h>
#include <stdexcept>
#include <string>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>

using taobao_port::json;
using taobao_port::SecretCall;

static const SecretSchema STORE_SCHEMA = {"org.taobao.desktop.LinuxPort",
                                          SECRET_SCHEMA_NONE,
                                          {{"application", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                           {"namespace", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                           {"key", SECRET_SCHEMA_ATTRIBUTE_STRING},
                                           {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}},
                                          0,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr,
                                          nullptr};

static std::string string_arg(const Napi::CallbackInfo &info, size_t index, const char *name) {
    if (index >= info.Length() || !info[index].IsString())
        throw Napi::TypeError::New(info.Env(), std::string(name) + " must be a string");
    std::string value = info[index].As<Napi::String>().Utf8Value();
    if (value.size() > 524288)
        throw Napi::RangeError::New(info.Env(), "input exceeds 512 KiB");
    return value;
}

static bool bool_arg(const Napi::CallbackInfo &info, size_t index, bool fallback) {
    if (index >= info.Length() || info[index].IsUndefined())
        return fallback;
    if (!info[index].IsBoolean())
        throw Napi::TypeError::New(info.Env(), "flag must be a boolean");
    return info[index].As<Napi::Boolean>().Value();
}

static std::string wire(const std::string &value) {
    gchar *encoded = g_base64_encode(reinterpret_cast<const guchar *>(value.data()), value.size());
    std::string result(encoded);
    g_free(encoded);
    return result;
}

class MyAddon : public Napi::ObjectWrap<MyAddon> {
    std::string namespace_ = "default";
    bool crypto_ready_ = false;
    bool security_ready_ = false;
    tb_security_context *security_ = nullptr;

    json native_request(const json &request) {
        char *text = nullptr;
        int result = tb_security_request(security_, request.dump().c_str(), &text);
        std::unique_ptr<char, decltype(&tb_security_free)> owned(text, tb_security_free);
        if (!text)
            throw std::runtime_error("Linux native library returned no response");
        auto response = json::parse(text);
        if (result < 0)
            throw std::runtime_error(response.value("error", "Linux native library failed"));
        return response;
    }

    static Napi::Value js_value(Napi::Env env, const json &value) {
        if (value.is_null())
            return env.Null();
        if (value.is_boolean())
            return Napi::Boolean::New(env, value.get<bool>());
        if (value.is_number())
            return Napi::Number::New(env, value.get<double>());
        if (value.is_string())
            return Napi::String::New(env, value.get<std::string>());
        Napi::Object result = Napi::Object::New(env);
        for (auto it = value.begin(); it != value.end(); ++it)
            result.Set(it.key(), js_value(env, it.value()));
        return result;
    }

    void validate_key(const std::string &value) {
        if (value.empty() || value.find('\0') != std::string::npos)
            throw std::invalid_argument("storage key must be nonempty and contain no NUL");
    }

    gchar *lookup(const std::string &key, SecretCall &call) {
        gchar *value = secret_password_lookup_sync(&STORE_SCHEMA, call, &call.error, "application",
                                                   "taobao-linux-port", "namespace",
                                                   namespace_.c_str(), "key", key.c_str(), nullptr);
        call.check();
        return value;
    }

    bool check_core() {
        auto response = taobao_port::run_core({{"operation", "selfTest"}});
        crypto_ready_ = response.value("success", false) &&
                        response.value("md5Wire", "") == "kAFQmDzST7DWlj99KOF/cg==" &&
                        response.value("sha1Wire", "") == "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=" &&
                        response.value("base64", "") == "YWJj";
        if (crypto_ready_) {
            const std::string probe = "linux-addon-initialization";
            auto encoded =
                taobao_port::run_core({{"operation", "staticEncrypt"}, {"inputWire", wire(probe)}});
            crypto_ready_ = encoded.value("success", false);
            if (crypto_ready_) {
                auto decoded = taobao_port::run_core(
                    {{"operation", "staticDecrypt"}, {"inputWire", encoded.at("outputWire")}});
                crypto_ready_ = decoded.value("success", false) &&
                                decoded.value("outputWire", "") == wire(probe);
            }
        }
        return crypto_ready_;
    }

    Napi::Value crypt_result(const Napi::CallbackInfo &info, bool encrypt) {
        if (!crypto_ready_)
            throw std::runtime_error("call initializeCrypto() before using the retained SDK core");
        if (info.Length() < 2 || !info[0].IsNumber())
            throw Napi::TypeError::New(info.Env(), "method and input are required");
        double method = info[0].As<Napi::Number>().DoubleValue();
        if (method != 1 && method != 2)
            throw Napi::RangeError::New(info.Env(), "method must be 1 or 2");
        std::string input = string_arg(info, 1, "input");
        bool input_base64 = bool_arg(info, 2, !encrypt);
        if (encrypt && input.size() > (input_base64 ? 349528u : 262144u))
            throw Napi::RangeError::New(info.Env(), "encryption input exceeds 256 KiB");
        auto response =
            taobao_port::run_core({{"operation", encrypt ? "staticEncrypt" : "staticDecrypt"},
                                   {"method", static_cast<int>(method)},
                                   {"inputWire", wire(input)},
                                   {"inputBase64", input_base64},
                                   {"outputBase64", bool_arg(info, 3, encrypt)}});
        return sdk_result(info.Env(), response);
    }

    static Napi::Object sdk_result(Napi::Env env, const json &response) {
        Napi::Object result = Napi::Object::New(env);
        result.Set("success", response.at("success").get<bool>());
        result.Set("errorCode", response.value("errorCode", -1));
        std::string encoded = response.value("outputWire", "");
        gsize length = 0;
        guchar *data = g_base64_decode(encoded.c_str(), &length);
        result.Set("output", Napi::String::New(env, reinterpret_cast<char *>(data), length));
        g_free(data);
        return result;
    }

  public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        exports.Set(
            "MyAddon",
            DefineClass(
                env, "MyAddon",
                {InstanceMethod("helloWorld", &MyAddon::HelloWorld),
                 InstanceMethod("initializeSecurity", &MyAddon::InitializeSecurity),
                 InstanceMethod("initializeCrypto", &MyAddon::InitializeCrypto),
                 InstanceMethod("cleanupSecurity", &MyAddon::CleanupSecurity),
                 InstanceMethod("getSecurityFactors", &MyAddon::GetSecurityFactors),
                 InstanceMethod("staticEncrypt", &MyAddon::StaticEncrypt),
                 InstanceMethod("staticDecrypt", &MyAddon::StaticDecrypt),
                 InstanceMethod("urlSign", &MyAddon::UrlSign),
                 InstanceMethod("storeWrite", &MyAddon::StoreWrite),
                 InstanceMethod("storeRead", &MyAddon::StoreRead),
                 InstanceMethod("storeDelete", &MyAddon::StoreDelete),
                 InstanceMethod("storeDeleteDatabase", &MyAddon::StoreDeleteDatabase),
                 InstanceMethod("testStorage", &MyAddon::TestStorage),
                 InstanceMethod("getCapabilities", &MyAddon::GetCapabilities),
                 InstanceMethod("getPlatformInfo", &MyAddon::GetPlatformInfo),
                 InstanceMethod("getSecurityStatus", &MyAddon::GetSecurityStatus),
                 InstanceMethod("getLinuxCollectionInfo", &MyAddon::GetLinuxCollectionInfo)}));
        return exports;
    }

    MyAddon(const Napi::CallbackInfo &info) : Napi::ObjectWrap<MyAddon>(info) {
        if (info.Length() && !info[0].IsUndefined()) {
            if (!info[0].IsString())
                throw Napi::TypeError::New(info.Env(), "storage namespace must be a string");
            namespace_ = info[0].As<Napi::String>().Utf8Value();
            if (namespace_.empty() || namespace_.size() > 128 ||
                namespace_.find('\0') != std::string::npos)
                throw std::invalid_argument("invalid storage namespace");
        }
        if (tb_security_abi_version() != 1)
            throw std::runtime_error("incompatible Linux security ABI");
        security_ = tb_security_create(namespace_.c_str());
        if (!security_)
            throw std::runtime_error("cannot create Linux security context");
    }

    ~MyAddon() {
        tb_security_destroy(security_);
    }

    Napi::Value HelloWorld(const Napi::CallbackInfo &info) {
        return Napi::String::New(
            info.Env(), "Hello from Linux: " + (info.Length() ? string_arg(info, 0, "input") : ""));
    }

    Napi::Value InitializeCrypto(const Napi::CallbackInfo &info) {
        return Napi::Boolean::New(info.Env(), check_core());
    }

    Napi::Value InitializeSecurity(const Napi::CallbackInfo &info) {
        security_ready_ = false;
        native_request({{"operation", "cleanup"}});
        if (!check_core())
            return Napi::Boolean::New(info.Env(), false);
        security_ready_ = native_request({{"operation", "initialize"}}).value("success", false);
        return Napi::Boolean::New(info.Env(), security_ready_);
    }

    void CleanupSecurity(const Napi::CallbackInfo &) {
        native_request({{"operation", "cleanup"}});
        crypto_ready_ = security_ready_ = false;
    }

    Napi::Value GetSecurityFactors(const Napi::CallbackInfo &info) {
        if (!security_ready_)
            throw std::runtime_error("security library not initialized");
        auto parameters = json::parse(string_arg(info, 0, "parameters"));
        return js_value(info.Env(), native_request({{"operation", "getSecurityFactors"},
                                                    {"parameters", parameters}}));
    }

    Napi::Value GetSecurityStatus(const Napi::CallbackInfo &info) {
        return js_value(info.Env(), native_request({{"operation", "status"}}).at("status"));
    }

    Napi::Value GetLinuxCollectionInfo(const Napi::CallbackInfo &info) {
        return js_value(info.Env(),
                        native_request({{"operation", "platformInfo"}}).at("platformInfo"));
    }

    Napi::Value StaticEncrypt(const Napi::CallbackInfo &info) {
        return crypt_result(info, true);
    }

    Napi::Value StaticDecrypt(const Napi::CallbackInfo &info) {
        return crypt_result(info, false);
    }

    Napi::Value UrlSign(const Napi::CallbackInfo &info) {
        if (!crypto_ready_)
            throw std::runtime_error("call initializeCrypto() first");
        std::string input = string_arg(info, 0, "input");
        if (input.empty() || input.size() > 16384 || input.find('\0') != std::string::npos)
            throw std::invalid_argument("invalid URL-sign input (maximum 16 KiB)");
        if (info.Length() > 1 && !info[1].IsUndefined() && !info[1].IsNumber())
            throw Napi::TypeError::New(info.Env(), "method must be a number");
        double method =
            info.Length() > 1 && info[1].IsNumber() ? info[1].As<Napi::Number>().DoubleValue() : 1;
        if (method != 1 && method != 2 && method != 3)
            throw std::invalid_argument("invalid URL-sign method");
        return sdk_result(info.Env(), taobao_port::run_core({{"operation", "urlSign"},
                                                             {"method", static_cast<int>(method)},
                                                             {"inputWire", wire(input)}}));
    }

    Napi::Value StoreWrite(const Napi::CallbackInfo &info) {
        std::string key = string_arg(info, 0, "key"), value = string_arg(info, 1, "value");
        validate_key(key);
        bool overwrite = bool_arg(info, 2, false);
        if (value.find('\0') != std::string::npos)
            throw std::invalid_argument("Secret Service values cannot contain NUL");
        SecretCall call;
        gchar *previous = lookup(key, call);
        bool exists = previous != nullptr;
        if (previous)
            secret_password_free(previous);
        if (exists && !overwrite)
            return Napi::Boolean::New(info.Env(), false);
        bool stored = secret_password_store_sync(
            &STORE_SCHEMA, SECRET_COLLECTION_DEFAULT, "Taobao Linux port data", value.c_str(), call,
            &call.error, "application", "taobao-linux-port", "namespace", namespace_.c_str(), "key",
            key.c_str(), nullptr);
        call.check();
        return Napi::Boolean::New(info.Env(), stored);
    }

    Napi::Value StoreRead(const Napi::CallbackInfo &info) {
        std::string key = string_arg(info, 0, "key");
        validate_key(key);
        SecretCall call;
        gchar *value = lookup(key, call);
        Napi::Object result = Napi::Object::New(info.Env());
        result.Set("success", value != nullptr);
        result.Set("value", value ? value : "");
        if (value)
            secret_password_free(value);
        return result;
    }

    Napi::Value StoreDelete(const Napi::CallbackInfo &info) {
        std::string key = string_arg(info, 0, "key");
        validate_key(key);
        SecretCall call;
        bool removed = secret_password_clear_sync(&STORE_SCHEMA, call, &call.error, "application",
                                                  "taobao-linux-port", "namespace",
                                                  namespace_.c_str(), "key", key.c_str(), nullptr);
        call.check();
        return Napi::Boolean::New(info.Env(), removed);
    }

    Napi::Value StoreDeleteDatabase(const Napi::CallbackInfo &info) {
        SecretCall call;
        bool removed = secret_password_clear_sync(&STORE_SCHEMA, call, &call.error, "application",
                                                  "taobao-linux-port", "namespace",
                                                  namespace_.c_str(), nullptr);
        call.check();
        return Napi::Boolean::New(info.Env(), removed);
    }

    Napi::Value TestStorage(const Napi::CallbackInfo &info) {
        SecretCall call;
        SecretService *service = secret_service_get_sync(SECRET_SERVICE_NONE, call, &call.error);
        call.check();
        bool available = service != nullptr;
        if (service)
            g_object_unref(service);
        return Napi::Boolean::New(info.Env(), available);
    }

    Napi::Value GetCapabilities(const Napi::CallbackInfo &info) {
        Napi::Object result = Napi::Object::New(info.Env());
        result.Set("nativePlatform", "linux");
        result.Set("staticCrypto", crypto_ready_);
        result.Set("urlSignCore", crypto_ready_);
        result.Set("secureStorageBackend", "libsecret");
        result.Set("securityFactors", security_ready_);
        result.Set("initialized", security_ready_);
        result.Set("miniWua", true);
        result.Set("nativeLibraryAbi", tb_security_abi_version());
        result.Set("serverUmidEnrollment", false);
        result.Set("serverAcceptance", "unverified");
        return result;
    }

    Napi::Value GetPlatformInfo(const Napi::CallbackInfo &info) {
        Napi::Object result = Napi::Object::New(info.Env());
        utsname system{};
        if (uname(&system))
            throw std::runtime_error("uname failed");
        result.Set("os", system.sysname);
        result.Set("release", system.release);
        result.Set("arch", system.machine);
        struct sysinfo memory{};
        if (::sysinfo(&memory))
            throw std::runtime_error("sysinfo failed");
        result.Set("memoryBytes", static_cast<double>(memory.totalram) * memory.mem_unit);
        result.Set("uptimeSeconds", static_cast<double>(memory.uptime));
        char executable[4096];
        ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable));
        if (length < 0 || length == sizeof(executable))
            throw std::runtime_error("cannot read executable path");
        result.Set("executable", Napi::String::New(info.Env(), executable, length));
        return result;
    }
};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    return MyAddon::Init(env, exports);
}
NODE_API_MODULE(my_addon, Init)
