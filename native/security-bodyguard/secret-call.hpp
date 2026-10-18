#pragma once
#include <chrono>
#include <condition_variable>
#include <libsecret/secret.h>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

namespace taobao_port {
class SecretCall {
    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    GCancellable *cancellation_ = g_cancellable_new();
    std::thread timer_{[this] {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!condition_.wait_for(lock, std::chrono::seconds(5), [this] { return done_; }))
            g_cancellable_cancel(cancellation_);
    }};

  public:
    GError *error = nullptr;

    operator GCancellable *() {
        return cancellation_;
    }

    void check() {
        if (error)
            throw std::runtime_error(std::string("Secret Service: ") + error->message);
    }

    ~SecretCall() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            done_ = true;
        }
        condition_.notify_one();
        timer_.join();
        if (error)
            g_error_free(error);
        g_object_unref(cancellation_);
    }
};
} // namespace taobao_port
