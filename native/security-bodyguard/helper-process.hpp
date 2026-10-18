#pragma once
#include <cerrno>
#include <chrono>
#include <csignal>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace taobao_port {
using nlohmann::json;

inline std::string helper_path() {
    Dl_info info{};
    if (!dladdr(reinterpret_cast<void *>(&helper_path), &info) || !info.dli_fname)
        throw std::runtime_error("cannot resolve native addon location");
    return (std::filesystem::absolute(info.dli_fname).parent_path() / "bin/security-core").string();
}

inline json run_core(const json &request) {
    std::string input = request.dump() + '\n', output;
    if (input.size() > 1048576)
        throw std::invalid_argument("core request exceeds 1 MiB");
    std::string executable = helper_path();
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets))
        throw std::runtime_error("cannot create core IPC socket");
    // A host may have closed stdin/stdout. Keep source descriptors above stdio
    // so dup2/close actions cannot accidentally close the child's new stdin.
    for (int index = 0; index < 2; ++index) {
        if (sockets[index] > STDERR_FILENO)
            continue;
        int duplicate = fcntl(sockets[index], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
        if (duplicate < 0) {
            close(sockets[0]);
            close(sockets[1]);
            throw std::runtime_error("cannot reserve core IPC descriptors");
        }
        close(sockets[index]);
        sockets[index] = duplicate;
    }
    // Child uses blocking stdio; the parent remains nonblocking and time bounded.
    int flags = fcntl(sockets[1], F_GETFL);
    if (flags < 0 || fcntl(sockets[1], F_SETFL, flags & ~O_NONBLOCK) < 0) {
        close(sockets[0]);
        close(sockets[1]);
        throw std::runtime_error("cannot configure core IPC socket");
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, sockets[1], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, sockets[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, sockets[0]);
    if (sockets[1] > STDERR_FILENO)
        posix_spawn_file_actions_addclose(&actions, sockets[1]);
    char *argv[] = {executable.data(), nullptr};
    pid_t child;
    int error = posix_spawn(&child, executable.c_str(), &actions, nullptr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(sockets[1]);
    if (error) {
        close(sockets[0]);
        throw std::runtime_error("cannot start native security core: " + std::to_string(error));
    }

    size_t sent = 0;
    bool eof = false, reaped = false;
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    try {
        while (!eof || !reaped) {
            if (std::chrono::steady_clock::now() >= deadline)
                throw std::runtime_error("native security core timed out");
            pollfd descriptor{sockets[0],
                              static_cast<short>(POLLIN | (sent < input.size() ? POLLOUT : 0)), 0};
            int result = poll(&descriptor, 1, 50);
            if (result < 0 && errno == EINTR)
                continue;
            if (result < 0 || descriptor.revents & (POLLERR | POLLNVAL))
                throw std::runtime_error("native security core IPC failed");
            if (descriptor.revents & POLLOUT) {
                ssize_t count =
                    send(sockets[0], input.data() + sent, input.size() - sent, MSG_NOSIGNAL);
                if (count > 0) {
                    sent += count;
                    if (sent == input.size())
                        shutdown(sockets[0], SHUT_WR);
                } else if (count < 0 && errno != EAGAIN && errno != EINTR) {
                    throw std::runtime_error("cannot send core request");
                }
            }
            if (descriptor.revents & (POLLIN | POLLHUP)) {
                char buffer[8192];
                ssize_t count = read(sockets[0], buffer, sizeof(buffer));
                if (count > 0) {
                    output.append(buffer, count);
                    if (output.size() > 2097152)
                        throw std::runtime_error("core response exceeds 2 MiB");
                } else if (count == 0)
                    eof = true;
                else if (errno != EAGAIN && errno != EINTR)
                    throw std::runtime_error("cannot read core response");
            }
            if (!reaped) {
                pid_t result = waitpid(child, &status, WNOHANG);
                if (result == child)
                    reaped = true;
                else if (result < 0 && errno != EINTR)
                    throw std::runtime_error("cannot wait for core process");
            }
        }
        close(sockets[0]);
        sockets[0] = -1;
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            throw std::runtime_error("native security core failed; status=" +
                                     std::to_string(status));
        auto response = json::parse(output);
        if (!response.is_object() || !response.contains("success") ||
            !response["success"].is_boolean())
            throw std::runtime_error("invalid core response");
        return response;
    } catch (...) {
        if (sockets[0] >= 0)
            close(sockets[0]);
        if (!reaped) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
        }
        throw;
    }
}
} // namespace taobao_port
