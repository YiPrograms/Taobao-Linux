#include "linux-platform.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

using nlohmann::json;

namespace {
std::string file_line(const char *path) {
    std::ifstream stream(path);
    std::string line;
    if (!std::getline(stream, line) || line.size() > 4096)
        return "";
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    return line;
}

std::string mac_address() {
    ifaddrs *addresses = nullptr;
    if (getifaddrs(&addresses))
        return "";
    std::vector<std::pair<std::string, std::string>> candidates;
    for (auto *entry = addresses; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_PACKET ||
            entry->ifa_flags & IFF_LOOPBACK || !(entry->ifa_flags & IFF_UP))
            continue;
        auto *address = reinterpret_cast<sockaddr_ll *>(entry->ifa_addr);
        if (address->sll_halen != 6)
            continue;
        char value[18];
        std::snprintf(value, sizeof(value), "%02x:%02x:%02x:%02x:%02x:%02x", address->sll_addr[0],
                      address->sll_addr[1], address->sll_addr[2], address->sll_addr[3],
                      address->sll_addr[4], address->sll_addr[5]);
        candidates.emplace_back(entry->ifa_name, value);
    }
    freeifaddrs(addresses);
    std::sort(candidates.begin(), candidates.end());
    return candidates.empty() ? "" : candidates.front().second;
}

std::string gateway() {
    std::ifstream stream("/proc/net/route");
    std::string line;
    std::getline(stream, line);
    while (std::getline(stream, line)) {
        std::istringstream row(line);
        std::string device, destination, address;
        unsigned flags = 0;
        if (!(row >> device >> destination >> address >> std::hex >> flags) ||
            destination != "00000000" || !(flags & 2) || address.size() != 8)
            continue;
        try {
            unsigned value = std::stoul(address, nullptr, 16);
            return std::to_string(value & 255) + "." + std::to_string((value >> 8) & 255) + "." +
                   std::to_string((value >> 16) & 255) + "." + std::to_string(value >> 24);
        } catch (...) {
            return "";
        }
    }
    return "";
}

// IDs verified against MacDataCollection.o's dispatch table. IDs 181..200
// otherwise have no documented mapping in the shipped macOS implementation.
std::string collect(int index, bool &supported) {
    supported = true;
    struct utsname name{};
    struct sysinfo system{};
    switch (index) {
    case 3:
        return file_line("/sys/class/dmi/id/product_serial");
    case 20:
        return file_line("/etc/machine-id");
    case 35:
        return mac_address();
    case 14:
        return "Linux";
    case 26:
        return uname(&name) ? "" : name.release;
    case 6:
        return file_line("/sys/class/dmi/id/product_name");
    case 5:
        return file_line("/sys/class/dmi/id/sys_vendor");
    case 13: {
        std::ifstream stream("/proc/stat");
        std::string key, line;
        while (stream >> key) {
            if (key == "btime") {
                unsigned long long time;
                if (stream >> time)
                    return std::to_string(time);
            }
            std::getline(stream, line);
        }
        return "";
    }
    case 17:
        return uname(&name) ? "" : name.machine;
    case 22:
        return ::sysinfo(&system)
                   ? ""
                   : std::to_string(static_cast<unsigned long long>(system.totalram) *
                                    system.mem_unit);
    case 23: {
        struct statvfs disk{};
        return ::statvfs("/", &disk)
                   ? ""
                   : std::to_string(static_cast<unsigned long long>(disk.f_blocks) * disk.f_frsize);
    }
    case 24:
        return uname(&name) ? "" : name.nodename;
    case 39:
        return gateway();
    case 184:
        // Original wire values: "0" = Apple anchor trusted, "1" = failed,
        // "2" = pending. This Linux executable has no Apple trust anchor.
        return "1";
    case 188:
        return ""; // No Apple Team ID exists for this Linux executable.
    default:
        supported = false;
        return "";
    }
}
} // namespace

extern "C" int tb_linux_collection(int index, char **output, size_t *length) {
    if (!output || !length)
        return EINVAL;
    *output = nullptr;
    *length = 0;
    try {
        bool supported;
        std::string value = collect(index, supported);
        *output = static_cast<char *>(std::malloc(value.size() + 1));
        if (!*output)
            return ENOMEM;
        std::memcpy(*output, value.c_str(), value.size() + 1);
        *length = value.size();
        return supported ? 0 : ENOTSUP;
    } catch (...) {
        return EIO;
    }
}

extern "C" char *tb_linux_platform_snapshot() {
    try {
        json fields = json::object();
        for (int index : {3,  20, 35, 14, 26, 6,  5,  13, 17, 22,  23,
                          24, 91, 38, 39, 40, 51, 52, 54, 56, 184, 188}) {
            char *data = nullptr;
            size_t length = 0;
            int error = tb_linux_collection(index, &data, &length);
            fields[std::to_string(index)] = {{"available", error == 0 && length != 0},
                                             {"supported", error != ENOTSUP},
                                             {"value", data ? data : ""}};
            std::free(data);
        }
        auto result = json({{"platform", "linux"},
                            {"appleTrustAnchor", false},
                            {"appleTeamId", nullptr},
                            {"fields", fields}})
                          .dump();
        return strdup(result.c_str());
    } catch (...) {
        return nullptr;
    }
}

extern "C" void tb_linux_platform_free(void *memory) {
    std::free(memory);
}
