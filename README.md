# Taobao Linux

[![Linux AppImage](https://github.com/YiPrograms/Taobao-Linux/actions/workflows/appimage.yml/badge.svg)](https://github.com/YiPrograms/Taobao-Linux/actions/workflows/appimage.yml)

Run Taobao Desktop on Linux with native Node-API adapters and an AppImage package.
The project provides scripts to extract the desktop client, build its Linux native modules,
and bundle the matching Electron runtime.

| Component | Version |
| --- | --- |
| Taobao Desktop | 3.0.0 |
| Electron | 37.2.0 |
| Architecture | Linux x86-64 |
| Release build environment | Ubuntu 22.04 |

## Download and run

Get the AppImage and checksum file from the [latest release](https://github.com/YiPrograms/Taobao-Linux/releases/latest).

| File | Download |
| --- | --- |
| Linux x86-64 AppImage | [Taobao-3.0.0-x86_64.AppImage](https://github.com/YiPrograms/Taobao-Linux/releases/download/v3.0.0/Taobao-3.0.0-x86_64.AppImage) |
| SHA-256 checksums | [SHA256SUMS](https://github.com/YiPrograms/Taobao-Linux/releases/download/v3.0.0/SHA256SUMS) |

To download and launch version 3.0.0 from a terminal:

```sh
curl -fLO https://github.com/YiPrograms/Taobao-Linux/releases/download/v3.0.0/Taobao-3.0.0-x86_64.AppImage
curl -fLO https://github.com/YiPrograms/Taobao-Linux/releases/download/v3.0.0/SHA256SUMS
sha256sum -c SHA256SUMS
chmod +x Taobao-3.0.0-x86_64.AppImage
./Taobao-3.0.0-x86_64.AppImage
```

The AppImage includes the client, Electron, and the Linux native modules. Run it in a Linux
desktop session with a Secret Service provider, such as GNOME Keyring, for secure credential
storage.

Open the login page and scan the QR code with the Taobao mobile app to sign in.

### Running without FUSE

If launching reports a FUSE mounting error, use the runtime's extraction mode:

```sh
./Taobao-3.0.0-x86_64.AppImage --appimage-extract-and-run
```

Distribution-specific FUSE setup is covered in the
[AppImage documentation](https://docs.appimage.org/user-guide/troubleshooting/fuse.html).

## Official Taobao downloads

| Resource | Link |
| --- | --- |
| Taobao Desktop website and downloads | [pc.taobao.com](https://pc.taobao.com/) |
| Windows x64 3.0.0 installer used by the build | [Download from Taobao's CDN](https://tblifecdn.taobao.com/taobaopc/shop/win10/taobao-setup-win-x64-3.0.0.exe) |
| macOS app | [Taobao Desktop on the Mac App Store](https://apps.apple.com/cn/app/%E6%B7%98%E5%AE%9D%E6%A1%8C%E9%9D%A2%E7%89%88/id6747376970?mt=12) |
| Taobao web app | [www.taobao.com](https://www.taobao.com/) |

The build extracts the desktop client's application files and SDK resources from the Windows
installer, then combines them with Linux Electron and the native modules built from this repository.

## Build from source

### Dependencies

- [Node.js](https://nodejs.org/en/download) and npm; CI uses Node.js 24.3.0
- Python 3.10 or later
- GCC with C++17 support, Clang, and LLVM 19 tools (`llvm-lipo`, `llvm-ar`, and `llvm-nm`)
- Node.js headers, GLib, libsecret, and nlohmann/json
- 7-Zip, libarchive tools, pkg-config, and node-gyp
- `file` and `desktop-file-utils` for AppImage packaging

On Debian or Ubuntu, enable the [LLVM package repository](https://apt.llvm.org/) for LLVM 19
and install the build packages:

```sh
sudo apt install build-essential clang-19 llvm-19 llvm-19-tools \
  libarchive-tools pkg-config libglib2.0-dev libsecret-1-dev \
  libnode-dev nlohmann-json3-dev p7zip-full python3 \
  desktop-file-utils file git
npm install --global node-gyp@13.1.0
```

The native builder reads Node.js headers from `/usr/include/node`. Set `NODE_INCLUDE_DIR`
to use another installation's headers:

```sh
export NODE_INCLUDE_DIR=/path/to/node/include/node
```

### Prepare, build, and launch

```sh
git clone https://github.com/YiPrograms/Taobao-Linux.git
cd Taobao-Linux

sh scripts/prepare.sh
sh scripts/build-sqlite.sh
python3 scripts/build-security-addon.py
sh scripts/run.sh
```

`prepare.sh` downloads the versioned official installer, verifies its SHA-256 checksum,
extracts the client, and installs Electron 37.2.0. To use an existing installer:

```sh
sh scripts/prepare.sh /path/to/taobao-setup-win-x64-3.0.0.exe
```

`build-sqlite.sh` rebuilds `better-sqlite3` for Linux Electron. The security builder compiles
the Node-API addon, shared library, and SDK helper; it downloads checksum-pinned objconv
and libc++ dependencies into `build/tools/`.

### Package an AppImage

After building the native modules:

```sh
python3 scripts/build-appimage.py
```

The output is `dist/Taobao-3.0.0-x86_64.AppImage` with a `dist/SHA256SUMS` file.
An alternative output directory can be passed as the first argument:

```sh
python3 scripts/build-appimage.py /path/to/output
```

### GitHub Actions

The [Linux AppImage workflow](https://github.com/YiPrograms/Taobao-Linux/actions/workflows/appimage.yml)
runs on pushes to `main`, version tags, pull requests, and manual dispatches. It prepares the
client, compiles and tests the native modules, packages the AppImage, and runs the desktop smoke test.

Each successful run uploads an artifact named `Taobao-Linux-x86_64` containing the AppImage
and `SHA256SUMS`. Published builds are available on the
[releases page](https://github.com/YiPrograms/Taobao-Linux/releases).

## Files and configuration

Generated build files are stored in the gitignored `build/` directory:

```text
build/
├── app-src/       Extracted desktop client
├── appimage/      AppImage staging files and packaging tools
├── extracted/     Installer contents
├── logs/          Test logs
├── native/        Compiled native modules
├── runtime/       Linux Electron runtime
├── tools/         Native build dependencies
└── vendor/        Installer archives
```

Final AppImages and checksums are written to the gitignored `dist/` directory.

| Setting | Default | Purpose |
| --- | --- | --- |
| `TAOBAO_HOME` | `<repository>/build` | Downloads, extracted files, and compilation output |
| `TAOBAO_STATE_DIR` | `~/.local/share/taobao-linux/state` | Browser profiles, session data, and cache |
| `NODE_INCLUDE_DIR` | `/usr/include/node` | Node.js headers for compiling the addon |

The profile directory follows `$XDG_DATA_HOME/taobao-linux/state` when `XDG_DATA_HOME` is set.
Credentials and the persistent device identity are stored through the desktop's Secret Service.

To launch with a separate profile:

```sh
TAOBAO_STATE_DIR="$PWD/build/test-profile" sh scripts/run.sh
```

The same setting works with the AppImage:

```sh
TAOBAO_STATE_DIR="$PWD/build/test-profile" ./Taobao-3.0.0-x86_64.AppImage
```

## Architecture

```text
native/
├── preload.cjs              Native module routing
├── linux-process-manager.cjs
├── linux-security.cjs       Desktop client compatibility interface
└── security-bodyguard/
    ├── addon.cpp            Node-API binding
    ├── security-linux.cpp   C ABI, device identity, and security factors
    ├── core-helper.cpp      SDK cryptography process
    ├── helper-process.hpp   Process lifecycle and bounded IPC
    ├── linux-compat.cpp     Linux replacements for Darwin runtime calls
    ├── linux-platform.cpp   System information from Linux APIs
    └── secret-call.hpp      Secret Service timeout handling
```

The preload routes the client's security and process-manager imports to Linux adapters.
The Node-API addon exposes the client's security interface, while the shared library manages
device identity, secure storage, and request headers.

A separate helper runs selected SDK cryptography objects converted from Mach-O to ELF with
objconv, using resources extracted from the installer. The helper has a five-second deadline
and exchanges bounded JSON messages with the library. Linux platform code uses `getrandom`,
`/proc`, sysfs, network interfaces, and libsecret.

## Testing

Install the test tools on Debian or Ubuntu:

```sh
sudo apt install dbus gnome-keyring util-linux
```

Run the native interoperability suite after building:

```sh
sh scripts/test-security-addon.sh
```

The suite exercises the C ABI and Node.js/Electron bindings, including encryption round trips,
URL signing, MiniWua, persistent device identity, secure storage, and helper failures.
Each run uses a temporary keyring and private D-Bus session.

Run the desktop smoke test against the prepared client or AppImage:

```sh
sh scripts/test-client-offline.sh
sh scripts/test-client-offline.sh "$PWD/dist/Taobao-3.0.0-x86_64.AppImage"
```

The desktop test uses an isolated network namespace to check native initialization,
security factor generation, and renderer loading. Logs are saved to `build/logs/client-offline.log`.

## Contributing

Report bugs and propose improvements through [GitHub issues](https://github.com/YiPrograms/Taobao-Linux/issues).
For bug reports, include your distribution, desktop environment, app version, launch command,
and the relevant error output. Code changes can be submitted as pull requests.

## License

Project source is available under the [MIT License](LICENSE). Taobao Desktop and the SecurityGuard
SDK retain their respective licenses; setup obtains their files from the installer.
