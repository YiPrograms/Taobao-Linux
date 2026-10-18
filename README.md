# Taobao Linux

Run Taobao Desktop on Linux with a native Node-API security adapter.

The project provides setup scripts and Linux replacements for the desktop client's native
dependencies. The current build targets **Taobao Desktop 3.0.0**, **Electron 37.2.0**, and **Linux
x86-64**.

## Dependencies

- Node.js and npm; tested with Node.js 24.3.0
- Python 3.10 or later
- GCC with C++17 support and Clang 17 or later
- LLVM 19 tools, including `llvm-lipo`, `llvm-ar`, and `llvm-nm`
- Node.js headers, GLib, libsecret, and nlohmann/json
- 7-Zip, libarchive tools, pkg-config, and node-gyp
- A desktop session with a Secret Service provider, such as GNOME Keyring

On Debian or Ubuntu, the build packages are:

```sh
sudo apt install build-essential clang-19 llvm-19 llvm-19-tools \
  libarchive-tools pkg-config libglib2.0-dev libsecret-1-dev \
  libnode-dev nlohmann-json3-dev p7zip-full python3 node-gyp
```

## Getting started

Run these commands from the project directory:

```sh
sh scripts/prepare.sh
sh scripts/build-sqlite.sh
python3 scripts/build-security-addon.py
sh scripts/run.sh
```

The setup script downloads the official installer, extracts the client, and installs its matching
Linux Electron runtime. An existing installer can be passed as the first argument to `prepare.sh`.
The native build downloads checksum-pinned objconv and libc++ dependencies.

For sign-in, open the client's login window and scan the QR code with the Taobao app.

## AppImage

The **Linux AppImage** GitHub Actions workflow builds on pushes to `main`, version tags, pull
requests, and manual runs. Download `Taobao-Linux-x86_64` from the run's **Artifacts** section,
extract it, then launch:

```sh
chmod +x Taobao-3.0.0-x86_64.AppImage
./Taobao-3.0.0-x86_64.AppImage
```

Build an AppImage locally after completing setup:

```sh
python3 scripts/build-appimage.py
```

The output is saved in `dist/` alongside `SHA256SUMS`. Packaging uses `file` and
`desktop-file-validate` from `desktop-file-utils`.

## Build files

Generated files are stored in the gitignored `build/` directory:

```text
build/
├── app-src/       Extracted desktop client
├── appimage/      AppImage staging files
├── extracted/     Installer contents
├── logs/          Test logs
├── native/        Compiled native modules
├── runtime/       Linux Electron runtime
├── tools/         Build dependencies
└── vendor/        Installer archives
```

Final AppImages and checksums are written to `dist/`.

Browser profiles and session data are stored in `~/.local/share/taobao-linux/state/`. `TAOBAO_HOME`
overrides the build directory; `TAOBAO_STATE_DIR` overrides the profile directory. Secret storage
uses the desktop's Secret Service.

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
    ├── helper-process.hpp  Process lifecycle and bounded IPC
    ├── linux-compat.cpp     Linux replacements for Darwin runtime calls
    ├── linux-platform.cpp   System information from Linux APIs
    └── secret-call.hpp      Secret Service timeout handling
```

The Node-API addon exposes the client's existing security interface. The shared library manages
device identity and assembles request headers. A separate helper runs selected SDK cryptography
objects converted from Mach-O to ELF, using the resources extracted from the installer.

Linux adapters use `getrandom`, `/proc`, sysfs, network interfaces, and libsecret. The helper has a
five-second deadline and exchanges bounded JSON messages with the addon and library.

## Development

Run the native interoperability suite:

```sh
sh scripts/test-security-addon.sh
```

It exercises the C ABI and the Node.js/Electron bindings, including encryption round trips, URL
signing, MiniWua, persistent device identity, secure storage, and helper failures. Each run uses a
temporary keyring and private D-Bus session.

Run the desktop smoke test:

```sh
sh scripts/test-client-offline.sh
```

To test the packaged application:

```sh
sh scripts/test-client-offline.sh "$PWD/dist/Taobao-3.0.0-x86_64.AppImage"
```

This test loads the client in an isolated network namespace and checks native initialization,
security factor generation, and renderer loading. It uses `unshare`, `dbus-run-session`, and
`gnome-keyring-daemon`.

## License

Project source is available under the [MIT License](LICENSE). Taobao Desktop and the SecurityGuard
SDK retain their respective licenses; setup obtains their files from the installer.
