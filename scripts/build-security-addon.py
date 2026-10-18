#!/usr/bin/env python3
"""Build the Linux security library, Node-API addon, and SDK helper."""

import hashlib
import importlib.util
import json
import os
import platform
import shlex
import shutil
import subprocess
import zipfile
from pathlib import Path

from download import download

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "taobao-linux"
DATA = Path(os.environ.get("TAOBAO_HOME", DEFAULT_DATA)).expanduser().resolve()
BUILD = DATA / "build/security-bodyguard"
TOOLS = DATA / "build/objconv"
LIBCXX = DATA / "build/libcxx"
APP = DATA / "app-src"
FRAMEWORK = (
    APP / "node_modules/@ali/pc-security-bodyguard/bin/mac/SecurityGuardSDKMac.framework/Versions/A"
)
SOURCE = ROOT / "native/security-bodyguard"
NODE_INCLUDE = Path(os.environ.get("NODE_INCLUDE_DIR", "/usr/include/node"))

SDK_SHA256 = "2cdb01306be29e7970fbf77e48810c9b8ab63ee0325d3b355986b0990a2c37bc"
OBJCONV_SHA256 = "0f604f93f97f689afd7615c86176eb15bc95001eadf8317f17ebd099c50c59e1"
OBJECTS = [
    "AESProcess",
    "Aes",
    "AlgorithmHelper",
    "Base64",
    "Byte",
    "CMd5",
    "CryptPadding",
    "DataConvertors",
    "HmacSha",
    "SGSha1",
    "TBString",
    "PicCryptStore",
    "StaticEncryptBox",
    "SignBox",
    "SecurityFactors-03e6b3aa3097045549354e06b9d21cb2",
]
RUNTIME_LIBRARIES = ["libc++.so.1", "libc++abi.so.1", "libunwind.so.1"]
DEBIAN_PACKAGES = {
    "libc++-19-dev": "21e79a3c1557f0dbc8dc2dd1f123523ab08784a8fa2204c0ef7937e3c9baad95",
    "libc++1-19": "5f0af130fa931b742a49f75d3f0c86d14d8de585ce8b2fce83dff74f450337b4",
    "libc++abi1-19": "3d046f5f5c2491bd1b811fe2d362ddfb2413452ceee9d0c14d23396fbba0ad2c",
    "libunwind-19": "0ee02e9a5d0c475c8a16d7475846814359dda1c63e0a3e23b7f02e1598f79112",
}


def run(*args, cwd=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def llvm_tool(name):
    executable = shutil.which(f"{name}-19") or shutil.which(name)
    if not executable:
        raise RuntimeError(f"Required tool missing: {name}")
    return executable


def package_flags(name):
    output = subprocess.check_output(["pkg-config", "--cflags", "--libs", name], text=True)
    return shlex.split(output)


def check_inputs():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("The SDK helper requires Linux x86-64")

    for tool in ["g++", "pkg-config", "bsdtar"]:
        if not shutil.which(tool):
            raise RuntimeError(f"Required tool missing: {tool}")

    for tool in ["clang++", "llvm-lipo", "llvm-ar", "llvm-nm"]:
        llvm_tool(tool)

    for path in [
        FRAMEWORK / "SecurityGuardSDKMac",
        NODE_INCLUDE / "node_api.h",
        Path("/usr/include/nlohmann/json.hpp"),
        APP / "node_modules/node-addon-api/napi.h",
    ]:
        if not path.is_file():
            raise RuntimeError(f"Required input missing: {path}")

    if hashlib.sha256((FRAMEWORK / "SecurityGuardSDKMac").read_bytes()).hexdigest() != SDK_SHA256:
        raise RuntimeError("Unsupported SecurityGuard SDK archive; expected version 1.8.5")


def prepare_converter():
    archive = TOOLS / "objconv.zip"
    download("https://www.agner.org/optimize/objconv.zip", archive, OBJCONV_SHA256)
    executable = TOOLS / "src/objconv"

    if not executable.exists():
        with zipfile.ZipFile(archive) as package:
            package.extract("source.zip", TOOLS)

        with zipfile.ZipFile(TOOLS / "source.zip") as source:
            source.extractall(TOOLS / "src")

        run("g++", "-O2", *sorted((TOOLS / "src").glob("*.cpp")), "-o", executable)

    return executable


def prepare_runtime():
    for name, checksum in DEBIAN_PACKAGES.items():
        filename = f"{name}_19.1.7-3~deb12u1_amd64.deb"
        archive = LIBCXX / filename
        download(
            f"https://deb.debian.org/debian/pool/main/l/llvm-toolchain-19/{filename}",
            archive,
            checksum,
        )
        run("bsdtar", "-xf", archive, "-C", LIBCXX)

        data = next(LIBCXX.glob("data.tar.*"))
        run("bsdtar", "-xf", data, "-C", LIBCXX)
        data.unlink()

    for name in RUNTIME_LIBRARIES:
        source = LIBCXX / "usr/lib/llvm-19/lib" / name
        shutil.copyfile(source.resolve(), BUILD / "lib" / name)


def convert_objects(converter):
    archive = BUILD / "sdk-x86_64.a"
    run(
        llvm_tool("llvm-lipo"),
        "-thin",
        "x86_64",
        FRAMEWORK / "SecurityGuardSDKMac",
        "-output",
        archive,
    )
    run(llvm_tool("llvm-ar"), "x", archive, cwd=BUILD / "macho")

    spec = importlib.util.spec_from_file_location(
        "normalize", ROOT / "scripts/normalize-macho-elf.py"
    )
    normalizer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(normalizer)
    report = []

    for name in OBJECTS:
        original = BUILD / f"macho/{name}.o"
        target = BUILD / f"elf/{name}.o"
        output = subprocess.check_output(
            [llvm_tool("llvm-nm"), "--undefined-only", str(original)], text=True
        )
        symbols = {line.split()[-1] for line in output.splitlines() if line.split()}
        renames = ["-nr:___bzero:bzero"] if "___bzero" in symbols else []

        run(converter, "-felf64", "-nu", *renames, original, target)
        relocations, weak_symbols = normalizer.normalize(original, target)
        report.append(
            {
                "object": name,
                "repairedRelocations": relocations,
                "restoredWeakSymbols": weak_symbols,
            }
        )

    resources = BUILD / "Resources/ps"
    if resources.is_symlink():
        resources.unlink()
    resources.symlink_to(os.path.relpath(FRAMEWORK / "Resources/ps", resources.parent))

    return report


def build_helper():
    # Retained SDK objects use libc++ and PC-relative relocations. A non-PIE
    # helper keeps their C++ ABI separate from Node's libstdc++ addon.
    run(
        llvm_tool("clang++"),
        "-std=c++17",
        "-O2",
        "-no-pie",
        "-nostdinc++",
        "-nostdlib++",
        "-I" + str(LIBCXX / "usr/lib/llvm-19/include/c++/v1"),
        SOURCE / "core-helper.cpp",
        SOURCE / "linux-compat.cpp",
        SOURCE / "linux-platform.cpp",
        *[BUILD / f"elf/{name}.o" for name in OBJECTS],
        *[BUILD / "lib" / name for name in RUNTIME_LIBRARIES],
        "-Wl,--disable-new-dtags,-rpath,$ORIGIN/../lib",
        "-Wl,-z,noexecstack",
        *package_flags("glib-2.0"),
        "-o",
        BUILD / "bin/security-core",
    )


def build_library():
    run(
        "g++",
        "-std=c++17",
        "-O2",
        "-fPIC",
        "-shared",
        "-fvisibility=hidden",
        SOURCE / "security-linux.cpp",
        SOURCE / "linux-platform.cpp",
        *package_flags("libsecret-1"),
        "-ldl",
        "-Wl,-soname,libtaobao-security-linux.so",
        "-Wl,-z,relro,-z,now",
        "-Wl,-z,noexecstack",
        "-Wl,--version-script=" + str(SOURCE / "security-linux.map"),
        "-o",
        BUILD / "libtaobao-security-linux.so",
    )


def build_addon():
    run(
        "g++",
        "-std=c++17",
        "-O2",
        "-fPIC",
        "-shared",
        "-fvisibility=hidden",
        "-DNAPI_VERSION=8",
        "-DNODE_ADDON_API_CPP_EXCEPTIONS_ALL",
        "-I" + str(NODE_INCLUDE),
        "-I" + str(APP / "node_modules/node-addon-api"),
        SOURCE / "addon.cpp",
        "-L" + str(BUILD),
        "-ltaobao-security-linux",
        "-Wl,-rpath,$ORIGIN",
        *package_flags("libsecret-1"),
        "-ldl",
        "-Wl,-z,noexecstack",
        "-Wl,-z,relro,-z,now",
        "-o",
        BUILD / "my_addon.node",
    )


def main():
    check_inputs()

    for directory in ["macho", "elf", "bin", "lib", "Resources"]:
        (BUILD / directory).mkdir(parents=True, exist_ok=True)

    converter = prepare_converter()
    prepare_runtime()
    report = convert_objects(converter)
    build_helper()
    build_library()
    build_addon()

    (BUILD / "build-report.json").write_text(
        json.dumps(
            {
                "sdkSha256": SDK_SHA256,
                "objects": report,
                "securityFactorsImplemented": True,
                "serverUmidEnrollmentImplemented": False,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Built {BUILD / 'my_addon.node'}", flush=True)


if __name__ == "__main__":
    main()
