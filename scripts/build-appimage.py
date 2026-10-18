#!/usr/bin/env python3
"""Bundle the prepared Linux client into an AppImage."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from download import download

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "taobao-linux"
DATA = Path(os.environ.get("TAOBAO_HOME", DEFAULT_DATA)).expanduser().resolve()
WORK = DATA / "build/appimage"
APPDIR = WORK / "Taobao.AppDir"
PAYLOAD = APPDIR / "usr/share/taobao-linux"
OUTPUT = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "dist").resolve()


def copy_native():
    source = DATA / "build/security-bodyguard"
    target = PAYLOAD / "build/security-bodyguard"
    target.mkdir(parents=True)

    for name in ["my_addon.node", "libtaobao-security-linux.so"]:
        shutil.copy2(source / name, target / name)

    for name in ["bin", "lib", "Resources"]:
        shutil.copytree(source / name, target / name)

    dependencies = subprocess.check_output(
        ["ldd", str(source / "libtaobao-security-linux.so")], text=True
    )
    for line in dependencies.splitlines():
        fields = line.split()
        if fields and fields[0].startswith(("libsecret-", "libgcrypt.", "libgpg-error.")):
            if len(fields) < 3 or not Path(fields[2]).is_file():
                raise RuntimeError(f"Missing runtime library: {fields[0]}")
            shutil.copy2(fields[2], target / "lib" / fields[0])


def create_appdir(version):
    if APPDIR.exists():
        shutil.rmtree(APPDIR)

    PAYLOAD.mkdir(parents=True)
    shutil.copytree(DATA / "app-src", PAYLOAD / "app-src", symlinks=True)
    shutil.copytree(
        DATA / "runtime/node_modules/electron/dist",
        PAYLOAD / "runtime/node_modules/electron/dist",
        symlinks=True,
    )
    copy_native()

    for directory, pattern in [("native", "*.cjs"), ("scripts", "*.sh")]:
        destination = PAYLOAD / directory
        destination.mkdir()
        names = ["common.sh", "run.sh"] if directory == "scripts" else None
        for source in (ROOT / directory).glob(pattern):
            if names is None or source.name in names:
                shutil.copy2(source, destination / source.name)

    shutil.copy2(ROOT / "LICENSE", PAYLOAD / "LICENSE")
    shutil.copy2(ROOT / "scripts/appimage-run.sh", APPDIR / "AppRun")
    (APPDIR / "AppRun").chmod(0o755)
    shutil.copy2(DATA / "app-src/out/renderer/assets/images/shop/taobao.png", APPDIR / "taobao.png")
    (APPDIR / ".DirIcon").symlink_to("taobao.png")
    (APPDIR / "taobao.desktop").write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Taobao\n"
        "Exec=AppRun %U\n"
        "Icon=taobao\n"
        "Categories=Network;\n"
        f"X-AppImage-Version={version}\n"
    )
    subprocess.run(["desktop-file-validate", str(APPDIR / "taobao.desktop")], check=True)


def main():
    version = json.loads((DATA / "app-src/package.json").read_text())["version"]
    WORK.mkdir(parents=True, exist_ok=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)

    tool = WORK / "appimagetool.AppImage"
    download(
        "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage",
        tool,
        "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0",
    )
    tool.chmod(0o755)

    runtime = WORK / "runtime-x86_64"
    download(
        "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64",
        runtime,
        "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d",
    )

    create_appdir(version)
    image = OUTPUT / f"Taobao-{version}-x86_64.AppImage"
    subprocess.run(
        [
            str(tool),
            "--appimage-extract-and-run",
            "--runtime-file",
            str(runtime),
            "--no-appstream",
            str(APPDIR),
            str(image),
        ],
        env={**os.environ, "ARCH": "x86_64", "VERSION": version},
        check=True,
    )
    with (OUTPUT / "SHA256SUMS").open("w") as sums:
        subprocess.run(["sha256sum", image.name], cwd=OUTPUT, stdout=sums, check=True)

    print(f"Built {image}", flush=True)


if __name__ == "__main__":
    main()
