#!/bin/sh
set -eu

. "$(dirname -- "$0")/common.sh"

INSTALLER=${1:-"$TAOBAO_HOME/vendor/taobao-setup-win-x64-3.0.0.exe"}
ARCHIVE="$TAOBAO_HOME/vendor/app-64.7z"
EXTRACTED="$TAOBAO_HOME/extracted"

for tool in 7z node npm npx python3 curl; do
    command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }
done

mkdir -p "$TAOBAO_HOME/vendor" "$EXTRACTED" "$TAOBAO_HOME/runtime"

if [ ! -f "$ARCHIVE" ]; then
    if [ "$#" -eq 0 ]; then
        python3 "$PROJECT_ROOT/scripts/download.py" \
            https://tblifecdn.taobao.com/taobaopc/shop/win10/taobao-setup-win-x64-3.0.0.exe \
            "$INSTALLER" \
            15be148bc455c61dd463f75a6a03542997e50e6d4bb64ab25261c48ca58d56e2
    fi

    [ -f "$INSTALLER" ] || { echo "Installer not found: $INSTALLER" >&2; exit 1; }
    7z x -y "$INSTALLER" -o"$EXTRACTED" '$PLUGINSDIR/app-64.7z' >/dev/null
    mv "$EXTRACTED/\$PLUGINSDIR/app-64.7z" "$ARCHIVE"
fi

if [ ! -f "$EXTRACTED/resources/app.asar" ]; then
    7z x -y "$ARCHIVE" -o"$EXTRACTED" >/dev/null
fi

if [ ! -f "$APP_DIR/package.json" ]; then
    npx --yes --package=@electron/asar@3.4.1 asar extract "$EXTRACTED/resources/app.asar" "$APP_DIR"
fi

VERSION=$(node -p 'require(process.argv[1]).version' "$APP_DIR/package.json")
ELECTRON_VERSION=$(node -p 'require(process.argv[1]).electronVersions.default' "$APP_DIR/package.json")

if [ "$VERSION" != 3.0.0 ] || [ "$ELECTRON_VERSION" != 37.2.0 ]; then
    echo "Unsupported client: Taobao $VERSION / Electron $ELECTRON_VERSION" >&2
    exit 1
fi

if [ ! -x "$ELECTRON" ]; then
    npm install --prefix "$TAOBAO_HOME/runtime" --no-save --no-audit --no-fund "electron@$ELECTRON_VERSION"
fi

printf 'Prepared Taobao %s with Electron %s\n' "$VERSION" "$ELECTRON_VERSION"
