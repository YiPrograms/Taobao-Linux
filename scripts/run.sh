#!/bin/sh
set -eu

. "$(dirname -- "$0")/common.sh"

for file in "$ELECTRON" "$APP_DIR/package.json" \
    "$BUILD_DIR/security-bodyguard/my_addon.node" \
    "$BUILD_DIR/security-bodyguard/libtaobao-security-linux.so" \
    "$BUILD_DIR/security-bodyguard/bin/security-core"; do
    if [ ! -f "$file" ]; then
        echo "Missing: $file. See README.md for setup." >&2
        exit 1
    fi
done

export XDG_CONFIG_HOME="$TAOBAO_HOME/state/config"
export XDG_CACHE_HOME="$TAOBAO_HOME/state/cache"
export XDG_DATA_HOME="$TAOBAO_HOME/state/data"

mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"

NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require=\"$PROJECT_ROOT/native/preload.cjs\""
export NODE_OPTIONS

exec "$ELECTRON" "$@" "$APP_DIR"
