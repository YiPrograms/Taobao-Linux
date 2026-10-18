#!/bin/sh
set -eu
. "$(dirname -- "$0")/common.sh"

if [ "${TAOBAO_OFFLINE_CLIENT_CHILD:-}" != 1 ]; then
    command -v unshare >/dev/null
    command -v dbus-run-session >/dev/null
    command -v gnome-keyring-daemon >/dev/null
    # Fail before starting the app if network namespaces are unavailable.
    unshare -Un --map-current-user true
    TEST_STATE=$(mktemp -d -t taobao-client-offline.XXXXXXXX)
    trap 'rm -rf "$TEST_STATE"' EXIT HUP INT TERM
    TAOBAO_TEST_PRELOAD="$TEST_STATE/client-smoke.cjs"
    cp "$PROJECT_ROOT/scripts/client-smoke.cjs" "$TAOBAO_TEST_PRELOAD"
    TAOBAO_TEST_LOG="$TAOBAO_HOME/logs/client-offline.log"
    mkdir -p "$(dirname "$TAOBAO_TEST_LOG")"
    export TAOBAO_TEST_LOG TAOBAO_TEST_PRELOAD
    mkdir -p "$TEST_STATE/data" "$TEST_STATE/config" "$TEST_STATE/cache" "$TEST_STATE/run"
    chmod 700 "$TEST_STATE/run"
    # Only the manually started test keyring can own services. Omit standard
    # activation directories so headless Chromium cannot launch desktop portals
    # or mount a GVfs filesystem in the throwaway runtime directory.
    cat > "$TEST_STATE/bus.conf" <<XML
<busconfig>
  <type>session</type>
  <listen>unix:path=$TEST_STATE/bus</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
XML
    TAOBAO_HOME="$TEST_STATE/client" \
      XDG_DATA_HOME="$TEST_STATE/data" XDG_CONFIG_HOME="$TEST_STATE/config" \
      XDG_CACHE_HOME="$TEST_STATE/cache" XDG_RUNTIME_DIR="$TEST_STATE/run" \
      GIO_USE_VFS=local NO_AT_BRIDGE=1 TAOBAO_OFFLINE_CLIENT_CHILD=1 \
      dbus-run-session --config-file="$TEST_STATE/bus.conf" -- sh "$0" "$@"
    exit 0
fi

printf 'offline-throwaway-keyring-password' | gnome-keyring-daemon \
    --unlock --components=secrets --control-directory "$XDG_RUNTIME_DIR/keyring" >/dev/null
NODE_OPTIONS="--require=\"$TAOBAO_TEST_PRELOAD\""

if [ "$#" -gt 0 ]; then
    CLIENT=$1
    set -- --appimage-extract-and-run --ozone-platform=headless --disable-gpu
else
    CLIENT=$ELECTRON
    NODE_OPTIONS="$NODE_OPTIONS --require=\"$PROJECT_ROOT/native/preload.cjs\""
    set -- --ozone-platform=headless --disable-gpu "$APP_DIR"
fi

if [ "$(id -u)" -eq 0 ]; then
    set -- "$@" --no-sandbox
fi

export NODE_OPTIONS
set +e
unshare -Un --map-current-user timeout --signal=TERM --kill-after=5s 20s \
    "$CLIENT" "$@" >"$TAOBAO_TEST_LOG" 2>&1
RESULT=$?
set -e
if [ "$RESULT" != 0 ]; then
    echo "Offline client exited with status $RESULT; inspect $TAOBAO_TEST_LOG" >&2
    exit 1
fi
python3 - "$TAOBAO_TEST_LOG" <<'PYTEST'
from pathlib import Path
import sys

log = Path(sys.argv[1])
text = log.read_text(errors="replace")

for marker in ("security initialized", "renderer loaded", "security factors generated"):
    if f"[taobao-linux] {marker}" not in text:
        sys.exit(f"Missing event: {marker}. See {log}")

print("Offline desktop smoke test: passed")
PYTEST
