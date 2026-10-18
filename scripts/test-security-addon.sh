#!/bin/sh
set -eu
. "$(dirname -- "$0")/common.sh"

if [ "${TAOBAO_TEST_KEYRING_CHILD:-}" != 1 ]; then
    command -v dbus-run-session >/dev/null
    command -v gnome-keyring-daemon >/dev/null
    # XDG paths + private D-Bus keep the user's actual keyring out of this test.
    TEST_STATE=$(mktemp -d -t taobao-keyring.XXXXXXXX)
    trap 'rm -rf "$TEST_STATE"' EXIT HUP INT TERM
    mkdir -p "$TEST_STATE/data" "$TEST_STATE/config" "$TEST_STATE/run"
    chmod 700 "$TEST_STATE/run"
    XDG_DATA_HOME="$TEST_STATE/data" XDG_CONFIG_HOME="$TEST_STATE/config" \
      XDG_RUNTIME_DIR="$TEST_STATE/run" TAOBAO_TEST_KEYRING_CHILD=1 \
      dbus-run-session -- sh "$0"
    exit 0
fi

# This password belongs only to the throwaway test keyring.
printf 'offline-throwaway-keyring-password' | gnome-keyring-daemon \
    --unlock --components=secrets --control-directory "$XDG_RUNTIME_DIR/keyring" >/dev/null
export TAOBAO_TEST_SECRET_SERVICE=1
python3 "$PROJECT_ROOT/scripts/test-native-library.py"
node "$PROJECT_ROOT/scripts/test-security-addon.cjs"
ELECTRON_RUN_AS_NODE=1 "$ELECTRON" "$PROJECT_ROOT/scripts/test-security-addon.cjs"
