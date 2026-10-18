#!/bin/sh
set -eu

APPDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TAOBAO_INSTALL_DIR="$APPDIR/usr/share/taobao-linux"
export LD_LIBRARY_PATH="$TAOBAO_INSTALL_DIR/build/security-bodyguard/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

exec sh "$TAOBAO_INSTALL_DIR/scripts/run.sh" "$@"
