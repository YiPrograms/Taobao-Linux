#!/bin/sh

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TAOBAO_HOME=${TAOBAO_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/taobao-linux}
TAOBAO_INSTALL_DIR=${TAOBAO_INSTALL_DIR:-$TAOBAO_HOME}
APP_DIR="$TAOBAO_INSTALL_DIR/app-src"
BUILD_DIR="$TAOBAO_INSTALL_DIR/build"
ELECTRON="$TAOBAO_INSTALL_DIR/runtime/node_modules/electron/dist/electron"

export TAOBAO_HOME TAOBAO_INSTALL_DIR
