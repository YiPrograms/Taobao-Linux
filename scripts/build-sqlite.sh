#!/bin/sh
set -eu

. "$(dirname -- "$0")/common.sh"

PACKAGE="$APP_DIR/node_modules/better-sqlite3"
WORK="$BUILD_DIR/sqlite"

[ -f "$PACKAGE/package.json" ] || { echo 'Run scripts/prepare.sh first' >&2; exit 1; }
[ -x "$ELECTRON" ] || { echo 'Electron runtime not installed' >&2; exit 1; }
command -v node-gyp >/dev/null || { echo 'node-gyp is required' >&2; exit 1; }

PKG_VERSION=$(node -p 'require(process.argv[1]).version' "$PACKAGE/package.json")
ELECTRON_VERSION=$(node -p 'require(process.argv[1]).electronVersions.default' "$APP_DIR/package.json")

mkdir -p "$WORK"
if [ ! -f "$WORK/better-sqlite3-$PKG_VERSION.tgz" ]; then
    (cd "$WORK" && npm pack "better-sqlite3@$PKG_VERSION" --silent)
fi

if [ ! -f "$WORK/package/binding.gyp" ]; then
    tar xzf "$WORK/better-sqlite3-$PKG_VERSION.tgz" -C "$WORK"
fi

node-gyp rebuild --directory "$WORK/package" --runtime=electron \
    --target="$ELECTRON_VERSION" --dist-url=https://electronjs.org/headers

TARGET="$PACKAGE/build/Release/better_sqlite3.node"
mkdir -p "$(dirname "$TARGET")"
cp "$WORK/package/build/Release/better_sqlite3.node" "$TARGET"

ELECTRON_RUN_AS_NODE=1 "$ELECTRON" -e '
const Database = require(process.argv[1]);
const db = new Database(":memory:");
db.exec("CREATE TABLE test (value INTEGER); INSERT INTO test VALUES (42)");
if (db.prepare("SELECT value FROM test").get().value !== 42) process.exit(1);
db.close();
console.log("better-sqlite3 Linux build: PASS");
' "$PACKAGE"
