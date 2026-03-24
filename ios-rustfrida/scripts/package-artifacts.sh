#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVICE_TARGET="${DEVICE_TARGET:-aarch64-apple-ios}"
HOST_TRIPLE="${HOST_TRIPLE:-$(rustc -vV | sed -n 's/^host: //p')}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
BUILD_DEB="${BUILD_DEB:-auto}"

AGENT_SRC="$ROOT_DIR/target/$DEVICE_TARGET/release/libagent.dylib"
CONTROLLER_SRC="$ROOT_DIR/target/$HOST_TRIPLE/release/ios-rustfrida"

mkdir -p "$DIST_DIR/agent-$DEVICE_TARGET" "$DIST_DIR/controller-$HOST_TRIPLE"

if [[ ! -f "$AGENT_SRC" ]]; then
  echo "missing agent artifact: $AGENT_SRC" >&2
  echo "build it first: cargo build -p agent --release --target $DEVICE_TARGET" >&2
  exit 1
fi

if [[ ! -f "$CONTROLLER_SRC" ]]; then
  echo "missing controller artifact: $CONTROLLER_SRC" >&2
  echo "build it first: cargo build -p controller --release --bin ios-rustfrida --target $HOST_TRIPLE" >&2
  exit 1
fi

cp "$AGENT_SRC" "$DIST_DIR/agent-$DEVICE_TARGET/"
cp "$CONTROLLER_SRC" "$DIST_DIR/controller-$HOST_TRIPLE/"
cp "$ROOT_DIR/../README.md" "$DIST_DIR/README.md"

tar -C "$DIST_DIR" -czf "$DIST_DIR/ios-rustfrida-agent-$DEVICE_TARGET.tar.gz" "agent-$DEVICE_TARGET" README.md
tar -C "$DIST_DIR" -czf "$DIST_DIR/ios-rustfrida-controller-$HOST_TRIPLE.tar.gz" "controller-$HOST_TRIPLE" README.md

build_deb_now=0
case "$BUILD_DEB" in
  1|true|yes|always)
    build_deb_now=1
    ;;
  0|false|no|never)
    build_deb_now=0
    ;;
  auto|'')
    if command -v dpkg-deb >/dev/null 2>&1; then
      build_deb_now=1
    fi
    ;;
  *)
    echo "invalid BUILD_DEB value: $BUILD_DEB" >&2
    exit 1
    ;;
esac

if [[ "$build_deb_now" -eq 1 ]]; then
  DIST_DIR="$DIST_DIR" DEVICE_TARGET="$DEVICE_TARGET" "$ROOT_DIR/scripts/package-agent-deb.sh" rootless
  DIST_DIR="$DIST_DIR" DEVICE_TARGET="$DEVICE_TARGET" "$ROOT_DIR/scripts/package-agent-deb.sh" rootful
fi

echo "packaged:"
echo "  $DIST_DIR/ios-rustfrida-agent-$DEVICE_TARGET.tar.gz"
echo "  $DIST_DIR/ios-rustfrida-controller-$HOST_TRIPLE.tar.gz"
if [[ "$build_deb_now" -eq 1 ]]; then
  ls -1 "$DIST_DIR"/ios-rustfrida-agent_*_rootless.deb "$DIST_DIR"/ios-rustfrida-agent_*_rootful.deb 2>/dev/null | sed 's/^/  /'
fi
