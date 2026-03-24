#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: package-agent-deb.sh [rootless|rootful]

Environment overrides:
  DEVICE_TARGET    cargo target for libagent.dylib, default aarch64-apple-ios
  DIST_DIR         output directory, default <workspace>/dist
  PACKAGE_LAYOUT   rootless or rootful, overridden by positional argument
  PACKAGE_VERSION  package version, default workspace version from Cargo.toml
  PACKAGE_ID       dpkg package id, default com.bringbasket.ios-rustfrida-agent
  PACKAGE_NAME     display name, default iOS RustFrida Agent
  MAINTAINER       package maintainer, default Bringbasket
  DESCRIPTION      package description

Examples:
  scripts/package-agent-deb.sh
  scripts/package-agent-deb.sh rootful
  PACKAGE_VERSION=0.1.0+dev scripts/package-agent-deb.sh rootless
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVICE_TARGET="${DEVICE_TARGET:-aarch64-apple-ios}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
PACKAGE_LAYOUT="${PACKAGE_LAYOUT:-${1:-rootless}}"
PACKAGE_ID="${PACKAGE_ID:-com.bringbasket.ios-rustfrida-agent}"
PACKAGE_NAME="${PACKAGE_NAME:-iOS RustFrida Agent}"
MAINTAINER="${MAINTAINER:-Bringbasket}"
DESCRIPTION="${DESCRIPTION:-RustFrida iOS jailbreak agent dylib for host-driven Mach injection workflows.}"
AGENT_SRC="${AGENT_SRC:-$ROOT_DIR/target/$DEVICE_TARGET/release/libagent.dylib}"

workspace_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1
}

PACKAGE_VERSION="${PACKAGE_VERSION:-$(workspace_version)}"
if [[ -z "$PACKAGE_VERSION" ]]; then
  echo "failed to detect package version from $ROOT_DIR/Cargo.toml" >&2
  exit 1
fi

case "$PACKAGE_LAYOUT" in
  rootless)
    PACKAGE_ARCH="${PACKAGE_ARCH:-iphoneos-arm64}"
    INSTALL_ROOT="/var/jb"
    ;;
  rootful)
    PACKAGE_ARCH="${PACKAGE_ARCH:-iphoneos-arm}"
    INSTALL_ROOT=""
    ;;
  *)
    echo "invalid package layout: $PACKAGE_LAYOUT (expected rootless or rootful)" >&2
    exit 1
    ;;
esac

if [[ ! -f "$AGENT_SRC" ]]; then
  echo "missing agent artifact: $AGENT_SRC" >&2
  echo "build it first: cargo build -p agent --release --target $DEVICE_TARGET" >&2
  exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "missing dpkg-deb in PATH" >&2
  exit 1
fi

package_file="$DIST_DIR/ios-rustfrida-agent_${PACKAGE_VERSION}_${PACKAGE_ARCH}_${PACKAGE_LAYOUT}.deb"
stage_dir="$DIST_DIR/deb-work/$PACKAGE_LAYOUT"
agent_install_path="$INSTALL_ROOT/usr/lib/libagent.dylib"
doc_dir="$INSTALL_ROOT/usr/share/doc/$PACKAGE_ID"

rm -rf "$stage_dir"
mkdir -p "$stage_dir/DEBIAN" "$(dirname "$stage_dir$agent_install_path")" "$stage_dir$doc_dir"

cp "$AGENT_SRC" "$stage_dir$agent_install_path"
chmod 755 "$stage_dir$agent_install_path"
cp "$ROOT_DIR/../README.md" "$stage_dir$doc_dir/README.md"

installed_size="$(du -sk "$stage_dir" | awk '{print $1}')"

cat > "$stage_dir/DEBIAN/control" <<EOF
Package: $PACKAGE_ID
Name: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Architecture: $PACKAGE_ARCH
Maintainer: $MAINTAINER
Section: Development
Priority: optional
Installed-Size: $installed_size
Description: $DESCRIPTION
EOF

cat > "$stage_dir/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e
chmod 755 '$agent_install_path' || true
echo 'ios-rustfrida agent installed at: $agent_install_path'
exit 0
EOF

cat > "$stage_dir/DEBIAN/prerm" <<EOF
#!/bin/sh
set -e
echo 'removing ios-rustfrida agent from: $agent_install_path'
exit 0
EOF

chmod 755 "$stage_dir/DEBIAN/postinst" "$stage_dir/DEBIAN/prerm"

mkdir -p "$DIST_DIR"

if dpkg-deb --help 2>/dev/null | grep -q -- '--root-owner-group'; then
  dpkg-deb --build --root-owner-group "$stage_dir" "$package_file"
else
  dpkg-deb --build "$stage_dir" "$package_file"
fi

echo "packaged:"
echo "  $package_file"
echo "layout:"
echo "  $PACKAGE_LAYOUT -> $agent_install_path"
