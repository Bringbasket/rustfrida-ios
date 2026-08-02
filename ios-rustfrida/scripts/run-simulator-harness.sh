#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: run-simulator-harness.sh

Builds the Rust agent for the current Apple host architecture, embeds it in
the SimulatorHarness app, and runs the protocol XCTest on an iOS Simulator.

Environment overrides:
  IOS_SIMULATOR_UDID    use a specific available Simulator device
  KEEP_SIMULATOR_BOOTED leave a device booted by this script running (0 or 1)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo "unexpected argument: $1" >&2
  usage >&2
  exit 1
fi

for tool in cargo install mktemp python3 rm rustup uname xcodebuild xcrun; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required command: $tool" >&2
    exit 1
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_PATH="$ROOT_DIR/simulator-harness/SimulatorHarness.xcodeproj"
STAGING_DIR="$ROOT_DIR/target/simulator-harness"
TEMP_BASE="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
WORK_DIR="$(mktemp -d "$TEMP_BASE/ios-rustfrida-simulator-harness.XXXXXX")"
BOOTED_BY_SCRIPT=0
SIMULATOR_UDID=""

cleanup() {
  if [[ "$BOOTED_BY_SCRIPT" -eq 1 && -n "$SIMULATOR_UDID" && "${KEEP_SIMULATOR_BOOTED:-0}" != "1" ]]; then
    xcrun simctl shutdown "$SIMULATOR_UDID" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

case "$(uname -m)" in
  arm64 | aarch64)
    RUST_TARGET="aarch64-apple-ios-sim"
    ;;
  x86_64)
    RUST_TARGET="x86_64-apple-ios"
    ;;
  *)
    echo "unsupported Apple host architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if ! rustup target list --installed | grep -Fxq "$RUST_TARGET"; then
  echo "missing Rust target: $RUST_TARGET" >&2
  echo "install it with: rustup target add $RUST_TARGET" >&2
  exit 2
fi

mkdir -p "$STAGING_DIR"
echo "==> building simulator agent ($RUST_TARGET)"
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p agent --release --target "$RUST_TARGET"
install -m 0755 "$ROOT_DIR/target/$RUST_TARGET/release/libagent.dylib" "$STAGING_DIR/libagent.dylib"

DEVICE_LIST="$WORK_DIR/available-devices.json"
xcrun simctl list devices available --json > "$DEVICE_LIST"
SELECTION="$(python3 - "$DEVICE_LIST" "${IOS_SIMULATOR_UDID:-}" <<'PY'
import json
import re
import sys

device_list_path, requested_udid = sys.argv[1:]
with open(device_list_path, encoding="utf-8") as source:
    payload = json.load(source)

candidates = []
for runtime, devices in payload.get("devices", {}).items():
    for device in devices:
        if not device.get("isAvailable", True) or not device.get("name", "").startswith("iPhone"):
            continue
        if device.get("state") not in {"Booted", "Shutdown"}:
            continue
        candidates.append((runtime, device))

if requested_udid:
    matches = [item for item in candidates if item[1].get("udid") == requested_udid]
    if not matches:
        raise SystemExit(f"requested Simulator is not an available Booted/Shutdown iPhone: {requested_udid}")
    selected = matches[0]
else:
    if not candidates:
        raise SystemExit("no available iPhone Simulator device was found")

    def runtime_key(item):
        return tuple(int(part) for part in re.findall(r"\d+", item[0]))

    booted = [item for item in candidates if item[1].get("state") == "Booted"]
    selected = max(booted or candidates, key=runtime_key)

device = selected[1]
print(device["udid"], device.get("state", "Unknown"))
PY
)"
read -r SIMULATOR_UDID SIMULATOR_STATE <<< "$SELECTION"

case "$SIMULATOR_STATE" in
  Booted)
    ;;
  Shutdown)
    echo "==> booting Simulator $SIMULATOR_UDID"
    xcrun simctl boot "$SIMULATOR_UDID"
    BOOTED_BY_SCRIPT=1
    ;;
  *)
    echo "unsupported Simulator state: $SIMULATOR_STATE" >&2
    exit 1
    ;;
esac
xcrun simctl bootstatus "$SIMULATOR_UDID" -b

echo "==> running agent protocol XCTest on $SIMULATOR_UDID"
xcodebuild test \
  -project "$PROJECT_PATH" \
  -scheme SimulatorHarness \
  -configuration Debug \
  -destination "platform=iOS Simulator,id=$SIMULATOR_UDID" \
  -derivedDataPath "$WORK_DIR/DerivedData" \
  -parallel-testing-enabled NO \
  -maximum-concurrent-test-simulator-destinations 1 \
  -test-timeouts-enabled YES \
  -default-test-execution-time-allowance 120 \
  -maximum-test-execution-time-allowance 180 \
  ONLY_ACTIVE_ARCH=YES
