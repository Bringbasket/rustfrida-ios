#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: check-apple-cross-build.sh

Environment overrides:
  APPLE_TARGETS         whitespace-separated targets, default aarch64-apple-ios
  APPLE_EXTRA_TARGETS   whitespace-separated targets appended to APPLE_TARGETS
  APPLE_PACKAGES        whitespace-separated packages, default native-api objc-api quickjs-runtime agent controller
  APPLE_EXTRA_PACKAGES  whitespace-separated packages appended to APPLE_PACKAGES

Examples:
  scripts/check-apple-cross-build.sh
  APPLE_EXTRA_TARGETS="aarch64-apple-ios-sim" scripts/check-apple-cross-build.sh
  APPLE_PACKAGES="native-api agent" scripts/check-apple-cross-build.sh
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

CHECKS_PASSED=0
TOTAL_CHECKS=0
FAILURE_CONTEXT="initialization"

finish() {
  local status="$1"
  trap - EXIT

  echo
  echo "apple cross-build summary:"
  echo "  cargo checks passed: $CHECKS_PASSED/$TOTAL_CHECKS"
  if [[ "$status" -eq 0 ]]; then
    echo "  result: pass"
  else
    echo "  result: fail" >&2
    echo "  stopped at: $FAILURE_CONTEXT" >&2
  fi

  exit "$status"
}

trap 'finish $?' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/Cargo.toml"

if [[ ! -f "$MANIFEST_PATH" ]]; then
  FAILURE_CONTEXT="workspace discovery"
  echo "missing workspace manifest: $MANIFEST_PATH" >&2
  exit 1
fi

read -r -a TARGETS <<< "${APPLE_TARGETS:-aarch64-apple-ios}"
if [[ -n "${APPLE_EXTRA_TARGETS:-}" ]]; then
  read -r -a EXTRA_TARGETS <<< "$APPLE_EXTRA_TARGETS"
  TARGETS+=("${EXTRA_TARGETS[@]}")
fi

read -r -a PACKAGES <<< "${APPLE_PACKAGES:-native-api objc-api quickjs-runtime agent controller}"
if [[ -n "${APPLE_EXTRA_PACKAGES:-}" ]]; then
  read -r -a EXTRA_PACKAGES <<< "$APPLE_EXTRA_PACKAGES"
  PACKAGES+=("${EXTRA_PACKAGES[@]}")
fi

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  FAILURE_CONTEXT="target configuration"
  echo "no targets configured; set APPLE_TARGETS to at least one Apple Rust target" >&2
  exit 1
fi

if [[ "${#PACKAGES[@]}" -eq 0 ]]; then
  FAILURE_CONTEXT="package configuration"
  echo "no packages configured; set APPLE_PACKAGES to at least one workspace package" >&2
  exit 1
fi

TOTAL_CHECKS=$(( ${#TARGETS[@]} * ${#PACKAGES[@]} ))

echo "apple cross-build check:"
echo "  workspace: $ROOT_DIR"
echo "  targets:   ${TARGETS[*]}"
echo "  packages:  ${PACKAGES[*]}"

FAILURE_CONTEXT="toolchain discovery"
echo
echo "==> checking required Rust tools"
for tool in cargo rustc rustup; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required command in PATH: $tool" >&2
    exit 1
  fi
  echo "  [ok] $tool"
done

HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$HOST_TRIPLE" ]]; then
  echo "failed to determine the Rust host triple" >&2
  exit 1
fi
echo "  host: $HOST_TRIPLE"

for target in "${TARGETS[@]}"; do
  if [[ "$target" != *-apple-* ]]; then
    FAILURE_CONTEXT="target validation: $target"
    echo "target is not an Apple Rust target: $target" >&2
    exit 1
  fi
done

FAILURE_CONTEXT="rustup target preflight"
echo
echo "==> checking installed Rust targets"
if ! INSTALLED_TARGETS="$(rustup target list --installed)"; then
  echo "failed to list installed Rust targets" >&2
  exit 1
fi

MISSING_TARGETS=()
for target in "${TARGETS[@]}"; do
  target_installed=0
  while IFS= read -r installed_target; do
    if [[ "$installed_target" == "$target" ]]; then
      target_installed=1
      break
    fi
  done <<< "$INSTALLED_TARGETS"

  if [[ "$target_installed" -eq 1 ]]; then
    echo "  [ok] $target"
  else
    echo "  [missing] $target" >&2
    MISSING_TARGETS+=("$target")
  fi
done

if [[ "${#MISSING_TARGETS[@]}" -ne 0 ]]; then
  echo >&2
  echo "install the missing target(s), then rerun this check:" >&2
  for target in "${MISSING_TARGETS[@]}"; do
    echo "  rustup target add $target" >&2
  done
  echo "no toolchain changes were made." >&2
  exit 2
fi

echo
if [[ "$HOST_TRIPLE" == *-apple-* ]]; then
  echo "==> Apple host detected; native Apple SDK compilation is available"
  echo "    cargo check still does not validate final linking, code signing, or device execution."
else
  echo "==> non-Apple host detected; running Rust cross-target checks only"
  echo "    quickjs-runtime uses its stub backend because an Apple SDK and target C toolchain are unavailable."
  echo "    Final native linking, code signing, and execution must be validated on an Apple host/device."
fi

cd "$ROOT_DIR"

for target in "${TARGETS[@]}"; do
  for package in "${PACKAGES[@]}"; do
    step=$((CHECKS_PASSED + 1))
    FAILURE_CONTEXT="cargo check target=$target package=$package"
    echo
    echo "==> [$step/$TOTAL_CHECKS] cargo check: target=$target package=$package"
    if cargo check --manifest-path "$MANIFEST_PATH" --target "$target" --package "$package"; then
      CHECKS_PASSED=$((CHECKS_PASSED + 1))
      echo "  [ok] target=$target package=$package"
    else
      cargo_status=$?
      echo "cargo check failed: target=$target package=$package" >&2
      exit "$cargo_status"
    fi
  done
done

FAILURE_CONTEXT="none"
