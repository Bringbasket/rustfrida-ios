#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: install-agent-deb-jailbreak.sh <user@device> [deb-path]

Environment overrides:
  SSH_PORT     ssh port, default 22
  SSH_PASSWORD optional ssh password; when set, uses sshpass
  REMOTE_SUDO  1 to install via sudo on the device, default 0
  SUDO_PASSWORD sudo password used when REMOTE_SUDO=1
  ROOTLESS     auto to probe /var/jb, 1 to force rootless package, 0 to force rootful package
  DEVICE_ARCH  package architecture override when deb-path is omitted; default probes remote dpkg arch
  DIST_DIR     local dist dir used when deb-path is omitted, default <workspace>/dist
  REMOTE_TMP   remote upload path for the deb, default /tmp/ios-rustfrida-agent.deb
  RUN_DOCTOR   1 to run doctor after install, 0 to skip, default 1

Examples:
  scripts/install-agent-deb-jailbreak.sh root@iphone.local
  SSH_PASSWORD=123 REMOTE_SUDO=1 SUDO_PASSWORD=123 scripts/install-agent-deb-jailbreak.sh mobile@192.168.1.10
  scripts/install-agent-deb-jailbreak.sh root@iphone.local dist/ios-rustfrida-agent_0.1.0_iphoneos-arm64_rootless.deb
  ROOTLESS=0 scripts/install-agent-deb-jailbreak.sh root@192.168.1.10
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

DEVICE="${1:-}"
if [[ -z "$DEVICE" ]]; then
  usage >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_PORT="${SSH_PORT:-22}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
REMOTE_SUDO="${REMOTE_SUDO:-0}"
SUDO_PASSWORD="${SUDO_PASSWORD:-}"
ROOTLESS="${ROOTLESS:-auto}"
DEVICE_ARCH="${DEVICE_ARCH:-auto}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
REMOTE_TMP="${REMOTE_TMP:-/tmp/ios-rustfrida-agent.deb}"
RUN_DOCTOR="${RUN_DOCTOR:-1}"

SSH_BASE=(ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
SCP_BASE=(scp -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
if [[ -n "$SSH_PASSWORD" ]]; then
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "SSH_PASSWORD was set but sshpass is not installed" >&2
    exit 1
  fi
  SSH_BASE=(sshpass -p "$SSH_PASSWORD" "${SSH_BASE[@]}")
  SCP_BASE=(sshpass -p "$SSH_PASSWORD" "${SCP_BASE[@]}")
fi

remote_shell() {
  "${SSH_BASE[@]}" "$DEVICE" "$@"
}

remote_copy() {
  "${SCP_BASE[@]}" "$1" "$DEVICE:$2"
}

quote_sq() {
  printf "'%s'" "${1//\'/\'\\\'\'}"
}

remote_privileged() {
  local command="$1"
  if [[ "$REMOTE_SUDO" =~ ^(1|true|yes)$ ]]; then
    if [[ -z "$SUDO_PASSWORD" ]]; then
      echo "REMOTE_SUDO=1 requires SUDO_PASSWORD" >&2
      exit 1
    fi
    remote_shell "printf '%s\n' $(quote_sq "$SUDO_PASSWORD") | sudo -S -p '' sh -lc $(quote_sq "$command")"
  else
    remote_shell "$command"
  fi
}

detect_layout() {
  case "$ROOTLESS" in
    1|true|yes)
      printf '%s\n' rootless
      ;;
    0|false|no)
      printf '%s\n' rootful
      ;;
    auto|'')
      remote_shell "if [ -d /var/jb/usr/lib ]; then printf '%s' rootless; else printf '%s' rootful; fi"
      ;;
    *)
      echo "invalid ROOTLESS value: $ROOTLESS (expected auto, 1, or 0)" >&2
      exit 1
      ;;
  esac
}

detect_device_arch() {
  case "$DEVICE_ARCH" in
    auto|'')
      remote_shell "dpkg --print-architecture 2>/dev/null || uname -m"
      ;;
    *)
      printf '%s\n' "$DEVICE_ARCH"
      ;;
  esac
}

resolve_latest_deb() {
  local layout="$1"
  local device_arch="$2"
  local match
  match="$(find "$DIST_DIR" -maxdepth 1 -type f -name "ios-rustfrida-agent_*_${device_arch}_${layout}.deb" | sort | tail -n 1)"
  if [[ -z "$match" ]]; then
    match="$(find "$DIST_DIR" -maxdepth 1 -type f -name "ios-rustfrida-agent_*_${layout}.deb" | sort | tail -n 1)"
  fi
  if [[ -z "$match" ]]; then
    echo "missing ${layout} deb under $DIST_DIR" >&2
    echo "build it first: scripts/package-agent-deb.sh $layout" >&2
    exit 1
  fi
  printf '%s\n' "$match"
}

LAYOUT="$(detect_layout)"
DETECTED_DEVICE_ARCH="$(detect_device_arch)"
DEB_PATH="${2:-$(resolve_latest_deb "$LAYOUT" "$DETECTED_DEVICE_ARCH")}"

if [[ ! -f "$DEB_PATH" ]]; then
  echo "missing deb artifact: $DEB_PATH" >&2
  exit 1
fi

echo "installing agent deb:"
echo "  device:  $DEVICE"
echo "  layout:  $LAYOUT"
echo "  arch:    $DETECTED_DEVICE_ARCH"
echo "  local:   $DEB_PATH"
echo "  remote:  $REMOTE_TMP"

remote_copy "$DEB_PATH" "$REMOTE_TMP"
remote_privileged "dpkg -i '$REMOTE_TMP' && rm -f '$REMOTE_TMP'"

if [[ "$RUN_DOCTOR" =~ ^(1|true|yes)$ ]]; then
  echo
  SSH_PORT="$SSH_PORT" SSH_PASSWORD="$SSH_PASSWORD" REMOTE_SUDO="$REMOTE_SUDO" SUDO_PASSWORD="$SUDO_PASSWORD" \
    "$ROOT_DIR/scripts/doctor-jailbreak.sh" "$DEVICE"
fi

cat <<EOF

package installed successfully.

Host platform note:
  Linux hosts can use install/deploy/doctor/package helpers, but controller preflight/inject/command for iOS targets currently requires an Apple host.

Suggested next step from your Apple host:
  ./target/\$(rustc -vV | sed -n 's/^host: //p')/release/ios-rustfrida --pid <pid> --preflight-only
EOF
