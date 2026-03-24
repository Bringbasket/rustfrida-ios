#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: deploy-agent-jailbreak.sh <user@device> [remote-path]

Environment overrides:
  AGENT_PATH      local libagent.dylib path
  SSH_PORT        ssh port, default 22
  SSH_PASSWORD    optional ssh password; when set, uses sshpass
  REMOTE_SUDO     1 to deploy via sudo on the device, default 0
  SUDO_PASSWORD   sudo password used when REMOTE_SUDO=1
  ROOTLESS        auto to probe /var/jb, 1 to force /var/jb/usr/lib, 0 to force /usr/lib, default auto
  RUN_DOCTOR      1 to run text doctor, json to run JSON doctor, 0 to skip, default 1

Examples:
  scripts/deploy-agent-jailbreak.sh root@iphone.local
  SSH_PASSWORD=123 REMOTE_SUDO=1 SUDO_PASSWORD=123 scripts/deploy-agent-jailbreak.sh mobile@192.168.1.10
  RUN_DOCTOR=json scripts/deploy-agent-jailbreak.sh root@iphone.local
  ROOTLESS=0 scripts/deploy-agent-jailbreak.sh root@192.168.1.10 /usr/lib/libagent.dylib
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
DEVICE_TARGET="${DEVICE_TARGET:-aarch64-apple-ios}"
ROOTLESS="${ROOTLESS:-auto}"
SSH_PORT="${SSH_PORT:-22}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
REMOTE_SUDO="${REMOTE_SUDO:-0}"
SUDO_PASSWORD="${SUDO_PASSWORD:-}"
RUN_DOCTOR="${RUN_DOCTOR:-1}"
AGENT_PATH="${AGENT_PATH:-$ROOT_DIR/target/$DEVICE_TARGET/release/libagent.dylib}"
JSON_MODE=0

if [[ "$RUN_DOCTOR" =~ ^(json)$ ]]; then
  JSON_MODE=1
fi

if [[ ! -f "$AGENT_PATH" ]]; then
  echo "missing agent artifact: $AGENT_PATH" >&2
  echo "build it first: cargo build -p agent --release --target $DEVICE_TARGET" >&2
  exit 1
fi

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

detect_remote_path() {
  case "$ROOTLESS" in
    1|true|yes)
      printf '%s\n' "/var/jb/usr/lib/libagent.dylib"
      ;;
    0|false|no)
      printf '%s\n' "/usr/lib/libagent.dylib"
      ;;
    auto|'')
      remote_shell "if [ -d /var/jb/usr/lib ]; then printf '%s' /var/jb/usr/lib/libagent.dylib; else printf '%s' /usr/lib/libagent.dylib; fi"
      ;;
    *)
      echo "invalid ROOTLESS value: $ROOTLESS (expected auto, 1, or 0)" >&2
      exit 1
      ;;
  esac
}

REMOTE_PATH="${2:-$(detect_remote_path)}"
REMOTE_DIR="$(dirname "$REMOTE_PATH")"

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

json_string() {
  printf '"%s"' "$(json_escape "$1")"
}

if [[ "$JSON_MODE" -eq 0 ]]; then
  echo "deploying agent:"
  echo "  local:  $AGENT_PATH"
  echo "  remote: $DEVICE:$REMOTE_PATH"
fi

if [[ "$REMOTE_SUDO" =~ ^(1|true|yes)$ ]]; then
  remote_tmp="/tmp/ios-rustfrida-agent-$$.dylib"
  remote_copy "$AGENT_PATH" "$remote_tmp"
  remote_privileged "mkdir -p '$REMOTE_DIR' && install -m 755 '$remote_tmp' '$REMOTE_PATH' && rm -f '$remote_tmp'"
  if [[ "$JSON_MODE" -eq 0 ]]; then
    remote_privileged "ls -l '$REMOTE_PATH'"
  fi
else
  remote_privileged "mkdir -p '$REMOTE_DIR'"
  if [[ "$JSON_MODE" -eq 1 ]]; then
    remote_copy "$AGENT_PATH" "$REMOTE_PATH"
    remote_privileged "chmod 755 '$REMOTE_PATH'"
  else
    remote_copy "$AGENT_PATH" "$REMOTE_PATH"
    remote_privileged "chmod 755 '$REMOTE_PATH' && ls -l '$REMOTE_PATH'"
  fi
fi

if [[ "$RUN_DOCTOR" =~ ^(1|true|yes)$ ]]; then
  echo
  SSH_PORT="$SSH_PORT" SSH_PASSWORD="$SSH_PASSWORD" REMOTE_SUDO="$REMOTE_SUDO" SUDO_PASSWORD="$SUDO_PASSWORD" \
    "$ROOT_DIR/scripts/doctor-jailbreak.sh" "$DEVICE" "$REMOTE_PATH"
elif [[ "$RUN_DOCTOR" =~ ^(json)$ ]]; then
  doctor_status=0
  doctor_json='null'
  if doctor_json="$(
    SSH_PORT="$SSH_PORT" SSH_PASSWORD="$SSH_PASSWORD" REMOTE_SUDO="$REMOTE_SUDO" SUDO_PASSWORD="$SUDO_PASSWORD" \
      "$ROOT_DIR/scripts/doctor-jailbreak.sh" --json "$DEVICE" "$REMOTE_PATH"
  )"; then
    :
  else
    doctor_status=$?
  fi

  printf '{'
  printf '"ok":%s,' "$( [[ "$doctor_status" -eq 0 ]] && printf true || printf false )"
  printf '"device":'; json_string "$DEVICE"; printf ','
  printf '"sshPort":'; json_string "$SSH_PORT"; printf ','
  printf '"localAgentPath":'; json_string "$AGENT_PATH"; printf ','
  printf '"remoteAgentPath":'; json_string "$REMOTE_PATH"; printf ','
  printf '"doctor":%s' "$doctor_json"
  printf '}\n'
  exit "$doctor_status"
fi

cat <<EOF

agent deployed successfully.

Host platform note:
  Linux hosts can use deploy/doctor/package helpers, but controller preflight/inject/command for iOS targets currently requires an Apple host.

Suggested next step from your Apple host:
  ./target/\$(rustc -vV | sed -n 's/^host: //p')/release/ios-rustfrida --pid <pid> --agent-path '$REMOTE_PATH' --preflight-only

Then, if the preflight output looks correct, run the full injection:
  ./target/\$(rustc -vV | sed -n 's/^host: //p')/release/ios-rustfrida --pid <pid> --agent-path '$REMOTE_PATH'

If you need a custom socket path:
  ./target/\$(rustc -vV | sed -n 's/^host: //p')/release/ios-rustfrida --pid <pid> --agent-path '$REMOTE_PATH' --socket-path /tmp/iosrf.sock --preflight-only
EOF
