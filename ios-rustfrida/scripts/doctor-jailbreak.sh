#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: doctor-jailbreak.sh [--json] <user@device> [remote-agent-path]

Environment overrides:
  SSH_PORT        ssh port, default 22
  SSH_PASSWORD    optional ssh password; when set, uses sshpass
  REMOTE_SUDO     1 to run remote checks through sudo, default 0
  SUDO_PASSWORD   sudo password used when REMOTE_SUDO=1
  ROOTLESS        auto to probe /var/jb, 1 to force /var/jb/usr/lib, 0 to force /usr/lib, default auto
  SOCKET_PATH     optional controller socket path to validate, default /tmp/iosrf.sock

Examples:
  scripts/doctor-jailbreak.sh root@iphone.local
  scripts/doctor-jailbreak.sh --json root@iphone.local
  SSH_PASSWORD=123 REMOTE_SUDO=1 SUDO_PASSWORD=123 scripts/doctor-jailbreak.sh mobile@192.168.1.10
  ROOTLESS=0 scripts/doctor-jailbreak.sh root@192.168.1.10 /usr/lib/libagent.dylib
USAGE
}

OUTPUT_FORMAT="text"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      OUTPUT_FORMAT="json"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

DEVICE="${1:-}"
if [[ -z "$DEVICE" ]]; then
  usage >&2
  exit 1
fi

ROOTLESS="${ROOTLESS:-auto}"
SSH_PORT="${SSH_PORT:-22}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
REMOTE_SUDO="${REMOTE_SUDO:-0}"
SUDO_PASSWORD="${SUDO_PASSWORD:-}"
SOCKET_PATH="${SOCKET_PATH:-/tmp/iosrf.sock}"

SSH_BASE=(ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
if [[ -n "$SSH_PASSWORD" ]]; then
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "SSH_PASSWORD was set but sshpass is not installed" >&2
    exit 1
  fi
  SSH_BASE=(sshpass -p "$SSH_PASSWORD" "${SSH_BASE[@]}")
fi

remote_shell() {
  "${SSH_BASE[@]}" "$DEVICE" "$@"
}

quote_sq() {
  printf "'%s'" "${1//\'/\'\\\'\'}"
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

if [[ "$OUTPUT_FORMAT" != "json" ]]; then
  echo "running jailbreak doctor:"
  echo "  device:      $DEVICE"
  echo "  agent path:  $REMOTE_PATH"
  echo "  socket path: $SOCKET_PATH"
fi

if [[ "$REMOTE_SUDO" =~ ^(1|true|yes)$ ]] && [[ -z "$SUDO_PASSWORD" ]]; then
  echo "REMOTE_SUDO=1 requires SUDO_PASSWORD" >&2
  exit 1
fi

remote_args="$(quote_sq "$REMOTE_PATH") $(quote_sq "$SOCKET_PATH") $(quote_sq "$OUTPUT_FORMAT") $(quote_sq "$DEVICE") $(quote_sq "$SSH_PORT")"
remote_command="/bin/sh -s -- $remote_args"
if [[ "$REMOTE_SUDO" =~ ^(1|true|yes)$ ]]; then
  remote_command="tmp=\$(mktemp /tmp/iosrf-doctor.XXXXXX) && cat >\"\$tmp\" && chmod 700 \"\$tmp\" && printf '%s\\n' $(quote_sq "$SUDO_PASSWORD") | sudo -S -p '' /bin/sh \"\$tmp\" $remote_args; rc=\$?; rm -f \"\$tmp\"; exit \$rc"
fi

remote_shell "$remote_command" <<'REMOTE'
agent_path="$1"
socket_path="$2"
output_format="$3"
device_name="$4"
ssh_port="$5"

failures=0
warnings=0
checks_file="${TMPDIR:-/tmp}/iosrf-doctor-checks.$$"
trap 'rm -f "$checks_file"' EXIT HUP INT TERM
: > "$checks_file"

normalize_text() {
  printf '%s' "$1" | tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//'
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

json_string() {
  printf '"%s"' "$(json_escape "$1")"
}

print_detail() {
  if [ -n "$1" ]; then
    printf '       %s\n' "$1"
  fi
}

record_check() {
  status="$1"
  fatal="$2"
  check_id="$3"
  summary="$4"
  detail="${5:-}"
  printf '%s\t%s\t%s\t%s\t%s\n' "$status" "$fatal" "$check_id" "$summary" "$detail" >> "$checks_file"
}

pass() {
  check_id="$1"
  summary="$2"
  detail="${3:-}"
  if [ "$output_format" != "json" ]; then
    printf '[pass] %s\n' "$summary"
    print_detail "$detail"
  fi
  record_check pass false "$check_id" "$summary" "$detail"
}

warn() {
  check_id="$1"
  summary="$2"
  detail="${3:-}"
  if [ "$output_format" != "json" ]; then
    printf '[warn] %s\n' "$summary"
    print_detail "$detail"
  fi
  warnings=$((warnings + 1))
  record_check warn false "$check_id" "$summary" "$detail"
}

fail() {
  check_id="$1"
  summary="$2"
  detail="${3:-}"
  if [ "$output_format" != "json" ]; then
    printf '[fail] %s\n' "$summary"
    print_detail "$detail"
  fi
  failures=$((failures + 1))
  record_check fail true "$check_id" "$summary" "$detail"
}

render_json() {
  root_kind="$1"
  user_name="$2"
  uid_value="$3"

  printf '{'
  printf '"ok":%s,' "$( [ "$failures" -eq 0 ] && printf true || printf false )"
  printf '"device":'; json_string "$device_name"; printf ','
  printf '"sshPort":%s,' "$ssh_port"
  printf '"agentPath":'; json_string "$agent_path"; printf ','
  printf '"socketPath":'; json_string "$socket_path"; printf ','
  printf '"root":'; json_string "$root_kind"; printf ','
  printf '"user":'; json_string "$user_name"; printf ','
  printf '"uid":'; json_string "$uid_value"; printf ','
  printf '"failures":%s,' "$failures"
  printf '"warnings":%s,' "$warnings"
  printf '"checks":['

  first=1
  tab_char=$(printf '\t')
  while IFS="$tab_char" read -r status fatal check_id summary detail; do
    [ -n "$check_id" ] || continue
    if [ "$first" -eq 0 ]; then
      printf ','
    fi
    first=0
    printf '{'
    printf '"id":'; json_string "$check_id"; printf ','
    printf '"status":'; json_string "$status"; printf ','
    printf '"fatal":%s,' "$fatal"
    printf '"summary":'; json_string "$summary"; printf ','
    printf '"detail":'
    if [ -n "$detail" ]; then
      json_string "$detail"
    else
      printf 'null'
    fi
    printf '}'
  done < "$checks_file"

  printf ']}'
}

agent_dir=$(dirname "$agent_path")
agent_file=$(basename "$agent_path")

if [ -d /var/jb/usr/lib ]; then
  jailbreak_root="rootless"
  pass "jailbreak-root" "detected rootless jailbreak prefix at /var/jb"
else
  jailbreak_root="rootful"
  warn "jailbreak-root" "did not detect /var/jb/usr/lib; assuming traditional rootful layout"
fi

uid="$(id -u 2>/dev/null || printf '?')"
user_name="$(id -un 2>/dev/null || whoami 2>/dev/null || printf '?')"
pass "remote-identity" "remote identity is $user_name (uid=$uid)"

ios_version="$(sw_vers -productVersion 2>/dev/null || printf 'unknown')"
kernel="$(uname -a 2>/dev/null || printf 'unknown')"
pass "platform-version" "platform version: iOS=$ios_version" "$(normalize_text "$kernel")"

if [ -d "$agent_dir" ]; then
  pass "agent-directory" "agent directory exists: $agent_dir"
else
  fail "agent-directory" "agent directory does not exist: $agent_dir"
fi

if [ -w "$agent_dir" ]; then
  pass "agent-directory-writable" "agent directory is writable: $agent_dir"
else
  warn "agent-directory-writable" "agent directory is not writable for the current ssh user: $agent_dir"
fi

if [ "$agent_file" = "agent.dylib" ]; then
  warn "agent-filename" "agent filename is still legacy: $agent_file" "prefer libagent.dylib to match controller defaults"
elif [ "$agent_file" = "libagent.dylib" ]; then
  pass "agent-filename" "agent filename matches current convention: $agent_file"
else
  warn "agent-filename" "agent filename is custom: $agent_file" "controller can still use it with --agent-path, but defaults assume libagent.dylib"
fi

if [ -e "$agent_path" ]; then
  agent_ls="$(ls -l "$agent_path" 2>/dev/null | sed 's/^ *//' | tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//')"
  pass "agent-file" "agent file exists: $agent_path" "$agent_ls"
  if [ -x "$agent_path" ]; then
    pass "agent-file-executable" "agent file is executable"
  else
    warn "agent-file-executable" "agent file is not marked executable"
  fi

  if command -v file >/dev/null 2>&1; then
    agent_file_info="$(file "$agent_path" 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//' | tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//')"
    if [ -n "$agent_file_info" ]; then
      if printf '%s' "$agent_file_info" | grep -qi 'Mach-O'; then
        pass "agent-binary-format" "agent binary looks like a Mach-O image" "$agent_file_info"
      else
        warn "agent-binary-format" "agent binary format is not reported as Mach-O" "$agent_file_info"
      fi
    else
      warn "agent-binary-format" "failed to inspect agent binary format with file"
    fi
  else
    warn "agent-binary-format" "remote tool 'file' is unavailable; skipped Mach-O format check"
  fi

  inspect_tool=""
  if command -v nm >/dev/null 2>&1; then
    inspect_tool="nm"
  elif command -v strings >/dev/null 2>&1; then
    inspect_tool="strings"
  fi

  if [ -n "$inspect_tool" ]; then
    symbol_detail="tool=$inspect_tool symbol=ios_agent_entry"
    if [ "$inspect_tool" = "nm" ]; then
      if nm "$agent_path" 2>/dev/null | grep -q 'ios_agent_entry'; then
        pass "agent-entry-symbol" "agent export symbol looks present" "$symbol_detail"
      else
        warn "agent-entry-symbol" "agent export symbol was not found in inspection output" "$symbol_detail"
      fi
    else
      if strings "$agent_path" 2>/dev/null | grep -q 'ios_agent_entry'; then
        pass "agent-entry-symbol" "agent export symbol string looks present" "$symbol_detail heuristic=true"
      else
        warn "agent-entry-symbol" "agent export symbol was not found in string scan" "$symbol_detail heuristic=true"
      fi
    fi
  else
    warn "agent-entry-symbol" "remote tools 'nm' and 'strings' are unavailable; skipped entry symbol check"
  fi
else
  warn "agent-file" "agent file is not present yet: $agent_path"
fi

socket_len=$(printf '%s' "$socket_path" | wc -c | tr -d ' ')
if [ "$socket_len" -gt 103 ]; then
  fail "socket-path" "socket path exceeds Darwin sockaddr_un limit: len=$socket_len path=$socket_path"
elif [ "$socket_len" -gt 90 ]; then
  warn "socket-path" "socket path is close to the Darwin limit: len=$socket_len path=$socket_path"
else
  pass "socket-path" "socket path length looks safe: len=$socket_len path=$socket_path"
fi

for candidate in \
  /var/jb/usr/lib/libellekit.dylib \
  /usr/lib/libellekit.dylib \
  /var/jb/usr/lib/libsubstrate.dylib \
  /usr/lib/libsubstrate.dylib \
  /var/jb/usr/lib/libsubstitute.dylib \
  /usr/lib/libsubstitute.dylib \
  /var/jb/usr/lib/libhooker.dylib \
  /usr/lib/libhooker.dylib
do
  if [ -e "$candidate" ]; then
    warn "hook-backend" "detected hook backend file: $candidate"
  fi
done

if [ "$jailbreak_root" = "rootless" ] && [ "${agent_path#"/var/jb/"}" = "$agent_path" ]; then
  warn "path-layout" "device looks rootless but agent path is outside /var/jb: $agent_path"
fi

if [ "$jailbreak_root" = "rootful" ] && [ "${agent_path#"/usr/lib/"}" = "$agent_path" ]; then
  warn "path-layout" "device looks rootful but agent path is outside /usr/lib: $agent_path"
fi

if [ "$output_format" = "json" ]; then
  render_json "$jailbreak_root" "$user_name" "$uid"
  printf '\n'
else
  printf 'summary: failures=%s warnings=%s\n' "$failures" "$warnings"
fi

exit "$failures"
REMOTE
