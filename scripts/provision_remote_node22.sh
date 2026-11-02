#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"

usage() {
  cat <<'USAGE'
Usage: scripts/provision_remote_node22.sh [--config PATH] [--host-label LABEL]

Installs/upgrades Node.js 22.x on the configured remote host using NodeSource apt repo.
Safe to re-run: if remote Node major version is already >=22, no changes are applied.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --host-label)
      HOST_LABEL="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for cmd in python3 ssh sshpass; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

mapfile -t _cfg < <(python3 - "$CONFIG_PATH" "$HOST_LABEL" <<'PY'
import json
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
label = sys.argv[2]
data = json.loads(cfg_path.read_text())
if label not in data:
    raise SystemExit(f"Host label not found in config: {label}")
entry = data[label]
required = ("ipv4", "ssh_username", "ssh_password", "sudopassword")
missing = [k for k in required if k not in entry or not str(entry[k]).strip()]
if missing:
    raise SystemExit(f"Missing required config keys for {label}: {', '.join(missing)}")
print(entry["ipv4"])
print(entry["ssh_username"])
print(entry["ssh_password"])
print(entry["sudopassword"])
PY
)

HOST="${_cfg[0]}"
SSH_USER="${_cfg[1]}"
SSH_PASSWORD="${_cfg[2]}"
SUDO_PASSWORD="${_cfg[3]}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=20
)

ssh_exec() {
  sshpass -p "${SSH_PASSWORD}" ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "$@"
}

REMOTE_CMD="$(printf "SUDOPASS=%q bash -s" "${SUDO_PASSWORD}")"

echo "[provision-node22] Provisioning Node.js 22 on ${HOST}"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  sudo -S -k -p '' "$@" <<<"$SUDOPASS"
}

current_major=0
if command -v node >/dev/null 2>&1; then
  current_major="$(node -p "parseInt(process.versions.node.split('.')[0], 10)" 2>/dev/null || echo 0)"
fi

if [[ "${current_major}" =~ ^[0-9]+$ ]] && (( current_major >= 22 )); then
  echo "[provision-node22] Node already satisfies requirement: $(node -v)"
  exit 0
fi

echo "[provision-node22] Installing NodeSource repository and Node.js 22.x"
run_sudo env DEBIAN_FRONTEND=noninteractive apt-get update
run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg
run_sudo mkdir -p /etc/apt/keyrings
tmp_key="$(mktemp)"
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o "${tmp_key}"
run_sudo rm -f /etc/apt/keyrings/nodesource.gpg
run_sudo gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg "${tmp_key}"
rm -f "${tmp_key}"
tmp_list="$(mktemp)"
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > "${tmp_list}"
run_sudo install -m 0644 "${tmp_list}" /etc/apt/sources.list.d/nodesource.list
rm -f "${tmp_list}"
run_sudo env DEBIAN_FRONTEND=noninteractive apt-get update
run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs

new_major="$(node -p "parseInt(process.versions.node.split('.')[0], 10)" 2>/dev/null || echo 0)"
if ! [[ "${new_major}" =~ ^[0-9]+$ ]] || (( new_major < 22 )); then
  echo "[provision-node22] ERROR: Node upgrade failed. Current: $(node -v 2>/dev/null || echo unavailable)" >&2
  exit 1
fi

echo "[provision-node22] Node upgraded successfully: $(node -v), npm $(npm -v)"
REMOTE

echo "[provision-node22] Complete"
