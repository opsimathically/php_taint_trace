#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
INSTALL_CHROMIUM=0

usage() {
  cat <<'USAGE'
Usage: scripts/prepare_remote_browser_probe.sh [--config PATH] [--host-label LABEL] [--remote-root PATH]
                                               [--install-chromium]

Installs remote dependencies for browser-aware XSS probe execution:
  - nodejs, npm
  - playwright npm package under <remote-root>/rewrite
  - optional chromium browser assets + system dependencies via playwright install-deps/install chromium
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
    --remote-root)
      REMOTE_ROOT="$2"
      shift 2
      ;;
    --install-chromium)
      INSTALL_CHROMIUM=1
      shift 1
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

for cmd in python3 ssh setsid; do
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
REMOTE_PROJECT_ROOT="${REMOTE_ROOT}/rewrite"

ASKPASS_SCRIPT="$(mktemp /tmp/php_taint_trace_askpass.XXXXXX)"
cleanup() {
  rm -f "${ASKPASS_SCRIPT}"
}
trap cleanup EXIT

cat > "${ASKPASS_SCRIPT}" <<'ASKPASS'
#!/usr/bin/env sh
printf '%s\n' "$SSH_PASSWORD"
ASKPASS
chmod 700 "${ASKPASS_SCRIPT}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=15
)

ssh_exec() {
  DISPLAY=:0 \
  SSH_ASKPASS="${ASKPASS_SCRIPT}" \
  SSH_ASKPASS_REQUIRE=force \
  SSH_PASSWORD="${SSH_PASSWORD}" \
  setsid -w ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "$@"
}

REMOTE_CMD="$(printf \
  "SUDOPASS=%q REMOTE_PROJECT_ROOT=%q INSTALL_CHROMIUM=%q bash -s" \
  "${SUDO_PASSWORD}" \
  "${REMOTE_PROJECT_ROOT}" \
  "${INSTALL_CHROMIUM}" \
)"

echo "[remote-browser-prepare] Installing system dependencies on ${HOST}"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  printf '%s\n' "$SUDOPASS" | sudo -S -k -p '' "$@"
}

if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  echo "[remote-browser-prepare] node/npm already available; skipping apt install."
else
  run_sudo apt-get update
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs npm
fi

if [[ ! -d "${REMOTE_PROJECT_ROOT}" ]]; then
  echo "Remote project root does not exist: ${REMOTE_PROJECT_ROOT}" >&2
  exit 1
fi

cd "${REMOTE_PROJECT_ROOT}"

if [[ ! -f package.json ]]; then
  npm init -y >/dev/null 2>&1
fi

if [[ -d node_modules/playwright ]]; then
  echo "[remote-browser-prepare] playwright package already installed; skipping npm install."
else
  npm install --no-save playwright >/dev/null
fi

if [[ "${INSTALL_CHROMIUM}" == "1" ]]; then
  run_sudo env PATH="${PATH}" npx playwright install-deps chromium >/dev/null
  npx playwright install chromium >/dev/null
fi
REMOTE

echo "[remote-browser-prepare] Complete."
echo "[remote-browser-prepare] Host: ${HOST}"
echo "[remote-browser-prepare] Project: ${REMOTE_PROJECT_ROOT}"
if [[ "${INSTALL_CHROMIUM}" == "1" ]]; then
  echo "[remote-browser-prepare] Chromium browser assets and system dependencies installed."
else
  echo "[remote-browser-prepare] Playwright package installed (chromium asset install skipped)."
fi
