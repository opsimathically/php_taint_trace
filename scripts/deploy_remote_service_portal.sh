#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
HOST_OVERRIDE=""
INSTALL_ROOT="/opt/php_audit_apps"
PORT="19163"
SLUG="service_portal"
LOCAL_PORTAL_DIR="${ROOT_DIR}/remote_linux_container/service_portal"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"

usage() {
  cat <<'USAGE'
Usage: scripts/deploy_remote_service_portal.sh [options]

Deploys a small browser portal listing every application in the installed-app
inventory. Portal links are generated from the current browser host and each
app's inventory port, so the page remains usable after DHCP IP changes.

Options:
  --config PATH       Host credential JSON
  --host-label LABEL  Host label in config (default: lab.example.invalid)
  --host-ip IP        SSH target override for the current run
  --install-root DIR  Remote install root (default: /opt/php_audit_apps)
  --port PORT         Portal port (default: 19163)
  -h, --help          Show this help
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
    --host-ip)
      HOST_OVERRIDE="$2"
      shift 2
      ;;
    --install-root)
      INSTALL_ROOT="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
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

for cmd in python3 ssh sshpass rsync; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -d "${LOCAL_PORTAL_DIR}/public" ]]; then
  echo "Portal source not found: ${LOCAL_PORTAL_DIR}/public" >&2
  exit 1
fi

if [[ ! -f "${INVENTORY_PATH}" ]]; then
  echo "Inventory not found: ${INVENTORY_PATH}" >&2
  exit 1
fi

mapfile -t _cfg < <(python3 - "$CONFIG_PATH" "$HOST_LABEL" "$HOST_OVERRIDE" <<'PY'
import json
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
label = sys.argv[2]
override = sys.argv[3].strip()
data = json.loads(cfg_path.read_text())
if label not in data:
    raise SystemExit(f"Host label not found in config: {label}")
entry = data[label]
required = ("ipv4", "ssh_username", "ssh_password", "sudopassword")
missing = [k for k in required if k not in entry or not str(entry[k]).strip()]
if missing:
    raise SystemExit(f"Missing required config keys for {label}: {', '.join(missing)}")
print(override or entry["ipv4"])
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

REMOTE_BASE="${INSTALL_ROOT}/${SLUG}"
REMOTE_CURRENT="${REMOTE_BASE}/current"
REMOTE_STAGING="${REMOTE_BASE}/.staging"

ssh_exec() {
  sshpass -p "${SSH_PASSWORD}" ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "$@"
}

RSYNC_SSH=(
  sshpass -p "${SSH_PASSWORD}" ssh
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=20
)

echo "[service-portal] deploying to ${HOST}:${PORT}"

ssh_exec "SUDOPASS=${SUDO_PASSWORD@Q} REMOTE_BASE=${REMOTE_BASE@Q} REMOTE_STAGING=${REMOTE_STAGING@Q} bash -s" <<'REMOTE'
set -euo pipefail
sudo -S -k -p '' install -d -m 0755 -o "$USER" -g "$USER" "$REMOTE_BASE" "$REMOTE_STAGING" <<<"$SUDOPASS"
rm -rf "${REMOTE_STAGING:?}/"*
REMOTE

rsync -az --delete -e "${RSYNC_SSH[*]}" \
  "${LOCAL_PORTAL_DIR}/" \
  "${SSH_USER}@${HOST}:${REMOTE_STAGING}/"

rsync -az -e "${RSYNC_SSH[*]}" \
  "${INVENTORY_PATH}" \
  "${SSH_USER}@${HOST}:${REMOTE_STAGING}/data/inventory.json"

ssh_exec "SUDOPASS=${SUDO_PASSWORD@Q} PORT=${PORT@Q} REMOTE_BASE=${REMOTE_BASE@Q} REMOTE_CURRENT=${REMOTE_CURRENT@Q} REMOTE_STAGING=${REMOTE_STAGING@Q} SLUG=${SLUG@Q} bash -s" <<'REMOTE'
set -euo pipefail

run_sudo() {
  sudo -S -k -p '' "$@" <<<"$SUDOPASS"
}

write_root_file() {
  local target="$1"
  local mode="${2:-0644}"
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  run_sudo install -m "$mode" "$tmp" "$target"
  rm -f "$tmp"
}

php_series="$(php -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;' 2>/dev/null || true)"
if [[ -z "$php_series" ]]; then
  php_series="$(ls -1 /etc/php 2>/dev/null | sort -Vr | head -n 1)"
fi
if [[ -z "$php_series" ]]; then
  echo "Unable to detect PHP series" >&2
  exit 1
fi

pool_conf="/etc/php/${php_series}/fpm/pool.d/${SLUG}-ptt.conf"
socket="/run/php/php${php_series}-fpm-${SLUG}.sock"
site_conf="/etc/nginx/sites-available/${SLUG}-ptt.conf"
site_link="/etc/nginx/sites-enabled/${SLUG}-ptt.conf"

run_sudo rm -rf "${REMOTE_CURRENT}.previous"
if run_sudo test -d "$REMOTE_CURRENT"; then
  run_sudo mv "$REMOTE_CURRENT" "${REMOTE_CURRENT}.previous"
fi
run_sudo mv "$REMOTE_STAGING" "$REMOTE_CURRENT"
run_sudo install -d -m 0755 -o "$USER" -g "$USER" "$REMOTE_STAGING"
run_sudo chown -R www-data:www-data "$REMOTE_CURRENT"
run_sudo find "$REMOTE_CURRENT" -type d -exec chmod 0755 {} +
run_sudo find "$REMOTE_CURRENT" -type f -exec chmod 0644 {} +

write_root_file "$pool_conf" 0644 <<POOL
[${SLUG}]
user = www-data
group = www-data
listen = ${socket}
listen.owner = www-data
listen.group = www-data
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 20s
chdir = /
php_admin_value[open_basedir] = ${REMOTE_CURRENT}:/tmp
php_admin_value[error_log] = /var/log/php${php_series}-fpm-${SLUG}.log
php_admin_flag[log_errors] = on
POOL

write_root_file "$site_conf" 0644 <<NGINX
server {
    listen ${PORT};
    listen [::]:${PORT};
    server_name _;
    root ${REMOTE_CURRENT}/public;
    index index.php;

    access_log /var/log/nginx/${SLUG}_access.log;
    error_log /var/log/nginx/${SLUG}_error.log;

    location / {
        try_files \$uri /index.php;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${socket};
    }
}
NGINX

run_sudo ln -sfn "$site_conf" "$site_link"
run_sudo systemctl restart "php${php_series}-fpm"
run_sudo nginx -t
run_sudo systemctl reload nginx

curl -fsS "http://127.0.0.1:${PORT}/" >/dev/null

cat <<STATUS
{
  "ok": true,
  "port": ${PORT},
  "remote_root": "${REMOTE_CURRENT}",
  "nginx_site_conf": "${site_conf}",
  "php_fpm_pool_conf": "${pool_conf}",
  "php_fpm_socket": "${socket}"
}
STATUS
REMOTE

echo "[service-portal] available at http://${HOST}:${PORT}/"
