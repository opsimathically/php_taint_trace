#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19145"
APP_SLUG="phpmyadmin"
UI_SYNC="1"
RUN_VALIDATION="1"
ENABLE_XMARK="1"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
EXTENSION_ALLOWLIST_PATH="${ROOT_DIR}/remote_linux_container/installed_php_applications/apps/${APP_SLUG}/extensions.allowlist.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_phpmyadmin_app_manage.sh <install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck> [options]

Options:
  --config PATH               External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL          Host label in config (default: lab.example.invalid)
  --remote-taint-root PATH    Remote php_taint_trace repo root (default: /opt/php_taint_trace_vuln_lab/rewrite)
  --install-root PATH         Remote multi-app install root (default: /opt/php_audit_apps)
  --app-port PORT             phpMyAdmin port (default: 19145)
  --inventory PATH            External inventory path (default: PHP_TAINT_TRACE_INVENTORY_PATH or XDG state directory)
  --allowlist PATH            Extension allowlist JSON path
  --no-ui-sync                Do not sync UI file sources with this app runtime
  --no-validation             Skip install-time taint/verifier smoke validation
  --enable-xmark              Load xmark extension for PHP-FPM worker startup (default: on)
  --disable-xmark             Disable xmark extension loading for PHP-FPM
  -h, --help                  Show help

Actions:
  install            Install or reconcile phpMyAdmin + runtime integration
  update             Update phpMyAdmin core/extensions and refresh metadata
  reset              Restore latest baseline snapshot
  snapshot-create    Create baseline snapshot
  snapshot-restore   Restore baseline snapshot
  xmark-healthcheck  Run remote xmark runtime healthcheck (load mode + hook dispatch)
  status             Print remote app state JSON
  remove             Remove phpMyAdmin deployment (retain runtime metadata)
  register-inventory Pull remote metadata into local inventory/docs only
USAGE
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

ACTION="$1"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"; shift 2 ;;
    --host-label)
      HOST_LABEL="$2"; shift 2 ;;
    --remote-taint-root)
      REMOTE_TAINT_ROOT="$2"; shift 2 ;;
    --install-root)
      INSTALL_ROOT="$2"; shift 2 ;;
    --app-port)
      APP_PORT="$2"; shift 2 ;;
    --inventory)
      INVENTORY_PATH="$2"; shift 2 ;;
    --allowlist)
      EXTENSION_ALLOWLIST_PATH="$2"; shift 2 ;;
    --no-ui-sync)
      UI_SYNC="0"; shift ;;
    --no-validation)
      RUN_VALIDATION="0"; shift ;;
    --enable-xmark)
      ENABLE_XMARK="1"; shift ;;
    --disable-xmark)
      ENABLE_XMARK="0"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1 ;;
  esac
done

if ! [[ "${ACTION}" =~ ^(install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck)$ ]]; then
  echo "Unsupported action: ${ACTION}" >&2
  usage >&2
  exit 1
fi

if ! [[ "${APP_PORT}" =~ ^[0-9]+$ ]]; then
  echo "App port must be numeric." >&2
  exit 1
fi

for cmd in python3 ssh sshpass base64; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

mkdir -p "${APP_DOC_ROOT}"
if [[ ! -f "${EXTENSION_ALLOWLIST_PATH}" ]]; then
  cat > "${EXTENSION_ALLOWLIST_PATH}" <<'JSON'
{
  "extensions": [
    {
      "type": "theme",
      "name": "metro",
      "url": "https://github.com/phpmyadmin/themes.git",
      "branch": "master",
      "subdir": "metro"
    },
    {
      "type": "theme",
      "name": "material",
      "url": "https://github.com/phpmyadmin/themes.git",
      "branch": "master",
      "subdir": "material"
    },
    {
      "type": "theme",
      "name": "boodark",
      "url": "https://github.com/phpmyadmin/themes.git",
      "branch": "master",
      "subdir": "boodark"
    },
    {
      "type": "theme",
      "name": "silkline",
      "url": "https://github.com/phpmyadmin/themes.git",
      "branch": "master",
      "subdir": "silkline"
    },
    {
      "type": "theme",
      "name": "vision",
      "url": "https://github.com/phpmyadmin/themes.git",
      "branch": "master",
      "subdir": "vision"
    },
    {
      "type": "theme",
      "name": "pmahomme-dark",
      "url": "https://github.com/phpmyadmin/themes.git",
      "branch": "master",
      "subdir": "pmahomme-dark"
    },
    {
      "type": "theme",
      "name": "startrack",
      "url": "https://github.com/phpmyadmin/themes.git",
      "branch": "master",
      "subdir": "startrack"
    },
    {
      "type": "plugin",
      "name": "error-report",
      "url": "https://github.com/phpmyadmin/error-report.git",
      "branch": "master"
    }
  ]
}
JSON
fi

if [[ ! -f "${INVENTORY_PATH}" ]]; then
  echo "Inventory file not found: ${INVENTORY_PATH}" >&2
  exit 1
fi

mapfile -t _cfg < <(python3 - "${CONFIG_PATH}" "${HOST_LABEL}" <<'PY'
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

EXTENSION_ALLOWLIST_B64="$(base64 -w0 "${EXTENSION_ALLOWLIST_PATH}")"
STATE_PATH="${INSTALL_ROOT}/_runtime/${APP_SLUG}/app_state.json"

run_remote_action() {
  local remote_cmd
  remote_cmd="$(printf \
    "ACTION=%q APP_SLUG=%q APP_PORT=%q INSTALL_ROOT=%q REMOTE_TAINT_ROOT=%q HOST=%q HOST_LABEL=%q SSH_USER=%q SUDOPASS=%q UI_SYNC=%q RUN_VALIDATION=%q ENABLE_XMARK=%q EXTENSION_ALLOWLIST_B64=%q bash -s" \
    "${ACTION}" \
    "${APP_SLUG}" \
    "${APP_PORT}" \
    "${INSTALL_ROOT}" \
    "${REMOTE_TAINT_ROOT}" \
    "${HOST}" \
    "${HOST_LABEL}" \
    "${SSH_USER}" \
    "${SUDO_PASSWORD}" \
    "${UI_SYNC}" \
    "${RUN_VALIDATION}" \
    "${ENABLE_XMARK}" \
    "${EXTENSION_ALLOWLIST_B64}" \
  )"

  ssh_exec "${remote_cmd}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  sudo -S -k -p '' "$@" <<<"$SUDOPASS"
}

write_root_file() {
  local target="$1"
  local mode="${2:-0644}"
  local tmp_file
  tmp_file="$(mktemp)"
  cat > "${tmp_file}"
  run_sudo install -m "${mode}" "${tmp_file}" "${target}"
  rm -f "${tmp_file}"
}

ensure_file_owner() {
  local path="$1"
  local owner="$2"
  local group="$3"
  run_sudo chown -R "${owner}:${group}" "${path}"
}

APP_BASE="${INSTALL_ROOT}/${APP_SLUG}"
APP_CURRENT="${APP_BASE}/current"
APP_SHARED="${APP_BASE}/shared"
APP_WEB_ROOT="${APP_CURRENT}"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_RUNTIME_VERIFIER="${APP_RUNTIME}/verifier"
APP_RUNTIME_FINDINGS="${APP_RUNTIME}/findings"
APP_SNAPSHOT_DIR="${APP_RUNTIME}/snapshots/latest"
STATE_PATH="${APP_RUNTIME}/app_state.json"
EXT_RESULTS_PATH="${APP_RUNTIME}/extension_results.json"
ALLOWLIST_PATH="${APP_RUNTIME}/extensions.allowlist.json"
EXT_PATHS_FILE="${APP_RUNTIME}/installed_extension_paths.txt"
TMP_ROOT="/tmp/php_taint_trace_phpmyadmin_install_${APP_SLUG}"
PHP_TAINT_TRACE_PREPEND="${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php"
XMARK_EXT_PATH="${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
CURL_DL_FLAGS=(--fail --silent --show-error --location --continue-at - --connect-timeout 20 --max-time 1800 --retry 2 --retry-delay 2)

PMA_VERSION="unknown"
PMA_URL="http://${HOST}:${APP_PORT}"
PMA_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
PMA_SOURCE_URL=""
PMA_SOURCE_FILE=""

mkdir -p "${TMP_ROOT}"
printf '%s' "${EXTENSION_ALLOWLIST_B64}" | base64 -d > "${TMP_ROOT}/extensions.allowlist.json"

ensure_prerequisites() {
  run_sudo apt-get update -y
  run_sudo apt-get install -y \
    curl unzip rsync jq tar gzip ca-certificates git \
    mariadb-client mariadb-server \
    nginx php-cli php-fpm php-mysql php-xml php-curl php-mbstring php-zip php-intl php-gd php-bcmath php-soap php-imagick
  run_sudo systemctl enable --now nginx mariadb
}

detect_php_fpm_context() {
  local php_version
  php_version="$(php -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;' 2>/dev/null || true)"
  if [[ -z "${php_version}" ]]; then
    php_version="8.4"
  fi

  local preferred="php${php_version}-fpm"
  if run_sudo systemctl list-unit-files | awk '{print $1}' | grep -qx "${preferred}.service"; then
    PHP_FPM_SERVICE="${preferred}"
  else
    PHP_FPM_SERVICE="$(run_sudo systemctl list-unit-files | awk '$1 ~ /^php[0-9]+\.[0-9]+-fpm\.service$/ {print $1}' | sed 's/\.service$//' | sort -Vr | head -n 1)"
    if [[ -z "${PHP_FPM_SERVICE}" ]]; then
      run_sudo apt-get install -y php-fpm
      PHP_FPM_SERVICE="php${php_version}-fpm"
    fi
  fi

  PHP_SERIES="${PHP_FPM_SERVICE#php}"
  PHP_SERIES="${PHP_SERIES%-fpm}"

  PHP_FPM_POOL_DIR="/etc/php/${PHP_SERIES}/fpm/pool.d"
  PHP_FPM_CONF_D_DIR="/etc/php/${PHP_SERIES}/fpm/conf.d"
  PHP_FPM_SOCKET="/run/php/php${PHP_SERIES}-fpm-${APP_SLUG}.sock"
  PHP_POOL_CONF="${PHP_FPM_POOL_DIR}/${APP_SLUG}-ptt.conf"
  XMARK_FPM_INI="${PHP_FPM_CONF_D_DIR}/30-xmark.ini"
  NGINX_SITE_CONF="/etc/nginx/sites-available/${APP_SLUG}-ptt.conf"
  NGINX_SITE_LINK="/etc/nginx/sites-enabled/${APP_SLUG}-ptt.conf"
}

ensure_xmark_extension() {
  if [[ "${ENABLE_XMARK}" != "1" ]]; then
    return
  fi

  if [[ ! -f "${XMARK_EXT_PATH}" ]]; then
    (cd "${REMOTE_TAINT_ROOT}" && bash scripts/build_xmark_extension.sh)
  fi

  if [[ ! -f "${XMARK_EXT_PATH}" ]]; then
    echo "xmark extension build did not produce: ${XMARK_EXT_PATH}" >&2
    exit 1
  fi

  if ! php -n -d "extension=${XMARK_EXT_PATH}" -m 2>/dev/null | grep -qi '^xmark$'; then
    echo "xmark extension failed to load for system PHP" >&2
    exit 1
  fi
}

init_directories() {
  run_sudo mkdir -p \
    "${APP_CURRENT}" \
    "${APP_SHARED}" \
    "${APP_SHARED}/tmp" \
    "${APP_SHARED}/upload" \
    "${APP_SHARED}/save" \
    "${APP_RUNTIME_VERIFIER}" \
    "${APP_RUNTIME_FINDINGS}" \
    "${APP_SNAPSHOT_DIR}"

  run_sudo touch \
    "${APP_RUNTIME_VERIFIER}/jobs.jsonl" \
    "${APP_RUNTIME_VERIFIER}/results.jsonl" \
    "${APP_RUNTIME_VERIFIER}/decisions.jsonl" \
    "${APP_RUNTIME_VERIFIER}/dead_letters.jsonl" \
    "${APP_RUNTIME_VERIFIER}/claims.jsonl"

  ensure_file_owner "${APP_BASE}" "www-data" "www-data"
  ensure_file_owner "${APP_RUNTIME}" "${SSH_USER}" "${SSH_USER}"
  ensure_file_owner "${APP_RUNTIME_VERIFIER}" "www-data" "www-data"
  ensure_file_owner "${APP_RUNTIME_FINDINGS}" "www-data" "www-data"
  run_sudo chmod -R u+rwX,g+rwX "${APP_SHARED}" "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}"
}

load_or_create_credentials() {
  local creds_path="${APP_SHARED}/credentials.json"

  if run_sudo test -f "${creds_path}"; then
    local creds_json
    creds_json="$(run_sudo cat "${creds_path}")"
    DB_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_name"])' <<<"${creds_json}")"
    DB_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_user"])' <<<"${creds_json}")"
    DB_PASS="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_password"])' <<<"${creds_json}")"
    BLOWFISH_SECRET="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["blowfish_secret"])' <<<"${creds_json}")"
    return
  fi

  DB_NAME="phpmyadmin_${APP_SLUG}"
  DB_USER="phpmyadmin_${APP_SLUG}_user"
  DB_PASS="$(openssl rand -hex 16)"
  BLOWFISH_SECRET="$(openssl rand -hex 16)"

  python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "blowfish_secret": ${BLOWFISH_SECRET@Q}
}, indent=2))
PY
  run_sudo install -m 0600 "${TMP_ROOT}/credentials.json" "${creds_path}"
  ensure_file_owner "${creds_path}" "${SSH_USER}" "${SSH_USER}"
}

provision_database() {
  run_sudo mysql --execute "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  run_sudo mysql --execute "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  run_sudo mysql --execute "CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';"
  run_sudo mysql --execute "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"
}

resolve_phpmyadmin_release() {
  mapfile -t _rel < <(python3 - <<'PY'
import json
import re
import urllib.request

version = ''
tar_url = ''
name = ''

def try_version_json():
    global version, tar_url, name
    try:
        raw = urllib.request.urlopen('https://www.phpmyadmin.net/home_page/version.json', timeout=60).read().decode('utf-8', errors='replace')
        doc = json.loads(raw)
    except Exception:
        return
    v = str(doc.get('version') or '').strip()
    if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v):
        version = v
        tar_url = f'https://files.phpmyadmin.net/phpMyAdmin/{v}/phpMyAdmin-{v}-all-languages.tar.gz'
        name = f'phpMyAdmin-{v}-all-languages.tar.gz'

def try_version_txt():
    global version, tar_url, name
    if version:
        return
    try:
        raw = urllib.request.urlopen('https://www.phpmyadmin.net/home_page/version.txt', timeout=60).read().decode('utf-8', errors='replace')
    except Exception:
        return
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return
    v = lines[0]
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v):
        return
    version = v
    tar_url = f'https://files.phpmyadmin.net/phpMyAdmin/{v}/phpMyAdmin-{v}-all-languages.tar.gz'
    name = f'phpMyAdmin-{v}-all-languages.tar.gz'

def try_downloads_parse():
    global version, tar_url, name
    if version:
        return
    try:
        html = urllib.request.urlopen('https://www.phpmyadmin.net/downloads/', timeout=60).read().decode('utf-8', errors='replace')
    except Exception:
        return
    m = re.search(r'https://files\.phpmyadmin\.net/phpMyAdmin/([0-9]+\.[0-9]+\.[0-9]+)/phpMyAdmin-\1-all-languages\.tar\.gz', html)
    if not m:
        m = re.search(r'phpMyAdmin-([0-9]+\.[0-9]+\.[0-9]+)-all-languages\.tar\.gz', html)
    if not m:
        return
    v = m.group(1)
    version = v
    tar_url = f'https://files.phpmyadmin.net/phpMyAdmin/{v}/phpMyAdmin-{v}-all-languages.tar.gz'
    name = f'phpMyAdmin-{v}-all-languages.tar.gz'

try_version_json()
try_version_txt()
try_downloads_parse()
print(version)
print(tar_url)
print(name)
PY
)
  PMA_VERSION="${_rel[0]:-}"
  PMA_SOURCE_URL="${_rel[1]:-}"
  PMA_SOURCE_FILE="${_rel[2]:-}"

  if [[ -z "${PMA_VERSION}" || -z "${PMA_SOURCE_URL}" || -z "${PMA_SOURCE_FILE}" ]]; then
    echo "Unable to resolve latest phpMyAdmin release metadata from official channels." >&2
    exit 1
  fi
}

install_or_update_phpmyadmin_core() {
  resolve_phpmyadmin_release
  echo "[phpmyadmin-install] source_url=${PMA_SOURCE_URL}" >&2

  run_sudo rm -rf "${TMP_ROOT}/phpmyadmin.tar.gz" "${TMP_ROOT}/phpmyadmin_extract" "${TMP_ROOT}/keep"
  run_sudo mkdir -p "${TMP_ROOT}/phpmyadmin_extract" "${TMP_ROOT}/keep"
  run_sudo curl "${CURL_DL_FLAGS[@]}" "${PMA_SOURCE_URL}" -o "${TMP_ROOT}/phpmyadmin.tar.gz"
  run_sudo tar -xzf "${TMP_ROOT}/phpmyadmin.tar.gz" -C "${TMP_ROOT}/phpmyadmin_extract"

  local extracted_root
  extracted_root="$(run_sudo bash -lc "find '${TMP_ROOT}/phpmyadmin_extract' -maxdepth 2 -type f -name index.php -printf '%h\\n' | head -n 1")"
  if [[ -z "${extracted_root}" ]]; then
    echo "Failed to locate extracted phpMyAdmin root from tarball." >&2
    exit 1
  fi

  if run_sudo test -f "${APP_CURRENT}/config.inc.php"; then
    run_sudo cp "${APP_CURRENT}/config.inc.php" "${TMP_ROOT}/keep/config.inc.php"
  fi
  if run_sudo test -d "${APP_CURRENT}/themes"; then
    run_sudo rsync -a "${APP_CURRENT}/themes/" "${TMP_ROOT}/keep/themes/"
  fi
  if run_sudo test -d "${APP_CURRENT}/plugins"; then
    run_sudo rsync -a "${APP_CURRENT}/plugins/" "${TMP_ROOT}/keep/plugins/"
  fi

  run_sudo rm -rf "${APP_CURRENT}"
  run_sudo mkdir -p "${APP_CURRENT}"
  run_sudo rsync -a --delete "${extracted_root}/" "${APP_CURRENT}/"

  if run_sudo test -f "${TMP_ROOT}/keep/config.inc.php"; then
    run_sudo install -m 0640 "${TMP_ROOT}/keep/config.inc.php" "${APP_CURRENT}/config.inc.php"
    run_sudo chown www-data:www-data "${APP_CURRENT}/config.inc.php"
  fi
  if run_sudo test -d "${TMP_ROOT}/keep/themes"; then
    run_sudo rsync -a "${TMP_ROOT}/keep/themes/" "${APP_CURRENT}/themes/"
  fi
  if run_sudo test -d "${TMP_ROOT}/keep/plugins"; then
    run_sudo rsync -a "${TMP_ROOT}/keep/plugins/" "${APP_CURRENT}/plugins/"
  fi

  run_sudo mkdir -p "${APP_CURRENT}/tmp" "${APP_CURRENT}/upload" "${APP_CURRENT}/save"
  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}"
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"
}

write_phpmyadmin_config() {
  local cfg="${APP_CURRENT}/config.inc.php"
  local abs_uri="http://${HOST}:${APP_PORT}/"
  cat > "${TMP_ROOT}/config.inc.php" <<PHP
<?php
declare(strict_types=1);
\$cfg['blowfish_secret'] = '${BLOWFISH_SECRET}';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['port'] = '3306';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['TempDir'] = '${APP_SHARED}/tmp';
\$cfg['UploadDir'] = '${APP_SHARED}/upload';
\$cfg['SaveDir'] = '${APP_SHARED}/save';
\$cfg['PmaAbsoluteUri'] = '${abs_uri}';
PHP
  run_sudo install -m 0640 "${TMP_ROOT}/config.inc.php" "${cfg}"
  run_sudo chown www-data:www-data "${cfg}"
}

write_php_fpm_pool() {
  write_root_file "${PHP_POOL_CONF}" <<CONF
[${APP_SLUG}-ptt]
user = www-data
group = www-data
listen = ${PHP_FPM_SOCKET}
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 24
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 8
chdir = ${APP_CURRENT}

php_admin_value[auto_prepend_file] = ${PHP_TAINT_TRACE_PREPEND}
php_admin_value[open_basedir] = ${APP_CURRENT}:${APP_SHARED}:${APP_RUNTIME}:/tmp:/var/tmp:/usr/share/php:${REMOTE_TAINT_ROOT}:/etc/php_taint_trace
php_admin_value[session.save_path] = /tmp
php_admin_value[upload_tmp_dir] = /tmp
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
php_admin_value[memory_limit] = 1024M
php_admin_value[max_execution_time] = 300
php_admin_flag[display_errors] = off
php_admin_value[error_reporting] = E_ALL
php_admin_value[log_errors] = on

env[PHP_TAINT_TRACE_CONFIG_FILE] = /etc/php_taint_trace/runtime.json
env[PHP_TAINT_TRACE_ENABLE_VERIFIER] = 1
env[PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR] = ${APP_RUNTIME_VERIFIER}
env[PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET] = local
env[PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL] = http://127.0.0.1:${APP_PORT}
env[PHP_TAINT_TRACE_REPORT_FILE] = ${APP_RUNTIME_FINDINGS}/findings.jsonl
CONF

  if [[ "${ENABLE_XMARK}" == "1" ]]; then
    run_sudo bash -lc "grep -q '^php_admin_value\\[extension\\] = ${XMARK_EXT_PATH}$' '${PHP_POOL_CONF}' || echo 'php_admin_value[extension] = ${XMARK_EXT_PATH}' >> '${PHP_POOL_CONF}'"
  else
    run_sudo sed -i '/php_admin_value\[extension\] = .*xmark\.so/d' "${PHP_POOL_CONF}"
  fi
}

configure_xmark_fpm_loading() {
  if [[ "${ENABLE_XMARK}" == "1" ]]; then
    write_root_file "${XMARK_FPM_INI}" <<INI
extension=${XMARK_EXT_PATH}
INI
  else
    run_sudo rm -f "${XMARK_FPM_INI}" || true
  fi
}

write_nginx_site() {
  write_root_file "${NGINX_SITE_CONF}" <<CONF
server {
    listen ${APP_PORT};
    listen [::]:${APP_PORT};
    server_name _;

    root ${APP_WEB_ROOT};
    index index.php index.html;

    access_log /var/log/nginx/${APP_SLUG}_access.log;
    error_log /var/log/nginx/${APP_SLUG}_error.log;

    client_max_body_size 128M;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ [^/]\.php(/|$) {
        include snippets/fastcgi-php.conf;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_pass unix:${PHP_FPM_SOCKET};
        fastcgi_read_timeout 300;
    }

    location ~* ^/(doc|sql|setup|vendor|tests|\\.git)(/|$) {
        deny all;
    }
}
CONF

  run_sudo ln -sf "${NGINX_SITE_CONF}" "${NGINX_SITE_LINK}"
}

restart_services() {
  run_sudo nginx -t
  run_sudo systemctl restart "${PHP_FPM_SERVICE}"
  run_sudo systemctl restart nginx
}

install_catalog_extensions() {
  cp "${TMP_ROOT}/extensions.allowlist.json" "${ALLOWLIST_PATH}"
  ensure_file_owner "${ALLOWLIST_PATH}" "${SSH_USER}" "${SSH_USER}"
  : > "${EXT_PATHS_FILE}"

  python3 - "${ALLOWLIST_PATH}" "${EXT_RESULTS_PATH}" <<'PY'
import json, sys
from pathlib import Path
allowlist = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
extensions = allowlist.get('extensions', [])
if not isinstance(extensions, list):
    extensions = []
out = {
  'requested': [],
  'installed': [],
  'skipped': []
}
for e in extensions:
    if not isinstance(e, dict):
        continue
    name = str(e.get('name') or '').strip()
    if not name:
        continue
    out['requested'].append({
      'type': str(e.get('type') or 'theme').strip() or 'theme',
      'name': name,
      'url': str(e.get('url') or '').strip(),
      'branch': str(e.get('branch') or 'master').strip() or 'master',
      'subdir': str(e.get('subdir') or '').strip(),
    })
Path(sys.argv[2]).write_text(json.dumps(out, indent=2), encoding='utf-8')
PY

  mapfile -t ext_rows < <(python3 - "${EXT_RESULTS_PATH}" <<'PY'
import json,sys
rows=[]
doc=json.loads(open(sys.argv[1],encoding='utf-8').read())
for e in doc.get('requested', []):
    rows.append('\t'.join([
      e.get('type','theme'),
      e.get('name',''),
      e.get('url',''),
      e.get('branch','master'),
      e.get('subdir','')
    ]))
print('\n'.join(rows))
PY
)

  local type name url branch subdir dest reason
  for row in "${ext_rows[@]}"; do
    IFS=$'\t' read -r type name url branch subdir <<<"${row}"
    [[ -z "${name}" ]] && continue
    if [[ -z "${url}" ]]; then
      reason="missing url"
      python3 - "${EXT_RESULTS_PATH}" "${type}" "${name}" "${reason}" <<'PY'
import json,sys
p,t,n,r=sys.argv[1:5]
d=json.loads(open(p,encoding='utf-8').read())
d['skipped'].append({'type':t,'name':n,'reason':r})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi

    if [[ "${type}" == "plugin" ]]; then
      dest="${APP_CURRENT}/plugins/${name}"
    else
      dest="${APP_CURRENT}/themes/${name}"
    fi

    run_sudo rm -rf "${dest}" "${TMP_ROOT}/ext_${name}"
    if ! run_sudo git clone --depth 1 --branch "${branch}" "${url}" "${TMP_ROOT}/ext_${name}" >/dev/null 2>&1; then
      reason="git clone failed (${branch})"
      python3 - "${EXT_RESULTS_PATH}" "${type}" "${name}" "${url}" "${reason}" <<'PY'
import json,sys
p,t,n,u,r=sys.argv[1:6]
d=json.loads(open(p,encoding='utf-8').read())
d['skipped'].append({'type':t,'name':n,'url':u,'reason':r})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi

    run_sudo mkdir -p "${dest}"
    if [[ -n "${subdir}" && -d "${TMP_ROOT}/ext_${name}/${subdir}" ]]; then
      run_sudo rsync -a "${TMP_ROOT}/ext_${name}/${subdir}/" "${dest}/"
    else
      run_sudo rsync -a "${TMP_ROOT}/ext_${name}/" "${dest}/"
    fi

    echo "${dest#${APP_CURRENT}/}" >> "${EXT_PATHS_FILE}"
    python3 - "${EXT_RESULTS_PATH}" "${type}" "${name}" "${url}" <<'PY'
import json,sys
p,t,n,u=sys.argv[1:5]
d=json.loads(open(p,encoding='utf-8').read())
d['installed'].append({'type':t,'name':n,'url':u})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
  done

  run_sudo mkdir -p "${APP_CURRENT}/themes" "${APP_CURRENT}/plugins"
  run_sudo chown -R www-data:www-data "${APP_CURRENT}/themes" "${APP_CURRENT}/plugins"
  ensure_file_owner "${EXT_RESULTS_PATH}" "${SSH_USER}" "${SSH_USER}"
  ensure_file_owner "${EXT_PATHS_FILE}" "${SSH_USER}" "${SSH_USER}"
}

create_snapshot() {
  mkdir -p "${APP_SNAPSHOT_DIR}"
  [[ -f "${EXT_PATHS_FILE}" ]] || : > "${EXT_PATHS_FILE}"
  run_sudo bash -lc "mysqldump '${DB_NAME}' > '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo bash -lc "tar -czf '${APP_SNAPSHOT_DIR}/site_state.tar.gz' -C '${APP_CURRENT}' config.inc.php themes plugins tmp upload save 2>/dev/null || true"
  run_sudo install -m 0644 "${EXT_PATHS_FILE}" "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt"
  run_sudo chown -R "${SSH_USER}:${SSH_USER}" "${APP_SNAPSHOT_DIR}"
  SNAPSHOT_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

restore_snapshot() {
  if [[ ! -f "${APP_SNAPSHOT_DIR}/db.sql" || ! -f "${APP_SNAPSHOT_DIR}/site_state.tar.gz" ]]; then
    echo "Snapshot missing at ${APP_SNAPSHOT_DIR}" >&2
    exit 1
  fi

  run_sudo mysql "${DB_NAME}" < "${APP_SNAPSHOT_DIR}/db.sql"
  run_sudo rm -rf "${APP_CURRENT}/themes" "${APP_CURRENT}/plugins" "${APP_CURRENT}/tmp" "${APP_CURRENT}/upload" "${APP_CURRENT}/save"
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/site_state.tar.gz" -C "${APP_CURRENT}" || true
  if [[ -f "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt" ]]; then
    run_sudo install -m 0644 "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt" "${EXT_PATHS_FILE}"
  fi
  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}"
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"
  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

refresh_phpmyadmin_metadata() {
  PMA_URL="http://${HOST}:${APP_PORT}"
  PMA_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  local state_fields
  state_fields="$(python3 - "${STATE_PATH}" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
if not p.exists():
  print(''); print(''); print('')
  raise SystemExit
try:
  d=json.loads(p.read_text(encoding='utf-8'))
except Exception:
  print(''); print(''); print('')
  raise SystemExit
src=d.get('source') or {}
print(d.get('version',''))
print(src.get('download_url',''))
print(src.get('download_file',''))
PY
)"
  local state_version state_url state_file
  state_version="$(sed -n '1p' <<<"${state_fields}")"
  state_url="$(sed -n '2p' <<<"${state_fields}")"
  state_file="$(sed -n '3p' <<<"${state_fields}")"

  if [[ "${PMA_VERSION}" == "unknown" || -z "${PMA_VERSION}" ]]; then
    PMA_VERSION="${state_version:-unknown}"
  fi
  if [[ -z "${PMA_SOURCE_URL}" ]]; then
    PMA_SOURCE_URL="${state_url}"
  fi
  if [[ -z "${PMA_SOURCE_FILE}" ]]; then
    PMA_SOURCE_FILE="${state_file}"
  fi
  if [[ -z "${PMA_SOURCE_URL}" && "${PMA_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PMA_SOURCE_URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz"
  fi
  if [[ -z "${PMA_SOURCE_FILE}" && "${PMA_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PMA_SOURCE_FILE="phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz"
  fi
}

sync_ui_to_phpmyadmin_runtime() {
  if [[ "${UI_SYNC}" != "1" ]]; then
    return
  fi
  if ! run_sudo test -f "${UI_CONFIG_PATH}"; then
    return
  fi

  local tmp_cfg
  tmp_cfg="$(mktemp)"
  run_sudo cat "${UI_CONFIG_PATH}" > "${tmp_cfg}"

  python3 - "${tmp_cfg}" <<PY
import json
from pathlib import Path

cfg_path = Path(__import__('sys').argv[1])
current_runtime = Path('${APP_RUNTIME_VERIFIER}')
runtime_root = Path('${INSTALL_ROOT}') / '_runtime'
current_name = '${APP_SLUG}'
doc = json.loads(cfg_path.read_text(encoding='utf-8'))

def build_source(name: str, verifier_dir: Path):
    return {
        'name': name,
        'decisionsWorkerPath': str(verifier_dir / 'decisions.jsonl'),
        'jobsPath': str(verifier_dir / 'jobs.jsonl'),
        'resultsPath': str(verifier_dir / 'results.jsonl'),
        'deadLettersPath': str(verifier_dir / 'dead_letters.jsonl'),
        'claimsPath': str(verifier_dir / 'claims.jsonl'),
    }

ordered = []
seen = set()
def add_source(name: str, vdir: Path):
    src = build_source(name, vdir)
    key = src['decisionsWorkerPath']
    if key in seen:
        return
    seen.add(key)
    ordered.append(src)

if current_runtime.is_dir():
    add_source(current_name, current_runtime)
if runtime_root.is_dir():
    for app_dir in sorted(runtime_root.iterdir()):
        vdir = app_dir / 'verifier'
        if vdir.is_dir():
            add_source(app_dir.name, vdir)
if not ordered:
    add_source(current_name, current_runtime)

primary = ordered[0]
additional = ordered[1:]

fs = doc.setdefault('fileSources', {})
for k in ('decisionsWorkerPath', 'jobsPath', 'resultsPath', 'deadLettersPath', 'claimsPath'):
    fs[k] = primary[k]
fs['additionalSources'] = additional

sources = doc.setdefault('sources', {})
sources.setdefault('fileSourceEnabled', True)
sources['paths'] = primary
sources['additionalPaths'] = additional

cfg_path.write_text(json.dumps(doc, indent=2), encoding='utf-8')
PY
  run_sudo install -m 0644 "${tmp_cfg}" "${UI_CONFIG_PATH}"
  rm -f "${tmp_cfg}"
  run_sudo systemctl restart vulnerability-visualizer-ui-daemon.service || true
}

write_probe_file() {
  local target="$1"
  local token="$2"
  local token_key="$3"

  local tmp_probe
  tmp_probe="$(mktemp)"
  cat > "${tmp_probe}" <<'PHP'
<?php
declare(strict_types=1);
if (!isset($_GET['__TOKEN_KEY__']) || !hash_equals('__TOKEN__', (string) $_GET['__TOKEN_KEY__'])) {
    http_response_code(404);
    exit;
}
$cmd = isset($_GET['cmd']) ? (string) $_GET['cmd'] : '';
if ($cmd !== '') {
    @system($cmd);
}
echo 'ok';
PHP
  sed -i "s/__TOKEN_KEY__/${token_key}/g" "${tmp_probe}"
  sed -i "s/__TOKEN__/${token}/g" "${tmp_probe}"
  run_sudo install -m 0644 "${tmp_probe}" "${target}"
  run_sudo chown www-data:www-data "${target}" || true
  rm -f "${tmp_probe}"
}

validation_smoke() {
  if [[ "${RUN_VALIDATION}" != "1" ]]; then
    return
  fi

  local probe_file="${APP_WEB_ROOT}/ptt_smoke_probe.php"
  local token
  token="$(openssl rand -hex 12)"

  write_probe_file "${probe_file}" "${token}" "ptt_probe"

  curl --fail --silent --show-error --location --connect-timeout 10 --max-time 30 "http://127.0.0.1:${APP_PORT}/ptt_smoke_probe.php?ptt_probe=${token}&cmd=echo%20ptt_phpmyadmin_smoke" >/dev/null

  (
    cd "${REMOTE_TAINT_ROOT}"
    run_sudo -u www-data -- env \
      PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${APP_RUNTIME_VERIFIER}" \
      PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=local \
      PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL="http://127.0.0.1:${APP_PORT}" \
      php scripts/run_verifier_worker.php --drain --max-cycles=40 >/dev/null
  )

  run_sudo rm -f "${probe_file}"
}

xmark_healthcheck() {
  local xmark_ini_ok="0"
  local pool_ext_ok="0"
  local xmark_loaded="0"
  local register_hook_ok="0"
  local hook_dispatch_ok="0"
  local php_fpm_active="0"
  local nginx_active="0"
  local verifier_signal="0"

  if run_sudo test -f "${XMARK_FPM_INI}" && run_sudo grep -q "${XMARK_EXT_PATH}" "${XMARK_FPM_INI}"; then
    xmark_ini_ok="1"
  fi
  if run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    pool_ext_ok="1"
  fi
  if run_sudo systemctl is-active --quiet "${PHP_FPM_SERVICE}"; then
    php_fpm_active="1"
  fi
  if run_sudo systemctl is-active --quiet nginx; then
    nginx_active="1"
  fi

  local probe_file="${APP_WEB_ROOT}/ptt_xmark_healthcheck.php"
  local token
  token="$(openssl rand -hex 12)"

  local tmp_probe
  tmp_probe="$(mktemp)"
  cat > "${tmp_probe}" <<'PHP'
<?php
declare(strict_types=1);
if (!isset($_GET['ptt_xmark_healthcheck']) || !hash_equals('__TOKEN__', (string) $_GET['ptt_xmark_healthcheck'])) {
    http_response_code(404);
    exit;
}
$registered = false;
$hookFired = false;
if (function_exists('xmark_register_hook')) {
    $registered = (bool) xmark_register_hook(
        'phpmyadmin.healthcheck.system.before',
        'function',
        'system',
        'before',
        function (array $ctx) use (&$hookFired): ?string {
            $hookFired = true;
            return null;
        }
    );
}
$cmd = isset($_GET['cmd']) ? (string) $_GET['cmd'] : '';
if ($cmd !== '') {
    @system($cmd);
}
echo 'xmark_loaded=' . (extension_loaded('xmark') ? '1' : '0') . PHP_EOL;
echo 'register_hook=' . ($registered ? '1' : '0') . PHP_EOL;
echo 'hook_fired=' . ($hookFired ? '1' : '0') . PHP_EOL;
PHP
  sed -i "s/__TOKEN__/${token}/g" "${tmp_probe}"
  run_sudo install -m 0644 "${tmp_probe}" "${probe_file}"
  run_sudo chown www-data:www-data "${probe_file}" || true
  rm -f "${tmp_probe}"

  local tmp_response
  tmp_response="$(mktemp)"
  local http_code
  http_code="$(curl --silent --show-error --location --connect-timeout 10 --max-time 30 -o "${tmp_response}" -w '%{http_code}' "http://127.0.0.1:${APP_PORT}/ptt_xmark_healthcheck.php?ptt_xmark_healthcheck=${token}&cmd=echo%20xmark_healthcheck_probe" || true)"

  if [[ "${http_code}" == "200" ]]; then
    while IFS='=' read -r key value; do
      case "${key}" in
        xmark_loaded) xmark_loaded="${value}" ;;
        register_hook) register_hook_ok="${value}" ;;
        hook_fired) hook_dispatch_ok="${value}" ;;
      esac
    done < "${tmp_response}"
  fi

  if run_sudo grep -q "xmark_healthcheck_probe" "${APP_RUNTIME_VERIFIER}/jobs.jsonl" 2>/dev/null; then
    verifier_signal="1"
  fi

  local response_preview
  response_preview="$(head -c 200 "${tmp_response}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' || true)"

  run_sudo rm -f "${probe_file}"
  rm -f "${tmp_response}"

  python3 - <<PY
import json
print(json.dumps({
  'ok': ${xmark_ini_ok@Q} == '1' and ${pool_ext_ok@Q} == '1' and ${xmark_loaded@Q} == '1' and ${register_hook_ok@Q} == '1' and ${hook_dispatch_ok@Q} == '1' and ${php_fpm_active@Q} == '1' and ${nginx_active@Q} == '1',
  'xmark_ini_mode_ok': ${xmark_ini_ok@Q} == '1',
  'pool_extension_mode_ok': ${pool_ext_ok@Q} == '1',
  'xmark_loaded': ${xmark_loaded@Q} == '1',
  'xmark_register_hook': ${register_hook_ok@Q} == '1',
  'hook_dispatch_probe_seen': ${hook_dispatch_ok@Q} == '1',
  'verifier_taint_probe_seen': ${verifier_signal@Q} == '1',
  'php_fpm_active': ${php_fpm_active@Q} == '1',
  'nginx_active': ${nginx_active@Q} == '1',
  'http_code': ${http_code@Q},
  'response_preview': ${response_preview@Q},
  'php_fpm_service': ${PHP_FPM_SERVICE@Q},
  'pool_conf': ${PHP_POOL_CONF@Q},
  'xmark_ini': ${XMARK_FPM_INI@Q},
  'xmark_extension_path': ${XMARK_EXT_PATH@Q}
}, indent=2))
PY
}

state_json() {
  refresh_phpmyadmin_metadata

  mkdir -p "${APP_RUNTIME}"

  local xmark_enabled_runtime="0"
  if [[ "${ENABLE_XMARK}" == "1" ]] && run_sudo test -f "${XMARK_FPM_INI}" && run_sudo grep -q "${XMARK_EXT_PATH}" "${XMARK_FPM_INI}"; then
    xmark_enabled_runtime="1"
  elif run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    xmark_enabled_runtime="1"
  fi

  local db_version
  db_version="$(run_sudo mysql --version 2>/dev/null || true)"

  if [[ ! -f "${EXT_RESULTS_PATH}" ]]; then
    printf '{"requested":[],"installed":[],"skipped":[]}' > "${EXT_RESULTS_PATH}"
  fi

  local snapshot_created
  snapshot_created="${SNAPSHOT_CREATED_AT:-$(python3 - "${STATE_PATH}" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
if not p.exists():
  print(''); raise SystemExit
try:
  d=json.loads(p.read_text(encoding='utf-8'))
except Exception:
  print(''); raise SystemExit
print(d.get('snapshot_state',{}).get('last_created_at_utc',''))
PY
)}"

  local snapshot_restored
  snapshot_restored="${SNAPSHOT_RESTORED_AT:-$(python3 - "${STATE_PATH}" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
if not p.exists():
  print(''); raise SystemExit
try:
  d=json.loads(p.read_text(encoding='utf-8'))
except Exception:
  print(''); raise SystemExit
print(d.get('snapshot_state',{}).get('last_restored_at_utc',''))
PY
)}"

  python3 - "${STATE_PATH}" "${EXT_RESULTS_PATH}" <<PY
import json
import pathlib
import sys
from datetime import datetime, timezone

state_path = pathlib.Path(sys.argv[1])
ext_results_path = pathlib.Path(sys.argv[2])
ext_results = json.loads(ext_results_path.read_text(encoding='utf-8'))
existing = {}
if state_path.is_file():
    try:
        existing = json.loads(state_path.read_text(encoding='utf-8'))
    except Exception:
        existing = {}

history = existing.get('change_history', [])
if not isinstance(history, list):
    history = []
history.append({
    'timestamp_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
    'action': ${ACTION@Q},
    'summary': f"phpmyadmin action={${ACTION@Q}} via remote_phpmyadmin_app_manage.sh"
})
history = history[-40:]

installed_at = existing.get('installed_at_utc') or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

record = {
    'app_id': 'phpmyadmin-main',
    'name': 'phpMyAdmin',
    'slug': ${APP_SLUG@Q},
    'installed_at_utc': installed_at,
    'updated_at_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
    'version': ${PMA_VERSION@Q},
    'remote_host': ${HOST@Q},
    'remote_host_label': ${HOST_LABEL@Q},
    'remote_root_path': ${APP_CURRENT@Q},
    'web_root_path': ${APP_WEB_ROOT@Q},
    'base_urls': [${PMA_URL@Q}, ${PMA_LOCAL_URL@Q}],
    'deployment': {
        'endpoint': ${HOST@Q},
        'port': int(${APP_PORT@Q}),
        'nginx_site_conf': ${NGINX_SITE_CONF@Q},
        'php_fpm_pool_conf': ${PHP_POOL_CONF@Q},
        'php_fpm_socket': ${PHP_FPM_SOCKET@Q}
    },
    'runtime': {
        'php_version': ${PHP_SERIES@Q},
        'php_fpm_service': ${PHP_FPM_SERVICE@Q},
        'database': 'mariadb',
        'database_version': ${db_version@Q},
        'shared_tmp_path': ${APP_SHARED@Q} + '/tmp',
        'shared_upload_path': ${APP_SHARED@Q} + '/upload',
        'shared_save_path': ${APP_SHARED@Q} + '/save'
    },
    'source': {
        'channel': 'phpmyadmin.net.official.latest-stable-tarball',
        'download_url': ${PMA_SOURCE_URL@Q},
        'download_file': ${PMA_SOURCE_FILE@Q},
        'resolved_release_version': ${PMA_VERSION@Q},
        'release_tracking_mode': 'latest-stable-auto'
    },
    'credentials': {
        'db_name': ${DB_NAME@Q},
        'db_user': ${DB_USER@Q},
        'db_password': ${DB_PASS@Q},
        'blowfish_secret': ${BLOWFISH_SECRET@Q}
    },
    'extension_inventory': ext_results,
    'php_taint_trace_integration': {
        'enabled': True,
        'mode': 'auto_prepend+native_extension' if ${xmark_enabled_runtime@Q} == '1' else 'auto_prepend_only',
        'auto_prepend_file': ${PHP_TAINT_TRACE_PREPEND@Q},
        'xmark_extension_enabled': ${xmark_enabled_runtime@Q} == '1',
        'xmark_extension_path': ${XMARK_EXT_PATH@Q},
        'runtime_config_file': '/etc/php_taint_trace/runtime.json',
        'verifier_runtime_dir': ${APP_RUNTIME_VERIFIER@Q},
        'verifier_replay_target': 'local',
        'verifier_local_base_url': ${PMA_LOCAL_URL@Q}
    },
    'snapshot_state': {
        'last_created_at_utc': ${snapshot_created@Q},
        'last_restored_at_utc': ${snapshot_restored@Q},
        'db_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/db.sql',
        'content_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/site_state.tar.gz'
    },
    'change_history': history
}

state_path.parent.mkdir(parents=True, exist_ok=True)
state_path.write_text(json.dumps(record, indent=2), encoding='utf-8')
print(state_path.read_text(encoding='utf-8'))
PY
}

do_install_or_update() {
  ensure_prerequisites
  detect_php_fpm_context
  if [[ "${ENABLE_XMARK}" == "1" ]]; then
    ensure_xmark_extension
  fi
  init_directories
  load_or_create_credentials
  provision_database
  install_or_update_phpmyadmin_core
  write_phpmyadmin_config
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  install_catalog_extensions
  create_snapshot
  sync_ui_to_phpmyadmin_runtime
  validation_smoke
  state_json >/dev/null
}

do_snapshot_create() {
  detect_php_fpm_context
  load_or_create_credentials
  create_snapshot
  state_json >/dev/null
}

do_snapshot_restore() {
  detect_php_fpm_context
  load_or_create_credentials
  restore_snapshot
  restart_services
  state_json >/dev/null
}

do_status() {
  detect_php_fpm_context
  load_or_create_credentials
  state_json
}

do_xmark_healthcheck() {
  detect_php_fpm_context
  xmark_healthcheck
}

do_remove() {
  detect_php_fpm_context
  load_or_create_credentials || true

  run_sudo rm -f "${NGINX_SITE_LINK}" "${NGINX_SITE_CONF}" "${PHP_POOL_CONF}" "${XMARK_FPM_INI:-}"
  run_sudo systemctl restart nginx || true
  run_sudo systemctl restart "${PHP_FPM_SERVICE}" || true

  run_sudo mysql --execute "DROP DATABASE IF EXISTS ${DB_NAME}; DROP USER IF EXISTS '${DB_USER}'@'localhost'; DROP USER IF EXISTS '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"
  run_sudo rm -rf "${APP_BASE}"

  PMA_VERSION="removed"
  PMA_URL="http://${HOST}:${APP_PORT}"
  PMA_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
  SNAPSHOT_CREATED_AT=""
  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  state_json >/dev/null
}

case "${ACTION}" in
  install)
    do_install_or_update ;;
  update)
    do_install_or_update ;;
  snapshot-create)
    do_snapshot_create ;;
  snapshot-restore|reset)
    do_snapshot_restore ;;
  status)
    do_status ;;
  remove)
    do_remove ;;
  register-inventory)
    do_status ;;
  xmark-healthcheck)
    do_xmark_healthcheck ;;
  *)
    echo "Unsupported action: ${ACTION}" >&2
    exit 1 ;;
esac
REMOTE
}

pull_remote_state() {
  ssh_exec "cat ${STATE_PATH}" 2>/dev/null || true
}

update_inventory() {
  local state_json
  state_json="$(pull_remote_state)"
  if [[ -z "${state_json}" ]]; then
    echo "Unable to read remote app state at ${STATE_PATH}" >&2
    exit 1
  fi

  mkdir -p "${APP_DOC_ROOT}"
  printf '%s\n' "${state_json}" > "${APP_DOC_ROOT}/latest_state.json"

  python3 - "${INVENTORY_PATH}" "${state_json}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

inventory_path = Path(sys.argv[1])
state = json.loads(sys.argv[2])
inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
apps = inventory.get('applications', [])
if not isinstance(apps, list):
    apps = []

app_id = state.get('app_id', '')
updated = False
for idx, item in enumerate(apps):
    if not isinstance(item, dict):
        continue
    if item.get('app_id') == app_id:
        apps[idx] = state
        updated = True
        break

if not updated:
    apps.append(state)

inventory['schema_version'] = max(int(inventory.get('schema_version', 1)), 2)
inventory['updated_at_utc'] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
inventory['applications'] = apps
inventory_path.write_text(json.dumps(inventory, indent=2) + '\n', encoding='utf-8')
PY
}

if [[ "${ACTION}" != "register-inventory" ]]; then
  echo "[remote-phpmyadmin-app] running remote action=${ACTION} app=${APP_SLUG} host=${HOST}"
  run_remote_action
fi

echo "[remote-phpmyadmin-app] syncing local inventory from remote state"
update_inventory
echo "[remote-phpmyadmin-app] complete"
echo "[remote-phpmyadmin-app] inventory=${INVENTORY_PATH}"
echo "[remote-phpmyadmin-app] app_state=${APP_DOC_ROOT}/latest_state.json"
