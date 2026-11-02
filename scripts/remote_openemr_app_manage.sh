#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19154"
APP_SLUG="openemr"
UI_SYNC="1"
RUN_VALIDATION="1"
ENABLE_XMARK="1"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
EXTENSION_ALLOWLIST_PATH="${ROOT_DIR}/remote_linux_container/installed_php_applications/apps/${APP_SLUG}/extensions.allowlist.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_openemr_app_manage.sh <install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck> [options]

Options:
  --config PATH               External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL          Host label in config (default: lab.example.invalid)
  --remote-taint-root PATH    Remote php_taint_trace repo root (default: /opt/php_taint_trace_vuln_lab/rewrite)
  --install-root PATH         Remote multi-app install root (default: /opt/php_audit_apps)
  --app-port PORT             OpenEMR port (default: 19154)
  --inventory PATH            External inventory path (default: PHP_TAINT_TRACE_INVENTORY_PATH or XDG state directory)
  --allowlist PATH            Extension allowlist JSON path
  --no-ui-sync                Do not sync UI file sources with this app runtime
  --no-validation             Skip install-time taint/verifier smoke validation
  --enable-xmark              Load xmark extension for PHP-FPM worker startup (default: on)
  --disable-xmark             Disable xmark extension loading for PHP-FPM
  -h, --help                  Show help

Actions:
  install            Install or reconcile OpenEMR + runtime integration
  update             Update OpenEMR core/extensions and refresh metadata
  reset              Restore latest baseline snapshot
  snapshot-create    Create baseline snapshot
  snapshot-restore   Restore baseline snapshot
  xmark-healthcheck  Run remote xmark runtime healthcheck (load mode + hook dispatch)
  status             Print remote app state JSON
  remove             Remove OpenEMR deployment (retain runtime metadata)
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
    { "name": "oe-module-faxsms", "type": "git-zip", "source_url": "https://github.com/openemr/oe-module-faxsms/archive/refs/heads/master.zip" },
    { "name": "oe-module-zend_modules", "type": "git-zip", "source_url": "https://github.com/openemr/oe-module-zend_modules/archive/refs/heads/master.zip" },
    { "name": "oe-module-cqm", "type": "git-zip", "source_url": "https://github.com/openemr/oe-module-cqm/archive/refs/heads/master.zip" }
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

LOCK_FILE="/tmp/php_taint_trace_${APP_SLUG}_manage.lock"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "Another ${APP_SLUG} manager run is already active (lock: ${LOCK_FILE})." >&2
  exit 99
fi

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
  run_sudo chown -R "${owner}:${group}" "${path}" || true
}

APP_BASE="${INSTALL_ROOT}/${APP_SLUG}"
APP_CURRENT="${APP_BASE}/current"
APP_SHARED="${APP_BASE}/shared"
APP_WEB_ROOT="${APP_CURRENT}"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_RUNTIME_VERIFIER="${APP_RUNTIME}/verifier"
APP_RUNTIME_FINDINGS="${APP_RUNTIME}/findings"
APP_SNAPSHOT_DIR="${APP_RUNTIME}/snapshots/latest"
COMPOSER_HOME_DIR="${APP_SHARED}/composer-home"
COMPOSER_CACHE_DIR="${APP_SHARED}/composer-cache"
STATE_PATH="${APP_RUNTIME}/app_state.json"
EXT_RESULTS_PATH="${APP_RUNTIME}/extension_results.json"
ALLOWLIST_PATH="${APP_RUNTIME}/extensions.allowlist.json"
EXT_PATHS_FILE="${APP_RUNTIME}/installed_extension_paths.txt"
TMP_ROOT="/tmp/php_taint_trace_openemr_install_${APP_SLUG}"
PHP_TAINT_TRACE_PREPEND="${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php"
XMARK_EXT_PATH="${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
CURL_DL_FLAGS=(--fail --silent --show-error --location --connect-timeout 20 --max-time 300 --retry 2 --retry-delay 2)
COMPOSER_BIN="/usr/local/bin/composer-ptt"

OPENEMR_VERSION="unknown"
OPENEMR_URL="http://${HOST}:${APP_PORT}"
OPENEMR_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
OPENEMR_SOURCE_URL=""
OPENEMR_SOURCE_FILE=""

mkdir -p "${TMP_ROOT}"
printf '%s' "${EXTENSION_ALLOWLIST_B64}" | base64 -d > "${TMP_ROOT}/extensions.allowlist.json"

ensure_prerequisites() {
  run_sudo systemctl enable --now nginx mariadb || true
  if ! run_sudo test -x "${COMPOSER_BIN}" || ! run_sudo php "${COMPOSER_BIN}" --version >/dev/null 2>&1; then
    run_sudo rm -f "${COMPOSER_BIN}" || true
    run_sudo bash -lc "set -euo pipefail; tmp_installer=\$(mktemp /tmp/composer-installer.XXXXXX.php); trap 'rm -f \"\${tmp_installer}\"' EXIT; curl --fail --silent --show-error --location 'https://getcomposer.org/installer' -o \"\${tmp_installer}\"; php \"\${tmp_installer}\" --quiet --install-dir='/usr/local/bin' --filename='composer-ptt'; chmod 0755 '${COMPOSER_BIN}'"
    run_sudo php "${COMPOSER_BIN}" --version >/dev/null
  fi
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
    "${APP_SHARED}/extensions" \
    "${COMPOSER_HOME_DIR}" \
    "${COMPOSER_CACHE_DIR}" \
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
  ensure_file_owner "${COMPOSER_HOME_DIR}" "www-data" "www-data"
  ensure_file_owner "${COMPOSER_CACHE_DIR}" "www-data" "www-data"
  ensure_file_owner "${APP_RUNTIME_VERIFIER}" "www-data" "www-data"
  ensure_file_owner "${APP_RUNTIME_FINDINGS}" "www-data" "www-data"
  run_sudo chmod -R u+rwX,g+rwX "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}" "${APP_SHARED}" "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}"
}

load_or_create_credentials() {
  local creds_path="${APP_SHARED}/credentials.json"

  if run_sudo test -f "${creds_path}"; then
    local creds_json
    creds_json="$(run_sudo cat "${creds_path}")"
    DB_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_name"])' <<<"${creds_json}")"
    DB_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_user"])' <<<"${creds_json}")"
    DB_PASS="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_password"])' <<<"${creds_json}")"
    ADMIN_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_name"])' <<<"${creds_json}")"
    ADMIN_EMAIL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_email"])' <<<"${creds_json}")"
    ADMIN_PASSWORD="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_password"])' <<<"${creds_json}")"
    ADMIN_USERNAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("admin_username", ""))' <<<"${creds_json}")"
    ADMIN_FIRST_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("admin_first_name", "Audit"))' <<<"${creds_json}")"
    ADMIN_LAST_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("admin_last_name", "Admin"))' <<<"${creds_json}")"
    APP_KEY="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("app_key", ""))' <<<"${creds_json}")"
    if [[ -z "${ADMIN_USERNAME}" ]]; then
      ADMIN_USERNAME="openemr_admin_${APP_SLUG}"
    fi
    return
  fi

  DB_NAME="openemr_${APP_SLUG}"
  DB_USER="openemr_${APP_SLUG}_user"
  DB_PASS="$(openssl rand -hex 16)"
  ADMIN_NAME="OpenEMR Audit Admin"
  ADMIN_USERNAME="openemr_admin_${APP_SLUG}"
  ADMIN_FIRST_NAME="Audit"
  ADMIN_LAST_NAME="Admin"
  ADMIN_EMAIL="audit+${APP_SLUG}@local.invalid"
  ADMIN_PASSWORD="$(openssl rand -hex 14)"
  APP_KEY=""

  python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "admin_name": ${ADMIN_NAME@Q},
  "admin_username": ${ADMIN_USERNAME@Q},
  "admin_first_name": ${ADMIN_FIRST_NAME@Q},
  "admin_last_name": ${ADMIN_LAST_NAME@Q},
  "admin_email": ${ADMIN_EMAIL@Q},
  "admin_password": ${ADMIN_PASSWORD@Q},
  "app_key": ${APP_KEY@Q}
}, indent=2))
PY
  run_sudo install -m 0600 "${TMP_ROOT}/credentials.json" "${creds_path}"
  ensure_file_owner "${creds_path}" "${SSH_USER}" "${SSH_USER}"
}

persist_credentials() {
  local creds_path="${APP_SHARED}/credentials.json"
  python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "admin_name": ${ADMIN_NAME@Q},
  "admin_username": ${ADMIN_USERNAME@Q},
  "admin_first_name": ${ADMIN_FIRST_NAME@Q},
  "admin_last_name": ${ADMIN_LAST_NAME@Q},
  "admin_email": ${ADMIN_EMAIL@Q},
  "admin_password": ${ADMIN_PASSWORD@Q},
  "app_key": ${APP_KEY@Q}
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

resolve_openemr_release() {
  run_sudo bash -lc "curl --fail --silent --show-error --location --connect-timeout 20 --max-time 60 -H 'User-Agent: php-taint-trace-openemr-installer' 'https://api.github.com/repos/openemr/openemr/tags?per_page=200' > '${TMP_ROOT}/openemr_tags.json'"

  mapfile -t _release < <(python3 - "${TMP_ROOT}/openemr_tags.json" <<'PY'
import json
import re
import sys
from pathlib import Path

doc = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
best = None

def parse_tag(tag: str):
    # OpenEMR stable tags look like v8_0_0_3
    m = re.match(r"^[vV](\d+)_(\d+)_(\d+)(?:_(\d+))?$", tag)
    if not m:
        return None
    major, minor, patch, hotfix = m.groups()
    return (int(major), int(minor), int(patch), int(hotfix or 0))

for row in doc:
    if not isinstance(row, dict):
        continue
    tag = str(row.get('name') or '').strip()
    parsed = parse_tag(tag)
    if not parsed:
        continue
    if best is None or parsed > best[0]:
        best = (parsed, tag)

if best is None:
    raise SystemExit('No stable OpenEMR tag found from GitHub API.')

_, tag = best
asset_url = f"https://github.com/openemr/openemr/archive/refs/tags/{tag}.tar.gz"
asset_name = f"openemr-{tag}.tar.gz"
print(tag)
print(asset_url)
print(asset_name)
PY
)

  OPENEMR_VERSION="${_release[0]}"
  OPENEMR_SOURCE_URL="${_release[1]}"
  OPENEMR_SOURCE_FILE="${_release[2]}"
}

install_or_update_openemr_core() {
  local composer_log="/tmp/openemr_composer_${APP_SLUG}.log"
  local extracted_root=""
  local nonce
  nonce="$(date +%s)_$RANDOM"
  local keep_dir="${TMP_ROOT}/keep_${nonce}"
  local pkg_path="${TMP_ROOT}/openemr_${nonce}.pkg"
  local extract_dir="${TMP_ROOT}/openemr_extract_${nonce}"
  local cache_pkg_path=""

  resolve_openemr_release
  echo "[openemr-install] source_url=${OPENEMR_SOURCE_URL}" >&2
  cache_pkg_path="${TMP_ROOT}/${OPENEMR_SOURCE_FILE:-openemr_cached.pkg}"

  # Remove prior transient artifacts from failed or interrupted runs.
  run_sudo find "${TMP_ROOT}" -maxdepth 1 -mindepth 1 \
    \( -name 'openemr_*.pkg' -o -name 'openemr_extract_*' -o -name 'keep_*' \) \
    -exec rm -rf {} + 2>/dev/null || true

  run_sudo mkdir -p "${APP_BASE}" "${APP_SHARED}" "${APP_SHARED}/tmp" "${APP_SHARED}/extensions"
  run_sudo chown -R www-data:www-data "${APP_BASE}" "${APP_SHARED}"

  run_sudo mkdir -p "${extract_dir}" "${keep_dir}"
  if run_sudo test -s "${cache_pkg_path}"; then
    run_sudo cp "${cache_pkg_path}" "${pkg_path}"
  else
    run_sudo curl --fail --silent --show-error --location --connect-timeout 20 --max-time 7200 "${OPENEMR_SOURCE_URL}" -o "${pkg_path}"
    run_sudo cp "${pkg_path}" "${cache_pkg_path}" || true
  fi
  case "${OPENEMR_SOURCE_FILE,,}" in
    *.zip)
      run_sudo unzip -q "${pkg_path}" -d "${extract_dir}"
      ;;
    *.tar.gz|*.tgz)
      run_sudo tar -xzf "${pkg_path}" -C "${extract_dir}"
      ;;
    *)
      echo "Unsupported OpenEMR package type: ${OPENEMR_SOURCE_FILE}" >&2
      exit 1
      ;;
  esac

  extracted_root="${extract_dir}"
  if ! run_sudo test -f "${extracted_root}/setup.php"; then
    extracted_root="$(run_sudo bash -lc "find '${extract_dir}' -mindepth 1 -maxdepth 2 -type f -name setup.php -printf '%h\n' | head -n 1")"
  fi
  if [[ -z "${extracted_root}" ]] || ! run_sudo test -f "${extracted_root}/setup.php"; then
    echo "Failed to locate extracted OpenEMR root from release payload." >&2
    exit 1
  fi

  if run_sudo test -f "${APP_CURRENT}/sites/default/sqlconf.php"; then
    run_sudo mkdir -p "${keep_dir}/sites/default"
    run_sudo cp "${APP_CURRENT}/sites/default/sqlconf.php" "${keep_dir}/sites/default/sqlconf.php"
  fi
  if run_sudo test -d "${APP_CURRENT}/sites/default/documents"; then
    run_sudo mkdir -p "${keep_dir}/sites/default/documents"
    run_sudo rsync -a "${APP_CURRENT}/sites/default/documents/" "${keep_dir}/sites/default/documents/"
  fi

  run_sudo rm -rf "${APP_CURRENT}"
  run_sudo mkdir -p "${APP_CURRENT}"
  run_sudo rsync -a --delete "${extracted_root}/" "${APP_CURRENT}/"

  if run_sudo test -f "${keep_dir}/sites/default/sqlconf.php"; then
    run_sudo mkdir -p "${APP_CURRENT}/sites/default"
    run_sudo install -m 0640 "${keep_dir}/sites/default/sqlconf.php" "${APP_CURRENT}/sites/default/sqlconf.php"
  fi
  if run_sudo test -d "${keep_dir}/sites/default/documents"; then
    run_sudo mkdir -p "${APP_CURRENT}/sites/default/documents"
    run_sudo rsync -a "${keep_dir}/sites/default/documents/" "${APP_CURRENT}/sites/default/documents/"
  fi

  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"

  if ! run_sudo test -f "${APP_CURRENT}/vendor/autoload.php"; then
    local composer_try=1
    local composer_max_tries=5
    local composer_ok=0
    run_sudo rm -f "${composer_log}" || true
    while (( composer_try <= composer_max_tries )); do
      # Normalize vendor ownership/state before each retry to avoid partial-tree failures.
      run_sudo rm -rf "${APP_CURRENT}/vendor" || true
      run_sudo mkdir -p "${APP_CURRENT}/vendor"
      run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
      run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}" || true

      local composer_env="HOME=${APP_SHARED} COMPOSER_HOME=${COMPOSER_HOME_DIR} COMPOSER_CACHE_DIR=${COMPOSER_CACHE_DIR} COMPOSER_DISABLE_XDEBUG_WARN=1 COMPOSER_MEMORY_LIMIT=-1 COMPOSER_MAX_PARALLEL_HTTP=2 COMPOSER_MAX_PARALLEL_PROCESSES=2 COMPOSER_PROCESS_TIMEOUT=900 COMPOSER_ALLOW_SUPERUSER=1"
      if run_sudo timeout 2400 bash -lc "cd '${APP_CURRENT}' && ${composer_env} '${COMPOSER_BIN}' install --no-interaction --prefer-source --no-dev --no-progress >'${composer_log}' 2>&1"; then
        composer_ok=1
        break
      fi
      echo "Composer install attempt ${composer_try}/${composer_max_tries} failed while preparing OpenEMR release payload." >&2
      run_sudo tail -n 80 "${composer_log}" >&2 || true
      composer_try=$((composer_try + 1))
      sleep 10
    done
    if (( composer_ok != 1 )); then
      echo "Composer install failed after ${composer_max_tries} attempts." >&2
      run_sudo tail -n 160 "${composer_log}" >&2 || true
      exit 1
    fi
  fi
  run_sudo bash -lc "cd '${APP_CURRENT}' && COMPOSER_ALLOW_SUPERUSER=1 '${COMPOSER_BIN}' dump-autoload -o >/dev/null" || true

  [[ -n "${OPENEMR_VERSION}" ]] || OPENEMR_VERSION="unknown"

  run_sudo mkdir -p \
    "${APP_CURRENT}/sites/default/documents" \
    "${APP_CURRENT}/sites/default/documents/logs_and_misc" \
    "${APP_CURRENT}/sites/default/documents/temp" \
    "${APP_CURRENT}/sites/default/documents/onsite_portal_documents"
  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"

  # Drop transient artifacts for this run while preserving the single cached source tarball.
  run_sudo rm -rf "${pkg_path}" "${extract_dir}" "${keep_dir}" 2>/dev/null || true
}

run_openemr_install_or_upgrade() {
  # If prior config exists and schema has core seed data, treat as already installed.
  if run_sudo test -f "${APP_CURRENT}/sites/default/sqlconf.php"; then
    local table_count
    local globals_count
    local users_count
    table_count="$(run_sudo mysql -Nse "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}';" 2>/dev/null || echo 0)"
    globals_count="$(run_sudo mysql -Nse "SELECT COUNT(*) FROM ${DB_NAME}.globals;" 2>/dev/null || echo 0)"
    users_count="$(run_sudo mysql -Nse "SELECT COUNT(*) FROM ${DB_NAME}.users;" 2>/dev/null || echo 0)"
    if [[ "${table_count}" =~ ^[0-9]+$ ]] && (( table_count > 0 )) && \
       [[ "${globals_count}" =~ ^[0-9]+$ ]] && (( globals_count > 0 )) && \
       [[ "${users_count}" =~ ^[0-9]+$ ]] && (( users_count > 0 )); then
      run_sudo mv "${APP_CURRENT}/setup.php" "${APP_SHARED}/setup.php.disabled.$(date +%s)" || true
      persist_credentials
      run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
      run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"
      return
    fi
    if [[ "${table_count}" =~ ^[0-9]+$ ]] && (( table_count > 0 )); then
      echo "Detected partial OpenEMR install state (tables=${table_count}, globals=${globals_count}, users=${users_count}); resetting database before bootstrap." >&2
      run_sudo mysql --execute "DROP DATABASE IF EXISTS ${DB_NAME}; CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
      run_sudo mysql --execute "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"
    fi
  fi

  local site_id="default"
  local iuser="${ADMIN_USERNAME}"
  local iuserpass="${ADMIN_PASSWORD}"
  local iufname="${ADMIN_FIRST_NAME}"
  local iuname="${ADMIN_LAST_NAME}"
  local igroup="Audit Practice"
  local setup_script="${TMP_ROOT}/openemr_setup_bootstrap.py"

  cat > "${setup_script}" <<'PY'
import re
import sys
import time
import requests

base_url = sys.argv[1].rstrip("/")
data_map = {
    "server": sys.argv[2],
    "port": sys.argv[3],
    "dbname": sys.argv[4],
    "login": sys.argv[5],
    "pass": sys.argv[6],
    "root": sys.argv[7],
    "rootpass": sys.argv[8],
    "loginhost": sys.argv[9],
    "iuser": sys.argv[10],
    "iuserpass": sys.argv[11],
    "iufname": sys.argv[12],
    "iuname": sys.argv[13],
    "igroup": sys.argv[14],
    "inst": "2",
    "site": "default",
}

def parse_inputs(html: str):
    payload = {}
    for m in re.finditer(r"<input[^>]*>", html, flags=re.IGNORECASE | re.DOTALL):
        tag = m.group(0)
        attrs = dict(
            (k.lower(), v)
            for k, _, v in re.findall(r"([A-Za-z0-9_:\-]+)\s*=\s*(['\"])(.*?)\2", tag, flags=re.DOTALL)
        )
        name = attrs.get("name")
        if not name:
            continue
        t = (attrs.get("type") or "text").lower()
        if t in {"submit", "button", "image", "file"}:
            continue
        if t == "checkbox" and "checked" not in tag.lower():
            continue
        payload[name] = attrs.get("value", "on" if t == "checkbox" else "")
    return payload

sess = requests.Session()
sess.verify = False
url = f"{base_url}/setup.php"

resp = sess.get(url, params={"site": "default"}, timeout=60)
resp.raise_for_status()
html = resp.text
for _ in range(12):
    if "Final step - Success" in html or "OpenEMR is now installed" in html:
        print("BOOTSTRAP_OK")
        sys.exit(0)

    payload = parse_inputs(html)
    if "state" not in payload:
        raise SystemExit("Could not find setup state form while bootstrapping OpenEMR.")

    for key, value in data_map.items():
        if key in payload or key in {"site", "inst"}:
            payload[key] = value

    # Force path: step1 -> step2 (inst=2), step2 -> step3 with credentials.
    if payload.get("state") == "2":
        payload["inst"] = "2"
    elif payload.get("state") == "3":
        payload["inst"] = "2"
        payload["collate"] = payload.get("collate", "utf8mb4_general_ci")

    resp = sess.post(url, data=payload, timeout=600)
    resp.raise_for_status()
    html = resp.text
    time.sleep(1)

raise SystemExit("OpenEMR setup did not reach success state within expected transitions.")
PY
  run_sudo chmod 0755 "${setup_script}"

  run_sudo -u www-data -- python3 "${setup_script}" \
    "http://127.0.0.1:${APP_PORT}" \
    "localhost" "3306" "${DB_NAME}" "${DB_USER}" "${DB_PASS}" \
    "root" "" "localhost" \
    "${iuser}" "${iuserpass}" "${iufname}" "${iuname}" "${igroup}" \
    >/tmp/openemr_bootstrap_${APP_SLUG}.log 2>&1

  if ! run_sudo test -f "${APP_CURRENT}/sites/default/sqlconf.php"; then
    echo "OpenEMR bootstrap did not create sqlconf.php" >&2
    run_sudo tail -n 200 "/tmp/openemr_bootstrap_${APP_SLUG}.log" >&2 || true
    exit 1
  fi

  # setup.php should not remain exposed after successful bootstrap.
  run_sudo mv "${APP_CURRENT}/setup.php" "${APP_SHARED}/setup.php.disabled.$(date +%s)" || true

  persist_credentials
  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"
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
        try_files \$uri /index.php?\$query_string;
    }

    location ~* ^/sites/.*/documents {
        deny all;
    }

    location ^~ /bin/ {
        deny all;
    }

    location ~ [^/]\.php(/|$) {
        include snippets/fastcgi-php.conf;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTP_AUTHORIZATION \$http_authorization;
        fastcgi_pass unix:${PHP_FPM_SOCKET};
        fastcgi_read_timeout 300;
    }

    location ~* /(\.env|composer\.(json|lock)|phpunit\.xml|node_modules|tests|\.git) {
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
import json
import sys
from pathlib import Path
allowlist = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
extensions = allowlist.get('extensions', [])
if not isinstance(extensions, list):
    extensions = []
out = {'requested': [], 'installed': [], 'skipped': []}
for e in extensions:
    if not isinstance(e, dict):
        continue
    name = str(e.get('name') or '').strip()
    if not name:
        continue
    out['requested'].append({
        'name': name,
        'version_constraint': str(e.get('version_constraint') or '*').strip() or '*',
        'type': str(e.get('type') or 'utility').strip() or 'utility',
    })
Path(sys.argv[2]).write_text(json.dumps(out, indent=2), encoding='utf-8')
PY

  mapfile -t ext_rows < <(python3 - "${ALLOWLIST_PATH}" <<'PY'
import json,sys
rows=[]
doc=json.loads(open(sys.argv[1],encoding='utf-8').read())
for e in doc.get('extensions', []):
    if not isinstance(e, dict):
        continue
    name=str(e.get('name') or '').strip()
    if not name:
        continue
    rows.append('\t'.join([name, str(e.get('type') or 'unknown'), str(e.get('source_url') or '')]))
print('\n'.join(rows))
PY
)

  local name type source_url reason ext_dir
  for row in "${ext_rows[@]}"; do
    IFS=$'\t' read -r name type source_url <<<"${row}"
    [[ -z "${name}" ]] && continue

    if [[ -z "${source_url}" ]]; then
      reason="missing source_url"
      python3 - "${EXT_RESULTS_PATH}" "${name}" "${reason}" <<'PY'
import json,sys
p,n,r=sys.argv[1:4]
d=json.loads(open(p,encoding='utf-8').read())
d['skipped'].append({'name':n,'reason':r})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi

    if [[ "${type}" != "git-zip" ]]; then
      reason="unsupported type"
      python3 - "${EXT_RESULTS_PATH}" "${name}" "${reason}" <<'PY'
import json,sys
p,n,r=sys.argv[1:4]
d=json.loads(open(p,encoding='utf-8').read())
d['skipped'].append({'name':n,'reason':r})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi

    ext_dir="${APP_SHARED}/extensions/${name}"
    run_sudo rm -rf "${ext_dir}" "${TMP_ROOT}/ext_${name}.zip" "${TMP_ROOT}/ext_${name}"
    run_sudo mkdir -p "${ext_dir}" "${TMP_ROOT}/ext_${name}"
    if ! run_sudo curl "${CURL_DL_FLAGS[@]}" "${source_url}" -o "${TMP_ROOT}/ext_${name}.zip"; then
      reason="download failed"
      python3 - "${EXT_RESULTS_PATH}" "${name}" "${reason}" <<'PY'
import json,sys
p,n,r=sys.argv[1:4]
d=json.loads(open(p,encoding='utf-8').read())
d['skipped'].append({'name':n,'reason':r})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi
    if ! run_sudo unzip -q "${TMP_ROOT}/ext_${name}.zip" -d "${TMP_ROOT}/ext_${name}"; then
      reason="unzip failed"
      python3 - "${EXT_RESULTS_PATH}" "${name}" "${reason}" <<'PY'
import json,sys
p,n,r=sys.argv[1:4]
d=json.loads(open(p,encoding='utf-8').read())
d['skipped'].append({'name':n,'reason':r})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi

    if ! run_sudo bash -lc "src=\$(find '${TMP_ROOT}/ext_${name}' -mindepth 1 -maxdepth 2 -type d | head -n 1); test -n \"\$src\" && rsync -a \"\$src/\" '${ext_dir}/'"; then
      reason="extract failed"
      python3 - "${EXT_RESULTS_PATH}" "${name}" "${reason}" <<'PY'
import json,sys
p,n,r=sys.argv[1:4]
d=json.loads(open(p,encoding='utf-8').read())
d['skipped'].append({'name':n,'reason':r})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi

    echo "git-zip:${name}:${ext_dir}" >> "${EXT_PATHS_FILE}"
    python3 - "${EXT_RESULTS_PATH}" "${name}" "${type}" <<'PY'
import json,sys
p,n,t=sys.argv[1:4]
d=json.loads(open(p,encoding='utf-8').read())
d['installed'].append({'name':n,'type':t})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
  done

  ensure_file_owner "${APP_SHARED}/extensions" "www-data" "www-data"
  ensure_file_owner "${EXT_RESULTS_PATH}" "${SSH_USER}" "${SSH_USER}"
  ensure_file_owner "${EXT_PATHS_FILE}" "${SSH_USER}" "${SSH_USER}"
}

create_snapshot() {
  mkdir -p "${APP_SNAPSHOT_DIR}"
  [[ -f "${EXT_PATHS_FILE}" ]] || : > "${EXT_PATHS_FILE}"
  run_sudo bash -lc "mysqldump '${DB_NAME}' > '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo bash -lc "
set -euo pipefail
cd '${APP_CURRENT}'
items=()
for p in sites/default/sqlconf.php sites/default/documents; do
  if [[ -e \"\$p\" ]]; then
    items+=(\"\$p\")
  fi
done
if [[ \${#items[@]} -eq 0 ]]; then
  echo 'No snapshot content candidates found for OpenEMR site state.' >&2
  exit 1
fi
tar -czf '${APP_SNAPSHOT_DIR}/site_state.tar.gz' \"\${items[@]}\"
"
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
  run_sudo rm -rf "${APP_CURRENT}/sites/default/documents"
  run_sudo rm -f "${APP_CURRENT}/sites/default/sqlconf.php"
  run_sudo mkdir -p "${APP_CURRENT}"
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/site_state.tar.gz" -C "${APP_CURRENT}"
  run_sudo mkdir -p \
    "${APP_CURRENT}/sites/default/documents" \
    "${APP_CURRENT}/sites/default/documents/logs_and_misc" \
    "${APP_CURRENT}/sites/default/documents/temp" \
    "${APP_CURRENT}/sites/default/documents/onsite_portal_documents"
  if [[ -f "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt" ]]; then
    run_sudo install -m 0644 "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt" "${EXT_PATHS_FILE}"
  fi
  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"
  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

refresh_openemr_metadata() {
  OPENEMR_URL="http://${HOST}:${APP_PORT}"
  OPENEMR_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

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

  if [[ "${OPENEMR_VERSION}" == "unknown" || -z "${OPENEMR_VERSION}" ]]; then
    OPENEMR_VERSION="${state_version:-unknown}"
  fi
  if [[ -z "${OPENEMR_SOURCE_URL}" ]]; then
    OPENEMR_SOURCE_URL="${state_url}"
  fi
  if [[ -z "${OPENEMR_SOURCE_FILE}" ]]; then
    OPENEMR_SOURCE_FILE="${state_file}"
  fi
}

sync_ui_to_openemr_runtime() {
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

  curl --fail --silent --show-error --location --connect-timeout 10 --max-time 30 "http://127.0.0.1:${APP_PORT}/ptt_smoke_probe.php?ptt_probe=${token}&cmd=echo%20ptt_openemr_smoke" >/dev/null

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
        'openemr.healthcheck.system.before',
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
  refresh_openemr_metadata

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
    'summary': f"openemr action={${ACTION@Q}} via remote_openemr_app_manage.sh"
})
history = history[-40:]

installed_at = existing.get('installed_at_utc') or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

record = {
    'app_id': 'openemr-main',
    'name': 'OpenEMR',
    'slug': ${APP_SLUG@Q},
    'installed_at_utc': installed_at,
    'updated_at_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
    'version': ${OPENEMR_VERSION@Q},
    'remote_host': ${HOST@Q},
    'remote_host_label': ${HOST_LABEL@Q},
    'remote_root_path': ${APP_CURRENT@Q},
    'web_root_path': ${APP_WEB_ROOT@Q},
    'base_urls': [${OPENEMR_URL@Q}, ${OPENEMR_LOCAL_URL@Q}],
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
        'shared_extensions_path': ${APP_SHARED@Q} + '/extensions'
    },
    'source': {
        'channel': 'github.openemr.openemr.latest-stable-release',
        'download_url': ${OPENEMR_SOURCE_URL@Q},
        'download_file': ${OPENEMR_SOURCE_FILE@Q},
        'resolved_release_version': ${OPENEMR_VERSION@Q},
        'release_tracking_mode': 'latest-stable-auto'
    },
    'credentials': {
        'db_name': ${DB_NAME@Q},
        'db_user': ${DB_USER@Q},
        'db_password': ${DB_PASS@Q},
        'openemr_admin_name': ${ADMIN_NAME@Q},
        'openemr_admin_username': ${ADMIN_USERNAME@Q},
        'openemr_admin_first_name': ${ADMIN_FIRST_NAME@Q},
        'openemr_admin_last_name': ${ADMIN_LAST_NAME@Q},
        'openemr_admin_email': ${ADMIN_EMAIL@Q},
        'openemr_admin_password': ${ADMIN_PASSWORD@Q},
        'openemr_app_key': ${APP_KEY@Q}
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
        'verifier_local_base_url': ${OPENEMR_LOCAL_URL@Q}
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
  install_or_update_openemr_core
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  run_openemr_install_or_upgrade
  install_catalog_extensions
  create_snapshot
  sync_ui_to_openemr_runtime
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

  OPENEMR_VERSION="removed"
  OPENEMR_URL="http://${HOST}:${APP_PORT}"
  OPENEMR_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
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

write_app_readme() {
  local state_file="${APP_DOC_ROOT}/latest_state.json"
  python3 - "${state_file}" "${APP_DOC_ROOT}/README.md" <<'PY'
import json
import sys
from pathlib import Path

state_path = Path(sys.argv[1])
readme_path = Path(sys.argv[2])
state = json.loads(state_path.read_text(encoding='utf-8'))
deployment = state.get('deployment') or {}
runtime = state.get('runtime') or {}
source = state.get('source') or {}

lines = [
    f"# {state.get('name', 'OpenEMR')} Remote App Record",
    "",
    "## Summary",
    f"- App ID: `{state.get('app_id', '')}`",
    f"- Slug: `{state.get('slug', '')}`",
    f"- Endpoint: `http://{deployment.get('endpoint', '')}:{deployment.get('port', '')}/`",
    f"- Installed at: `{state.get('installed_at_utc', '')}`",
    f"- Last updated: `{state.get('updated_at_utc', '')}`",
    f"- Version: `{state.get('version', '')}`",
    "",
    "## Remote Paths",
    f"- App root: `{state.get('remote_root_path', '')}`",
    f"- Web root: `{state.get('web_root_path', '')}`",
    f"- Verifier runtime: `{(state.get('php_taint_trace_integration') or {}).get('verifier_runtime_dir', '')}`",
    "",
    "## Runtime",
    f"- PHP-FPM service: `{runtime.get('php_fpm_service', '')}`",
    f"- PHP series: `{runtime.get('php_version', '')}`",
    f"- Database: `{runtime.get('database', '')}`",
    "",
    "## Source",
    f"- Channel: `{source.get('channel', '')}`",
    f"- URL: `{source.get('download_url', '')}`",
    "",
    "## Inventory Files",
    f"- State: `{state_path}`",
    "- Extension allowlist: `extensions.allowlist.json`",
]

readme_path.write_text("\n".join(lines) + "\n", encoding='utf-8')
PY
}

update_root_installed_apps_readme() {
  python3 - "${ROOT_DIR}/remote_linux_container/installed_php_applications/README.md" "${INVENTORY_PATH}" <<'PY'
import json
import re
import sys
from pathlib import Path

readme_path = Path(sys.argv[1])
inventory_path = Path(sys.argv[2])
doc = inventory_path.read_text(encoding='utf-8')
inventory = json.loads(doc)
apps = inventory.get('applications') or []
apps = [a for a in apps if isinstance(a, dict)]
apps.sort(key=lambda a: int((a.get('deployment') or {}).get('port') or 0))

text = readme_path.read_text(encoding='utf-8')
start = text.find("Installed applications currently tracked:")
if start == -1:
    raise SystemExit(0)
fence = text.find("```bash", start)
if fence == -1:
    raise SystemExit(0)
head = text[:start]
tail = text[fence:]

lines = ["Installed applications currently tracked:", ""]
for idx, app in enumerate(apps, 1):
    dep = app.get('deployment') or {}
    slug = app.get('slug') or ''
    app_id = app.get('app_id') or ''
    endpoint = dep.get('endpoint') or ''
    port = dep.get('port') or ''
    root = app.get('remote_root_path') or ''
    runtime = (app.get('php_taint_trace_integration') or {}).get('verifier_runtime_dir') or ''
    state_path = f"remote_linux_container/installed_php_applications/apps/{slug}/latest_state.json"
    lines.extend([
        f"{idx}. `{slug}` (`{app_id}`)",
        f"   - Endpoint: `http://{endpoint}:{port}/`",
        f"   - Install root: `{root}`",
        f"   - Runtime root: `{runtime.rsplit('/verifier', 1)[0] if runtime else ''}`",
        f"   - State record: [{state_path}](latest_state.json)",
    ])

new_block = "\n".join(lines).rstrip() + "\n\n"
text = head + new_block + tail

cmd_lines = []
for app in apps:
    slug = app.get('slug') or ''
    if not slug:
        continue
    cmd_lines.append(f"bash scripts/remote_{slug}_app_manage.sh register-inventory")

text = re.sub(
    r"```bash\n.*?\n```",
    "```bash\n" + "\n".join(cmd_lines) + "\n```",
    text,
    count=1,
    flags=re.S,
)
readme_path.write_text(text, encoding='utf-8')
PY
}

if [[ "${ACTION}" != "register-inventory" ]]; then
  echo "[remote-openemr-app] running remote action=${ACTION} app=${APP_SLUG} host=${HOST}"
  run_remote_action
fi

echo "[remote-openemr-app] syncing local inventory from remote state"
update_inventory
write_app_readme
update_root_installed_apps_readme
echo "[remote-openemr-app] complete"
echo "[remote-openemr-app] inventory=${INVENTORY_PATH}"
echo "[remote-openemr-app] app_state=${APP_DOC_ROOT}/latest_state.json"
