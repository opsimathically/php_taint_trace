#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19160"
APP_SLUG="mantisbt"
UI_SYNC="1"
RUN_VALIDATION="1"
ENABLE_XMARK="1"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
EXTENSION_ALLOWLIST_PATH="${ROOT_DIR}/remote_linux_container/installed_php_applications/apps/${APP_SLUG}/plugins.allowlist.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_mantisbt_app_manage.sh <install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck> [options]

Options:
  --config PATH               External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL          Host label in config (default: lab.example.invalid)
  --remote-taint-root PATH    Remote php_taint_trace repo root (default: /opt/php_taint_trace_vuln_lab/rewrite)
  --install-root PATH         Remote multi-app install root (default: /opt/php_audit_apps)
  --app-port PORT             MantisBT port (default: 19160)
  --inventory PATH            External inventory path (default: PHP_TAINT_TRACE_INVENTORY_PATH or XDG state directory)
  --allowlist PATH            Plugin allowlist JSON path
  --no-ui-sync                Do not sync UI file sources with this app runtime
  --no-validation             Skip install-time taint/verifier smoke validation
  --enable-xmark              Load xmark extension for PHP-FPM worker startup (default: on)
  --disable-xmark             Disable xmark extension loading for PHP-FPM
  -h, --help                  Show help

Actions:
  install            Install or reconcile MantisBT + runtime integration
  update             Update MantisBT core/plugins and refresh metadata
  reset              Restore latest baseline snapshot
  snapshot-create    Create baseline snapshot (db + MantisBT mutable content)
  snapshot-restore   Restore baseline snapshot
  xmark-healthcheck  Run remote xmark runtime healthcheck (load mode + hook dispatch)
  status             Print remote app state JSON
  remove             Remove MantisBT deployment (retain runtime metadata)
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
      CONFIG_PATH="$2"
      shift 2
      ;;
    --host-label)
      HOST_LABEL="$2"
      shift 2
      ;;
    --remote-taint-root)
      REMOTE_TAINT_ROOT="$2"
      shift 2
      ;;
    --install-root)
      INSTALL_ROOT="$2"
      shift 2
      ;;
    --app-port)
      APP_PORT="$2"
      shift 2
      ;;
    --inventory)
      INVENTORY_PATH="$2"
      shift 2
      ;;
    --allowlist)
      EXTENSION_ALLOWLIST_PATH="$2"
      shift 2
      ;;
    --no-ui-sync)
      UI_SYNC="0"
      shift
      ;;
    --no-validation)
      RUN_VALIDATION="0"
      shift
      ;;
    --enable-xmark)
      ENABLE_XMARK="1"
      shift
      ;;
    --disable-xmark)
      ENABLE_XMARK="0"
      shift
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
    { "name": "source-integration", "url": "https://github.com/mantisbt-plugins/source-integration.git", "branch": "master", "type": "git-plugin" },
    { "name": "tasks", "url": "https://github.com/mantisbt-plugins/Tasks.git", "branch": "master", "type": "git-plugin" },
    { "name": "linked-custom-fields", "url": "https://github.com/mantisbt-plugins/LinkedCustomFields.git", "branch": "master", "type": "git-plugin" }
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
MANTISBT_FILES_DIR="${APP_SHARED}/files"
MANTISBT_PLUGIN_DIR="${APP_CURRENT}/plugins"
MANTISBT_CONFIG_DIR="${APP_CURRENT}/config"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_RUNTIME_VERIFIER="${APP_RUNTIME}/verifier"
APP_RUNTIME_FINDINGS="${APP_RUNTIME}/findings"
APP_SNAPSHOT_DIR="${APP_RUNTIME}/snapshots/latest"
STATE_PATH="${APP_RUNTIME}/app_state.json"
PLUGIN_RESULTS_PATH="${APP_RUNTIME}/extension_results.json"
ALLOWLIST_PATH="${APP_RUNTIME}/plugins.allowlist.json"
PLUGIN_PATHS_FILE="${APP_RUNTIME}/installed_extension_paths.txt"
TMP_ROOT="/tmp/php_taint_trace_mantisbt_install_${APP_SLUG}"
PHP_TAINT_TRACE_PREPEND="${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php"
XMARK_EXT_PATH="${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
CURL_DL_FLAGS=(--fail --silent --show-error --location --connect-timeout 20 --max-time 1800 --retry 2 --retry-delay 2)
COMPOSER_BIN="/usr/local/bin/composer-ptt"

MANTISBT_VERSION="unknown"
MANTISBT_URL="http://${HOST}:${APP_PORT}"
MANTISBT_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
MANTISBT_SOURCE_URL=""
MANTISBT_SOURCE_FILE=""
MANTISBT_SOURCE_SHA256=""
MANTISBT_CONFIG_PATH="${MANTISBT_CONFIG_DIR}/config_inc.php"

mkdir -p "${TMP_ROOT}"
printf '%s' "${EXTENSION_ALLOWLIST_B64}" | base64 -d > "${TMP_ROOT}/plugins.allowlist.json"

ensure_prerequisites() {
  run_sudo apt-get update -y
  run_sudo apt-get install -y \
    curl wget unzip rsync jq tar gzip ca-certificates git \
    mariadb-client mariadb-server \
    nginx php-cli php-fpm php-mysql php-xml php-curl php-mbstring php-zip php-intl php-gd php-bcmath php-soap php-imagick
  run_sudo systemctl enable --now nginx mariadb
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
    "${MANTISBT_FILES_DIR}" \
    "${MANTISBT_PLUGIN_DIR}" \
    "${MANTISBT_CONFIG_DIR}" \
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
  run_sudo chmod -R u+rwX,g+rwX "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}" "${APP_SHARED}/tmp" "${MANTISBT_FILES_DIR}" "${MANTISBT_PLUGIN_DIR}" "${MANTISBT_CONFIG_DIR}"
}

load_or_create_credentials() {
  local creds_path="${APP_SHARED}/credentials.json"

  if run_sudo test -f "${creds_path}"; then
    local creds_json
    creds_json="$(run_sudo cat "${creds_path}")"
    DB_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_name"])' <<<"${creds_json}")"
    DB_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_user"])' <<<"${creds_json}")"
    DB_PASS="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_password"])' <<<"${creds_json}")"
    DB_PREFIX="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("db_prefix", "mantis_"))' <<<"${creds_json}")"
    ADMIN_USER="administrator"
    ADMIN_PASSWORD="root"
    ADMIN_EMAIL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_email"])' <<<"${creds_json}")"
  else
    DB_NAME="mantisbt_${APP_SLUG}"
    DB_USER="mantisbt_${APP_SLUG}_user"
    DB_PASS="$(openssl rand -hex 16)"
    DB_PREFIX="mantis_"
    ADMIN_USER="administrator"
    ADMIN_PASSWORD="root"
    ADMIN_EMAIL="audit+${APP_SLUG}@local.invalid"
  fi

  python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "db_prefix": ${DB_PREFIX@Q},
  "admin_user": ${ADMIN_USER@Q},
  "admin_password": ${ADMIN_PASSWORD@Q},
  "admin_email": ${ADMIN_EMAIL@Q}
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

resolve_mantisbt_release() {
  run_sudo bash -lc "curl --fail --silent --show-error --location --connect-timeout 20 --max-time 120 -H 'User-Agent: php-taint-trace-mantisbt-installer' 'https://api.github.com/repos/mantisbt/mantisbt/tags?per_page=50' > '${TMP_ROOT}/mantisbt_release.json'"
  mapfile -t _release < <(python3 - "${TMP_ROOT}/mantisbt_release.json" <<'PY'
import json
import sys
from pathlib import Path

rows = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if not isinstance(rows, list):
    raise SystemExit(2)

def parse_name(name: str):
    if not name.startswith("release-"):
        return None
    ver = name[len("release-"):]
    parts = ver.split(".")
    if len(parts) != 3:
        return None
    try:
        return tuple(int(p) for p in parts)
    except Exception:
        return None

candidates = []
for row in rows:
    if not isinstance(row, dict):
        continue
    name = str(row.get("name") or "").strip()
    parsed = parse_name(name)
    if not parsed:
        continue
    tar_url = str(row.get("tarball_url") or "").strip()
    if not tar_url:
        continue
    candidates.append((parsed, name, tar_url))

if not candidates:
    raise SystemExit(3)

candidates.sort(reverse=True)
_, tag, tar_url = candidates[0]
filename = f"mantisbt-{tag}.tar.gz"
print(tag)
print(tar_url)
print(filename)
PY
  ) || true

  if [[ ${#_release[@]} -lt 3 ]]; then
    echo "Failed to resolve latest stable MantisBT release metadata." >&2
    exit 1
  fi

  MANTISBT_VERSION="${_release[0]}"
  MANTISBT_SOURCE_URL="${_release[1]}"
  MANTISBT_SOURCE_FILE="${_release[2]}"
}

install_or_update_mantisbt_core() {
  resolve_mantisbt_release

  local cache_dir="${APP_SHARED}/downloads"
  local cache_tar="${cache_dir}/${MANTISBT_SOURCE_FILE}"
  run_sudo rm -rf "${TMP_ROOT}/mantisbt.tar.gz" "${TMP_ROOT}/mantisbt_extract"
  run_sudo mkdir -p "${TMP_ROOT}/mantisbt_extract"
  run_sudo mkdir -p "${cache_dir}"
  if run_sudo test -f "${cache_tar}"; then
    run_sudo cp "${cache_tar}" "${TMP_ROOT}/mantisbt.tar.gz"
  else
    run_sudo wget -q --show-progress --progress=dot:giga --tries=3 --timeout=30 --read-timeout=120 -O "${TMP_ROOT}/mantisbt.tar.gz" "${MANTISBT_SOURCE_URL}"
    run_sudo cp "${TMP_ROOT}/mantisbt.tar.gz" "${cache_tar}"
  fi
  MANTISBT_SOURCE_SHA256="$(run_sudo sha256sum "${TMP_ROOT}/mantisbt.tar.gz" | awk '{print $1}')"
  run_sudo tar -xzf "${TMP_ROOT}/mantisbt.tar.gz" -C "${TMP_ROOT}/mantisbt_extract"

  local extracted_root
  extracted_root="$(run_sudo bash -lc "candidate=\$(find '${TMP_ROOT}/mantisbt_extract' -mindepth 1 -maxdepth 5 -type f -path '*/admin/install.php' | head -n 1); if [[ -n \"\$candidate\" ]]; then dirname \"\$(dirname \"\$candidate\")\"; fi")"
  if [[ -z "${extracted_root}" ]] || ! run_sudo test -f "${extracted_root}/index.php"; then
    echo "Failed to locate extracted MantisBT root from tarball." >&2
    exit 1
  fi

  local keep_dir="${TMP_ROOT}/keep"
  run_sudo rm -rf "${keep_dir}"
  run_sudo mkdir -p "${keep_dir}"

  if run_sudo test -f "${MANTISBT_CONFIG_PATH}"; then
    run_sudo cp "${MANTISBT_CONFIG_PATH}" "${keep_dir}/config_inc.php"
  fi
  if run_sudo test -d "${MANTISBT_PLUGIN_DIR}"; then
    run_sudo rsync -a "${MANTISBT_PLUGIN_DIR}/" "${keep_dir}/plugins/"
  fi

  run_sudo rm -rf "${APP_CURRENT}"
  run_sudo mkdir -p "${APP_CURRENT}"
  run_sudo rsync -a --delete "${extracted_root}/" "${APP_CURRENT}/"

  run_sudo mkdir -p "${MANTISBT_CONFIG_DIR}" "${MANTISBT_PLUGIN_DIR}" "${MANTISBT_FILES_DIR}" "${APP_CURRENT}/core/cache"
  if run_sudo test -f "${keep_dir}/config_inc.php"; then
    run_sudo install -m 0640 "${keep_dir}/config_inc.php" "${MANTISBT_CONFIG_PATH}"
    run_sudo chown www-data:www-data "${MANTISBT_CONFIG_PATH}"
  fi
  if run_sudo test -d "${keep_dir}/plugins"; then
    run_sudo rsync -a "${keep_dir}/plugins/" "${MANTISBT_PLUGIN_DIR}/"
  fi

  run_sudo rm -rf "${APP_CURRENT}/admin/install.php~" "${APP_CURRENT}/admin/install.php.bak" 2>/dev/null || true

  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}" || true
  if ! run_sudo test -f "${APP_CURRENT}/vendor/autoload.php"; then
    run_sudo rm -rf "${APP_CURRENT}/vendor" || true
    if ! run_sudo -u www-data -- timeout 5400 bash -lc "cd '${APP_CURRENT}' && COMPOSER_DISABLE_XDEBUG_WARN=1 COMPOSER_MEMORY_LIMIT=-1 COMPOSER_HOME='${APP_SHARED}/tmp' COMPOSER_CACHE_DIR='${APP_SHARED}/downloads' '${COMPOSER_BIN}' install --no-interaction --prefer-dist --no-dev >/tmp/mantisbt_composer_install.log 2>&1"; then
      echo "MantisBT composer install failed." >&2
      run_sudo tail -n 200 /tmp/mantisbt_composer_install.log >&2 || true
      exit 1
    fi
  fi

  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo rm -rf "${TMP_ROOT}/mantisbt_extract" "${TMP_ROOT}/keep" 2>/dev/null || true
}

run_mantisbt_install_or_upgrade() {
  if run_sudo test -f "${MANTISBT_CONFIG_PATH}"; then
    local table_count
    table_count="$(run_sudo mysql -Nse "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}';" 2>/dev/null || echo 0)"
    if [[ "${table_count}" =~ ^[0-9]+$ ]] && (( table_count > 0 )); then
      if run_sudo test -f "${APP_CURRENT}/admin/install.php"; then
        run_sudo mv "${APP_CURRENT}/admin/install.php" "${APP_CURRENT}/admin/install.php.disabled"
      fi
      return
    fi
  fi

  run_sudo rm -f "${MANTISBT_CONFIG_PATH}" || true
  run_sudo mkdir -p "${MANTISBT_CONFIG_DIR}" "${MANTISBT_FILES_DIR}" "${APP_CURRENT}/core/cache"
  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}"
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}"

  local install_out="/tmp/mantisbt_install_http_${APP_SLUG}.html"
  if ! run_sudo -u www-data -- bash -lc "curl -sS -L -X POST 'http://127.0.0.1:${APP_PORT}/admin/install.php' \
    --data-urlencode 'install=2' \
    --data-urlencode 'db_type=mysqli' \
    --data-urlencode 'hostname=127.0.0.1' \
    --data-urlencode 'db_username=${DB_USER}' \
    --data-urlencode 'db_password=${DB_PASS}' \
    --data-urlencode 'database_name=${DB_NAME}' \
    --data-urlencode 'admin_username=${DB_USER}' \
    --data-urlencode 'admin_password=${DB_PASS}' \
    --data-urlencode 'db_table_prefix=${DB_PREFIX}' \
    --data-urlencode 'db_table_plugin_prefix=plugin_' \
    --data-urlencode 'db_table_suffix=' \
    --data-urlencode 'timezone=UTC' \
    --data-urlencode 'path=${MANTISBT_URL}/' \
    --data-urlencode 'go=Install/Upgrade Database' \
    > '${install_out}'"; then
    echo "MantisBT HTTP installer request failed." >&2
    run_sudo tail -n 160 "${install_out}" >&2 || true
    exit 1
  fi

  if ! run_sudo test -f "${MANTISBT_CONFIG_PATH}"; then
    echo "MantisBT installer did not create ${MANTISBT_CONFIG_PATH}." >&2
    run_sudo tail -n 220 "${install_out}" >&2 || true
    exit 1
  fi
  if ! run_sudo grep -q "Installation Complete\\|MantisBT was installed successfully" "${install_out}" 2>/dev/null; then
    run_sudo grep -q "Installation Failed" "${install_out}" && { run_sudo tail -n 220 "${install_out}" >&2 || true; exit 1; }
  fi

  # Default installer account is administrator/root; keep it deterministic in inventory.
  if run_sudo test -f "${APP_CURRENT}/admin/install.php"; then
    run_sudo mv "${APP_CURRENT}/admin/install.php" "${APP_CURRENT}/admin/install.php.disabled"
  fi

  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}" || true
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}" "${APP_SHARED}" || true
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
    include /etc/nginx/mime.types;
    types { application/javascript mjs; }

    location / {
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }

    location ~ [^/]\.php(/|$) {
        include snippets/fastcgi-php.conf;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_pass unix:${PHP_FPM_SOCKET};
        fastcgi_read_timeout 300;
    }

    location ~* \.(?:css|js|mjs|jpg|jpeg|gif|png|svg|ico|webp|woff2?)$ {
        expires 1h;
        access_log off;
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }

    location ~* /(core|doc|tests)/ {
        deny all;
    }

    location ~* /\.(git|svn|hg) {
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

install_catalog_plugins() {
  cp "${TMP_ROOT}/plugins.allowlist.json" "${ALLOWLIST_PATH}"
  ensure_file_owner "${ALLOWLIST_PATH}" "${SSH_USER}" "${SSH_USER}"
  : > "${PLUGIN_PATHS_FILE}"

  python3 - "${ALLOWLIST_PATH}" "${PLUGIN_RESULTS_PATH}" <<'PY'
import json
import sys
from pathlib import Path

allowlist = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
extensions = allowlist.get('extensions', [])
if not isinstance(extensions, list):
    extensions = []
result = {'requested': [], 'installed': [], 'skipped': []}
for entry in extensions:
    if not isinstance(entry, dict):
        continue
    name = str(entry.get('name', '')).strip()
    if not name:
        continue
    result['requested'].append({
        'name': name,
        'url': str(entry.get('url', '')).strip(),
        'branch': str(entry.get('branch', '')).strip() or 'master',
        'type': str(entry.get('type', '')).strip() or 'plugin'
    })
Path(sys.argv[2]).write_text(json.dumps(result, indent=2), encoding='utf-8')
PY

  mapfile -t plugin_rows < <(python3 - "${PLUGIN_RESULTS_PATH}" <<'PY'
import json, sys
rows = []
doc = json.loads(open(sys.argv[1], 'r', encoding='utf-8').read())
for item in (doc.get('requested') or []):
    if not isinstance(item, dict):
        continue
    rows.append('\t'.join([
        str(item.get('name', '')).strip(),
        str(item.get('url', '')).strip(),
        str(item.get('branch', '')).strip() or 'master',
        str(item.get('type', '')).strip() or 'plugin',
    ]))
print('\n'.join([r for r in rows if r]))
PY
)

  local plugin url branch ext_type reason plugin_dir
  for row in "${plugin_rows[@]}"; do
    IFS=$'\t' read -r plugin url branch ext_type <<<"${row}"
    [[ -z "${plugin}" ]] && continue

    if [[ "${ext_type}" == "reference" ]]; then
      reason="reference-only entry (not installable plugin package)"
      python3 - "${PLUGIN_RESULTS_PATH}" "${plugin}" "${url}" "${reason}" <<'PY'
import json, sys
p, plugin, url, reason = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['skipped'].append({'name': plugin, 'url': url, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
      continue
    fi

    if [[ -z "${url}" ]]; then
      reason="missing url"
      python3 - "${PLUGIN_RESULTS_PATH}" "${plugin}" "${reason}" <<'PY'
import json, sys
p, plugin, reason = sys.argv[1:4]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['skipped'].append({'name': plugin, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
      continue
    fi

    plugin_dir="${APP_CURRENT}/plugins/${plugin}"
    run_sudo rm -rf "${TMP_ROOT}/ext_${plugin}"
    if ! run_sudo git clone --depth 1 --branch "${branch}" "${url}" "${TMP_ROOT}/ext_${plugin}" >/dev/null 2>&1; then
      reason="git clone failed (${branch})"
      python3 - "${PLUGIN_RESULTS_PATH}" "${plugin}" "${url}" "${reason}" <<'PY'
import json, sys
p, plugin, url, reason = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['skipped'].append({'name': plugin, 'url': url, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
      continue
    fi

    run_sudo mkdir -p "${plugin_dir}"
    run_sudo rsync -a --delete "${TMP_ROOT}/ext_${plugin}/" "${plugin_dir}/"
    echo "plugins/${plugin}" >> "${PLUGIN_PATHS_FILE}"
    python3 - "${PLUGIN_RESULTS_PATH}" "${plugin}" "${url}" "${ext_type}" <<'PY'
import json, sys
p, plugin, url, ext_type = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['installed'].append({'name': plugin, 'url': url, 'type': ext_type})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
  done

  run_sudo chown -R www-data:www-data "${APP_CURRENT}/plugins" || true
  ensure_file_owner "${PLUGIN_RESULTS_PATH}" "${SSH_USER}" "${SSH_USER}"
  ensure_file_owner "${PLUGIN_PATHS_FILE}" "${SSH_USER}" "${SSH_USER}"
}

create_snapshot() {
  mkdir -p "${APP_SNAPSHOT_DIR}"
  if [[ ! -f "${PLUGIN_PATHS_FILE}" ]]; then
    : > "${PLUGIN_PATHS_FILE}"
  fi
  run_sudo bash -lc "mysqldump '${DB_NAME}' > '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo bash -lc "tar -czf '${APP_SNAPSHOT_DIR}/site_state.tar.gz' -C '${APP_BASE}' current/config current/core/cache current/plugins shared/files shared/tmp 2>/dev/null || true"
  run_sudo install -m 0644 "${PLUGIN_PATHS_FILE}" "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt"
  run_sudo chown -R "${SSH_USER}:${SSH_USER}" "${APP_SNAPSHOT_DIR}"
  SNAPSHOT_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

restore_snapshot() {
  if [[ ! -f "${APP_SNAPSHOT_DIR}/db.sql" || ! -f "${APP_SNAPSHOT_DIR}/site_state.tar.gz" ]]; then
    echo "Snapshot missing at ${APP_SNAPSHOT_DIR}" >&2
    exit 1
  fi

  run_sudo mysql "${DB_NAME}" < "${APP_SNAPSHOT_DIR}/db.sql"
  run_sudo rm -rf "${APP_CURRENT}/config" "${APP_CURRENT}/core/cache" "${APP_CURRENT}/plugins" "${APP_SHARED}/files" "${APP_SHARED}/tmp"
  run_sudo mkdir -p "${APP_BASE}"
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/site_state.tar.gz" -C "${APP_BASE}" || true
  run_sudo mkdir -p "${APP_CURRENT}/config" "${APP_CURRENT}/core/cache" "${APP_CURRENT}/plugins" "${APP_SHARED}/files" "${APP_SHARED}/tmp"

  if [[ -f "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt" ]]; then
    run_sudo install -m 0644 "${APP_SNAPSHOT_DIR}/installed_extension_paths.txt" "${PLUGIN_PATHS_FILE}"
  fi

  ensure_file_owner "${APP_CURRENT}" "www-data" "www-data"
  ensure_file_owner "${APP_SHARED}" "www-data" "www-data"
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}"
  run_sudo chmod -R u+rwX,g+rwX "${APP_SHARED}"

  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

refresh_mantisbt_metadata() {
  MANTISBT_URL="http://${HOST}:${APP_PORT}"
  MANTISBT_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  local detected
  detected="$(run_sudo bash -lc "php -r \"\$f='${APP_CURRENT}/core/constant_inc.php'; if (!is_file(\$f)) { exit(0);} \$c=file_get_contents(\$f); if (preg_match('/MANTIS_VERSION\\s*,\\s*\\x27([^\\x27]+)\\x27/', \$c, \$m)) { echo \$m[1]; }\" 2>/dev/null || true")"
  if [[ -n "${detected}" ]]; then
    MANTISBT_VERSION="${detected}"
  fi

  if [[ -z "${MANTISBT_VERSION}" || "${MANTISBT_VERSION}" == "unknown" ]]; then
    MANTISBT_VERSION="$(python3 - "${STATE_PATH}" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print('unknown')
    raise SystemExit
try:
    doc = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    print('unknown')
    raise SystemExit
print(doc.get('version', 'unknown'))
PY
)"
  fi

  if [[ -z "${MANTISBT_VERSION}" ]]; then
    MANTISBT_VERSION="unknown"
  fi
}

sync_ui_to_mantisbt_runtime() {
  if [[ "${UI_SYNC}" != "1" ]]; then
    return
  fi

  if ! run_sudo test -f "${UI_CONFIG_PATH}"; then
    return
  fi

  run_sudo python3 -c "
import json
from pathlib import Path

cfg_path = Path('${UI_CONFIG_PATH}')
current_runtime = Path('${APP_RUNTIME_VERIFIER}')
runtime_root = Path('${INSTALL_ROOT}') / '_runtime'
current_name = '${APP_SLUG}'
doc = json.loads(cfg_path.read_text(encoding='utf-8'))

def build_source(name: str, verifier_dir: Path) -> dict[str, str]:
    return {
        'name': name,
        'decisionsWorkerPath': str(verifier_dir / 'decisions.jsonl'),
        'jobsPath': str(verifier_dir / 'jobs.jsonl'),
        'resultsPath': str(verifier_dir / 'results.jsonl'),
        'deadLettersPath': str(verifier_dir / 'dead_letters.jsonl'),
        'claimsPath': str(verifier_dir / 'claims.jsonl'),
    }

ordered_sources = []
seen_decisions_paths = set()

def add_source(name: str, verifier_dir: Path) -> None:
    source = build_source(name, verifier_dir)
    key = source['decisionsWorkerPath']
    if key in seen_decisions_paths:
        return
    seen_decisions_paths.add(key)
    ordered_sources.append(source)

if current_runtime.is_dir():
    add_source(current_name, current_runtime)

if runtime_root.is_dir():
    for app_dir in sorted(runtime_root.iterdir()):
        verifier_dir = app_dir / 'verifier'
        if verifier_dir.is_dir():
            add_source(app_dir.name, verifier_dir)

if not ordered_sources:
    add_source(current_name, current_runtime)

primary = ordered_sources[0]
additional = ordered_sources[1:]
file_sources = doc.setdefault('fileSources', {})
for key in ('decisionsWorkerPath', 'jobsPath', 'resultsPath', 'deadLettersPath', 'claimsPath'):
    file_sources[key] = primary[key]
file_sources['additionalSources'] = additional

sources = doc.setdefault('sources', {})
sources.setdefault('fileSourceEnabled', True)
sources['paths'] = primary
sources['additionalPaths'] = additional

cfg_path.write_text(json.dumps(doc, indent=2), encoding='utf-8')
"

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

  curl --fail --silent --show-error --location --connect-timeout 10 --max-time 30 "http://127.0.0.1:${APP_PORT}/ptt_smoke_probe.php?ptt_probe=${token}&cmd=echo%20ptt_mantisbt_smoke" >/dev/null

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
        'mantisbt.healthcheck.system.before',
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
  refresh_mantisbt_metadata

  mkdir -p "${APP_RUNTIME}"

  if [[ -z "${MANTISBT_SOURCE_URL}" || -z "${MANTISBT_SOURCE_FILE}" || -z "${MANTISBT_SOURCE_SHA256}" ]]; then
    local existing_source
    existing_source="$(python3 - "${STATE_PATH}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print('{}')
    raise SystemExit
try:
    doc = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    print('{}')
    raise SystemExit
print(json.dumps(doc.get('source') or {}))
PY
)"
    if [[ -z "${MANTISBT_SOURCE_URL}" ]]; then
      MANTISBT_SOURCE_URL="$(python3 -c 'import json,sys; print((json.loads(sys.stdin.read()) or {}).get("download_url",""))' <<<"${existing_source}")"
    fi
    if [[ -z "${MANTISBT_SOURCE_FILE}" ]]; then
      MANTISBT_SOURCE_FILE="$(python3 -c 'import json,sys; print((json.loads(sys.stdin.read()) or {}).get("download_file",""))' <<<"${existing_source}")"
    fi
    if [[ -z "${MANTISBT_SOURCE_SHA256}" ]]; then
      MANTISBT_SOURCE_SHA256="$(python3 -c 'import json,sys; print((json.loads(sys.stdin.read()) or {}).get("download_sha256",""))' <<<"${existing_source}")"
    fi
  fi

  local xmark_enabled_runtime="0"
  if [[ "${ENABLE_XMARK}" == "1" ]] && run_sudo test -f "${XMARK_FPM_INI}" && run_sudo grep -q "${XMARK_EXT_PATH}" "${XMARK_FPM_INI}"; then
    xmark_enabled_runtime="1"
  elif run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    xmark_enabled_runtime="1"
  fi

  local db_version
  db_version="$(run_sudo mysql --version 2>/dev/null || true)"

  if [[ ! -f "${PLUGIN_RESULTS_PATH}" ]]; then
    printf '{"requested":[],"installed":[],"skipped":[]}' > "${PLUGIN_RESULTS_PATH}"
  fi

  local snapshot_created
  snapshot_created="${SNAPSHOT_CREATED_AT:-$(python3 - "${STATE_PATH}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print('')
    raise SystemExit
try:
    doc = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    print('')
    raise SystemExit
print(doc.get('snapshot_state', {}).get('last_created_at_utc', ''))
PY
)}"

  local snapshot_restored
  snapshot_restored="${SNAPSHOT_RESTORED_AT:-$(python3 - "${STATE_PATH}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print('')
    raise SystemExit
try:
    doc = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    print('')
    raise SystemExit
print(doc.get('snapshot_state', {}).get('last_restored_at_utc', ''))
PY
)}"

  python3 - "${STATE_PATH}" "${PLUGIN_RESULTS_PATH}" <<PY
import json
import pathlib
import sys
from datetime import datetime, timezone

state_path = pathlib.Path(sys.argv[1])
plugin_results_path = pathlib.Path(sys.argv[2])
plugin_results = json.loads(plugin_results_path.read_text(encoding='utf-8'))
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
    'summary': f"mantisbt action={${ACTION@Q}} via remote_mantisbt_app_manage.sh"
})
history = history[-40:]

installed_at = existing.get('installed_at_utc') or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

record = {
    'app_id': 'mantisbt-main',
    'name': 'MantisBT',
    'slug': ${APP_SLUG@Q},
    'installed_at_utc': installed_at,
    'updated_at_utc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
    'version': ${MANTISBT_VERSION@Q},
    'remote_host': ${HOST@Q},
    'remote_host_label': ${HOST_LABEL@Q},
    'remote_root_path': ${APP_CURRENT@Q},
    'web_root_path': ${APP_WEB_ROOT@Q},
    'base_urls': [${MANTISBT_URL@Q}, ${MANTISBT_LOCAL_URL@Q}],
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
        'private_files_path': ${MANTISBT_FILES_DIR@Q},
        'plugin_path': ${MANTISBT_PLUGIN_DIR@Q}
    },
    'source': {
        'channel': 'github.mantisbt.official-stable-release',
        'download_url': ${MANTISBT_SOURCE_URL@Q},
        'download_file': ${MANTISBT_SOURCE_FILE@Q},
        'download_sha256': ${MANTISBT_SOURCE_SHA256@Q},
        'resolved_release_version': ${MANTISBT_VERSION@Q},
        'release_tracking_mode': 'latest-stable-auto'
    },
    'credentials': {
        'db_name': ${DB_NAME@Q},
        'db_user': ${DB_USER@Q},
        'db_password': ${DB_PASS@Q},
        'db_prefix': ${DB_PREFIX@Q},
        'mantisbt_admin_user': ${ADMIN_USER@Q},
        'mantisbt_admin_password': ${ADMIN_PASSWORD@Q},
        'mantisbt_admin_email': ${ADMIN_EMAIL@Q}
    },
    'extension_inventory': plugin_results,
    'php_taint_trace_integration': {
        'enabled': True,
        'mode': 'auto_prepend+native_extension' if ${xmark_enabled_runtime@Q} == '1' else 'auto_prepend_only',
        'auto_prepend_file': ${PHP_TAINT_TRACE_PREPEND@Q},
        'xmark_extension_enabled': ${xmark_enabled_runtime@Q} == '1',
        'xmark_extension_path': ${XMARK_EXT_PATH@Q},
        'runtime_config_file': '/etc/php_taint_trace/runtime.json',
        'verifier_runtime_dir': ${APP_RUNTIME_VERIFIER@Q},
        'verifier_replay_target': 'local',
        'verifier_local_base_url': ${MANTISBT_LOCAL_URL@Q}
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
  install_or_update_mantisbt_core
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  run_mantisbt_install_or_upgrade
  install_catalog_plugins
  create_snapshot
  sync_ui_to_mantisbt_runtime
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

  MANTISBT_VERSION="removed"
  MANTISBT_URL="http://${HOST}:${APP_PORT}"
  MANTISBT_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
  SNAPSHOT_CREATED_AT=""
  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  state_json >/dev/null
}

case "${ACTION}" in
  install)
    do_install_or_update
    ;;
  update)
    do_install_or_update
    ;;
  snapshot-create)
    do_snapshot_create
    ;;
  snapshot-restore|reset)
    do_snapshot_restore
    ;;
  status)
    do_status
    ;;
  remove)
    do_remove
    ;;
  register-inventory)
    do_status
    ;;
  xmark-healthcheck)
    do_xmark_healthcheck
    ;;
  *)
    echo "Unsupported action: ${ACTION}" >&2
    exit 1
    ;;
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
    f"# {state.get('name', 'MantisBT')} Remote App Record",
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
    f"- SHA256: `{source.get('download_sha256', '')}`",
    "",
    "## Inventory Files",
    f"- State: `{state_path}`",
    "- Extension allowlist: `plugins.allowlist.json`",
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
  echo "[remote-mantisbt-app] running remote action=${ACTION} app=${APP_SLUG} host=${HOST}"
  run_remote_action
fi

echo "[remote-mantisbt-app] syncing local inventory from remote state"
update_inventory
write_app_readme
update_root_installed_apps_readme
echo "[remote-mantisbt-app] complete"
echo "[remote-mantisbt-app] inventory=${INVENTORY_PATH}"
echo "[remote-mantisbt-app] app_state=${APP_DOC_ROOT}/latest_state.json"
