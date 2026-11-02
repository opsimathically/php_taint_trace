#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19138"
APP_SLUG="magento"
SOURCE_CHANNEL="mageos"
UI_SYNC="1"
RUN_VALIDATION="1"
ENABLE_XMARK="1"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
MODULE_ALLOWLIST_PATH="${ROOT_DIR}/remote_linux_container/installed_php_applications/apps/${APP_SLUG}/modules.allowlist.json"
REPO_PUBLIC_KEY=""
REPO_PRIVATE_KEY=""
REPO_KEY_FILE=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_magento_app_manage.sh <install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck> [options]

Options:
  --config PATH               External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL          Host label in config (default: lab.example.invalid)
  --remote-taint-root PATH    Remote php_taint_trace repo root (default: /opt/php_taint_trace_vuln_lab/rewrite)
  --install-root PATH         Remote multi-app install root (default: /opt/php_audit_apps)
  --app-port PORT             Magento Open Source port (default: 19138)
  --inventory PATH            External inventory path (default: PHP_TAINT_TRACE_INVENTORY_PATH or XDG state directory)
  --allowlist PATH            Module allowlist JSON path
  --repo-public-key KEY       repo.magento.com public key (username)
  --repo-private-key KEY      repo.magento.com private key (password)
  --repo-key-file PATH        JSON file with repo.magento.com keys (keys: public_key, private_key)
  --source-channel CHANNEL    Source channel: mageos|adobe (default: mageos)
  --no-ui-sync                Do not repoint UI daemon artifact sources to this app runtime
  --no-validation             Skip install-time taint/verifier smoke validation
  --enable-xmark              Load xmark extension for PHP-FPM worker startup (default: on)
  --disable-xmark             Explicitly disable xmark extension loading for PHP-FPM
  -h, --help                  Show help

Actions:
  install            Install or reconcile Magento Open Source + runtime integration
  update             Update Magento Open Source core/modules and refresh metadata
  reset              Restore latest baseline snapshot
  snapshot-create    Create baseline snapshot (db + mutable app content)
  snapshot-restore   Restore baseline snapshot
  xmark-healthcheck  Run remote xmark runtime healthcheck (load mode + hook dispatch)
  status             Print remote app state JSON
  remove             Remove Magento Open Source deployment (retain runtime metadata)
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
      MODULE_ALLOWLIST_PATH="$2"
      shift 2
      ;;
    --repo-public-key)
      REPO_PUBLIC_KEY="$2"
      shift 2
      ;;
    --repo-private-key)
      REPO_PRIVATE_KEY="$2"
      shift 2
      ;;
    --repo-key-file)
      REPO_KEY_FILE="$2"
      shift 2
      ;;
    --source-channel)
      SOURCE_CHANNEL="$2"
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

if ! [[ "${SOURCE_CHANNEL}" =~ ^(mageos|adobe)$ ]]; then
  echo "Invalid --source-channel '${SOURCE_CHANNEL}'. Allowed: mageos|adobe" >&2
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

if [[ -n "${REPO_KEY_FILE}" ]]; then
  if [[ ! -f "${REPO_KEY_FILE}" ]]; then
    echo "repo key file not found: ${REPO_KEY_FILE}" >&2
    exit 1
  fi
  mapfile -t _repo_keys < <(python3 - "${REPO_KEY_FILE}" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
print(str(obj.get('public_key', '')).strip())
print(str(obj.get('private_key', '')).strip())
PY
)
  REPO_PUBLIC_KEY="${_repo_keys[0]}"
  REPO_PRIVATE_KEY="${_repo_keys[1]}"
fi

mkdir -p "${APP_DOC_ROOT}"
if [[ ! -f "${MODULE_ALLOWLIST_PATH}" ]]; then
  cat > "${MODULE_ALLOWLIST_PATH}" <<'JSON'
{
  "composer_packages": [
    { "package": "yireo/magento2-replace-tools", "constraint": "*" },
    { "package": "yireo/magento2-extensionchecker", "constraint": "*" },
    { "package": "integer-net/magento2-reviews", "constraint": "*" }
  ],
  "git_modules": [
    { "name": "Yireo_Webp2", "repo": "https://github.com/yireo/Yireo_Webp2.git", "branch": "master", "target": "app/code/Yireo/Webp2" },
    { "name": "Mage2tv_MagentoCacheClean", "repo": "https://github.com/mage2tv/magento-cache-clean.git", "branch": "main", "target": "app/code/Mage2tv/MagentoCacheClean" }
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

MODULE_ALLOWLIST_B64="$(base64 -w0 "${MODULE_ALLOWLIST_PATH}")"
STATE_PATH="${INSTALL_ROOT}/_runtime/${APP_SLUG}/app_state.json"

run_remote_action() {
  local remote_cmd
  remote_cmd="$(printf \
    "ACTION=%q APP_SLUG=%q APP_PORT=%q INSTALL_ROOT=%q REMOTE_TAINT_ROOT=%q HOST=%q HOST_LABEL=%q SSH_USER=%q SUDOPASS=%q UI_SYNC=%q RUN_VALIDATION=%q ENABLE_XMARK=%q MODULE_ALLOWLIST_B64=%q REPO_PUBLIC_KEY=%q REPO_PRIVATE_KEY=%q SOURCE_CHANNEL=%q bash -s" \
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
    "${MODULE_ALLOWLIST_B64}" \
    "${REPO_PUBLIC_KEY}" \
    "${REPO_PRIVATE_KEY}" \
    "${SOURCE_CHANNEL}" \
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
APP_WEB_ROOT="${APP_CURRENT}/pub"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_RUNTIME_VERIFIER="${APP_RUNTIME}/verifier"
APP_RUNTIME_FINDINGS="${APP_RUNTIME}/findings"
APP_SNAPSHOT_DIR="${APP_RUNTIME}/snapshots/latest"
STATE_PATH="${APP_RUNTIME}/app_state.json"
MODULE_RESULTS_PATH="${APP_RUNTIME}/module_results.json"
ALLOWLIST_PATH="${APP_RUNTIME}/modules.allowlist.json"
MODULE_PATHS_FILE="${APP_RUNTIME}/installed_module_paths.txt"
TMP_ROOT="/tmp/php_taint_trace_magento_install_${APP_SLUG}"
PHP_TAINT_TRACE_PREPEND="${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php"
XMARK_EXT_PATH="${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
CURL_DL_FLAGS=(--fail --silent --show-error --location --continue-at - --connect-timeout 20 --max-time 1800 --retry 2 --retry-delay 2)

MGT_VERSION="unknown"
MGT_URL="http://${HOST}:${APP_PORT}"
MGT_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
MGT_SOURCE_URL="https://repo.magento.com"
MGT_VERSION_CONSTRAINT="2.4.*"
COMPOSER_BIN="/usr/local/bin/composer-ptt"
COMPOSER_SCAN_DIR=""
SOURCE_CHANNEL="${SOURCE_CHANNEL:-mageos}"
mkdir -p "${TMP_ROOT}"
printf '%s' "${MODULE_ALLOWLIST_B64}" | base64 -d > "${TMP_ROOT}/modules.allowlist.json"

ensure_prerequisites() {
  local detected_php_version php_series php_prefix
  detected_php_version="$(php -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;' 2>/dev/null || true)"
  if [[ -z "${detected_php_version}" ]]; then
    detected_php_version="8.4"
  fi
  php_series="${detected_php_version}"
  php_prefix="php${php_series}"

  run_sudo apt-get update -y
  run_sudo apt-get install -y \
    curl unzip rsync jq tar gzip git ca-certificates gnupg apt-transport-https lsb-release \
    mercurial subversion fossil \
    mariadb-client mariadb-server \
    nginx composer \
    openjdk-17-jre-headless

  local required_php_pkgs=(
    "${php_prefix}-cli"
    "${php_prefix}-fpm"
    "${php_prefix}-mysql"
    "${php_prefix}-xml"
    "${php_prefix}-gd"
    "${php_prefix}-curl"
    "${php_prefix}-mbstring"
    "${php_prefix}-zip"
    "${php_prefix}-intl"
    "${php_prefix}-bcmath"
    "${php_prefix}-soap"
    "${php_prefix}-opcache"
  )
  local optional_php_pkgs=(
    "${php_prefix}-ldap"
    "${php_prefix}-imagick"
    "${php_prefix}-sodium"
    "php-imagick"
  )

  local pkg
  for pkg in "${required_php_pkgs[@]}"; do
    if ! run_sudo apt-cache show "${pkg}" >/dev/null 2>&1; then
      echo "Missing required PHP package on host apt sources: ${pkg}" >&2
      exit 1
    fi
  done
  run_sudo apt-get install -y "${required_php_pkgs[@]}"

  local install_optional=()
  for pkg in "${optional_php_pkgs[@]}"; do
    if run_sudo apt-cache show "${pkg}" >/dev/null 2>&1; then
      install_optional+=("${pkg}")
    fi
  done
  if [[ ${#install_optional[@]} -gt 0 ]]; then
    run_sudo apt-get install -y "${install_optional[@]}"
  fi

  run_sudo systemctl enable --now nginx mariadb
}

ensure_modern_composer() {
  if run_sudo test -x "${COMPOSER_BIN}"; then
    return
  fi
  run_sudo bash -lc "php -r \"copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');\""
  run_sudo bash -lc "php /tmp/composer-setup.php --2 --install-dir=/usr/local/bin --filename=$(basename "${COMPOSER_BIN}")"
  run_sudo rm -f /tmp/composer-setup.php
}

prepare_composer_scan_dir() {
  COMPOSER_SCAN_DIR="/tmp/php_taint_trace_${APP_SLUG}_composer_scan"
  run_sudo rm -rf "${COMPOSER_SCAN_DIR}"
  run_sudo mkdir -p "${COMPOSER_SCAN_DIR}"
  run_sudo bash -lc "for f in /etc/php/${PHP_SERIES}/cli/conf.d/*.ini; do b=\$(basename \"\$f\"); case \"\$b\" in *xdebug*|*xmark*) continue ;; esac; ln -s \"\$f\" \"${COMPOSER_SCAN_DIR}/\$b\"; done"
  run_sudo chown -R www-data:www-data "${COMPOSER_SCAN_DIR}"
}

composer_exec() {
  run_sudo env \
    HOME=/root \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    COMPOSER_HOME="${APP_SHARED}/composer" \
    COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_DISABLE_XDEBUG_WARN=1 \
    COMPOSER_PROCESS_TIMEOUT=0 \
    XDEBUG_MODE=off \
    PHP_INI_SCAN_DIR="${COMPOSER_SCAN_DIR}" \
    php -d default_socket_timeout=1800 "${COMPOSER_BIN}" "$@"
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

configure_opensearch_repo_and_install() {
  if run_sudo dpkg -s opensearch >/dev/null 2>&1; then
    return
  fi

  run_sudo mkdir -p /usr/share/keyrings
  run_sudo bash -lc "curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch.pgp | gpg --dearmor -o /usr/share/keyrings/opensearch-keyring.gpg"
  write_root_file /etc/apt/sources.list.d/opensearch-2.x.list <<'SRC'
deb [signed-by=/usr/share/keyrings/opensearch-keyring.gpg] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main
SRC
  run_sudo apt-get update -y
  run_sudo env OPENSEARCH_INITIAL_ADMIN_PASSWORD='PtTAuditOpensearch!123' apt-get install -y opensearch
}

configure_opensearch_runtime() {
  configure_opensearch_repo_and_install

  write_root_file /etc/opensearch/opensearch.yml <<'YML'
cluster.name: magento-ptt
node.name: magento-ptt-1
path.data: /var/lib/opensearch
path.logs: /var/log/opensearch
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
plugins.security.disabled: true
YML

  run_sudo systemctl enable opensearch
  run_sudo systemctl restart opensearch

  local ok="0"
  for _ in $(seq 1 60); do
    if run_sudo curl -fsS http://127.0.0.1:9200 >/dev/null 2>&1; then
      ok="1"
      break
    fi
    sleep 1
  done

  if [[ "${ok}" != "1" ]]; then
    run_sudo systemctl status opensearch --no-pager || true
    echo "OpenSearch did not become healthy on 127.0.0.1:9200" >&2
    exit 1
  fi
}

init_directories() {
  run_sudo mkdir -p \
    "${APP_CURRENT}" \
    "${APP_SHARED}" \
    "${APP_SHARED}/var" \
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
  run_sudo chmod -R u+rwX,g+rwX "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}" "${APP_SHARED}/var"
}

load_or_create_credentials() {
  local creds_path="${APP_SHARED}/credentials.json"
  run_sudo mkdir -p "${APP_SHARED}"

  if run_sudo test -f "${creds_path}"; then
    local creds_json
    creds_json="$(run_sudo cat "${creds_path}")"
    DB_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_name"])' <<<"${creds_json}")"
    DB_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_user"])' <<<"${creds_json}")"
    DB_PASS="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_password"])' <<<"${creds_json}")"
    DB_PREFIX="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_prefix"])' <<<"${creds_json}")"
    ADMIN_FIRSTNAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_firstname"])' <<<"${creds_json}")"
    ADMIN_LASTNAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_lastname"])' <<<"${creds_json}")"
    ADMIN_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_user"])' <<<"${creds_json}")"
    ADMIN_PASSWORD="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_password"])' <<<"${creds_json}")"
    ADMIN_EMAIL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_email"])' <<<"${creds_json}")"
    REPO_KEY_PUBLIC="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("repo_public_key", ""))' <<<"${creds_json}")"
    REPO_KEY_PRIVATE="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("repo_private_key", ""))' <<<"${creds_json}")"
  else
    DB_NAME="magento_${APP_SLUG}"
    DB_USER="magento_${APP_SLUG}_user"
    DB_PASS="$(openssl rand -hex 16)"
    DB_PREFIX="mgt_"
    ADMIN_FIRSTNAME="Audit"
    ADMIN_LASTNAME="Operator"
    ADMIN_USER="magento_admin_${APP_SLUG}"
    ADMIN_PASSWORD="$(openssl rand -hex 14)"
    ADMIN_EMAIL="audit+${APP_SLUG}@local.invalid"
    REPO_KEY_PUBLIC="${REPO_PUBLIC_KEY}"
    REPO_KEY_PRIVATE="${REPO_PRIVATE_KEY}"
  fi

  if [[ -n "${REPO_PUBLIC_KEY}" ]]; then
    REPO_KEY_PUBLIC="${REPO_PUBLIC_KEY}"
  fi
  if [[ -n "${REPO_PRIVATE_KEY}" ]]; then
    REPO_KEY_PRIVATE="${REPO_PRIVATE_KEY}"
  fi

  python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "db_prefix": ${DB_PREFIX@Q},
  "admin_firstname": ${ADMIN_FIRSTNAME@Q},
  "admin_lastname": ${ADMIN_LASTNAME@Q},
  "admin_user": ${ADMIN_USER@Q},
  "admin_password": ${ADMIN_PASSWORD@Q},
  "admin_email": ${ADMIN_EMAIL@Q},
  "repo_public_key": ${REPO_KEY_PUBLIC@Q},
  "repo_private_key": ${REPO_KEY_PRIVATE@Q}
}, indent=2))
PY
  run_sudo install -m 0600 "${TMP_ROOT}/credentials.json" "${creds_path}"
  ensure_file_owner "${creds_path}" "${SSH_USER}" "${SSH_USER}"

  if [[ "${SOURCE_CHANNEL}" == "adobe" && "${ACTION}" =~ ^(install|update)$ ]] && ([[ -z "${REPO_KEY_PUBLIC}" ]] || [[ -z "${REPO_KEY_PRIVATE}" ]]); then
    echo "repo.magento.com keys are required for install/update. Provide --repo-public-key and --repo-private-key (or --repo-key-file)." >&2
    exit 1
  fi
}

configure_composer_auth() {
  run_sudo mkdir -p "${APP_SHARED}/composer"
  python3 - <<PY > "${TMP_ROOT}/auth.json"
import json
print(json.dumps({
  "http-basic": {
    "repo.magento.com": {
      "username": ${REPO_KEY_PUBLIC@Q},
      "password": ${REPO_KEY_PRIVATE@Q}
    }
  }
}, indent=2))
PY
  run_sudo install -m 0600 "${TMP_ROOT}/auth.json" "${APP_SHARED}/composer/auth.json"
  run_sudo chown -R www-data:www-data "${APP_SHARED}/composer"
}

provision_database() {
  run_sudo mysql --execute "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  run_sudo mysql --execute "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  run_sudo mysql --execute "CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';"
  run_sudo mysql --execute "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"
}

is_magento_installed() {
  if ! run_sudo test -f "${APP_CURRENT}/app/etc/env.php"; then
    return 1
  fi

  local cnt
  cnt="$(run_sudo mysql --batch --raw --skip-column-names --execute "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}' AND table_name='${DB_PREFIX}setup_module';" 2>/dev/null || echo 0)"
  if [[ "${cnt}" == "0" ]]; then
    return 1
  fi

  local rows
  rows="$(run_sudo mysql --batch --raw --skip-column-names --execute "SELECT COUNT(*) FROM ${DB_NAME}.${DB_PREFIX}setup_module;" 2>/dev/null || echo 0)"
  [[ "${rows}" != "0" ]]
}

install_or_update_magento_core() {
  run_sudo mkdir -p "${APP_BASE}"
  if [[ "${SOURCE_CHANNEL}" == "adobe" ]]; then
    configure_composer_auth
    MGT_SOURCE_URL="https://repo.magento.com"
  else
    MGT_SOURCE_URL="https://repo.mage-os.org"
  fi

  if ! is_magento_installed; then
    run_sudo rm -rf "${APP_CURRENT}"
    run_sudo mkdir -p "${APP_CURRENT}"

    local project_package
    if [[ "${SOURCE_CHANNEL}" == "adobe" ]]; then
      project_package="magento/project-community-edition=${MGT_VERSION_CONSTRAINT}"
    else
      project_package="mage-os/project-community-edition"
    fi

    local attempt
    local max_attempts=3
    local create_ok="0"
    for attempt in $(seq 1 "${max_attempts}"); do
      if composer_exec create-project --repository-url="${MGT_SOURCE_URL}" \
        "${project_package}" \
        "${APP_CURRENT}" --no-interaction --no-dev --prefer-dist --no-progress; then
        create_ok="1"
        break
      fi
      if [[ "${attempt}" -lt "${max_attempts}" ]]; then
        echo "Magento create-project failed (attempt ${attempt}/${max_attempts}); retrying..." >&2
        run_sudo rm -rf "${APP_CURRENT}"
        run_sudo mkdir -p "${APP_CURRENT}"
        sleep 3
      fi
    done
    if [[ "${create_ok}" != "1" ]]; then
      echo "Composer create-project for Magento failed." >&2
      exit 1
    fi
  else
    if [[ "${ACTION}" == "install" ]]; then
      echo "Magento already installed; skipping composer update during install reconciliation."
    else
    local attempt
    local max_attempts=3
    local update_ok="0"
    for attempt in $(seq 1 "${max_attempts}"); do
      if run_sudo env \
        HOME=/root \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        COMPOSER_HOME="${APP_SHARED}/composer" \
        COMPOSER_ALLOW_SUPERUSER=1 \
        COMPOSER_DISABLE_XDEBUG_WARN=1 \
        COMPOSER_PROCESS_TIMEOUT=0 \
        XDEBUG_MODE=off \
        PHP_INI_SCAN_DIR="${COMPOSER_SCAN_DIR}" \
        bash -lc "cd '${APP_CURRENT}' && php -d default_socket_timeout=1800 '${COMPOSER_BIN}' update --no-interaction --with-all-dependencies --no-dev --prefer-dist --no-progress"; then
        update_ok="1"
        break
      fi
      if [[ "${attempt}" -lt "${max_attempts}" ]]; then
        echo "Magento composer update failed (attempt ${attempt}/${max_attempts}); retrying..." >&2
        sleep 3
      fi
    done
    if [[ "${update_ok}" != "1" ]]; then
      echo "Magento composer update failed." >&2
      exit 1
    fi
    fi
  fi

  ensure_file_owner "${APP_CURRENT}" "www-data" "www-data"
  run_sudo mkdir -p "${APP_CURRENT}/var" "${APP_CURRENT}/generated" "${APP_CURRENT}/pub/static" "${APP_CURRENT}/pub/media"
  run_sudo chmod -R u+rwX,g+rwX "${APP_CURRENT}/var" "${APP_CURRENT}/generated" "${APP_CURRENT}/pub/static" "${APP_CURRENT}/pub/media"

  local detected
  detected="$(run_sudo -u www-data -- php -r 'if (file_exists($argv[1])) { $c = include $argv[1]; if (is_array($c) && isset($c["version"])) echo $c["version"]; }' "${APP_CURRENT}/composer.json" 2>/dev/null || true)"
  if [[ -n "${detected}" ]]; then
    MGT_VERSION="${detected}"
  fi
}

run_magento_install_or_upgrade() {
  MGT_URL="http://${HOST}:${APP_PORT}"
  MGT_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  if is_magento_installed; then
    run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" setup:upgrade --keep-generated >/dev/null 2>&1 || true
    run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" indexer:reindex >/dev/null 2>&1 || true
    return
  fi

  run_sudo mysql --execute "DROP DATABASE IF EXISTS ${DB_NAME}; CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  run_sudo mysql --execute "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"

  run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" setup:install \
    --base-url="${MGT_URL}" \
    --db-host=127.0.0.1 \
    --db-name="${DB_NAME}" \
    --db-user="${DB_USER}" \
    --db-password="${DB_PASS}" \
    --db-prefix="${DB_PREFIX}" \
    --admin-firstname="${ADMIN_FIRSTNAME}" \
    --admin-lastname="${ADMIN_LASTNAME}" \
    --admin-email="${ADMIN_EMAIL}" \
    --admin-user="${ADMIN_USER}" \
    --admin-password="${ADMIN_PASSWORD}" \
    --language=en_US \
    --currency=USD \
    --timezone=Pacific/Honolulu \
    --use-rewrites=1 \
    --search-engine=opensearch \
    --opensearch-host=127.0.0.1 \
    --opensearch-port=9200 \
    --opensearch-index-prefix="magento_${APP_SLUG}"

  run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" setup:upgrade --keep-generated >/dev/null 2>&1 || true
  run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" indexer:reindex >/dev/null 2>&1 || true
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
upstream fastcgi_backend {
    server unix:${PHP_FPM_SOCKET};
}

server {
    listen ${APP_PORT};
    listen [::]:${APP_PORT};
    server_name _;

    set \$MAGE_ROOT ${APP_CURRENT};
    include ${APP_CURRENT}/nginx.conf.sample;

    access_log /var/log/nginx/${APP_SLUG}_access.log;
    error_log /var/log/nginx/${APP_SLUG}_error.log;

    client_max_body_size 128M;
}
CONF

  run_sudo ln -sf "${NGINX_SITE_CONF}" "${NGINX_SITE_LINK}"
}

restart_services() {
  run_sudo nginx -t
  run_sudo systemctl restart "${PHP_FPM_SERVICE}"
  run_sudo systemctl restart nginx
}

install_catalog_modules() {
  cp "${TMP_ROOT}/modules.allowlist.json" "${ALLOWLIST_PATH}"
  ensure_file_owner "${ALLOWLIST_PATH}" "${SSH_USER}" "${SSH_USER}"
  : > "${MODULE_PATHS_FILE}"

  python3 - "${ALLOWLIST_PATH}" "${MODULE_RESULTS_PATH}" <<'PY'
import json
import sys
from pathlib import Path

allowlist = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
result = {
    'official': {'requested': [], 'installed': [], 'skipped': []},
    'third_party': {'requested': [], 'installed': [], 'skipped': []},
}
for entry in (allowlist.get('composer_packages') or []):
    if isinstance(entry, dict) and str(entry.get('package', '')).strip():
        result['official']['requested'].append({'type': 'composer', **entry})
for entry in (allowlist.get('git_modules') or []):
    if isinstance(entry, dict) and str(entry.get('repo', '')).strip() and str(entry.get('target', '')).strip():
        result['official']['requested'].append({'type': 'git', **entry})
Path(sys.argv[2]).write_text(json.dumps(result, indent=2), encoding='utf-8')
PY

  python3 - "${ALLOWLIST_PATH}" > "${TMP_ROOT}/module_actions.json" <<'PY'
import json, sys
obj=json.loads(open(sys.argv[1],'r',encoding='utf-8').read())
actions=[]
for e in (obj.get('composer_packages') or []):
    if not isinstance(e,dict):
        continue
    pkg=str(e.get('package','')).strip()
    if not pkg:
        continue
    con=str(e.get('constraint','*')).strip() or '*'
    actions.append({'kind':'composer','package':pkg,'constraint':con})
for e in (obj.get('git_modules') or []):
    if not isinstance(e,dict):
        continue
    repo=str(e.get('repo','')).strip()
    tgt=str(e.get('target','')).strip()
    if not repo or not tgt:
        continue
    actions.append({'kind':'git','name':str(e.get('name','')).strip() or tgt.replace('/','_'),'repo':repo,'branch':str(e.get('branch','')).strip() or 'main','target':tgt})
print(json.dumps(actions))
PY

  mapfile -t actions < <(python3 - "${TMP_ROOT}/module_actions.json" <<'PY'
import json,sys
for a in json.loads(open(sys.argv[1],'r',encoding='utf-8').read()):
    if a['kind']=='composer':
        print('composer\t{}\t{}'.format(a['package'],a['constraint']))
    else:
        print('git\t{}\t{}\t{}\t{}'.format(a['name'],a['repo'],a['branch'],a['target']))
PY
)

  local kind name repo branch target package constraint reason
  for row in "${actions[@]}"; do
    IFS=$'\t' read -r kind name repo branch target <<<"${row}"

    if [[ "${kind}" == "composer" ]]; then
      package="${name}"
      constraint="${repo}"
      if ! run_sudo env \
        HOME=/root \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        COMPOSER_HOME="${APP_SHARED}/composer" \
        COMPOSER_ALLOW_SUPERUSER=1 \
        COMPOSER_DISABLE_XDEBUG_WARN=1 \
        XDEBUG_MODE=off \
        PHP_INI_SCAN_DIR="${COMPOSER_SCAN_DIR}" \
        bash -lc "cd '${APP_CURRENT}' && '${COMPOSER_BIN}' require --no-interaction '${package}:${constraint}'" >/dev/null 2>&1; then
        reason="composer require failed"
        python3 - "${MODULE_RESULTS_PATH}" "${package}" "${constraint}" "${reason}" <<'PY'
import json,sys
p,package,constraint,reason=sys.argv[1:5]
d=json.loads(open(p,'r',encoding='utf-8').read())
d['official']['skipped'].append({'type':'composer','package':package,'constraint':constraint,'reason':reason})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
        continue
      fi
      run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" setup:upgrade >/dev/null 2>&1 || true
      python3 - "${MODULE_RESULTS_PATH}" "${package}" "${constraint}" <<'PY'
import json,sys
p,package,constraint=sys.argv[1:4]
d=json.loads(open(p,'r',encoding='utf-8').read())
d['official']['installed'].append({'type':'composer','package':package,'constraint':constraint})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
      continue
    fi

    if [[ "${kind}" == "git" ]]; then
      run_sudo mkdir -p "${APP_CURRENT}/$(dirname "${target}")"
      run_sudo rm -rf "${APP_CURRENT}/${target}"
      if ! run_sudo -u www-data -- git clone --depth 1 --branch "${branch}" "${repo}" "${APP_CURRENT}/${target}" >/dev/null 2>&1; then
        reason="git clone failed (${branch})"
        python3 - "${MODULE_RESULTS_PATH}" "${name}" "${repo}" "${branch}" "${target}" "${reason}" <<'PY'
import json,sys
p,name,repo,branch,target,reason=sys.argv[1:7]
d=json.loads(open(p,'r',encoding='utf-8').read())
d['official']['skipped'].append({'type':'git','name':name,'repo':repo,'branch':branch,'target':target,'reason':reason})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
        continue
      fi
      echo "${target}" >> "${MODULE_PATHS_FILE}"
      run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" setup:upgrade >/dev/null 2>&1 || true
      python3 - "${MODULE_RESULTS_PATH}" "${name}" "${repo}" "${branch}" "${target}" <<'PY'
import json,sys
p,name,repo,branch,target=sys.argv[1:6]
d=json.loads(open(p,'r',encoding='utf-8').read())
d['official']['installed'].append({'type':'git','name':name,'repo':repo,'branch':branch,'target':target})
open(p,'w',encoding='utf-8').write(json.dumps(d,indent=2))
PY
    fi
  done

  ensure_file_owner "${MODULE_RESULTS_PATH}" "${SSH_USER}" "${SSH_USER}"
  ensure_file_owner "${MODULE_PATHS_FILE}" "${SSH_USER}" "${SSH_USER}"
}

create_snapshot() {
  mkdir -p "${APP_SNAPSHOT_DIR}"
  if [[ ! -f "${MODULE_PATHS_FILE}" ]]; then
    : > "${MODULE_PATHS_FILE}"
  fi
  run_sudo bash -lc "mysqldump '${DB_NAME}' > '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo bash -lc "tar -czf '${APP_SNAPSHOT_DIR}/site_state.tar.gz' -C '${APP_CURRENT}' app/etc/env.php pub/media var"
  run_sudo install -m 0644 "${MODULE_PATHS_FILE}" "${APP_SNAPSHOT_DIR}/installed_module_paths.txt"
  run_sudo chown -R "${SSH_USER}:${SSH_USER}" "${APP_SNAPSHOT_DIR}"
  SNAPSHOT_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

restore_snapshot() {
  if [[ ! -f "${APP_SNAPSHOT_DIR}/db.sql" || ! -f "${APP_SNAPSHOT_DIR}/site_state.tar.gz" ]]; then
    echo "Snapshot missing at ${APP_SNAPSHOT_DIR}" >&2
    exit 1
  fi

  run_sudo mysql "${DB_NAME}" < "${APP_SNAPSHOT_DIR}/db.sql"
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/site_state.tar.gz" -C "${APP_CURRENT}"

  if [[ -f "${APP_SNAPSHOT_DIR}/installed_module_paths.txt" ]]; then
    run_sudo install -m 0644 "${APP_SNAPSHOT_DIR}/installed_module_paths.txt" "${MODULE_PATHS_FILE}"
  fi

  ensure_file_owner "${APP_CURRENT}/app/etc/env.php" "www-data" "www-data"
  run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" setup:upgrade >/dev/null 2>&1 || true
  run_sudo -u www-data -- php -d memory_limit=2G "${APP_CURRENT}/bin/magento" cache:flush >/dev/null 2>&1 || true
  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

refresh_magento_metadata() {
  MGT_URL="http://${HOST}:${APP_PORT}"
  MGT_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  local detected
  detected="$(run_sudo -u www-data -- php -r 'if (file_exists($argv[1])) { $j=json_decode(file_get_contents($argv[1]), true); if (is_array($j) && isset($j["version"])) echo $j["version"]; }' "${APP_CURRENT}/composer.json" 2>/dev/null || true)"
  if [[ -n "${detected}" ]]; then
    MGT_VERSION="${detected}"
  fi

  if [[ -z "${MGT_VERSION}" || "${MGT_VERSION}" == "unknown" ]]; then
    MGT_VERSION="$(python3 - "${STATE_PATH}" <<'PY'
import json, pathlib, sys
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

  if [[ -z "${MGT_VERSION}" ]]; then
    MGT_VERSION="unknown"
  fi
}

sync_ui_to_magento_runtime() {
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

  local probe_file="${APP_WEB_ROOT}/health_check.php"
  local backup_file="${TMP_ROOT}/health_check.php.validation.bak"
  local token
  token="$(openssl rand -hex 12)"

  if run_sudo test -f "${probe_file}"; then
    run_sudo cp "${probe_file}" "${backup_file}"
  fi

  write_probe_file "${probe_file}" "${token}" "ptt_probe"

  curl --fail --silent --show-error --location --connect-timeout 10 --max-time 30 "http://127.0.0.1:${APP_PORT}/health_check.php?ptt_probe=${token}&cmd=echo%20ptt_magento_smoke" >/dev/null

  (
    cd "${REMOTE_TAINT_ROOT}"
    run_sudo -u www-data -- env \
      PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${APP_RUNTIME_VERIFIER}" \
      PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=local \
      PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL="http://127.0.0.1:${APP_PORT}" \
      php scripts/run_verifier_worker.php --drain --max-cycles=40 >/dev/null
  )

  if run_sudo test -f "${backup_file}"; then
    run_sudo mv "${backup_file}" "${probe_file}"
  else
    run_sudo rm -f "${probe_file}"
  fi
}

xmark_healthcheck() {
  local xmark_ini_ok="0"
  local pool_ext_ok="0"
  local xmark_loaded="0"
  local register_hook_ok="0"
  local hook_dispatch_ok="0"
  local php_fpm_active="0"
  local nginx_active="0"

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

  local probe_file="${APP_WEB_ROOT}/health_check.php"
  local backup_file="${TMP_ROOT}/health_check.php.xmark.bak"
  local token
  token="$(openssl rand -hex 12)"

  if run_sudo test -f "${probe_file}"; then
    run_sudo cp "${probe_file}" "${backup_file}"
  fi

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
        'magento.healthcheck.system.before',
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
  http_code="$(curl --silent --show-error --location --connect-timeout 10 --max-time 30 -o "${tmp_response}" -w '%{http_code}' "http://127.0.0.1:${APP_PORT}/health_check.php?ptt_xmark_healthcheck=${token}&cmd=echo%20xmark_healthcheck_probe" || true)"

  if [[ "${http_code}" == "200" ]]; then
    while IFS='=' read -r key value; do
      case "${key}" in
        xmark_loaded) xmark_loaded="${value}" ;;
        register_hook) register_hook_ok="${value}" ;;
        hook_fired) hook_dispatch_ok="${value}" ;;
      esac
    done < "${tmp_response}"
  fi

  if run_sudo test -f "${backup_file}"; then
    run_sudo mv "${backup_file}" "${probe_file}"
  else
    run_sudo rm -f "${probe_file}"
  fi
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
  'php_fpm_active': ${php_fpm_active@Q} == '1',
  'nginx_active': ${nginx_active@Q} == '1',
  'php_fpm_service': ${PHP_FPM_SERVICE@Q},
  'pool_conf': ${PHP_POOL_CONF@Q},
  'xmark_ini': ${XMARK_FPM_INI@Q},
  'xmark_extension_path': ${XMARK_EXT_PATH@Q}
}, indent=2))
PY
}

state_json() {
  refresh_magento_metadata

  run_sudo mkdir -p "${APP_RUNTIME}"

  local xmark_enabled_runtime="0"
  if [[ "${ENABLE_XMARK}" == "1" ]] && run_sudo test -f "${XMARK_FPM_INI}" && run_sudo grep -q "${XMARK_EXT_PATH}" "${XMARK_FPM_INI}"; then
    xmark_enabled_runtime="1"
  elif run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    xmark_enabled_runtime="1"
  fi

  local deployment_status="not_installed"
  if run_sudo test -f "${APP_CURRENT}/app/etc/env.php"; then
    deployment_status="installed"
  fi
  if [[ "${ACTION}" == "remove" ]]; then
    deployment_status="removed"
  fi

  local db_version
  db_version="$(run_sudo mysql --version 2>/dev/null || true)"

  if [[ ! -f "${MODULE_RESULTS_PATH}" ]]; then
    printf '{"official":{"requested":[],"installed":[],"skipped":[]},"third_party":{"requested":[],"installed":[],"skipped":[]}}' > "${TMP_ROOT}/module_results.json"
    run_sudo install -m 0644 "${TMP_ROOT}/module_results.json" "${MODULE_RESULTS_PATH}"
    ensure_file_owner "${MODULE_RESULTS_PATH}" "${SSH_USER}" "${SSH_USER}"
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
print(((doc.get('snapshot_state') or {}).get('last_created_at_utc')) or '')
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
print(((doc.get('snapshot_state') or {}).get('last_restored_at_utc')) or '')
PY
)}"

  local installed_at
  installed_at="${INSTALL_TIMESTAMP:-$(python3 - "${STATE_PATH}" <<'PY'
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
print(doc.get('installed_at_utc') or '')
PY
)}"

  if [[ -z "${installed_at}" ]]; then
    installed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi

  local prev_history_json
  prev_history_json="$(python3 - "${STATE_PATH}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print('[]')
    raise SystemExit
try:
    doc = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    print('[]')
    raise SystemExit
hist = doc.get('change_history')
print(json.dumps(hist if isinstance(hist, list) else []))
PY
)"

  local action_summary
  action_summary="magento action=${ACTION} via remote_magento_app_manage.sh"

  python3 - <<PY
import json
from datetime import datetime, timezone

now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
prev = json.loads(${prev_history_json@Q})
prev.append({
    'timestamp_utc': now,
    'action': ${ACTION@Q},
    'summary': ${action_summary@Q}
})

modules = json.loads(open(${MODULE_RESULTS_PATH@Q}, 'r', encoding='utf-8').read())

state = {
    'app_id': 'magento-main',
    'name': ('Magento Open Source' if ${SOURCE_CHANNEL@Q} == 'adobe' else 'Mage-OS Distribution'),
    'slug': 'magento',
    'status': ${deployment_status@Q},
    'version': ${MGT_VERSION@Q},
    'installed_at_utc': ${installed_at@Q},
    'installed_by': 'codex',
    'remote_host_label': ${HOST_LABEL@Q},
    'remote_root_path': ${APP_CURRENT@Q},
    'web_root_path': ${APP_WEB_ROOT@Q},
    'base_urls': [${MGT_URL@Q}, ${MGT_LOCAL_URL@Q}],
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
        'search_backend': 'opensearch',
        'opensearch_url': 'http://127.0.0.1:9200'
    },
    'source': {
        'channel': ('repo.magento.com/latest-stable-2.4.x' if ${SOURCE_CHANNEL@Q} == 'adobe' else 'repo.mage-os.org/latest-stable'),
        'download_url': ('https://repo.magento.com' if ${SOURCE_CHANNEL@Q} == 'adobe' else 'https://repo.mage-os.org'),
        'resolved_release_version': ${MGT_VERSION@Q},
        'release_tracking_mode': ('latest-stable-2.4x-auto' if ${SOURCE_CHANNEL@Q} == 'adobe' else 'latest-stable-auto')
    },
    'credentials': {
        'db_name': ${DB_NAME@Q},
        'db_user': ${DB_USER@Q},
        'db_password': ${DB_PASS@Q},
        'db_prefix': ${DB_PREFIX@Q},
        'magento_admin_firstname': ${ADMIN_FIRSTNAME@Q},
        'magento_admin_lastname': ${ADMIN_LASTNAME@Q},
        'magento_admin_user': ${ADMIN_USER@Q},
        'magento_admin_password': ${ADMIN_PASSWORD@Q},
        'magento_admin_email': ${ADMIN_EMAIL@Q},
        'repo_public_key': ${REPO_KEY_PUBLIC@Q},
        'repo_private_key': ${REPO_KEY_PRIVATE@Q}
    },
    'module_inventory': modules,
    'php_taint_trace_integration': {
        'enabled': True,
        'mode': 'auto_prepend+native_extension',
        'auto_prepend_file': ${PHP_TAINT_TRACE_PREPEND@Q},
        'xmark_extension_enabled': ${xmark_enabled_runtime@Q} == '1',
        'xmark_extension_path': ${XMARK_EXT_PATH@Q},
        'runtime_config_file': '/etc/php_taint_trace/runtime.json',
        'verifier_runtime_dir': ${APP_RUNTIME_VERIFIER@Q},
        'verifier_replay_target': 'local',
        'verifier_local_base_url': f'http://127.0.0.1:{${APP_PORT@Q}}'
    },
    'snapshot_state': {
        'last_created_at_utc': ${snapshot_created@Q},
        'last_restored_at_utc': ${snapshot_restored@Q},
        'db_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/db.sql',
        'content_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/site_state.tar.gz'
    },
    'change_history': prev[-30:]
}
print(json.dumps(state, indent=2))
PY
}

persist_state() {
  state_json > "${TMP_ROOT}/state.json"
  run_sudo install -m 0644 "${TMP_ROOT}/state.json" "${STATE_PATH}"
  ensure_file_owner "${STATE_PATH}" "${SSH_USER}" "${SSH_USER}"
}

remove_deployment() {
  run_sudo rm -f "${NGINX_SITE_LINK}" "${NGINX_SITE_CONF}" "${PHP_POOL_CONF}"
  run_sudo rm -rf "${APP_BASE}"
  restart_services
  persist_state
}

register_inventory_only() {
  if run_sudo test -f "${STATE_PATH}"; then
    run_sudo cat "${STATE_PATH}"
  else
    persist_state
    run_sudo cat "${STATE_PATH}"
  fi
}

perform_install_or_update() {
  ensure_prerequisites
  ensure_modern_composer
  detect_php_fpm_context
  prepare_composer_scan_dir
  ensure_xmark_extension
  load_or_create_credentials
  init_directories
  provision_database
  install_or_update_magento_core
  configure_opensearch_runtime
  run_magento_install_or_upgrade
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  install_catalog_modules
  create_snapshot
  sync_ui_to_magento_runtime
  validation_smoke
  persist_state
}

perform_update() {
  ensure_prerequisites
  ensure_modern_composer
  detect_php_fpm_context
  prepare_composer_scan_dir
  ensure_xmark_extension
  load_or_create_credentials
  init_directories
  provision_database
  install_or_update_magento_core
  configure_opensearch_runtime
  run_magento_install_or_upgrade
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  install_catalog_modules
  sync_ui_to_magento_runtime
  validation_smoke
  persist_state
}

perform_status() {
  detect_php_fpm_context
  load_or_create_credentials
  persist_state
  register_inventory_only
}

perform_snapshot_create() {
  detect_php_fpm_context
  load_or_create_credentials
  create_snapshot
  persist_state
}

perform_snapshot_restore() {
  detect_php_fpm_context
  load_or_create_credentials
  restore_snapshot
  restart_services
  persist_state
}

perform_reset() {
  perform_snapshot_restore
}

case "${ACTION}" in
  install)
    perform_install_or_update
    ;;
  update)
    perform_update
    ;;
  status)
    perform_status
    ;;
  snapshot-create)
    perform_snapshot_create
    ;;
  snapshot-restore)
    perform_snapshot_restore
    ;;
  reset)
    perform_reset
    ;;
  remove)
    detect_php_fpm_context
    remove_deployment
    ;;
  register-inventory)
    register_inventory_only
    ;;
  xmark-healthcheck)
    detect_php_fpm_context
    load_or_create_credentials
    xmark_healthcheck
    persist_state
    ;;
  *)
    echo "unsupported action ${ACTION}" >&2
    exit 1
    ;;
esac
REMOTE
}

refresh_local_inventory_from_remote_state() {
  local remote_state
  remote_state="$(ssh_exec "cat '${STATE_PATH}'" 2>/dev/null || true)"
  if [[ -z "${remote_state}" ]]; then
    echo "Remote app state file not found: ${STATE_PATH}" >&2
    return 1
  fi

  python3 - "${INVENTORY_PATH}" "${APP_DOC_ROOT}/latest_state.json" "${remote_state}" <<'PY'
import json
import sys
from pathlib import Path

inventory_path = Path(sys.argv[1])
latest_state_path = Path(sys.argv[2])
state_raw = sys.argv[3]

inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
state = json.loads(state_raw)

apps = inventory.setdefault('applications', [])
if not isinstance(apps, list):
    raise SystemExit('inventory applications field must be a list')

updated = False
for idx, app in enumerate(apps):
    if isinstance(app, dict) and app.get('app_id') == state.get('app_id'):
        apps[idx] = state
        updated = True
        break
if not updated:
    apps.append(state)

inventory['updated_at_utc'] = state.get('change_history', [{}])[-1].get('timestamp_utc') or inventory.get('updated_at_utc')
inventory_path.write_text(json.dumps(inventory, indent=2), encoding='utf-8')
latest_state_path.parent.mkdir(parents=True, exist_ok=True)
latest_state_path.write_text(json.dumps(state, indent=2), encoding='utf-8')
PY
}

echo "[remote-magento-app] running remote action=${ACTION} app=${APP_SLUG} host=${HOST}"
run_remote_action

if [[ "${ACTION}" != "register-inventory" ]]; then
  echo "[remote-magento-app] syncing local inventory from remote state"
fi
refresh_local_inventory_from_remote_state

echo "[remote-magento-app] complete"
echo "[remote-magento-app] inventory=${INVENTORY_PATH}"
echo "[remote-magento-app] app_state=${APP_DOC_ROOT}/latest_state.json"
