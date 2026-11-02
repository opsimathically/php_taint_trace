#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19136"
APP_SLUG="moodle"
UI_SYNC="1"
RUN_VALIDATION="1"
ENABLE_XMARK="1"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
PLUGIN_ALLOWLIST_PATH="${ROOT_DIR}/remote_linux_container/installed_php_applications/apps/${APP_SLUG}/plugins.allowlist.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_moodle_app_manage.sh <install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck> [options]

Options:
  --config PATH               External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL          Host label in config (default: lab.example.invalid)
  --remote-taint-root PATH    Remote php_taint_trace repo root (default: /opt/php_taint_trace_vuln_lab/rewrite)
  --install-root PATH         Remote multi-app install root (default: /opt/php_audit_apps)
  --app-port PORT             Moodle port (default: 19136)
  --inventory PATH            External inventory path (default: PHP_TAINT_TRACE_INVENTORY_PATH or XDG state directory)
  --allowlist PATH            Plugin allowlist JSON path
  --no-ui-sync                Do not repoint UI daemon artifact sources to this app runtime
  --no-validation             Skip install-time taint/verifier smoke validation
  --enable-xmark              Load xmark extension for PHP-FPM worker startup (default: on)
  --disable-xmark             Explicitly disable xmark extension loading for PHP-FPM
  -h, --help                  Show help

Actions:
  install            Install or reconcile Moodle + runtime integration
  update             Update Moodle core/plugins and refresh metadata
  reset              Restore latest baseline snapshot
  snapshot-create    Create baseline snapshot (db + moodledata/config)
  snapshot-restore   Restore baseline snapshot
  xmark-healthcheck  Run remote xmark runtime healthcheck (load mode + hook dispatch)
  status             Print remote app state JSON
  remove             Remove Moodle deployment (retain runtime metadata)
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
      PLUGIN_ALLOWLIST_PATH="$2"
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
if [[ ! -f "${PLUGIN_ALLOWLIST_PATH}" ]]; then
  cat > "${PLUGIN_ALLOWLIST_PATH}" <<'JSON'
{
  "plugins": [
    { "component": "mod_attendance", "git_url": "https://github.com/danmarsden/moodle-mod_attendance.git", "branch": "master" },
    { "component": "mod_checklist", "git_url": "https://github.com/davosmith/moodle-mod_checklist.git", "branch": "master" },
    { "component": "mod_publication", "git_url": "https://github.com/FMCorz/moodle-mod_publication.git", "branch": "master" },
    { "component": "block_xp", "git_url": "https://github.com/FMCorz/moodle-block_xp.git", "branch": "master" },
    { "component": "local_mailtest", "git_url": "https://github.com/moodlehq/moodle-local_mailtest.git", "branch": "master" },
    { "component": "theme_moove", "git_url": "https://github.com/willianmano/moodle-theme_moove.git", "branch": "master" },
    { "component": "enrol_autoenrol", "git_url": "https://github.com/bmbrands/moodle-enrol_autoenrol.git", "branch": "master" },
    { "component": "tool_certificate", "git_url": "https://github.com/mdjnelson/moodle-tool_certificate.git", "branch": "master" }
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

PLUGIN_ALLOWLIST_B64="$(base64 -w0 "${PLUGIN_ALLOWLIST_PATH}")"
STATE_PATH="${INSTALL_ROOT}/_runtime/${APP_SLUG}/app_state.json"

run_remote_action() {
  local remote_cmd
  remote_cmd="$(printf \
    "ACTION=%q APP_SLUG=%q APP_PORT=%q INSTALL_ROOT=%q REMOTE_TAINT_ROOT=%q HOST=%q HOST_LABEL=%q SSH_USER=%q SUDOPASS=%q UI_SYNC=%q RUN_VALIDATION=%q ENABLE_XMARK=%q PLUGIN_ALLOWLIST_B64=%q bash -s" \
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
    "${PLUGIN_ALLOWLIST_B64}" \
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
APP_WEB_ROOT="${APP_CURRENT}/public"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_RUNTIME_VERIFIER="${APP_RUNTIME}/verifier"
APP_RUNTIME_FINDINGS="${APP_RUNTIME}/findings"
APP_SNAPSHOT_DIR="${APP_RUNTIME}/snapshots/latest"
STATE_PATH="${APP_RUNTIME}/app_state.json"
PLUGIN_RESULTS_PATH="${APP_RUNTIME}/plugin_results.json"
ALLOWLIST_PATH="${APP_RUNTIME}/plugins.allowlist.json"
PLUGIN_PATHS_FILE="${APP_RUNTIME}/installed_plugin_paths.txt"
TMP_ROOT="/tmp/php_taint_trace_moodle_install_${APP_SLUG}"
PHP_TAINT_TRACE_PREPEND="${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php"
XMARK_EXT_PATH="${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
CURL_DL_FLAGS=(--fail --silent --show-error --location --continue-at - --connect-timeout 20 --max-time 1800 --retry 2 --retry-delay 2)

MDL_VERSION="unknown"
MDL_URL="http://${HOST}:${APP_PORT}"
MDL_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
MDL_SOURCE_URL=""
mkdir -p "${TMP_ROOT}"
printf '%s' "${PLUGIN_ALLOWLIST_B64}" | base64 -d > "${TMP_ROOT}/plugins.allowlist.json"

ensure_prerequisites() {
  run_sudo apt-get update -y
  run_sudo apt-get install -y \
    curl unzip rsync jq tar gzip git ca-certificates \
    mariadb-client mariadb-server \
    nginx php-cli php-fpm php-mysql php-xml php-gd php-curl php-mbstring php-zip php-intl php-apcu php-bcmath php-soap php-ldap php-imagick
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
    "${APP_SHARED}/moodledata" \
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
  run_sudo chmod -R u+rwX,g+rwX "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}" "${APP_SHARED}/moodledata"
}

load_or_create_credentials() {
  local creds_path="${APP_SHARED}/credentials.json"
  local credentials_changed="0"

  if run_sudo test -f "${creds_path}"; then
    local creds_json
    creds_json="$(run_sudo cat "${creds_path}")"
    DB_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_name"])' <<<"${creds_json}")"
    DB_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_user"])' <<<"${creds_json}")"
    DB_PASS="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_password"])' <<<"${creds_json}")"
    DB_PREFIX="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_prefix"])' <<<"${creds_json}")"
    ADMIN_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_name"])' <<<"${creds_json}")"
    ADMIN_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_user"])' <<<"${creds_json}")"
    ADMIN_PASSWORD="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_password"])' <<<"${creds_json}")"
    ADMIN_EMAIL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_email"])' <<<"${creds_json}")"
  else
    DB_NAME="moodle_${APP_SLUG}"
    DB_USER="moodle_${APP_SLUG}_user"
    DB_PASS="$(openssl rand -hex 16)"
    DB_PREFIX="mdlm_"
    ADMIN_NAME="Moodle Audit"
    ADMIN_USER="moodle_admin_${APP_SLUG}"
    ADMIN_PASSWORD="$(openssl rand -hex 14)"
    ADMIN_EMAIL="audit+${APP_SLUG}@local.invalid"

    python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "db_prefix": ${DB_PREFIX@Q},
  "admin_name": ${ADMIN_NAME@Q},
  "admin_user": ${ADMIN_USER@Q},
  "admin_password": ${ADMIN_PASSWORD@Q},
  "admin_email": ${ADMIN_EMAIL@Q}
}, indent=2))
PY
    run_sudo install -m 0600 "${TMP_ROOT}/credentials.json" "${creds_path}"
    ensure_file_owner "${creds_path}" "${SSH_USER}" "${SSH_USER}"
    return
  fi

  if ! [[ "${DB_PREFIX}" =~ ^[a-z_]+$ ]] || [[ ${#DB_PREFIX} -gt 10 ]]; then
    DB_PREFIX="mdlm_"
    credentials_changed="1"
  fi

  if [[ "${credentials_changed}" == "1" ]]; then
    python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "db_prefix": ${DB_PREFIX@Q},
  "admin_name": ${ADMIN_NAME@Q},
  "admin_user": ${ADMIN_USER@Q},
  "admin_password": ${ADMIN_PASSWORD@Q},
  "admin_email": ${ADMIN_EMAIL@Q}
}, indent=2))
PY
    run_sudo install -m 0600 "${TMP_ROOT}/credentials.json" "${creds_path}"
    ensure_file_owner "${creds_path}" "${SSH_USER}" "${SSH_USER}"
  fi
}

provision_database() {
  run_sudo mysql --execute "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  run_sudo mysql --execute "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  run_sudo mysql --execute "CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';"
  run_sudo mysql --execute "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"
}

resolve_moodle_release() {
  local html
  html="$(run_sudo curl --fail --silent --show-error --location --connect-timeout 20 --max-time 60 -A 'Mozilla/5.0 (X11; Linux x86_64)' 'https://download.moodle.org/releases/latest/' || true)"

  mapfile -t _release < <(HTML_CONTENT="${html}" python3 - <<'PY'
import re
import os

html = os.environ.get('HTML_CONTENT', '')

patterns = [
    r'https://download\.moodle\.org/download\.php/direct/(stable\d+)/([^"\']+?\.tgz)',
    r'https://download\.moodle\.org/download\.php/(stable\d+)/([^"\']+?\.tgz)'
]

seen = []
for pattern in patterns:
    for stable, file_name in re.findall(pattern, html):
        url = f"https://download.moodle.org/download.php/direct/{stable}/{file_name}"
        if url not in seen:
            seen.append(url)

if not seen:
    seen.extend([
        "https://download.moodle.org/download.php/direct/stable502/moodle-latest-502.tgz",
        "https://download.moodle.org/download.php/direct/stable501/moodle-latest-501.tgz",
        "https://download.moodle.org/download.php/direct/stable500/moodle-latest-500.tgz",
    ])

def stable_rank(url: str) -> int:
    m = re.search(r'/stable(\d+)/', url)
    return int(m.group(1)) if m else 0

def version_rank(url: str):
    m = re.search(r'/moodle-(\d+)\.(\d+)(?:\.(\d+))?\.tgz$', url)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

candidates = sorted(seen, key=lambda u: (stable_rank(u), version_rank(u)), reverse=True)
if not candidates:
    raise SystemExit("unable to resolve Moodle latest stable package URL")

candidate = candidates[0]
print(candidate)
print(candidate)
PY
)

  if [[ ${#_release[@]} -lt 2 ]]; then
    echo "Failed to resolve Moodle latest stable package URL" >&2
    exit 1
  fi

  MDL_SOURCE_URL="${_release[0]}"
  local effective_url="${_release[1]}"
  local detected
  detected="$(python3 - <<PY
import re
url = ${effective_url@Q}
m = re.search(r'moodle-([0-9]+(?:\.[0-9]+){1,2})\.tgz', url)
if m:
    print(m.group(1))
else:
    print('unknown')
PY
)"
  if [[ -n "${detected}" ]]; then
    MDL_VERSION="${detected}"
  fi
}

install_or_update_moodle_core() {
  run_sudo mkdir -p "${APP_BASE}"
  resolve_moodle_release

  run_sudo rm -rf "${TMP_ROOT}/moodle" "${TMP_ROOT}/moodle.tgz"
  run_sudo curl "${CURL_DL_FLAGS[@]}" "${MDL_SOURCE_URL}" -o "${TMP_ROOT}/moodle.tgz"
  run_sudo tar -xzf "${TMP_ROOT}/moodle.tgz" -C "${TMP_ROOT}"

  local has_existing_install="0"
  if run_sudo test -f "${APP_CURRENT}/config.php" || run_sudo test -f "${APP_CURRENT}/public/config.php"; then
    has_existing_install="1"
  fi

  if [[ "${has_existing_install}" != "1" ]]; then
    run_sudo rm -rf "${APP_CURRENT}"
    run_sudo mkdir -p "${APP_CURRENT}"
    run_sudo bash -lc "shopt -s dotglob; mv '${TMP_ROOT}/moodle'/* '${APP_CURRENT}'/"
  else
    local preserve_config_root="0"
    local preserve_config_public="0"
    if run_sudo test -f "${APP_CURRENT}/config.php"; then
      preserve_config_root="1"
      run_sudo cp "${APP_CURRENT}/config.php" "${TMP_ROOT}/config.php.keep"
    fi
    if run_sudo test -f "${APP_CURRENT}/public/config.php"; then
      preserve_config_public="1"
      run_sudo cp "${APP_CURRENT}/public/config.php" "${TMP_ROOT}/public.config.php.keep"
    fi

    run_sudo rsync -a --delete \
      --exclude=config.php \
      --exclude=public/config.php \
      --exclude=moodledata \
      --exclude=cache \
      --exclude=localcache \
      --exclude=temp \
      --exclude=trashdir \
      --exclude=sessions \
      --exclude=lang \
      "${TMP_ROOT}/moodle/" "${APP_CURRENT}/"

    if [[ "${preserve_config_root}" == "1" ]] && run_sudo test -f "${TMP_ROOT}/config.php.keep"; then
      run_sudo mv "${TMP_ROOT}/config.php.keep" "${APP_CURRENT}/config.php"
      run_sudo chown www-data:www-data "${APP_CURRENT}/config.php"
      run_sudo chmod 640 "${APP_CURRENT}/config.php"
    fi
    if [[ "${preserve_config_public}" == "1" ]] && run_sudo test -f "${TMP_ROOT}/public.config.php.keep"; then
      run_sudo mv "${TMP_ROOT}/public.config.php.keep" "${APP_CURRENT}/public/config.php"
      run_sudo chown www-data:www-data "${APP_CURRENT}/public/config.php"
      run_sudo chmod 640 "${APP_CURRENT}/public/config.php"
    fi
  fi

  run_sudo mkdir -p "${APP_SHARED}/moodledata"
  run_sudo chown -R www-data:www-data "${APP_CURRENT}" "${APP_SHARED}/moodledata"
  run_sudo chmod -R u+rwX,g+rwX "${APP_SHARED}/moodledata"

  if ! run_sudo test -d "${APP_CURRENT}/public"; then
    APP_WEB_ROOT="${APP_CURRENT}"
  else
    APP_WEB_ROOT="${APP_CURRENT}/public"
  fi
}

run_moodle_install_or_upgrade() {
  MDL_URL="http://${HOST}:${APP_PORT}"
  MDL_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  local config_path=""
  if run_sudo test -f "${APP_CURRENT}/config.php"; then
    config_path="${APP_CURRENT}/config.php"
  elif run_sudo test -f "${APP_CURRENT}/public/config.php"; then
    config_path="${APP_CURRENT}/public/config.php"
  fi

  if [[ -n "${config_path}" ]]; then
    if run_sudo grep -Eq "\$CFG->dbtype[[:space:]]*=[[:space:]]*'mysqli'" "${config_path}"; then
      run_sudo sed -i "s/\$CFG->dbtype\s*=\s*'mysqli'/\$CFG->dbtype = 'mariadb'/" "${config_path}"
    fi
    run_sudo -u www-data -- php -d max_input_vars=10000 "${APP_CURRENT}/admin/cli/upgrade.php" --non-interactive --allow-unstable >/dev/null 2>&1 || true
    return
  fi

  run_sudo mysql --execute "DROP DATABASE IF EXISTS ${DB_NAME}; CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  run_sudo mysql --execute "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;"

  run_sudo -u www-data -- php -d max_input_vars=10000 "${APP_CURRENT}/admin/cli/install.php" \
    --lang=en \
    --wwwroot="${MDL_URL}" \
    --dataroot="${APP_SHARED}/moodledata" \
    --dbtype=mariadb \
    --dbhost=localhost \
    --dbname="${DB_NAME}" \
    --dbuser="${DB_USER}" \
    --dbpass="${DB_PASS}" \
    --prefix="${DB_PREFIX}" \
    --fullname="Moodle Audit ${APP_SLUG}" \
    --shortname="MoodleAudit" \
    --adminuser="${ADMIN_USER}" \
    --adminpass="${ADMIN_PASSWORD}" \
    --adminemail="${ADMIN_EMAIL}" \
    --non-interactive \
    --agree-license

  run_sudo chown www-data:www-data "${APP_CURRENT}/config.php"
  run_sudo chmod 640 "${APP_CURRENT}/config.php"
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

    location ~* /(\.git|composer\.(json|lock)|config-dist\.php|phpunit\.xml|behat\.yml)$ {
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

plugin_component_to_relpath() {
  local component="$1"
  local type="${component%%_*}"
  local name="${component#*_}"

  if [[ -z "${type}" || -z "${name}" || "${type}" == "${component}" ]]; then
    return 1
  fi

  case "${type}" in
    mod) printf 'mod/%s\n' "${name}" ;;
    block) printf 'blocks/%s\n' "${name}" ;;
    local) printf 'local/%s\n' "${name}" ;;
    theme) printf 'theme/%s\n' "${name}" ;;
    auth) printf 'auth/%s\n' "${name}" ;;
    enrol) printf 'enrol/%s\n' "${name}" ;;
    tool) printf 'admin/tool/%s\n' "${name}" ;;
    qtype) printf 'question/type/%s\n' "${name}" ;;
    filter) printf 'filter/%s\n' "${name}" ;;
    report) printf 'report/%s\n' "${name}" ;;
    format) printf 'course/format/%s\n' "${name}" ;;
    assignfeedback) printf 'mod/assign/feedback/%s\n' "${name}" ;;
    assignsubmission) printf 'mod/assign/submission/%s\n' "${name}" ;;
    atto) printf 'lib/editor/atto/plugins/%s\n' "${name}" ;;
    tiny) printf 'lib/editor/tiny/plugins/%s\n' "${name}" ;;
    *) return 1 ;;
  esac
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
plugins = allowlist.get('plugins', [])
if not isinstance(plugins, list):
    plugins = []
result = {
    'official': {'requested': [], 'installed': [], 'skipped': []},
    'third_party': {'requested': [], 'installed': [], 'skipped': []},
}
for entry in plugins:
    if not isinstance(entry, dict):
        continue
    component = str(entry.get('component', '')).strip()
    git_url = str(entry.get('git_url', '')).strip()
    branch = str(entry.get('branch', '')).strip() or 'master'
    if not component:
        continue
    result['official']['requested'].append({'component': component, 'git_url': git_url, 'branch': branch})
Path(sys.argv[2]).write_text(json.dumps(result, indent=2), encoding='utf-8')
PY

  mapfile -t plugin_rows < <(python3 - "${PLUGIN_RESULTS_PATH}" <<'PY'
import json
import sys
rows = []
doc = json.loads(open(sys.argv[1], 'r', encoding='utf-8').read())
for item in ((doc.get('official') or {}).get('requested') or []):
    if not isinstance(item, dict):
        continue
    rows.append('\t'.join([
        str(item.get('component', '')).strip(),
        str(item.get('git_url', '')).strip(),
        str(item.get('branch', '')).strip() or 'master',
    ]))
print('\n'.join([r for r in rows if r]))
PY
)

  local component git_url branch rel_path plugin_dir reason upgrade_out
  for row in "${plugin_rows[@]}"; do
    IFS=$'\t' read -r component git_url branch <<<"${row}"
    [[ -z "${component}" ]] && continue

    if ! rel_path="$(plugin_component_to_relpath "${component}")"; then
      reason="unsupported component type"
      python3 - "${PLUGIN_RESULTS_PATH}" "${component}" "${reason}" "${git_url}" <<'PY'
import json, sys
p, component, reason, git_url = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['official']['skipped'].append({'component': component, 'git_url': git_url, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
      continue
    fi

    if [[ -z "${git_url}" ]]; then
      reason="missing git_url"
      python3 - "${PLUGIN_RESULTS_PATH}" "${component}" "${reason}" "${git_url}" <<'PY'
import json, sys
p, component, reason, git_url = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['official']['skipped'].append({'component': component, 'git_url': git_url, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
      continue
    fi

    plugin_dir="${APP_CURRENT}/${rel_path}"
    run_sudo mkdir -p "$(dirname "${plugin_dir}")"

    if run_sudo test -d "${plugin_dir}/.git"; then
      if ! run_sudo -u www-data -- git -C "${plugin_dir}" fetch --depth 1 origin "${branch}" >/dev/null 2>&1 || \
         ! run_sudo -u www-data -- git -C "${plugin_dir}" checkout -f FETCH_HEAD >/dev/null 2>&1; then
        reason="git update failed (${branch})"
        python3 - "${PLUGIN_RESULTS_PATH}" "${component}" "${reason}" "${git_url}" <<'PY'
import json, sys
p, component, reason, git_url = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['official']['skipped'].append({'component': component, 'git_url': git_url, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
        continue
      fi
    else
      run_sudo rm -rf "${plugin_dir}"
      if ! run_sudo -u www-data -- git clone --depth 1 --branch "${branch}" "${git_url}" "${plugin_dir}" >/dev/null 2>&1; then
        reason="git clone failed (${branch})"
        python3 - "${PLUGIN_RESULTS_PATH}" "${component}" "${reason}" "${git_url}" <<'PY'
import json, sys
p, component, reason, git_url = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['official']['skipped'].append({'component': component, 'git_url': git_url, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
        continue
      fi
    fi

    echo "${rel_path}" >> "${PLUGIN_PATHS_FILE}"

    if ! upgrade_out="$(run_sudo -u www-data -- php -d max_input_vars=10000 "${APP_CURRENT}/admin/cli/upgrade.php" --non-interactive --allow-unstable 2>&1)"; then
      reason="upgrade failed: $(printf '%s' "${upgrade_out}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | cut -c1-240)"
      python3 - "${PLUGIN_RESULTS_PATH}" "${component}" "${reason}" "${git_url}" <<'PY'
import json, sys
p, component, reason, git_url = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
doc['official']['skipped'].append({'component': component, 'git_url': git_url, 'reason': reason})
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
      continue
    fi

    python3 - "${PLUGIN_RESULTS_PATH}" "${component}" "${branch}" "${rel_path}" <<'PY'
import json, sys
p, component, branch, rel_path = sys.argv[1:5]
doc = json.loads(open(p, 'r', encoding='utf-8').read())
if component not in doc['official']['installed']:
    doc['official']['installed'].append(component)
for req in doc['official']['requested']:
    if isinstance(req, dict) and req.get('component') == component:
        req['resolved_branch'] = branch
        req['path'] = rel_path
open(p, 'w', encoding='utf-8').write(json.dumps(doc, indent=2))
PY
  done

  ensure_file_owner "${PLUGIN_RESULTS_PATH}" "${SSH_USER}" "${SSH_USER}"
  ensure_file_owner "${PLUGIN_PATHS_FILE}" "${SSH_USER}" "${SSH_USER}"
}

create_snapshot() {
  mkdir -p "${APP_SNAPSHOT_DIR}"
  if [[ ! -f "${PLUGIN_PATHS_FILE}" ]]; then
    : > "${PLUGIN_PATHS_FILE}"
  fi
  run_sudo bash -lc "mysqldump '${DB_NAME}' > '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo bash -lc "tar -czf '${APP_SNAPSHOT_DIR}/site_state.tar.gz' -C '${APP_CURRENT}' config.php"
  run_sudo bash -lc "tar -czf '${APP_SNAPSHOT_DIR}/data_state.tar.gz' -C '${APP_SHARED}' moodledata"
  run_sudo install -m 0644 "${PLUGIN_PATHS_FILE}" "${APP_SNAPSHOT_DIR}/installed_plugin_paths.txt"
  run_sudo chown -R "${SSH_USER}:${SSH_USER}" "${APP_SNAPSHOT_DIR}"
  SNAPSHOT_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

restore_snapshot() {
  if [[ ! -f "${APP_SNAPSHOT_DIR}/db.sql" || ! -f "${APP_SNAPSHOT_DIR}/site_state.tar.gz" || ! -f "${APP_SNAPSHOT_DIR}/data_state.tar.gz" ]]; then
    echo "Snapshot missing at ${APP_SNAPSHOT_DIR}" >&2
    exit 1
  fi

  run_sudo mysql "${DB_NAME}" < "${APP_SNAPSHOT_DIR}/db.sql"
  run_sudo rm -rf "${APP_SHARED}/moodledata"
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/site_state.tar.gz" -C "${APP_CURRENT}"
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/data_state.tar.gz" -C "${APP_SHARED}"

  if [[ -f "${APP_SNAPSHOT_DIR}/installed_plugin_paths.txt" ]]; then
    run_sudo install -m 0644 "${APP_SNAPSHOT_DIR}/installed_plugin_paths.txt" "${PLUGIN_PATHS_FILE}"
  fi

  ensure_file_owner "${APP_CURRENT}/config.php" "www-data" "www-data"
  ensure_file_owner "${APP_SHARED}/moodledata" "www-data" "www-data"
  run_sudo chmod -R u+rwX,g+rwX "${APP_SHARED}/moodledata"
  run_sudo -u www-data -- php -d max_input_vars=10000 "${APP_CURRENT}/admin/cli/upgrade.php" --non-interactive --allow-unstable >/dev/null 2>&1 || true

  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

refresh_moodle_metadata() {
  MDL_URL="http://${HOST}:${APP_PORT}"
  MDL_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  local detected
  detected="$(run_sudo php -r 'if (file_exists($argv[1])) { include $argv[1]; if (isset($release)) { echo $release; } }' "${APP_CURRENT}/version.php" 2>/dev/null || true)"
  if [[ -n "${detected}" ]]; then
    MDL_VERSION="${detected}"
  fi

  if [[ -z "${MDL_VERSION}" || "${MDL_VERSION}" == "unknown" ]]; then
    MDL_VERSION="$(python3 - "${STATE_PATH}" <<'PY'
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

  if [[ -z "${MDL_VERSION}" ]]; then
    MDL_VERSION="unknown"
  fi
}

sync_ui_to_moodle_runtime() {
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

  curl --fail --silent --show-error --location --connect-timeout 10 --max-time 30 "http://127.0.0.1:${APP_PORT}/ptt_smoke_probe.php?ptt_probe=${token}&cmd=echo%20xtanzi_moodle" >/dev/null

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
        'moodle.healthcheck.system.before',
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
  refresh_moodle_metadata

  mkdir -p "${APP_RUNTIME}"

  local xmark_enabled_runtime="0"
  if [[ "${ENABLE_XMARK}" == "1" ]] && run_sudo test -f "${XMARK_FPM_INI}" && run_sudo grep -q "${XMARK_EXT_PATH}" "${XMARK_FPM_INI}"; then
    xmark_enabled_runtime="1"
  elif run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    xmark_enabled_runtime="1"
  fi

  local db_version
  db_version="$(run_sudo mysql --version 2>/dev/null || true)"

  if [[ ! -f "${PLUGIN_RESULTS_PATH}" ]]; then
    printf '{"official":{"requested":[],"installed":[],"skipped":[]},"third_party":{"requested":[],"installed":[],"skipped":[]}}' > "${PLUGIN_RESULTS_PATH}"
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
    'summary': f"moodle action={${ACTION@Q}} via remote_moodle_app_manage.sh"
})
history = history[-40:]

installed_at = existing.get('installed_at_utc') or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

record = {
    'app_id': 'moodle-main',
    'name': 'Moodle',
    'slug': 'moodle',
    'status': 'removed' if ${ACTION@Q} == 'remove' else 'installed',
    'version': ${MDL_VERSION@Q},
    'installed_at_utc': installed_at,
    'installed_by': 'codex',
    'remote_host_label': ${HOST_LABEL@Q},
    'remote_root_path': ${APP_CURRENT@Q},
    'web_root_path': ${APP_WEB_ROOT@Q},
    'base_urls': [${MDL_URL@Q}, ${MDL_LOCAL_URL@Q}],
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
        'moodledata_path': ${APP_SHARED@Q} + '/moodledata'
    },
    'source': {
        'channel': 'moodle.org/latest-stable-tarball',
        'download_url': ${MDL_SOURCE_URL@Q},
        'resolved_release_version': ${MDL_VERSION@Q},
        'release_tracking_mode': 'latest-stable-auto'
    },
    'credentials': {
        'db_name': ${DB_NAME@Q},
        'db_user': ${DB_USER@Q},
        'db_password': ${DB_PASS@Q},
        'db_prefix': ${DB_PREFIX@Q},
        'moodle_admin_display_name': ${ADMIN_NAME@Q},
        'moodle_admin_user': ${ADMIN_USER@Q},
        'moodle_admin_password': ${ADMIN_PASSWORD@Q},
        'moodle_admin_email': ${ADMIN_EMAIL@Q}
    },
    'plugin_inventory': plugin_results,
    'php_taint_trace_integration': {
        'enabled': True,
        'mode': 'auto_prepend+native_extension' if ${xmark_enabled_runtime@Q} == '1' else 'auto_prepend_only',
        'auto_prepend_file': ${PHP_TAINT_TRACE_PREPEND@Q},
        'xmark_extension_enabled': ${xmark_enabled_runtime@Q} == '1',
        'xmark_extension_path': ${XMARK_EXT_PATH@Q},
        'runtime_config_file': '/etc/php_taint_trace/runtime.json',
        'verifier_runtime_dir': ${APP_RUNTIME_VERIFIER@Q},
        'verifier_replay_target': 'local',
        'verifier_local_base_url': ${MDL_LOCAL_URL@Q}
    },
    'snapshot_state': {
        'last_created_at_utc': ${snapshot_created@Q},
        'last_restored_at_utc': ${snapshot_restored@Q},
        'db_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/db.sql',
        'content_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/site_state.tar.gz',
        'data_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/data_state.tar.gz'
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
  install_or_update_moodle_core
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  run_moodle_install_or_upgrade
  install_catalog_plugins
  create_snapshot
  sync_ui_to_moodle_runtime
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

  run_sudo mysql --execute "DROP DATABASE IF EXISTS ${DB_NAME}; DROP USER IF EXISTS '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;"
  run_sudo rm -rf "${APP_BASE}"

  MDL_VERSION="removed"
  MDL_URL="http://${HOST}:${APP_PORT}"
  MDL_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
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

if [[ "${ACTION}" != "register-inventory" ]]; then
  echo "[remote-moodle-app] running remote action=${ACTION} app=${APP_SLUG} host=${HOST}"
  run_remote_action
fi

echo "[remote-moodle-app] syncing local inventory from remote state"
update_inventory
echo "[remote-moodle-app] complete"
echo "[remote-moodle-app] inventory=${INVENTORY_PATH}"
echo "[remote-moodle-app] app_state=${APP_DOC_ROOT}/latest_state.json"
