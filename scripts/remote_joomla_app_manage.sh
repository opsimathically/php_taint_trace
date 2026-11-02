#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19131"
APP_SLUG="joomla"
UI_SYNC="1"
RUN_VALIDATION="1"
ENABLE_XMARK="1"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
EXTENSION_ALLOWLIST_PATH="${ROOT_DIR}/remote_linux_container/installed_php_applications/apps/${APP_SLUG}/extensions.allowlist.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_joomla_app_manage.sh <install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck> [options]

Options:
  --config PATH               External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL          Host label in config (default: lab.example.invalid)
  --remote-taint-root PATH    Remote php_taint_trace repo root (default: /opt/php_taint_trace_vuln_lab/rewrite)
  --install-root PATH         Remote multi-app install root (default: /opt/php_audit_apps)
  --app-port PORT             Joomla port (default: 19131)
  --inventory PATH            External inventory path (default: PHP_TAINT_TRACE_INVENTORY_PATH or XDG state directory)
  --allowlist PATH            Extension allowlist JSON path
  --no-ui-sync                Do not repoint UI daemon artifact sources to this app runtime
  --no-validation             Skip install-time taint/verifier smoke validation
  --enable-xmark              Load xmark extension for PHP-FPM worker startup (default: on)
  --disable-xmark             Explicitly disable xmark extension loading for PHP-FPM
  -h, --help                  Show help

Actions:
  install            Install or reconcile Joomla + runtime integration
  update             Update Joomla core/extensions and refresh metadata
  reset              Restore latest baseline snapshot
  snapshot-create    Create baseline snapshot (db + site archive)
  snapshot-restore   Restore baseline snapshot
  xmark-healthcheck  Run remote xmark runtime healthcheck (load mode + hook dispatch + fatal guard)
  status             Print remote app state JSON
  remove             Remove Joomla deployment (retain runtime metadata)
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
    {
      "slug": "akeebabackup",
      "name": "Akeeba Backup Core",
      "package_url": "https://www.akeeba.com/download/akeeba-backup/9-9-5/akeeba-backup-core-9-9-5.zip"
    },
    {
      "slug": "admintools",
      "name": "Admin Tools Core",
      "package_url": "https://www.akeeba.com/download/admintools/7-5-3/admin-tools-core-7-5-3.zip"
    },
    {
      "slug": "aclmanager",
      "name": "ACL Manager",
      "package_url": "https://github.com/ACLManager/aclmanager/releases/download/3.0.6/pkg_aclmanager-3.0.6.zip"
    },
    {
      "slug": "jce",
      "name": "JCE Editor",
      "package_url": "https://www.joomlacontenteditor.net/downloads/editor/pro/download"
    },
    {
      "slug": "rsfirewall",
      "name": "RSFirewall",
      "package_url": "https://www.rsjoomla.com/downloads/rsfirewall/rsfirewall.zip"
    },
    {
      "slug": "aesirx_first_party_server_side_tag",
      "name": "AesirX First-Party Server-Side Tag",
      "package_url": "https://github.com/aesirxio/joomla-extension-aesirx-first-party-server-side-tag/releases/download/v1.2.1/pkg_aesirx_first_party_server_side_tag_v1.2.1.zip"
    },
    {
      "slug": "aesirx_consent",
      "name": "AesirX Consent",
      "package_url": "https://github.com/aesirxio/joomla-extension-aesirx-consent/releases/download/v1.1.0/pkg_aesirx_consent_v1.1.0.zip"
    },
    {
      "slug": "jsitemap",
      "name": "JSitemap",
      "package_url": "https://storejextensions.org/media/com_ars/repository/jsitemap.zip"
    },
    {
      "slug": "convertforms",
      "name": "Convert Forms",
      "package_url": "https://www.tassos.gr/download/convert-forms"
    },
    {
      "slug": "engagebox",
      "name": "EngageBox",
      "package_url": "https://www.tassos.gr/download/engagebox"
    },
    {
      "slug": "sourcerer",
      "name": "Sourcerer",
      "package_url": "https://regularlabs.com/downloads/sourcerer"
    },
    {
      "slug": "advancedmodulemanager",
      "name": "Advanced Module Manager",
      "package_url": "https://regularlabs.com/downloads/advancedmodulemanager"
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
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_RUNTIME_VERIFIER="${APP_RUNTIME}/verifier"
APP_RUNTIME_FINDINGS="${APP_RUNTIME}/findings"
APP_SNAPSHOT_DIR="${APP_RUNTIME}/snapshots/latest"
STATE_PATH="${APP_RUNTIME}/app_state.json"
EXT_RESULTS_PATH="${APP_RUNTIME}/extension_results.json"
ALLOWLIST_PATH="${APP_RUNTIME}/extensions.allowlist.json"
TMP_ROOT="/tmp/php_taint_trace_joomla_install_${APP_SLUG}"
PHP_TAINT_TRACE_PREPEND="${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php"
XMARK_EXT_PATH="${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"

# defaults for state output
JOOMLA_VERSION="unknown"
JOOMLA_URL="http://${HOST}:${APP_PORT}"
JOOMLA_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
JOOMLA_DOWNLOAD_URL=""

mkdir -p "${TMP_ROOT}"
printf '%s' "${EXTENSION_ALLOWLIST_B64}" | base64 -d > "${TMP_ROOT}/extensions.allowlist.json"

ensure_prerequisites() {
  run_sudo apt-get update -y
  run_sudo apt-get install -y \
    curl unzip rsync jq \
    mariadb-client mariadb-server \
    nginx

  local php_bin
  php_bin="$(command -v php || true)"
  if [[ -z "${php_bin}" ]]; then
    run_sudo apt-get install -y php-cli
  fi

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

  local php_bin
  php_bin="$(command -v php || true)"
  if [[ -z "${php_bin}" ]]; then
    echo "php binary not found for xmark load verification" >&2
    exit 1
  fi

  if ! "${php_bin}" -n -d "extension=${XMARK_EXT_PATH}" -m 2>/dev/null | grep -qi '^xmark$'; then
    echo "xmark extension failed to load for PHP binary ${php_bin}" >&2
    exit 1
  fi
}

init_directories() {
  run_sudo mkdir -p "${APP_CURRENT}" "${APP_SHARED}" "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}" "${APP_SNAPSHOT_DIR}"
  run_sudo touch "${APP_RUNTIME_VERIFIER}/jobs.jsonl" "${APP_RUNTIME_VERIFIER}/results.jsonl" "${APP_RUNTIME_VERIFIER}/decisions.jsonl" "${APP_RUNTIME_VERIFIER}/dead_letters.jsonl" "${APP_RUNTIME_VERIFIER}/claims.jsonl"
  ensure_file_owner "${APP_BASE}" "${SSH_USER}" "${SSH_USER}"
  ensure_file_owner "${APP_RUNTIME}" "${SSH_USER}" "${SSH_USER}"
  # Runtime writers run in the PHP-FPM worker context (www-data), so keep queue/report
  # paths owned by the web worker to prevent lock/report write failures.
  ensure_file_owner "${APP_RUNTIME_VERIFIER}" "www-data" "www-data"
  ensure_file_owner "${APP_RUNTIME_FINDINGS}" "www-data" "www-data"
  run_sudo chmod -R u+rwX,g+rwX "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}"
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
    ADMIN_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_user"])' <<<"${creds_json}")"
    ADMIN_PASSWORD="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_password"])' <<<"${creds_json}")"
    ADMIN_EMAIL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["admin_email"])' <<<"${creds_json}")"
    DB_PREFIX="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_prefix"])' <<<"${creds_json}")"
  else
    DB_NAME="joomla_${APP_SLUG}"
    DB_USER="joomla_${APP_SLUG}_user"
    DB_PASS="$(openssl rand -hex 16)"
    ADMIN_NAME="Joomla Audit Admin"
    ADMIN_USER="joomla_admin_${APP_SLUG}"
    ADMIN_PASSWORD="$(openssl rand -hex 16)"
    ADMIN_EMAIL="audit+${APP_SLUG}@local.invalid"
    DB_PREFIX="j$(openssl rand -hex 2)_"

    python3 - <<PY > "${TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASS@Q},
  "admin_name": ${ADMIN_NAME@Q},
  "admin_user": ${ADMIN_USER@Q},
  "admin_password": ${ADMIN_PASSWORD@Q},
  "admin_email": ${ADMIN_EMAIL@Q},
  "db_prefix": ${DB_PREFIX@Q}
}, indent=2))
PY
    run_sudo install -m 0600 "${TMP_ROOT}/credentials.json" "${creds_path}"
    ensure_file_owner "${creds_path}" "${SSH_USER}" "${SSH_USER}"
  fi
}

provision_database() {
  run_sudo mysql --execute "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  run_sudo mysql --execute "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  run_sudo mysql --execute "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;"
}

resolve_latest_joomla_download() {
  curl -A 'Mozilla/5.0' -fsSL 'https://downloads.joomla.org/us/latest' -o "${TMP_ROOT}/joomla_latest.html"

  JOOMLA_DOWNLOAD_URL="$(python3 - "${TMP_ROOT}/joomla_latest.html" <<'PY'
import re
import sys
html = open(sys.argv[1], 'r', encoding='utf-8', errors='ignore').read()
m = re.search(r'(/us/cms/joomla[0-9]+/[0-9-]+/Joomla_[0-9-]+-Stable-Full_Package[.]zip[?]format=zip)', html, re.IGNORECASE)
if not m:
    raise SystemExit('Unable to resolve latest Joomla zip URL from downloads page')
print('https://downloads.joomla.org' + m.group(1))
PY
)"

  JOOMLA_VERSION="$(python3 - <<PY
import re
url = ${JOOMLA_DOWNLOAD_URL@Q}
m = re.search(r'Joomla_([0-9]+-[0-9]+-[0-9]+)-Stable-Full_Package[.]zip', url)
print((m.group(1).replace('-', '.') if m else 'unknown'))
PY
)"
}

install_joomla_core() {
  resolve_latest_joomla_download

  local zip_path="${TMP_ROOT}/joomla-latest.zip"
  local extract_dir="${TMP_ROOT}/extract"
  local existing_config="${TMP_ROOT}/configuration.php"

  rm -rf "${extract_dir}"
  mkdir -p "${extract_dir}"
  curl -A 'Mozilla/5.0' -fsSL "${JOOMLA_DOWNLOAD_URL}" -o "${zip_path}"

  if run_sudo test -f "${APP_CURRENT}/configuration.php"; then
    run_sudo cp "${APP_CURRENT}/configuration.php" "${existing_config}"
  fi

  unzip -q -o "${zip_path}" -d "${extract_dir}"
  run_sudo rsync -a --delete "${extract_dir}/" "${APP_CURRENT}/"

  if [[ -f "${existing_config}" ]]; then
    run_sudo cp "${existing_config}" "${APP_CURRENT}/configuration.php"
  fi

  ensure_file_owner "${APP_CURRENT}" "www-data" "www-data"
}

run_joomla_install() {
  JOOMLA_URL="http://${HOST}:${APP_PORT}"
  JOOMLA_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  if run_sudo test -f "${APP_CURRENT}/configuration.php"; then
    return
  fi

  run_sudo -u www-data -- php "${APP_CURRENT}/installation/joomla.php" install \
    --no-interaction \
    --site-name="Joomla Audit ${APP_SLUG}" \
    --admin-user="${ADMIN_NAME}" \
    --admin-username="${ADMIN_USER}" \
    --admin-password="${ADMIN_PASSWORD}" \
    --admin-email="${ADMIN_EMAIL}" \
    --db-type="mysqli" \
    --db-host="localhost" \
    --db-user="${DB_USER}" \
    --db-pass="${DB_PASS}" \
    --db-name="${DB_NAME}" \
    --db-prefix="${DB_PREFIX}"

  run_sudo rm -rf "${APP_CURRENT}/installation"
  ensure_file_owner "${APP_CURRENT}" "www-data" "www-data"
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
pm.max_children = 20
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 6
chdir = ${APP_CURRENT}

php_admin_value[auto_prepend_file] = ${PHP_TAINT_TRACE_PREPEND}
php_admin_value[open_basedir] = ${APP_CURRENT}:${APP_RUNTIME}:/tmp:/var/tmp:${REMOTE_TAINT_ROOT}:/etc/php_taint_trace
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
    run_sudo bash -lc "grep -q '^php_admin_value\[extension\] = ${XMARK_EXT_PATH}$' '${PHP_POOL_CONF}' || echo 'php_admin_value[extension] = ${XMARK_EXT_PATH}' >> '${PHP_POOL_CONF}'"
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

    root ${APP_CURRENT};
    index index.php index.html;

    access_log /var/log/nginx/${APP_SLUG}_access.log;
    error_log /var/log/nginx/${APP_SLUG}_error.log;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_pass unix:${PHP_FPM_SOCKET};
    }

    location ~* /(?:configuration\\.php|composer\\.(?:json|lock)|\.git|\.env) {
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

  local req_file="${TMP_ROOT}/ext_requested.txt"
  local rows_file="${TMP_ROOT}/ext_rows.txt"

  python3 - "${ALLOWLIST_PATH}" "${rows_file}" "${req_file}" <<'PY'
import json
import sys
from pathlib import Path

allowlist = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
rows_path = Path(sys.argv[2])
requested_path = Path(sys.argv[3])
extensions = allowlist.get('extensions', [])
if not isinstance(extensions, list):
    extensions = []

rows = []
requested = []
for entry in extensions:
    if not isinstance(entry, dict):
        continue
    slug = str(entry.get('slug', '')).strip()
    if not slug:
        continue
    requested.append(slug)
    name = str(entry.get('name', '')).strip()
    package_url = str(entry.get('package_url', '')).strip()
    checksum = str(entry.get('sha256', '')).strip()
    rows.append('\t'.join([slug, name, package_url, checksum]))

rows_path.write_text('\n'.join(rows), encoding='utf-8')
requested_path.write_text('\n'.join(requested), encoding='utf-8')
PY

  mapfile -t requested < <(cat "${req_file}" 2>/dev/null || true)

  local installed_json="${TMP_ROOT}/ext_installed.json"
  local skipped_json="${TMP_ROOT}/ext_skipped.json"
  printf '[]' > "${installed_json}"
  printf '[]' > "${skipped_json}"

  if [[ -f "${rows_file}" ]]; then
    while IFS=$'\t' read -r slug name package_url checksum; do
      [[ -z "${slug}" ]] && continue

      if [[ -z "${package_url}" ]]; then
        python3 - "${skipped_json}" "${slug}" "missing package_url" <<'PY'
import json,sys
p=sys.argv[1]
slug=sys.argv[2]
reason=sys.argv[3]
doc=json.loads(open(p,'r',encoding='utf-8').read())
doc.append({'slug':slug,'reason':reason})
open(p,'w',encoding='utf-8').write(json.dumps(doc))
PY
        continue
      fi

      local zip_path="${TMP_ROOT}/${slug}.zip"
      if ! curl -A 'Mozilla/5.0' -fsSL "${package_url}" -o "${zip_path}"; then
        python3 - "${skipped_json}" "${slug}" "download failed" "${package_url}" <<'PY'
import json,sys
p=sys.argv[1]
slug=sys.argv[2]
reason=sys.argv[3]
url=sys.argv[4]
doc=json.loads(open(p,'r',encoding='utf-8').read())
doc.append({'slug':slug,'reason':reason,'package_url':url})
open(p,'w',encoding='utf-8').write(json.dumps(doc))
PY
        continue
      fi

      if [[ -n "${checksum}" ]]; then
        local actual
        actual="$(sha256sum "${zip_path}" | awk '{print $1}')"
        if [[ "${actual}" != "${checksum}" ]]; then
          python3 - "${skipped_json}" "${slug}" "checksum mismatch" "${package_url}" <<'PY'
import json,sys
p=sys.argv[1]
slug=sys.argv[2]
reason=sys.argv[3]
url=sys.argv[4]
doc=json.loads(open(p,'r',encoding='utf-8').read())
doc.append({'slug':slug,'reason':reason,'package_url':url})
open(p,'w',encoding='utf-8').write(json.dumps(doc))
PY
          continue
        fi
      fi

      if run_sudo -u www-data -- env HTTP_HOST=127.0.0.1 REQUEST_URI=/ php "${APP_CURRENT}/cli/joomla.php" extension:install --path "${zip_path}" >/dev/null 2>&1; then
        python3 - "${installed_json}" "${slug}" "${package_url}" <<'PY'
import json,sys
p=sys.argv[1]
slug=sys.argv[2]
url=sys.argv[3]
doc=json.loads(open(p,'r',encoding='utf-8').read())
doc.append({'slug':slug,'package_url':url})
open(p,'w',encoding='utf-8').write(json.dumps(doc))
PY
      else
        local reason
        reason="$(run_sudo -u www-data -- env HTTP_HOST=127.0.0.1 REQUEST_URI=/ php "${APP_CURRENT}/cli/joomla.php" extension:install --path "${zip_path}" 2>&1 || true)"
        python3 - "${skipped_json}" "${slug}" "${reason}" "${package_url}" <<'PY'
import json,sys
p=sys.argv[1]
slug=sys.argv[2]
reason=sys.argv[3].strip() or 'extension install failed'
url=sys.argv[4]
doc=json.loads(open(p,'r',encoding='utf-8').read())
doc.append({'slug':slug,'reason':reason,'package_url':url})
open(p,'w',encoding='utf-8').write(json.dumps(doc))
PY
      fi
    done < "${rows_file}"
  fi

  python3 - "${EXT_RESULTS_PATH}" "${installed_json}" "${skipped_json}" "${req_file}" <<'PY'
import json,sys
out_path=sys.argv[1]
installed=json.loads(open(sys.argv[2],'r',encoding='utf-8').read())
skipped=json.loads(open(sys.argv[3],'r',encoding='utf-8').read())
requested=[line.strip() for line in open(sys.argv[4],'r',encoding='utf-8').read().splitlines() if line.strip()]
out={
  'official': {
    'requested': requested,
    'installed': [item.get('slug') for item in installed if isinstance(item,dict) and item.get('slug')],
    'skipped': skipped,
  },
  'third_party': {
    'requested': [],
    'installed': [],
    'skipped': [],
  }
}
open(out_path,'w',encoding='utf-8').write(json.dumps(out,indent=2))
PY

  ensure_file_owner "${EXT_RESULTS_PATH}" "${SSH_USER}" "${SSH_USER}"
}

create_snapshot() {
  mkdir -p "${APP_SNAPSHOT_DIR}"
  run_sudo bash -lc "mysqldump '${DB_NAME}' > '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo bash -lc "tar --exclude='./cache/*' --exclude='./tmp/*' --exclude='./logs/*' -czf '${APP_SNAPSHOT_DIR}/site.tar.gz' -C '${APP_CURRENT}' ."
  run_sudo chown -R "${SSH_USER}:${SSH_USER}" "${APP_SNAPSHOT_DIR}"
  SNAPSHOT_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

restore_snapshot() {
  if [[ ! -f "${APP_SNAPSHOT_DIR}/db.sql" || ! -f "${APP_SNAPSHOT_DIR}/site.tar.gz" ]]; then
    echo "Snapshot missing at ${APP_SNAPSHOT_DIR}" >&2
    exit 1
  fi

  run_sudo mysql "${DB_NAME}" < "${APP_SNAPSHOT_DIR}/db.sql"
  run_sudo find "${APP_CURRENT}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/site.tar.gz" -C "${APP_CURRENT}"
  ensure_file_owner "${APP_CURRENT}" "www-data" "www-data"
  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

refresh_joomla_metadata() {
  JOOMLA_URL="http://${HOST}:${APP_PORT}"
  JOOMLA_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  if run_sudo test -d "${APP_CURRENT}/cli"; then
    local detected
    detected="$(run_sudo -u www-data -- php "${APP_CURRENT}/cli/joomla.php" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
    if [[ -n "${detected}" ]]; then
      JOOMLA_VERSION="${detected}"
    fi
  fi

  if [[ -z "${JOOMLA_VERSION}" || "${JOOMLA_VERSION}" == "unknown" ]]; then
    JOOMLA_VERSION="$(python3 - "${STATE_PATH}" <<'PY'
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

  if [[ -z "${JOOMLA_VERSION}" ]]; then
    JOOMLA_VERSION="unknown"
  fi

  if [[ -z "${JOOMLA_DOWNLOAD_URL}" ]]; then
    JOOMLA_DOWNLOAD_URL="$(python3 - "${STATE_PATH}" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print('')
    raise SystemExit
try:
    doc = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    print('')
    raise SystemExit
source = doc.get('source') or {}
if not isinstance(source, dict):
    print('')
    raise SystemExit
print(source.get('download_url', ''))
PY
)"
  fi
}

sync_ui_to_joomla_runtime() {
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

ordered_sources: list[dict[str, str]] = []
seen_decisions_paths: set[str] = set()

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

validation_smoke() {
  if [[ "${RUN_VALIDATION}" != "1" ]]; then
    return
  fi

  local probe_file="${APP_CURRENT}/ptt_smoke_probe.php"
  local token
  token="$(openssl rand -hex 12)"

  write_root_file "${probe_file}" <<PHP
<?php
declare(strict_types=1);
if (!isset(
    \$_GET['ptt_probe']) || !hash_equals('${token}', (string) \$_GET['ptt_probe'])) {
    http_response_code(404);
    exit;
}
\$cmd = isset(\$_GET['cmd']) ? (string) \$_GET['cmd'] : '';
if (\$cmd !== '') {
    @system(\$cmd);
}
echo 'ok';
PHP
  ensure_file_owner "${probe_file}" "www-data" "www-data"

  curl -fsS "http://127.0.0.1:${APP_PORT}/ptt_smoke_probe.php?ptt_probe=${token}&cmd=echo%20xtanzi_joomla" >/dev/null

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

  local probe_file="${APP_CURRENT}/ptt_xmark_healthcheck.php"
  local token
  token="$(openssl rand -hex 12)"

  write_root_file "${probe_file}" <<PHP
<?php
declare(strict_types=1);
if (!isset(\$_GET['ptt_xmark_healthcheck']) || !hash_equals('${token}', (string) \$_GET['ptt_xmark_healthcheck'])) {
    http_response_code(404);
    exit;
}
\$registered = false;
\$hookFired = false;
if (function_exists('xmark_register_hook')) {
    \$registered = (bool) xmark_register_hook(
        'joomla.healthcheck.system.before',
        'function',
        'system',
        'before',
        function (array \$ctx) use (&\$hookFired): ?string {
            \$hookFired = true;
            return null;
        }
    );
}
\$cmd = isset(\$_GET['cmd']) ? (string) \$_GET['cmd'] : '';
if (\$cmd !== '') {
    @system(\$cmd);
}
echo 'xmark_loaded=' . (extension_loaded('xmark') ? '1' : '0') . PHP_EOL;
echo 'register_hook=' . (\$registered ? '1' : '0') . PHP_EOL;
echo 'hook_fired=' . (\$hookFired ? '1' : '0') . PHP_EOL;
PHP
  ensure_file_owner "${probe_file}" "www-data" "www-data"

  local tmp_response
  tmp_response="$(mktemp)"
  local http_code
  http_code="$(curl -sS -o "${tmp_response}" -w '%{http_code}' "http://127.0.0.1:${APP_PORT}/ptt_xmark_healthcheck.php?ptt_xmark_healthcheck=${token}&cmd=echo%20xmark_healthcheck_probe" || true)"

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
  'ok': ${xmark_ini_ok@Q} == '1' and ${pool_ext_ok@Q} == '1' and ${xmark_loaded@Q} == '1' and ${php_fpm_active@Q} == '1' and ${nginx_active@Q} == '1',
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
  refresh_joomla_metadata

  local xmark_enabled_runtime="0"
  if [[ "${ENABLE_XMARK}" == "1" ]] && run_sudo test -f "${XMARK_FPM_INI}" && run_sudo grep -q "${XMARK_EXT_PATH}" "${XMARK_FPM_INI}"; then
    xmark_enabled_runtime="1"
  elif run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    xmark_enabled_runtime="1"
  fi

  local db_version
  db_version="$(run_sudo mysql --version 2>/dev/null || true)"

  if [[ ! -f "${EXT_RESULTS_PATH}" ]]; then
    printf '{"official":{"requested":[],"installed":[],"skipped":[]},"third_party":{"requested":[],"installed":[],"skipped":[]}}' > "${EXT_RESULTS_PATH}"
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

  python3 - "${STATE_PATH}" "${EXT_RESULTS_PATH}" <<PY
import json
import pathlib
import sys
from datetime import datetime, timezone

state_path = pathlib.Path(sys.argv[1])
ext_results_path = pathlib.Path(sys.argv[2])
extension_results = json.loads(ext_results_path.read_text(encoding='utf-8'))
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
    'summary': f"joomla action={${ACTION@Q}} via remote_joomla_app_manage.sh"
})
history = history[-40:]

installed_at = existing.get('installed_at_utc') or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

record = {
    'app_id': 'joomla-main',
    'name': 'Joomla',
    'slug': 'joomla',
    'status': 'removed' if ${ACTION@Q} == 'remove' else 'installed',
    'version': ${JOOMLA_VERSION@Q},
    'installed_at_utc': installed_at,
    'installed_by': 'codex',
    'remote_host_label': ${HOST_LABEL@Q},
    'remote_root_path': ${APP_CURRENT@Q},
    'web_root_path': ${APP_CURRENT@Q},
    'base_urls': [${JOOMLA_URL@Q}, ${JOOMLA_LOCAL_URL@Q}],
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
        'database_version': ${db_version@Q}
    },
    'source': {
        'channel': 'joomla.org/latest',
        'download_url': ${JOOMLA_DOWNLOAD_URL@Q},
        'resolved_release_version': ${JOOMLA_VERSION@Q},
        'release_tracking_mode': 'latest-stable-auto'
    },
    'credentials': {
        'db_name': ${DB_NAME@Q},
        'db_user': ${DB_USER@Q},
        'db_password': ${DB_PASS@Q},
        'joomla_admin_name': ${ADMIN_NAME@Q},
        'joomla_admin_user': ${ADMIN_USER@Q},
        'joomla_admin_password': ${ADMIN_PASSWORD@Q},
        'joomla_admin_email': ${ADMIN_EMAIL@Q},
        'db_prefix': ${DB_PREFIX@Q}
    },
    'extension_inventory': extension_results,
    'php_taint_trace_integration': {
        'enabled': True,
        'mode': 'auto_prepend+native_extension' if ${xmark_enabled_runtime@Q} == '1' else 'auto_prepend_only',
        'auto_prepend_file': ${PHP_TAINT_TRACE_PREPEND@Q},
        'xmark_extension_enabled': ${xmark_enabled_runtime@Q} == '1',
        'xmark_extension_path': ${XMARK_EXT_PATH@Q},
        'runtime_config_file': '/etc/php_taint_trace/runtime.json',
        'verifier_runtime_dir': ${APP_RUNTIME_VERIFIER@Q},
        'verifier_replay_target': 'local',
        'verifier_local_base_url': ${JOOMLA_LOCAL_URL@Q}
    },
    'snapshot_state': {
        'last_created_at_utc': ${snapshot_created@Q},
        'last_restored_at_utc': ${snapshot_restored@Q},
        'db_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/db.sql',
        'content_snapshot_path': ${APP_SNAPSHOT_DIR@Q} + '/site.tar.gz'
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
  install_joomla_core
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  run_joomla_install
  install_catalog_extensions
  create_snapshot
  sync_ui_to_joomla_runtime
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
  JOOMLA_VERSION="removed"
  JOOMLA_URL="http://${HOST}:${APP_PORT}"
  JOOMLA_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
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
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
apps = inventory.get("applications", [])
if not isinstance(apps, list):
    apps = []

app_id = state.get("app_id", "")
updated = False
for idx, item in enumerate(apps):
    if not isinstance(item, dict):
        continue
    if item.get("app_id") == app_id:
        apps[idx] = state
        updated = True
        break

if not updated:
    apps.append(state)

inventory["schema_version"] = max(int(inventory.get("schema_version", 1)), 2)
inventory["updated_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
inventory["applications"] = apps
inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
PY
}

if [[ "${ACTION}" != "register-inventory" ]]; then
  echo "[remote-joomla-app] running remote action=${ACTION} app=${APP_SLUG} host=${HOST}"
  run_remote_action
fi

echo "[remote-joomla-app] syncing local inventory from remote state"
update_inventory
echo "[remote-joomla-app] complete"
echo "[remote-joomla-app] inventory=${INVENTORY_PATH}"
echo "[remote-joomla-app] app_state=${APP_DOC_ROOT}/latest_state.json"
