#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19130"
APP_SLUG="wordpress"
UI_SYNC="1"
RUN_VALIDATION="1"
ENABLE_XMARK="1"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
THIRD_PARTY_ALLOWLIST_PATH="${ROOT_DIR}/remote_linux_container/installed_php_applications/apps/${APP_SLUG}/third_party_plugins.allowlist.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_php_app_manage.sh <install|update|reset|status|remove|register-inventory|snapshot-create|snapshot-restore|xmark-healthcheck> [options]

Options:
  --config PATH               External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL          Host label in config (default: lab.example.invalid)
  --remote-taint-root PATH    Remote php_taint_trace repo root (default: /opt/php_taint_trace_vuln_lab/rewrite)
  --install-root PATH         Remote multi-app install root (default: /opt/php_audit_apps)
  --app-port PORT             WordPress port (default: 19130)
  --inventory PATH            External inventory path (default: PHP_TAINT_TRACE_INVENTORY_PATH or XDG state directory)
  --allowlist PATH            Third-party plugin allowlist JSON path
  --no-ui-sync                Do not repoint UI daemon artifact sources to this app runtime
  --no-validation             Skip install-time taint/verifier smoke validation
  --enable-xmark              Load xmark extension for PHP-FPM worker startup (default: on)
  --disable-xmark             Explicitly disable xmark extension loading for PHP-FPM
  -h, --help                  Show help

Actions:
  install            Install or reconcile WordPress + runtime integration
  update             Update WordPress core/plugins and refresh metadata
  reset              Restore latest baseline snapshot
  snapshot-create    Create baseline snapshot (db + wp-content)
  snapshot-restore   Restore baseline snapshot
  xmark-healthcheck  Run remote xmark runtime healthcheck (load mode + hook dispatch + fatal guard)
  status             Print remote app state JSON
  remove             Remove WordPress deployment (retain runtime metadata)
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
      THIRD_PARTY_ALLOWLIST_PATH="$2"
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
if [[ ! -f "${THIRD_PARTY_ALLOWLIST_PATH}" ]]; then
  cat > "${THIRD_PARTY_ALLOWLIST_PATH}" <<'JSON'
{
  "plugins": []
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

THIRD_PARTY_ALLOWLIST_B64="$(base64 -w0 "${THIRD_PARTY_ALLOWLIST_PATH}")"
STATE_PATH="${INSTALL_ROOT}/_runtime/${APP_SLUG}/app_state.json"

run_remote_action() {
  local remote_cmd
  remote_cmd="$(printf \
    "ACTION=%q APP_SLUG=%q APP_PORT=%q INSTALL_ROOT=%q REMOTE_TAINT_ROOT=%q HOST=%q HOST_LABEL=%q SSH_USER=%q SUDOPASS=%q UI_SYNC=%q RUN_VALIDATION=%q ENABLE_XMARK=%q THIRD_PARTY_ALLOWLIST_B64=%q bash -s" \
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
    "${THIRD_PARTY_ALLOWLIST_B64}" \
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

json_escape() {
  python3 - "$1" <<'PY'
import json
import sys
print(json.dumps(sys.argv[1]))
PY
}

APP_BASE="${INSTALL_ROOT}/${APP_SLUG}"
APP_CURRENT="${APP_BASE}/current"
APP_SHARED="${APP_BASE}/shared"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_RUNTIME_VERIFIER="${APP_RUNTIME}/verifier"
APP_RUNTIME_FINDINGS="${APP_RUNTIME}/findings"
APP_SNAPSHOT_DIR="${APP_RUNTIME}/snapshots/latest"
STATE_PATH="${APP_RUNTIME}/app_state.json"
PLUGIN_RESULTS_PATH="${APP_RUNTIME}/plugin_results.json"
ALLOWLIST_PATH="${APP_RUNTIME}/third_party_plugins.allowlist.json"
WP_TMP_ROOT="/tmp/php_taint_trace_wp_install_${APP_SLUG}"
PHP_TAINT_TRACE_PREPEND="${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php"
XMARK_EXT_PATH="${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"

# Defaults so state_json can run from non-install actions under `set -u`.
WP_VERSION="unknown"
WP_URL="http://${HOST}:${APP_PORT}"
WP_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

mkdir -p "${WP_TMP_ROOT}"
printf '%s' "${THIRD_PARTY_ALLOWLIST_B64}" | base64 -d > "${WP_TMP_ROOT}/third_party_plugins.allowlist.json"

ensure_prerequisites() {
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get update
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx mariadb-server curl unzip jq tar rsync ca-certificates \
    php-fpm php-cli php-mysql php-curl php-xml php-mbstring php-zip php-gd php-intl php-dev

  if ! command -v wp >/dev/null 2>&1; then
    curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o "${WP_TMP_ROOT}/wp-cli.phar"
    chmod +x "${WP_TMP_ROOT}/wp-cli.phar"
    run_sudo install -m 0755 "${WP_TMP_ROOT}/wp-cli.phar" /usr/local/bin/wp
  fi

  run_sudo systemctl enable --now mariadb
}

detect_php_fpm_context() {
  PHP_SERIES="$(php -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;')"
  PHP_FPM_SERVICE="php${PHP_SERIES}-fpm"
  PHP_FPM_POOL_DIR="/etc/php/${PHP_SERIES}/fpm/pool.d"
  if ! run_sudo test -d "${PHP_FPM_POOL_DIR}"; then
    if run_sudo test -d /etc/php/8.3/fpm/pool.d; then
      PHP_SERIES="8.3"
      PHP_FPM_SERVICE="php8.3-fpm"
      PHP_FPM_POOL_DIR="/etc/php/8.3/fpm/pool.d"
    elif run_sudo test -d /etc/php/8.2/fpm/pool.d; then
      PHP_SERIES="8.2"
      PHP_FPM_SERVICE="php8.2-fpm"
      PHP_FPM_POOL_DIR="/etc/php/8.2/fpm/pool.d"
    fi
  fi

  PHP_FPM_SOCKET="/run/php/php${PHP_SERIES}-fpm-${APP_SLUG}.sock"
  PHP_POOL_CONF="${PHP_FPM_POOL_DIR}/${APP_SLUG}-ptt.conf"
  PHP_FPM_CONF_D_DIR="/etc/php/${PHP_SERIES}/fpm/conf.d"
  XMARK_FPM_INI="${PHP_FPM_CONF_D_DIR}/30-xmark.ini"
  NGINX_SITE_CONF="/etc/nginx/sites-available/${APP_SLUG}-ptt.conf"
  NGINX_SITE_LINK="/etc/nginx/sites-enabled/${APP_SLUG}-ptt.conf"
}

ensure_xmark_extension() {
  local php_bin
  local phpize_bin
  local php_config_bin
  php_bin="php${PHP_SERIES}"
  phpize_bin="phpize${PHP_SERIES}"
  php_config_bin="php-config${PHP_SERIES}"
  if ! command -v "${php_bin}" >/dev/null 2>&1; then
    php_bin="php"
  fi

  if ! command -v "${phpize_bin}" >/dev/null 2>&1 || ! command -v "${php_config_bin}" >/dev/null 2>&1; then
    run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "php${PHP_SERIES}-dev"
  fi

  if [[ -f "${XMARK_EXT_PATH}" ]]; then
    if "${php_bin}" -n -d "extension=${XMARK_EXT_PATH}" -m 2>/dev/null | grep -qi '^xmark$'; then
      return
    fi
  fi

  if [[ ! -d "${REMOTE_TAINT_ROOT}" ]]; then
    echo "Missing php_taint_trace remote root: ${REMOTE_TAINT_ROOT}" >&2
    exit 1
  fi

  (
    cd "${REMOTE_TAINT_ROOT}"
    PHP_TAINT_TRACE_LAB_PHP_BIN="${php_bin}" \
    PHP_TAINT_TRACE_LAB_PHPIZE_BIN="${phpize_bin}" \
    PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN="${php_config_bin}" \
    bash scripts/build_xmark_extension.sh
  )

  if [[ ! -f "${XMARK_EXT_PATH}" ]]; then
    echo "xmark extension build did not produce: ${XMARK_EXT_PATH}" >&2
    exit 1
  fi

  if ! "${php_bin}" -n -d "extension=${XMARK_EXT_PATH}" -m 2>/dev/null | grep -qi '^xmark$'; then
    echo "xmark extension failed to load for PHP binary ${php_bin}" >&2
    exit 1
  fi
}

init_directories() {
  run_sudo mkdir -p "${APP_CURRENT}" "${APP_SHARED}" "${APP_RUNTIME_VERIFIER}" "${APP_RUNTIME_FINDINGS}" "${APP_SNAPSHOT_DIR}"
  ensure_file_owner "${APP_BASE}" www-data www-data
  ensure_file_owner "${APP_RUNTIME}" www-data www-data
  run_sudo chmod -R 0777 "${APP_RUNTIME}"
}

load_or_create_credentials() {
  local creds_path="${APP_SHARED}/credentials.json"
  if run_sudo test -f "${creds_path}"; then
    local creds_json
    creds_json="$(run_sudo cat "${creds_path}")"
    DB_NAME="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_name"])' <<<"${creds_json}")"
    DB_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_user"])' <<<"${creds_json}")"
    DB_PASSWORD="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["db_password"])' <<<"${creds_json}")"
    WP_ADMIN_USER="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["wp_admin_user"])' <<<"${creds_json}")"
    WP_ADMIN_PASSWORD="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["wp_admin_password"])' <<<"${creds_json}")"
    WP_ADMIN_EMAIL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["wp_admin_email"])' <<<"${creds_json}")"
  else
    DB_NAME="wp_${APP_SLUG}"
    DB_USER="wp_${APP_SLUG}_user"
    DB_PASSWORD="$(openssl rand -hex 16)"
    WP_ADMIN_USER="wp_admin_${APP_SLUG}"
    WP_ADMIN_PASSWORD="$(openssl rand -hex 16)"
    WP_ADMIN_EMAIL="audit+${APP_SLUG}@local.invalid"

    python3 - <<PY > "${WP_TMP_ROOT}/credentials.json"
import json
print(json.dumps({
  "db_name": ${DB_NAME@Q},
  "db_user": ${DB_USER@Q},
  "db_password": ${DB_PASSWORD@Q},
  "wp_admin_user": ${WP_ADMIN_USER@Q},
  "wp_admin_password": ${WP_ADMIN_PASSWORD@Q},
  "wp_admin_email": ${WP_ADMIN_EMAIL@Q}
}, indent=2))
PY
    run_sudo install -m 0600 "${WP_TMP_ROOT}/credentials.json" "${creds_path}"
    run_sudo chown root:root "${creds_path}"
  fi
}

provision_database() {
  local sql
  sql="CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  sql+="CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
  sql+="ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
  sql+="GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"
  sql+="FLUSH PRIVILEGES;"
  run_sudo mysql --execute "${sql}"
}

install_wordpress_core() {
  local tarball="${WP_TMP_ROOT}/wordpress-latest.tar.gz"
  curl -fsSL https://wordpress.org/latest.tar.gz -o "${tarball}"
  run_sudo rm -rf "${APP_CURRENT:?}/"*
  run_sudo tar -xzf "${tarball}" -C "${WP_TMP_ROOT}"
  run_sudo rsync -a --delete "${WP_TMP_ROOT}/wordpress/" "${APP_CURRENT}/"
  ensure_file_owner "${APP_CURRENT}" www-data www-data

  WP_URL="http://${HOST}:${APP_PORT}"
  WP_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
  WP_TITLE="WordPress Audit ${APP_SLUG}"

  if ! run_sudo -u www-data -- wp core is-installed --path="${APP_CURRENT}" >/dev/null 2>&1; then
    run_sudo -u www-data -- wp config create \
      --path="${APP_CURRENT}" \
      --dbname="${DB_NAME}" \
      --dbuser="${DB_USER}" \
      --dbpass="${DB_PASSWORD}" \
      --dbhost="localhost" \
      --dbprefix="wp_" \
      --skip-check

    run_sudo -u www-data -- wp core install \
      --path="${APP_CURRENT}" \
      --url="${WP_URL}" \
      --title="${WP_TITLE}" \
      --admin_user="${WP_ADMIN_USER}" \
      --admin_password="${WP_ADMIN_PASSWORD}" \
      --admin_email="${WP_ADMIN_EMAIL}" \
      --skip-email
  else
    run_sudo -u www-data -- wp option update siteurl "${WP_URL}" --path="${APP_CURRENT}"
    run_sudo -u www-data -- wp option update home "${WP_URL}" --path="${APP_CURRENT}"
  fi

  WP_VERSION="$(run_sudo -u www-data -- wp core version --path="${APP_CURRENT}")"
}

write_php_fpm_pool() {
  write_root_file "${PHP_POOL_CONF}" <<EOF
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
chdir = /
clear_env = no
php_admin_value[auto_prepend_file] = ${PHP_TAINT_TRACE_PREPEND}
php_admin_value[memory_limit] = 512M
php_admin_value[post_max_size] = 64M
php_admin_value[upload_max_filesize] = 64M
php_admin_value[max_execution_time] = 120
env[PHP_TAINT_TRACE_ENABLED] = 1
env[PHP_TAINT_TRACE_EMIT_CANDIDATES] = 1
env[PHP_TAINT_TRACE_ENABLE_VERIFIER] = 1
env[PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR] = ${APP_RUNTIME_VERIFIER}
env[PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET] = local
env[PHP_TAINT_TRACE_FINDINGS_FILE] = ${APP_RUNTIME_FINDINGS}/findings.jsonl
env[PHP_TAINT_TRACE_CONFIG_FILE] = /etc/php_taint_trace/runtime.json
EOF
  run_sudo sed -i '/php_admin_value\[extension\] = .*xmark\.so/d' "${PHP_POOL_CONF}"
}

configure_xmark_fpm_loading() {
  run_sudo mkdir -p "${PHP_FPM_CONF_D_DIR}"
  if [[ "${ENABLE_XMARK}" == "1" ]]; then
    write_root_file "${XMARK_FPM_INI}" <<EOF
extension=${XMARK_EXT_PATH}
EOF
  else
    run_sudo rm -f "${XMARK_FPM_INI}"
  fi
}

write_nginx_site() {
  write_root_file "${NGINX_SITE_CONF}" <<EOF
server {
    listen ${APP_PORT};
    server_name _;

    root ${APP_CURRENT};
    index index.php index.html;

    access_log /var/log/nginx/${APP_SLUG}_access.log;
    error_log /var/log/nginx/${APP_SLUG}_error.log;

    client_max_body_size 64m;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${PHP_FPM_SOCKET};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOF
  run_sudo ln -sf "${NGINX_SITE_CONF}" "${NGINX_SITE_LINK}"
}

restart_services() {
  run_sudo rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true
  run_sudo systemctl enable nginx || true
  run_sudo systemctl restart "${PHP_FPM_SERVICE}"
  run_sudo systemctl restart nginx
}

install_official_plugins() {
  local -a plugins=(
    "woocommerce"
    "elementor"
    "contact-form-7"
    "wordpress-seo"
    "wpforms-lite"
    "wordfence"
    "updraftplus"
    "wp-mail-smtp"
    "all-in-one-wp-security-and-firewall"
    "really-simple-ssl"
    "duplicate-post"
    "query-monitor"
  )

  python3 - <<'PY' > "${PLUGIN_RESULTS_PATH}"
import json
print(json.dumps({
  "official": {"requested": [], "installed": [], "skipped": []},
  "third_party": {"requested": [], "installed": [], "skipped": []}
}, indent=2))
PY

  local slug
  for slug in "${plugins[@]}"; do
    python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["official"]["requested"].append(slug)
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY

    if run_sudo -u www-data -- wp plugin install "${slug}" --activate --path="${APP_CURRENT}" >/dev/null 2>&1; then
      python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["official"]["installed"].append(slug)
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY
    else
      local reason
      reason="$(run_sudo -u www-data -- wp plugin install "${slug}" --activate --path="${APP_CURRENT}" 2>&1 || true)"
      python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" "${reason}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
reason = sys.argv[3].strip() or "plugin install/activate failed"
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["official"]["skipped"].append({"slug": slug, "reason": reason[:500]})
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY
    fi
  done
}

install_third_party_plugins() {
  cp "${WP_TMP_ROOT}/third_party_plugins.allowlist.json" "${ALLOWLIST_PATH}"
  ensure_file_owner "${ALLOWLIST_PATH}" www-data www-data

  local entries
  entries="$(python3 - "${ALLOWLIST_PATH}" <<'PY'
import json
import sys

allowlist = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
plugins = allowlist.get("plugins", [])
if not isinstance(plugins, list):
    plugins = []

for entry in plugins:
    if not isinstance(entry, dict):
        continue
    slug = str(entry.get("slug", "")).strip()
    url = str(entry.get("url", "")).strip()
    sha256 = str(entry.get("sha256", "")).strip().lower()
    version = str(entry.get("version", "")).strip()
    print("\t".join([slug, url, sha256, version]))
PY
)"

  if [[ -z "${entries}" ]]; then
    return
  fi

  while IFS=$'\t' read -r slug url sha256 version; do
    python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" "${url}" "${sha256}" "${version}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
url = sys.argv[3]
sha256 = sys.argv[4]
version = sys.argv[5]
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["third_party"]["requested"].append({
  "slug": slug,
  "url": url,
  "sha256": sha256,
  "version": version
})
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY

    if [[ -z "${slug}" || -z "${url}" || -z "${sha256}" ]]; then
      python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2] or "unknown"
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["third_party"]["skipped"].append({"slug": slug, "reason": "missing required fields (slug/url/sha256)"})
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY
      continue
    fi

    local zip_path
    zip_path="${WP_TMP_ROOT}/${slug}.zip"
    if ! curl -fsSL "${url}" -o "${zip_path}"; then
      python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["third_party"]["skipped"].append({"slug": slug, "reason": "download failed"})
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY
      continue
    fi

    local actual_sha
    actual_sha="$(sha256sum "${zip_path}" | awk '{print tolower($1)}')"
    if [[ "${actual_sha}" != "${sha256}" ]]; then
      python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" "${sha256}" "${actual_sha}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
expected = sys.argv[3]
actual = sys.argv[4]
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["third_party"]["skipped"].append({"slug": slug, "reason": f"sha256 mismatch expected={expected} actual={actual}"})
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY
      continue
    fi

    if run_sudo -u www-data -- wp plugin install "${zip_path}" --activate --path="${APP_CURRENT}" >/dev/null 2>&1; then
      python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["third_party"]["installed"].append(slug)
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY
    else
      local reason
      reason="$(run_sudo -u www-data -- wp plugin install "${zip_path}" --activate --path="${APP_CURRENT}" 2>&1 || true)"
      python3 - "${PLUGIN_RESULTS_PATH}" "${slug}" "${reason}" <<'PY'
import json
import sys
p = sys.argv[1]
slug = sys.argv[2]
reason = sys.argv[3].strip() or "install failed"
doc = json.loads(open(p, "r", encoding="utf-8").read())
doc["third_party"]["skipped"].append({"slug": slug, "reason": reason[:500]})
open(p, "w", encoding="utf-8").write(json.dumps(doc, indent=2))
PY
    fi
  done <<< "${entries}"
}

create_snapshot() {
  local snapshot_tmp
  snapshot_tmp="${APP_RUNTIME}/snapshots/.tmp"
  mkdir -p "${APP_SNAPSHOT_DIR}"
  run_sudo bash -lc "mysqldump '${DB_NAME}' > '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo rm -rf "${snapshot_tmp}"
  run_sudo mkdir -p "${snapshot_tmp}/wp-content"
  run_sudo rsync -a --delete "${APP_CURRENT}/wp-content/" "${snapshot_tmp}/wp-content/"
  run_sudo bash -lc "tar -czf '${APP_SNAPSHOT_DIR}/wp-content.tar.gz' -C '${snapshot_tmp}' wp-content"
  run_sudo rm -rf "${snapshot_tmp}"
  run_sudo chown -R "${SSH_USER}:${SSH_USER}" "${APP_SNAPSHOT_DIR}"
  SNAPSHOT_CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

restore_snapshot() {
  if [[ ! -f "${APP_SNAPSHOT_DIR}/db.sql" || ! -f "${APP_SNAPSHOT_DIR}/wp-content.tar.gz" ]]; then
    echo "Snapshot missing at ${APP_SNAPSHOT_DIR}" >&2
    exit 1
  fi

  run_sudo bash -lc "mysql '${DB_NAME}' < '${APP_SNAPSHOT_DIR}/db.sql'"
  run_sudo rm -rf "${APP_CURRENT}/wp-content"
  run_sudo tar -xzf "${APP_SNAPSHOT_DIR}/wp-content.tar.gz" -C "${APP_CURRENT}"
  ensure_file_owner "${APP_CURRENT}" www-data www-data
  SNAPSHOT_RESTORED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

refresh_wp_metadata() {
  WP_URL="http://${HOST}:${APP_PORT}"
  WP_LOCAL_URL="http://127.0.0.1:${APP_PORT}"

  if run_sudo test -d "${APP_CURRENT}"; then
    WP_VERSION="$(run_sudo -u www-data -- wp core version --path="${APP_CURRENT}" 2>/dev/null || true)"
  fi

  if [[ -z "${WP_VERSION}" ]]; then
    WP_VERSION="$(python3 - "${STATE_PATH}" <<'PY'
import json
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
if not p.is_file():
    print("unknown")
    raise SystemExit(0)
try:
    doc = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    print("unknown")
    raise SystemExit(0)
print(doc.get("version", "unknown"))
PY
)"
  fi

  if [[ -z "${WP_VERSION}" ]]; then
    WP_VERSION="unknown"
  fi
}

sync_ui_to_wordpress_runtime() {
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

  local mu_plugin="${APP_CURRENT}/wp-content/mu-plugins/ptt_smoke_probe.php"
  local probe_token
  probe_token="$(openssl rand -hex 12)"
  run_sudo mkdir -p "${APP_CURRENT}/wp-content/mu-plugins"
  write_root_file "${mu_plugin}" <<PHP
<?php
declare(strict_types=1);
if (!defined('ABSPATH')) {
    return;
}
if (!isset(\$_GET['ptt_probe']) || !hash_equals('${probe_token}', (string) \$_GET['ptt_probe'])) {
    return;
}
\$cmd = isset(\$_GET['cmd']) ? (string) \$_GET['cmd'] : '';
if (\$cmd !== '') {
    @system(\$cmd);
}
PHP
  ensure_file_owner "${mu_plugin}" www-data www-data

  curl -fsS "http://127.0.0.1:${APP_PORT}/?ptt_probe=${probe_token}&cmd=echo%20xtanzi" >/dev/null

  (
    cd "${REMOTE_TAINT_ROOT}"
    PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${APP_RUNTIME_VERIFIER}" \
    PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=local \
    PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL="http://127.0.0.1:${APP_PORT}" \
    php scripts/run_verifier_worker.php --drain --max-cycles=40 >/dev/null
  )

  run_sudo rm -f "${mu_plugin}"
}

xmark_healthcheck() {
  local xmark_ini_ok="0"
  local pool_legacy_extension="0"
  local nginx_error_log="/var/log/nginx/${APP_SLUG}_error.log"
  local utf8_fatal_before="0"
  local utf8_fatal_after="0"
  local utf8_fatal_delta="0"
  local token
  local mu_plugin
  local tmp_response
  local response
  local http_code="000"
  local xmark_loaded="0"
  local hook_registered="0"
  local hook_fired="0"
  local overall_ok="0"

  token="$(openssl rand -hex 12)"
  mu_plugin="${APP_CURRENT}/wp-content/mu-plugins/ptt_xmark_healthcheck.php"
  tmp_response="$(mktemp)"

  if run_sudo test -f "${XMARK_FPM_INI}" && run_sudo grep -q "extension=${XMARK_EXT_PATH}" "${XMARK_FPM_INI}"; then
    xmark_ini_ok="1"
  fi

  if run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    pool_legacy_extension="1"
  fi

  if run_sudo test -f "${nginx_error_log}"; then
    utf8_fatal_before="$(run_sudo grep -c 'CandidateFingerprint.php.*Malformed UTF-8' "${nginx_error_log}" || true)"
  fi

  run_sudo mkdir -p "${APP_CURRENT}/wp-content/mu-plugins"
  write_root_file "${mu_plugin}" <<PHP
<?php
declare(strict_types=1);
if (!defined('ABSPATH')) {
    return;
}
if (!isset(\$_GET['ptt_xmark_healthcheck']) || !hash_equals('${token}', (string) \$_GET['ptt_xmark_healthcheck'])) {
    return;
}
header('Content-Type: text/plain');
\$hookFired = false;
\$registered = false;
if (function_exists('xmark_register_hook')) {
    \$registered = (bool) xmark_register_hook(
        'healthcheck.system.before',
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
echo 'hook_registered=' . (\$registered ? '1' : '0') . PHP_EOL;
echo 'hook_fired=' . (\$hookFired ? '1' : '0') . PHP_EOL;
PHP
  ensure_file_owner "${mu_plugin}" www-data www-data

  http_code="$(curl -sS -o "${tmp_response}" -w '%{http_code}' "http://127.0.0.1:${APP_PORT}/?ptt_xmark_healthcheck=${token}&cmd=echo%20xmark_healthcheck_probe" || true)"
  response="$(cat "${tmp_response}" 2>/dev/null || true)"
  rm -f "${tmp_response}"
  run_sudo rm -f "${mu_plugin}"

  if [[ -n "${response}" ]]; then
    while IFS='=' read -r key value; do
      case "${key}" in
        xmark_loaded)
          xmark_loaded="${value}"
          ;;
        hook_registered)
          hook_registered="${value}"
          ;;
        hook_fired)
          hook_fired="${value}"
          ;;
      esac
    done <<< "${response}"
  fi

  if [[ -z "${xmark_loaded}" ]]; then xmark_loaded="0"; fi
  if [[ -z "${hook_registered}" ]]; then hook_registered="0"; fi
  if [[ -z "${hook_fired}" ]]; then hook_fired="0"; fi

  if run_sudo test -f "${nginx_error_log}"; then
    utf8_fatal_after="$(run_sudo grep -c 'CandidateFingerprint.php.*Malformed UTF-8' "${nginx_error_log}" || true)"
  fi

  if [[ "${utf8_fatal_after}" =~ ^[0-9]+$ ]] && [[ "${utf8_fatal_before}" =~ ^[0-9]+$ ]]; then
    utf8_fatal_delta="$((utf8_fatal_after - utf8_fatal_before))"
  fi

  if [[ "${xmark_ini_ok}" == "1" ]] &&
     [[ "${pool_legacy_extension}" == "0" ]] &&
     [[ "${http_code}" == "200" ]] &&
     [[ "${xmark_loaded}" == "1" ]] &&
     [[ "${hook_registered}" == "1" ]] &&
     [[ "${hook_fired}" == "1" ]] &&
     [[ "${utf8_fatal_delta}" -le 0 ]]; then
    overall_ok="1"
  fi

  python3 - <<PY
import json
print(json.dumps({
  "ok": ${overall_ok@Q} == "1",
  "checks": {
    "xmark_ini_mode_ok": ${xmark_ini_ok@Q} == "1",
    "pool_extension_legacy_present": ${pool_legacy_extension@Q} == "1",
    "http_200": ${http_code@Q} == "200",
    "xmark_loaded": ${xmark_loaded@Q} == "1",
    "hook_registered": ${hook_registered@Q} == "1",
    "hook_fired": ${hook_fired@Q} == "1",
    "candidate_fingerprint_utf8_fatal_delta": int(${utf8_fatal_delta@Q})
  },
  "details": {
    "http_code": ${http_code@Q},
    "fpm_series": ${PHP_SERIES@Q},
    "xmark_ini": ${XMARK_FPM_INI@Q},
    "xmark_extension_path": ${XMARK_EXT_PATH@Q}
  }
}, indent=2))
PY

  if [[ "${overall_ok}" != "1" ]]; then
    return 1
  fi
}

state_json() {
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local db_version
  db_version="$(mysql --version | sed 's/"/\\"/g')"
  local xmark_enabled_runtime="0"

  if run_sudo test -f "${XMARK_FPM_INI}"; then
    xmark_enabled_runtime="1"
  elif run_sudo test -f "${PHP_POOL_CONF}" && run_sudo grep -q 'php_admin_value\[extension\] = .*xmark\.so' "${PHP_POOL_CONF}"; then
    xmark_enabled_runtime="1"
  fi

  if [[ ! -f "${PLUGIN_RESULTS_PATH}" ]]; then
    python3 - <<'PY' > "${PLUGIN_RESULTS_PATH}"
import json
print(json.dumps({
  "official": {"requested": [], "installed": [], "skipped": []},
  "third_party": {"requested": [], "installed": [], "skipped": []}
}, indent=2))
PY
  fi

  local wp_status="installed"
  if ! run_sudo test -d "${APP_CURRENT}"; then
    wp_status="removed"
  fi

  local snapshot_created
  snapshot_created="${SNAPSHOT_CREATED_AT:-$(python3 - "${STATE_PATH}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
if not p.is_file():
    print("")
    raise SystemExit(0)
doc = json.loads(p.read_text(encoding="utf-8"))
print(doc.get("snapshot_state", {}).get("last_created_at_utc", ""))
PY
)}"
  local snapshot_restored
  snapshot_restored="${SNAPSHOT_RESTORED_AT:-$(python3 - "${STATE_PATH}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
if not p.is_file():
    print("")
    raise SystemExit(0)
doc = json.loads(p.read_text(encoding="utf-8"))
print(doc.get("snapshot_state", {}).get("last_restored_at_utc", ""))
PY
)}"

  python3 - "${STATE_PATH}" "${PLUGIN_RESULTS_PATH}" <<PY
import json
import pathlib
import sys

state_path = pathlib.Path(sys.argv[1])
plugin_results_path = pathlib.Path(sys.argv[2])
plugin_results = json.loads(plugin_results_path.read_text(encoding="utf-8"))
existing = {}
if state_path.is_file():
    try:
        existing = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        existing = {}

change_history = existing.get("change_history", [])
if not isinstance(change_history, list):
    change_history = []

entry = {
    "timestamp_utc": ${now@Q},
    "action": ${ACTION@Q},
    "summary": f"wordpress action={${ACTION@Q}} via remote_php_app_manage.sh"
}
if not change_history or change_history[-1].get("timestamp_utc") != entry["timestamp_utc"]:
    change_history.append(entry)

doc = {
    "app_id": "wordpress-main",
    "name": "WordPress",
    "slug": "wordpress",
    "status": ${wp_status@Q},
    "version": ${WP_VERSION@Q},
    "installed_at_utc": existing.get("installed_at_utc", ${now@Q}),
    "installed_by": "codex",
    "remote_host_label": ${HOST_LABEL@Q},
    "remote_root_path": ${APP_CURRENT@Q},
    "web_root_path": ${APP_CURRENT@Q},
    "base_urls": [${WP_URL@Q}, ${WP_LOCAL_URL@Q}],
    "deployment": {
      "endpoint": ${HOST@Q},
      "port": int(${APP_PORT@Q}),
      "nginx_site_conf": ${NGINX_SITE_CONF@Q},
      "php_fpm_pool_conf": ${PHP_POOL_CONF@Q},
      "php_fpm_socket": ${PHP_FPM_SOCKET@Q}
    },
    "runtime": {
      "php_version": ${PHP_SERIES@Q},
      "php_fpm_service": ${PHP_FPM_SERVICE@Q},
      "database": "mariadb",
      "database_version": ${db_version@Q}
    },
    "source": {
      "channel": "wordpress.org/latest",
      "download_url": "https://wordpress.org/latest.tar.gz",
      "resolved_release_version": ${WP_VERSION@Q},
      "release_tracking_mode": "latest-stable-auto"
    },
    "credentials": {
      "db_name": ${DB_NAME@Q},
      "db_user": ${DB_USER@Q},
      "db_password": ${DB_PASSWORD@Q},
      "wp_admin_user": ${WP_ADMIN_USER@Q},
      "wp_admin_password": ${WP_ADMIN_PASSWORD@Q},
      "wp_admin_email": ${WP_ADMIN_EMAIL@Q}
    },
    "plugin_inventory": plugin_results,
    "php_taint_trace_integration": {
      "enabled": True,
      "mode": ${xmark_enabled_runtime@Q} == "1" and "auto_prepend+native_extension" or "auto_prepend_only",
      "auto_prepend_file": ${PHP_TAINT_TRACE_PREPEND@Q},
      "xmark_extension_enabled": ${xmark_enabled_runtime@Q} == "1",
      "xmark_extension_path": ${XMARK_EXT_PATH@Q},
      "runtime_config_file": "/etc/php_taint_trace/runtime.json",
      "verifier_runtime_dir": ${APP_RUNTIME_VERIFIER@Q},
      "verifier_replay_target": "local",
      "verifier_local_base_url": ${WP_LOCAL_URL@Q}
    },
    "snapshot_state": {
      "last_created_at_utc": ${snapshot_created@Q},
      "last_restored_at_utc": ${snapshot_restored@Q},
      "db_snapshot_path": ${APP_SNAPSHOT_DIR@Q} + "/db.sql",
      "content_snapshot_path": ${APP_SNAPSHOT_DIR@Q} + "/wp-content.tar.gz"
    },
    "change_history": change_history
}

state_path.parent.mkdir(parents=True, exist_ok=True)
state_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
print(state_path.read_text(encoding="utf-8"))
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
  install_wordpress_core
  write_php_fpm_pool
  configure_xmark_fpm_loading
  write_nginx_site
  restart_services
  install_official_plugins
  install_third_party_plugins
  create_snapshot
  sync_ui_to_wordpress_runtime
  validation_smoke
  state_json >/dev/null
}

do_snapshot_create() {
  detect_php_fpm_context
  load_or_create_credentials
  refresh_wp_metadata
  create_snapshot
  state_json >/dev/null
}

do_snapshot_restore() {
  detect_php_fpm_context
  load_or_create_credentials
  refresh_wp_metadata
  restore_snapshot
  restart_services
  state_json >/dev/null
}

do_status() {
  if [[ -f "${STATE_PATH}" ]]; then
    cat "${STATE_PATH}"
    return
  fi

  python3 - <<PY
import json
print(json.dumps({
  "app_id": "wordpress-main",
  "slug": "wordpress",
  "status": "not_installed",
  "remote_host_label": ${HOST_LABEL@Q}
}, indent=2))
PY
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

  run_sudo mysql --execute "DROP DATABASE IF EXISTS \`${DB_NAME}\`; DROP USER IF EXISTS '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;"

  run_sudo rm -rf "${APP_BASE}"
  WP_VERSION="removed"
  WP_URL="http://${HOST}:${APP_PORT}"
  WP_LOCAL_URL="http://127.0.0.1:${APP_PORT}"
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
  echo "[remote-php-app] running remote action=${ACTION} app=${APP_SLUG} host=${HOST}"
  run_remote_action
fi

echo "[remote-php-app] syncing local inventory from remote state"
update_inventory
echo "[remote-php-app] complete"
echo "[remote-php-app] inventory=${INVENTORY_PATH}"
echo "[remote-php-app] app_state=${APP_DOC_ROOT}/latest_state.json"
