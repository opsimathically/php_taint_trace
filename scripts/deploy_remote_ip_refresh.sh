#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
HOST_OVERRIDE=""

usage() {
  cat <<'USAGE'
Usage: scripts/deploy_remote_ip_refresh.sh [--config PATH] [--host-label LABEL] [--host-ip IP]

Installs a remote boot-time IP refresh service for the PHP audit app container.
The service detects the current LAN IP and rewrites app canonical URLs/configs
that otherwise pin browser redirects to a stale DHCP lease.
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

echo "[ip-refresh] installing remote refresh service on ${HOST}"
sshpass -p "${SSH_PASSWORD}" ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "SUDOPASS=${SUDO_PASSWORD@Q} bash -s" <<'REMOTE'
set -euo pipefail

run_sudo() {
  sudo -S -k -p '' "$@" <<<"$SUDOPASS"
}

write_root_file() {
  local target="$1"
  local mode="${2:-0644}"
  local tmp_file
  tmp_file="$(mktemp)"
  cat >"${tmp_file}"
  run_sudo install -m "${mode}" "${tmp_file}" "${target}"
  rm -f "${tmp_file}"
}

run_sudo install -d -m 0755 /usr/local/sbin /etc/php_taint_trace /var/log/php_taint_trace

write_root_file /usr/local/sbin/php-audit-apps-refresh-current-ip.sh 0755 <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

APPS_ROOT="${PHP_AUDIT_APPS_ROOT:-/opt/php_audit_apps}"
RUNTIME_ROOT="${PHP_AUDIT_RUNTIME_ROOT:-/opt/php_audit_apps/_runtime}"
LOG_PREFIX="[ip-refresh]"

detect_current_ip() {
  local preferred
  preferred="$(ip -4 -o addr show scope global | awk '{split($4,a,"/"); if (a[1] ~ /^192[.]168[.]/) {print a[1]; exit}}')"
  if [[ -n "${preferred}" ]]; then
    printf '%s\n' "${preferred}"
    return
  fi

  ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]; exit}'
}

sql_escape() {
  printf '%s' "$1" | sed "s/'/''/g"
}

mysql_db_exec() {
  local db="$1"
  local sql="$2"
  if [[ -z "${db}" ]]; then
    return 0
  fi
  mysql --batch --skip-column-names "${db}" -e "${sql}" >/dev/null 2>&1 || true
}

replace_ip_in_file() {
  local file="$1"
  local ip="$2"
  local port="$3"
  [[ -f "${file}" ]] || return 0
  grep -Iq '192[.]168[.]11[.][0-9]' "${file}" || return 0
  perl -pi -e "s#http://192\\.168\\.11\\.[0-9]+:${port}#http://${ip}:${port}#g; s#https://192\\.168\\.11\\.[0-9]+:${port}#https://${ip}:${port}#g; s#192\\.168\\.11\\.[0-9]+#${ip}#g" "${file}"
  echo "${LOG_PREFIX} updated file ${file}"
}

refresh_config_files() {
  local slug="$1"
  local ip="$2"
  local port="$3"
  local app_root="${APPS_ROOT}/${slug}"
  local runtime_dir="${RUNTIME_ROOT}/${slug}"
  local current="${app_root}/current"
  local files=()
  shopt -s nullglob

  files+=(
    "${current}/.env"
    "${current}/config.php"
    "${current}/LocalSettings.php"
    "${current}/config.inc.php"
    "${current}/config/config.php"
    "${current}/config/config_inc.php"
    "${current}/config/config.inc.php"
    "${current}/config/defines.inc.php"
    "${current}/config/settings.php"
    "${current}/config/settings.inc.php"
    "${current}/config/config.ini.php"
    "${current}/config/config_db.php"
    "${current}/config/autoload/local.php"
    "${current}/config/system/settings.php"
    "${current}/app/etc/env.php"
    "${current}/app/etc/config.php"
    "${current}/app/config/parameters.php"
    "${current}/app/config/config.php"
    "${current}/app/config/local.php"
    "${current}/app/config/parameters.yml"
    "${current}/data/config.php"
    "${current}/htdocs/conf/conf.php"
    "${current}/include/ost-config.php"
    "${current}/includes/configure.php"
    "${current}/sites/default/settings.php"
    "${current}/public/config.php"
    "${current}/admin/config.php"
    "${runtime_dir}/app_state.json"
    "${runtime_dir}/extension_results.json"
    "${runtime_dir}/plugin_results.json"
    "${runtime_dir}/module_results.json"
    "${runtime_dir}/app_results.json"
    "/etc/nginx/sites-available/${slug}-ptt.conf"
    "/etc/php_taint_trace/visualizer_ui_daemon.json"
  )

  local file
  for file in "${files[@]}"; do
    replace_ip_in_file "${file}" "${ip}" "${port}"
  done
}

refresh_common_database_urls() {
  local slug="$1"
  local db="$2"
  local prefix="$3"
  local ip="$4"
  local port="$5"
  local url="http://${ip}:${port}"
  local url_slash="${url}/"
  local host_port="${ip}:${port}"
  local sql_url
  local sql_url_slash
  local sql_ip
  local sql_host_port
  sql_url="$(sql_escape "${url}")"
  sql_url_slash="$(sql_escape "${url_slash}")"
  sql_ip="$(sql_escape "${ip}")"
  sql_host_port="$(sql_escape "${host_port}")"

  case "${slug}" in
    wordpress)
      local wp_prefix="${prefix:-wp_}"
      mysql_db_exec "${db}" "UPDATE \`${wp_prefix}options\` SET option_value='${sql_url}' WHERE option_name IN ('siteurl','home');"
      ;;
    prestashop)
      local ps_prefix="${prefix:-ps_}"
      mysql_db_exec "${db}" "UPDATE \`${ps_prefix}shop_url\` SET domain='${sql_host_port}', domain_ssl='${sql_host_port}', physical_uri='/'; UPDATE \`${ps_prefix}configuration\` SET value='${sql_host_port}' WHERE name IN ('PS_SHOP_DOMAIN','PS_SHOP_DOMAIN_SSL');"
      ;;
    magento)
      local mgt_prefix="${prefix:-mgt_}"
      mysql_db_exec "${db}" "UPDATE \`${mgt_prefix}core_config_data\` SET value='${sql_url_slash}' WHERE path IN ('web/unsecure/base_url','web/secure/base_url');"
      ;;
    moodle)
      local mdl_prefix="${prefix:-mdl_}"
      mysql_db_exec "${db}" "UPDATE \`${mdl_prefix}config\` SET value='${sql_url}' WHERE name='wwwroot';"
      ;;
    matomo)
      local matomo_prefix="${prefix:-matomo_}"
      mysql_db_exec "${db}" "UPDATE \`${matomo_prefix}option\` SET option_value=REPLACE(option_value, '192.0.2.10', '${sql_ip}') WHERE option_value LIKE '%192.168.11.%';"
      ;;
    opencart)
      local oc_prefix="${prefix:-opencart_}"
      mysql_db_exec "${db}" "UPDATE \`${oc_prefix}setting\` SET value='${sql_url_slash}' WHERE \`key\` IN ('config_url','config_ssl');"
      ;;
    dolibarr)
      local dol_prefix="${prefix:-dolibarr_}"
      mysql_db_exec "${db}" "UPDATE \`${dol_prefix}const\` SET value='${sql_url}' WHERE name IN ('MAIN_APPLICATION_TITLE_URL','MAIN_INFO_SOCIETE_WEB');"
      ;;
    osticket)
      local ost_prefix="${prefix:-ost_}"
      mysql_db_exec "${db}" "UPDATE \`${ost_prefix}config\` SET value='${sql_url}' WHERE \`key\` IN ('helpdesk_url','base_url');"
      ;;
  esac
}

clear_runtime_caches() {
  local slug="$1"
  local current="${APPS_ROOT}/${slug}/current"
  [[ -d "${current}" ]] || return 0

  rm -f "${current}/bootstrap/cache/config.php" "${current}/bootstrap/cache/services.php" 2>/dev/null || true
  rm -rf "${current}/var/cache/"* "${current}/app/cache/"* 2>/dev/null || true
}

current_ip="${PHP_AUDIT_CURRENT_IP:-$(detect_current_ip)}"
if [[ ! "${current_ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "${LOG_PREFIX} could not detect current IPv4 address" >&2
  exit 1
fi

echo "${LOG_PREFIX} current_ip=${current_ip}"
echo "${current_ip}" > "${RUNTIME_ROOT}/current_ip"

python3 - "${RUNTIME_ROOT}" <<'PY' | while IFS=$'\t' read -r slug port db prefix; do
import glob
import json
import os
import sys

runtime_root = sys.argv[1]
for path in sorted(glob.glob(os.path.join(runtime_root, "*", "app_state.json"))):
    slug = os.path.basename(os.path.dirname(path))
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
    except Exception:
        continue
    deployment = data.get("deployment") or {}
    credentials = data.get("credentials") or {}
    port = deployment.get("port")
    db = credentials.get("db_name") or credentials.get("database_name") or ""
    prefix = credentials.get("db_prefix") or credentials.get("table_prefix") or ""
    if not isinstance(port, int):
        continue
    print(f"{slug}\t{port}\t{db}\t{prefix}")
PY
  [[ -n "${slug}" && -n "${port}" ]] || continue
  echo "${LOG_PREFIX} refreshing slug=${slug} port=${port}"
  refresh_config_files "${slug}" "${current_ip}" "${port}"
  refresh_common_database_urls "${slug}" "${db}" "${prefix}" "${current_ip}" "${port}"
  clear_runtime_caches "${slug}"
done

systemctl restart nginx || true
systemctl restart php8.4-fpm || true
systemctl restart vulnerability-visualizer-ui-daemon.service || true

echo "${LOG_PREFIX} complete current_ip=${current_ip}"
SCRIPT

write_root_file /etc/systemd/system/php-audit-apps-ip-refresh.service <<'SERVICE'
[Unit]
Description=Refresh PHP audit app URLs for current DHCP address
After=network-online.target mariadb.service nginx.service php8.4-fpm.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/php-audit-apps-refresh-current-ip.sh
TimeoutStartSec=180
StandardOutput=append:/var/log/php_taint_trace/ip_refresh.log
StandardError=append:/var/log/php_taint_trace/ip_refresh.log
SERVICE

write_root_file /etc/systemd/system/php-audit-apps-ip-refresh.timer <<'TIMER'
[Unit]
Description=Periodically refresh PHP audit app URLs for current DHCP address

[Timer]
OnBootSec=20s
OnUnitActiveSec=2min
AccuracySec=10s
Persistent=true
Unit=php-audit-apps-ip-refresh.service

[Install]
WantedBy=timers.target
TIMER

run_sudo systemctl daemon-reload
run_sudo systemctl enable --now php-audit-apps-ip-refresh.timer
run_sudo systemctl start php-audit-apps-ip-refresh.service
run_sudo systemctl --no-pager --full status php-audit-apps-ip-refresh.timer | sed -n '1,25p'
run_sudo tail -n 80 /var/log/php_taint_trace/ip_refresh.log || true
REMOTE

echo "[ip-refresh] installed"
