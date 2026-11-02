#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_TAINT_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
INSTALL_ROOT="/opt/php_audit_apps"
APP_PORT="19162"
APP_SLUG="custom_vuln_lab"
INVENTORY_PATH="${PHP_TAINT_TRACE_INVENTORY_PATH:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications/inventory.json}"
APP_DOC_ROOT="${PHP_TAINT_TRACE_INVENTORY_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/php_taint_trace/installed_php_applications}/apps/${APP_SLUG}"
LOCAL_APP_DIR="${ROOT_DIR}/remote_linux_container/custom_php_applications/${APP_SLUG}"

DB_NAME="custom_vuln_lab"
DB_USER="custom_vuln_lab_user"
DB_PASSWORD="synthetic-lab-database-only"
DB_HOST="127.0.0.1"
DB_PORT="3306"

usage() {
  cat <<'USAGE'
Usage:
  scripts/remote_custom_vuln_lab_app_manage.sh <install|update|reset|status|remove|register-inventory> [options]

Options:
  --config PATH             Host credential JSON
  --host-label LABEL        Host label in config
  --remote-taint-root PATH  Remote php_taint_trace repo root
  --install-root PATH       Remote multi-app root
  --app-port PORT           App port (default 19162)
  --inventory PATH          Local inventory path
  --db-name NAME            DB name
  --db-user USER            DB user
  --db-password PASS        DB password
  --db-host HOST            DB host
  --db-port PORT            DB port
  -h, --help                Show help
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
    --db-name)
      DB_NAME="$2"
      shift 2
      ;;
    --db-user)
      DB_USER="$2"
      shift 2
      ;;
    --db-password)
      DB_PASSWORD="$2"
      shift 2
      ;;
    --db-host)
      DB_HOST="$2"
      shift 2
      ;;
    --db-port)
      DB_PORT="$2"
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

if ! [[ "${ACTION}" =~ ^(install|update|reset|status|remove|register-inventory)$ ]]; then
  echo "Unsupported action: ${ACTION}" >&2
  usage >&2
  exit 1
fi

for cmd in python3 ssh sshpass rsync; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

if [[ ! -d "${LOCAL_APP_DIR}" ]]; then
  echo "Local app directory not found: ${LOCAL_APP_DIR}" >&2
  exit 1
fi

mkdir -p "${APP_DOC_ROOT}"

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

rsync_ssh_cmd=(
  sshpass -p "${SSH_PASSWORD}" ssh
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=20
)

APP_BASE="${INSTALL_ROOT}/${APP_SLUG}"
APP_CURRENT="${APP_BASE}/current"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_VERIFIER="${APP_RUNTIME}/verifier"
APP_FINDINGS="${APP_RUNTIME}/findings"
APP_UPLOADS="${APP_RUNTIME}/uploads"
APP_STATE="${APP_RUNTIME}/app_state.json"
APP_SERVICE="custom-vuln-lab.service"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
RUNTIME_CONFIG_PATH="/etc/php_taint_trace/runtime.json"

remote_manage() {
  local mode="$1"
  local remote_cmd
  remote_cmd="$(printf \
    "MODE=%q APP_SLUG=%q APP_PORT=%q INSTALL_ROOT=%q REMOTE_TAINT_ROOT=%q DB_NAME=%q DB_USER=%q DB_PASSWORD=%q DB_HOST=%q DB_PORT=%q SUDOPASS=%q SSH_USER=%q HOST=%q bash -s" \
    "${mode}" "${APP_SLUG}" "${APP_PORT}" "${INSTALL_ROOT}" "${REMOTE_TAINT_ROOT}" \
    "${DB_NAME}" "${DB_USER}" "${DB_PASSWORD}" "${DB_HOST}" "${DB_PORT}" \
    "${SUDO_PASSWORD}" "${SSH_USER}" "${HOST}")"

  ssh_exec "${remote_cmd}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  sudo -S -k -p '' "$@" <<<"$SUDOPASS"
}

run_sudo_with_input() {
  local tmp
  local rc
  tmp="$(mktemp)"
  cat > "${tmp}"
  {
    printf '%s\n' "${SUDOPASS}"
    cat "${tmp}"
  } | sudo -S -k -p '' "$@"
  rc=$?
  rm -f "${tmp}"
  return "${rc}"
}

write_root_file() {
  local target="$1"
  local mode="${2:-0644}"
  local tmp
  tmp="$(mktemp)"
  cat > "${tmp}"
  run_sudo install -m "${mode}" "${tmp}" "${target}"
  rm -f "${tmp}"
}

APP_BASE="${INSTALL_ROOT}/${APP_SLUG}"
APP_CURRENT="${APP_BASE}/current"
APP_RUNTIME="${INSTALL_ROOT}/_runtime/${APP_SLUG}"
APP_VERIFIER="${APP_RUNTIME}/verifier"
APP_FINDINGS="${APP_RUNTIME}/findings"
APP_UPLOADS="${APP_RUNTIME}/uploads"
APP_STATE="${APP_RUNTIME}/app_state.json"
APP_SERVICE="custom-vuln-lab.service"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
RUNTIME_CONFIG_PATH="/etc/php_taint_trace/runtime.json"

ensure_runtime_dirs() {
  run_sudo mkdir -p "${APP_BASE}" "${APP_CURRENT}" "${APP_RUNTIME}" "${APP_VERIFIER}" "${APP_FINDINGS}" "${APP_UPLOADS}"
  run_sudo touch "${APP_FINDINGS}/${APP_SLUG}.jsonl" "${APP_VERIFIER}/jobs.jsonl" "${APP_VERIFIER}/results.jsonl" "${APP_VERIFIER}/decisions.jsonl" "${APP_VERIFIER}/dead_letters.jsonl" "${APP_VERIFIER}/claims.jsonl"
  run_sudo chown -R www-data:www-data "${APP_RUNTIME}" "${APP_BASE}"
  run_sudo find "${APP_RUNTIME}" -type d -exec chmod 2775 {} +
  run_sudo find "${APP_RUNTIME}" -type f -exec chmod 664 {} +
}

ensure_database() {
  run_sudo mysql -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  run_sudo mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
  run_sudo mysql -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASSWORD}';"
  run_sudo mysql -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"
  run_sudo mysql -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';"
  run_sudo mysql -e "FLUSH PRIVILEGES;"
}

seed_database() {
  run_sudo_with_input mysql "${DB_NAME}" <<'SQL'
SET FOREIGN_KEY_CHECKS=0;
DROP TABLE IF EXISTS transfer_log;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS=1;
SQL
  run_sudo_with_input mysql "${DB_NAME}" < "${APP_CURRENT}/schema.sql"
}

write_service() {
  local php_bin="/usr/bin/php"
  if run_sudo test -x /usr/bin/php8.4; then
    php_bin="/usr/bin/php8.4"
  elif run_sudo test -x /usr/bin/php8.3; then
    php_bin="/usr/bin/php8.3"
  fi

  write_root_file "/etc/systemd/system/${APP_SERVICE}" 0644 <<UNIT
[Unit]
Description=Custom Vulnerable Fuzzer Lab
After=network.target mariadb.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${APP_CURRENT}
Environment=PHP_TAINT_TRACE_ENABLED=1
Environment=PHP_TAINT_TRACE_ENABLE_VERIFIER=1
Environment=PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR=${APP_VERIFIER}
Environment=PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=local
Environment=PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL=http://127.0.0.1:${APP_PORT}
Environment=PHP_TAINT_TRACE_FINDINGS_FILE=${APP_FINDINGS}/${APP_SLUG}.jsonl
Environment=CUSTOM_VULN_LAB_DB_HOST=${DB_HOST}
Environment=CUSTOM_VULN_LAB_DB_PORT=${DB_PORT}
Environment=CUSTOM_VULN_LAB_DB_NAME=${DB_NAME}
Environment=CUSTOM_VULN_LAB_DB_USER=${DB_USER}
Environment=CUSTOM_VULN_LAB_DB_PASSWORD=${DB_PASSWORD}
ExecStart=${php_bin} -d allow_url_include=1 -d extension=${REMOTE_TAINT_ROOT}/ext/xmark/modules/xmark.so -d auto_prepend_file=${REMOTE_TAINT_ROOT}/scripts/auto_prepend.php -S 0.0.0.0:${APP_PORT} -t ${APP_CURRENT}/public ${APP_CURRENT}/public/router.php
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

  run_sudo systemctl daemon-reload
  run_sudo systemctl enable "${APP_SERVICE}"
  run_sudo systemctl restart "${APP_SERVICE}"
}

patch_ui_sources() {
  run_sudo_with_input python3 - "${UI_CONFIG_PATH}" "${APP_SLUG}" "${APP_VERIFIER}" <<'PY'
import json
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
slug = sys.argv[2]
verifier = Path(sys.argv[3])
if not cfg_path.exists():
    print(f"ui source patch skipped: missing config {cfg_path}")
    raise SystemExit(0)
doc = json.loads(cfg_path.read_text(encoding='utf-8'))

source = {
    'name': slug,
    'decisionsWorkerPath': str(verifier / 'decisions.jsonl'),
    'jobsPath': str(verifier / 'jobs.jsonl'),
    'resultsPath': str(verifier / 'results.jsonl'),
    'deadLettersPath': str(verifier / 'dead_letters.jsonl'),
    'claimsPath': str(verifier / 'claims.jsonl'),
}
collector_source = {
    'source_id': slug,
    'decisions_path': str(verifier / 'decisions.jsonl'),
    'jobs_path': str(verifier / 'jobs.jsonl'),
    'results_path': str(verifier / 'results.jsonl'),
    'dead_letters_path': str(verifier / 'dead_letters.jsonl'),
    'claims_path': str(verifier / 'claims.jsonl'),
}

file_sources = doc.setdefault('fileSources', {})
arr = file_sources.setdefault('additionalSources', [])
arr = [item for item in arr if isinstance(item, dict) and item.get('name') != slug]
arr.append(source)
file_sources['additionalSources'] = arr

sources = doc.setdefault('sources', {})
arr2 = sources.setdefault('additionalPaths', [])
arr2 = [item for item in arr2 if isinstance(item, dict) and item.get('name') != slug]
arr2.append(source)
sources['additionalPaths'] = arr2

collector = doc.setdefault('collector', {})
arr3 = collector.setdefault('additional_sources', [])
arr3 = [item for item in arr3 if isinstance(item, dict) and item.get('source_id') != slug]
arr3.append(collector_source)
collector['additional_sources'] = arr3

cfg_path.write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8')
print(
    f"patched ui sources: fileSources.additionalSources={len(file_sources.get('additionalSources', []))} "
    f"sources.additionalPaths={len(sources.get('additionalPaths', []))} "
    f"collector.additional_sources={len(collector.get('additional_sources', []))}"
)
PY

  run_sudo systemctl restart vulnerability-visualizer-ui-daemon.service || true
}

write_state() {
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  run_sudo_with_input python3 - "${APP_STATE}" "${HOST}" "${APP_PORT}" "${APP_SLUG}" "${DB_NAME}" "${DB_USER}" "${DB_PASSWORD}" "${DB_HOST}" "${DB_PORT}" "${APP_CURRENT}" "${APP_RUNTIME}" "${REMOTE_TAINT_ROOT}" "${now}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

state_path = Path(sys.argv[1])
host = sys.argv[2]
port = int(sys.argv[3])
slug = sys.argv[4]
db_name = sys.argv[5]
db_user = sys.argv[6]
db_pass = sys.argv[7]
db_host = sys.argv[8]
db_port = sys.argv[9]
app_current = sys.argv[10]
app_runtime = sys.argv[11]
remote_taint_root = sys.argv[12]
now = sys.argv[13]

service = 'custom-vuln-lab.service'
service_status = 'unknown'
try:
    out = subprocess.check_output(['systemctl', 'is-active', service], text=True).strip()
    service_status = out
except Exception:
    pass

state = {
    'app_id': f'{slug}-main',
    'name': 'Custom Vulnerable Fuzzer Lab',
    'slug': slug,
    'status': 'installed' if service_status == 'active' else 'updated',
    'version': '1.0.0',
    'installed_at_utc': now,
    'installed_by': 'codex',
    'remote_host_label': 'lab.example.invalid',
    'remote_root_path': app_current,
    'web_root_path': app_current + '/public',
    'base_urls': [f'http://{host}:{port}', f'http://127.0.0.1:{port}'],
    'deployment': {
      'endpoint': host,
      'port': port,
      'service': service,
      'php_server_mode': 'php -S',
    },
    'runtime': {
      'php_version': subprocess.getoutput('php -v | head -n 1'),
      'sapi': 'cli-server',
      'database': 'mariadb',
      'database_version': subprocess.getoutput("mysql --version 2>/dev/null | head -n 1"),
    },
    'source': {
      'channel': 'local-custom-app',
      'local_repo_path': 'remote_linux_container/custom_php_applications/custom_vuln_lab',
      'release_tracking_mode': 'manual',
    },
    'credentials': {
      'db_name': db_name,
      'db_user': db_user,
      'db_password': db_pass,
      'db_host': db_host,
      'db_port': db_port,
      'alice_user': 'alice',
      'alice_password': 'synthetic-lab-alice-only',
      'bob_user': 'bob',
      'bob_password': 'synthetic-lab-bob-only',
      'admin_user': 'admin',
      'admin_password': 'synthetic-lab-admin-only',
    },
    'php_taint_trace_integration': {
      'enabled': True,
      'mode': 'auto_prepend+native_extension',
      'auto_prepend_file': remote_taint_root + '/scripts/auto_prepend.php',
      'xmark_extension_enabled': True,
      'xmark_extension_path': remote_taint_root + '/ext/xmark/modules/xmark.so',
      'runtime_config_file': '/etc/php_taint_trace/runtime.json',
      'verifier_runtime_dir': app_runtime + '/verifier',
      'verifier_replay_target': 'local',
      'verifier_local_base_url': f'http://127.0.0.1:{port}',
    },
    'snapshot_state': {
      'last_created_at_utc': None,
      'last_restored_at_utc': None,
      'db_snapshot_path': app_runtime + '/snapshots/latest/db.sql',
      'content_snapshot_path': app_runtime + '/snapshots/latest/content.tar.gz',
    },
    'change_history': [
      {
        'timestamp_utc': now,
        'action': 'update',
        'summary': 'custom_vuln_lab managed by remote_custom_vuln_lab_app_manage.sh',
      }
    ],
  }

state_path.parent.mkdir(parents=True, exist_ok=True)
state_path.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
PY

  if ! run_sudo test -f "${APP_STATE}"; then
    write_root_file "${APP_STATE}" 0644 <<EOF
{
  "app_id": "${APP_SLUG}-main",
  "name": "Custom Vulnerable Fuzzer Lab",
  "slug": "${APP_SLUG}",
  "status": "installed",
  "version": "1.0.0",
  "installed_at_utc": "${now}",
  "installed_by": "codex"
}
EOF
  fi

  run_sudo chown www-data:www-data "${APP_STATE}" || true
  run_sudo chmod 664 "${APP_STATE}" || true
}

if [[ "${MODE}" == "install" || "${MODE}" == "update" ]]; then
  ensure_runtime_dirs
  ensure_database
  seed_database
  write_service
  patch_ui_sources
  write_state
  curl -fsS "http://127.0.0.1:${APP_PORT}/catalog.json" >/dev/null
  echo "${MODE}: OK"
  exit 0
fi

if [[ "${MODE}" == "reset" ]]; then
  ensure_database
  seed_database
  run_sudo rm -f "${APP_UPLOADS}"/* || true
  write_state
  echo "reset: OK"
  exit 0
fi

if [[ "${MODE}" == "status" ]]; then
  run_sudo systemctl status "${APP_SERVICE}" --no-pager || true
  run_sudo test -f "${APP_STATE}" && run_sudo cat "${APP_STATE}" || true
  curl -fsS "http://127.0.0.1:${APP_PORT}/catalog.json" || true
  exit 0
fi

if [[ "${MODE}" == "remove" ]]; then
  run_sudo systemctl disable --now "${APP_SERVICE}" || true
  run_sudo rm -f "/etc/systemd/system/${APP_SERVICE}"
  run_sudo systemctl daemon-reload
  run_sudo rm -rf "${APP_CURRENT}"
  run_sudo test -f "${APP_STATE}" && run_sudo python3 - "${APP_STATE}" <<'PY'
import json
import sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.exists():
    raise SystemExit(0)
d = json.loads(p.read_text(encoding='utf-8'))
d['status'] = 'removed'
p.write_text(json.dumps(d, indent=2) + '\n', encoding='utf-8')
PY
  echo "remove: OK"
  exit 0
fi
REMOTE
}

sync_app() {
  echo "[custom-vuln-lab] syncing app files"
  ssh_exec "sudo -S -k -p '' mkdir -p '${APP_CURRENT}' '${APP_RUNTIME}' <<< '${SUDO_PASSWORD}'"
  ssh_exec "sudo -S -k -p '' chown -R '${SSH_USER}:${SSH_USER}' '${APP_BASE}' '${APP_RUNTIME}' <<< '${SUDO_PASSWORD}'"
  rsync -az --delete -e "${rsync_ssh_cmd[*]}" \
    "${LOCAL_APP_DIR}/" \
    "${SSH_USER}@${HOST}:${APP_CURRENT}/"
  ssh_exec "sudo -S -k -p '' chown -R www-data:www-data '${APP_BASE}' <<< '${SUDO_PASSWORD}'"
}

register_inventory_local() {
  local tmp_state
  tmp_state="$(mktemp)"
  ssh_exec "sudo -S -k -p '' cat '${APP_STATE}' <<< '${SUDO_PASSWORD}'" > "${tmp_state}"

  python3 - "${tmp_state}" "${HOST}" "${APP_PORT}" "${APP_SLUG}" "${APP_CURRENT}" "${APP_RUNTIME}" "${REMOTE_TAINT_ROOT}" "${DB_NAME}" "${DB_USER}" "${DB_PASSWORD}" "${DB_HOST}" "${DB_PORT}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

state_path = Path(sys.argv[1])
host = sys.argv[2]
port = int(sys.argv[3])
slug = sys.argv[4]
app_current = sys.argv[5]
app_runtime = sys.argv[6]
taint_root = sys.argv[7]
db_name = sys.argv[8]
db_user = sys.argv[9]
db_password = sys.argv[10]
db_host = sys.argv[11]
db_port = sys.argv[12]

raw = json.loads(state_path.read_text(encoding='utf-8'))
now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
state = dict(raw)
state.setdefault('app_id', f'{slug}-main')
state.setdefault('name', 'Custom Vulnerable Fuzzer Lab')
state.setdefault('slug', slug)
state.setdefault('status', 'installed')
state.setdefault('version', '1.0.0')
state.setdefault('installed_at_utc', now)
state.setdefault('installed_by', 'codex')
state.setdefault('remote_host_label', 'lab.example.invalid')
state.setdefault('remote_root_path', app_current)
state.setdefault('web_root_path', app_current + '/public')
state.setdefault('base_urls', [f'http://{host}:{port}', f'http://127.0.0.1:{port}'])
state.setdefault('deployment', {
    'endpoint': host,
    'port': port,
    'service': 'custom-vuln-lab.service',
    'php_server_mode': 'php -S',
})
state.setdefault('runtime', {
    'php_version': 'unknown',
    'sapi': 'cli-server',
    'database': 'mariadb',
    'database_version': 'unknown',
})
state.setdefault('source', {
    'channel': 'local-custom-app',
    'local_repo_path': 'remote_linux_container/custom_php_applications/custom_vuln_lab',
    'release_tracking_mode': 'manual',
})
state.setdefault('credentials', {
    'db_name': db_name,
    'db_user': db_user,
    'db_password': db_password,
    'db_host': db_host,
    'db_port': db_port,
    'alice_user': 'alice',
    'alice_password': 'synthetic-lab-alice-only',
    'bob_user': 'bob',
    'bob_password': 'synthetic-lab-bob-only',
    'admin_user': 'admin',
    'admin_password': 'synthetic-lab-admin-only',
})
state.setdefault('php_taint_trace_integration', {
    'enabled': True,
    'mode': 'auto_prepend+native_extension',
    'auto_prepend_file': taint_root + '/scripts/auto_prepend.php',
    'xmark_extension_enabled': True,
    'xmark_extension_path': taint_root + '/ext/xmark/modules/xmark.so',
    'runtime_config_file': '/etc/php_taint_trace/runtime.json',
    'verifier_runtime_dir': app_runtime + '/verifier',
    'verifier_replay_target': 'local',
    'verifier_local_base_url': f'http://127.0.0.1:{port}',
})
state.setdefault('snapshot_state', {
    'last_created_at_utc': None,
    'last_restored_at_utc': None,
    'db_snapshot_path': app_runtime + '/snapshots/latest/db.sql',
    'content_snapshot_path': app_runtime + '/snapshots/latest/content.tar.gz',
})
history = state.get('change_history')
if not isinstance(history, list):
    history = []
history.append({
    'timestamp_utc': now,
    'action': 'register-inventory',
    'summary': 'custom_vuln_lab inventory refresh',
})
state['change_history'] = history[-20:]

state_path.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
PY

  cp "${tmp_state}" "${APP_DOC_ROOT}/latest_state.json"

  python3 - "${INVENTORY_PATH}" "${tmp_state}" <<'PY'
import json
import sys
from pathlib import Path

inv_path = Path(sys.argv[1])
state_path = Path(sys.argv[2])
inv = json.loads(inv_path.read_text(encoding='utf-8'))
state = json.loads(state_path.read_text(encoding='utf-8'))
apps = inv.get('applications')
if not isinstance(apps, list):
    apps = []

apps = [a for a in apps if isinstance(a, dict) and a.get('slug') != state.get('slug')]
apps.append(state)
apps.sort(key=lambda x: str(x.get('slug', '')))
inv['applications'] = apps
inv['updated_at_utc'] = state.get('installed_at_utc')
inv_path.write_text(json.dumps(inv, indent=2) + '\n', encoding='utf-8')
PY

  cat > "${APP_DOC_ROOT}/README.md" <<'MD'
# custom_vuln_lab

State metadata is stored in `latest_state.json`.

Source app files are in:

- `remote_linux_container/custom_php_applications/custom_vuln_lab/`

Management script:

- `scripts/remote_custom_vuln_lab_app_manage.sh`
MD

  rm -f "${tmp_state}"
  echo "[custom-vuln-lab] inventory updated"
}

case "${ACTION}" in
  install|update)
    sync_app
    remote_manage "${ACTION}"
    register_inventory_local
    ;;
  reset|status|remove)
    remote_manage "${ACTION}"
    if [[ "${ACTION}" != "remove" ]]; then
      register_inventory_local
    fi
    ;;
  register-inventory)
    register_inventory_local
    ;;
esac

echo "[custom-vuln-lab] done: ${ACTION}"
