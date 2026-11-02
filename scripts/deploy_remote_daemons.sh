#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
UI_PORT="${PHP_TAINT_TRACE_REMOTE_UI_DAEMON_PORT:-19120}"
UI_HOST="${PHP_TAINT_TRACE_REMOTE_UI_DAEMON_HOST:-0.0.0.0}"
PROVISION_NODE22="${PHP_TAINT_TRACE_REMOTE_PROVISION_NODE22:-1}"

usage() {
  cat <<'USAGE'
Usage: scripts/deploy_remote_daemons.sh [--config PATH] [--host-label LABEL] [--remote-root PATH]
                                        [--ui-port PORT] [--ui-host HOST]
                                        [--provision-node22] [--no-provision-node22]

Deploys and starts:
  - vulnerability_visualizer_ui_daemon
  - vulnerability-verifier-worker.service + timer
on the configured remote host via systemd.
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
    --remote-root)
      REMOTE_ROOT="$2"
      shift 2
      ;;
    --ui-port)
      UI_PORT="$2"
      shift 2
      ;;
    --ui-host)
      UI_HOST="$2"
      shift 2
      ;;
    --provision-node22)
      PROVISION_NODE22=1
      shift 1
      ;;
    --no-provision-node22)
      PROVISION_NODE22=0
      shift 1
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

if ! [[ "${UI_PORT}" =~ ^[0-9]+$ ]]; then
  echo "UI port must be numeric." >&2
  exit 1
fi

for cmd in python3 ssh rsync sshpass; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

if [[ "${PROVISION_NODE22}" != "0" ]]; then
  echo "[deploy-daemons] Ensuring remote Node.js >=22"
  "${ROOT_DIR}/scripts/provision_remote_node22.sh" --config "${CONFIG_PATH}" --host-label "${HOST_LABEL}"
fi

mapfile -t _cfg < <(python3 - "$CONFIG_PATH" "$HOST_LABEL" <<'PY'
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

REMOTE_RUNTIME_ROOT="${REMOTE_ROOT}/.remote_vuln_lab_runtime"
REMOTE_VERIFIER_RUNTIME_DIR="${REMOTE_RUNTIME_ROOT}/verifier"
REMOTE_UI_RUNTIME_DIR="${REMOTE_RUNTIME_ROOT}/ui"
REMOTE_UI_DIR="${REMOTE_ROOT}/subprojects/vulnerability_visualizer_ui_daemon"

echo "[deploy-daemons] Ensuring remote directory skeleton"
ssh_exec "mkdir -p ${REMOTE_UI_DIR} ${REMOTE_VERIFIER_RUNTIME_DIR} ${REMOTE_UI_RUNTIME_DIR}"

echo "[deploy-daemons] Syncing UI daemon"
rsync -az --delete --exclude node_modules --exclude dist -e "${rsync_ssh_cmd[*]}" \
  "${ROOT_DIR}/subprojects/vulnerability_visualizer_ui_daemon/" \
  "${SSH_USER}@${HOST}:${REMOTE_UI_DIR}/"

REMOTE_SETUP_CMD="$(printf \
  "REMOTE_UI_DIR=%q REMOTE_VERIFIER_RUNTIME_DIR=%q REMOTE_UI_RUNTIME_DIR=%q REMOTE_ROOT=%q SSH_USER=%q SUDOPASS=%q UI_PORT=%q UI_HOST=%q bash -s" \
  "${REMOTE_UI_DIR}" \
  "${REMOTE_VERIFIER_RUNTIME_DIR}" \
  "${REMOTE_UI_RUNTIME_DIR}" \
  "${REMOTE_ROOT}" \
  "${SSH_USER}" \
  "${SUDO_PASSWORD}" \
  "${UI_PORT}" \
  "${UI_HOST}" \
)"

echo "[deploy-daemons] Installing dependencies, building, and configuring UI service"
ssh_exec "${REMOTE_SETUP_CMD}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  sudo -S -k -p '' "$@" <<<"$SUDOPASS"
}

write_root_file() {
  local target="$1"
  local tmp_file
  tmp_file="$(mktemp)"
  cat >"${tmp_file}"
  run_sudo install -m 0644 "${tmp_file}" "${target}"
  rm -f "${tmp_file}"
}

mkdir -p "${REMOTE_VERIFIER_RUNTIME_DIR}" "${REMOTE_UI_RUNTIME_DIR}"

cd "${REMOTE_UI_DIR}"
npm install
npm run build

run_sudo mkdir -p /etc/php_taint_trace /var/log/php_taint_trace
run_sudo systemctl unmask vulnerability-visualizer-ui-daemon.service || true
run_sudo install -d -m 0755 -o www-data -g www-data "${REMOTE_UI_RUNTIME_DIR}"
run_sudo install -d -m 0755 -o www-data -g www-data "${REMOTE_VERIFIER_RUNTIME_DIR}"
run_sudo chown -R www-data:www-data "${REMOTE_UI_RUNTIME_DIR}" "${REMOTE_VERIFIER_RUNTIME_DIR}"

if ! run_sudo test -f /etc/php_taint_trace/runtime.json; then
write_root_file /etc/php_taint_trace/runtime.json <<'RUNTIMECFG'
{
  "runtime": {
    "enabled": true,
    "verifier_daemon_enabled": true
  }
}
RUNTIMECFG
fi
run_sudo chgrp www-data /etc/php_taint_trace
run_sudo chmod 2775 /etc/php_taint_trace
run_sudo chown www-data:www-data /etc/php_taint_trace/runtime.json
run_sudo chmod 0644 /etc/php_taint_trace/runtime.json

ADDITIONAL_SOURCES_JSON="$(
  python3 - <<'PY'
import glob
import json
import os

sources = []
for verifier_dir in sorted(glob.glob('/opt/php_audit_apps/_runtime/*/verifier')):
    if not os.path.isdir(verifier_dir):
        continue
    slug = os.path.basename(os.path.dirname(verifier_dir))
    if not slug:
        continue
    sources.append({
        "name": slug,
        "decisionsWorkerPath": f"{verifier_dir}/decisions.jsonl",
        "jobsPath": f"{verifier_dir}/jobs.jsonl",
        "resultsPath": f"{verifier_dir}/results.jsonl",
        "deadLettersPath": f"{verifier_dir}/dead_letters.jsonl",
        "claimsPath": f"{verifier_dir}/claims.jsonl",
    })

print(json.dumps(sources, separators=(",", ":")))
PY
)"

write_root_file /etc/php_taint_trace/visualizer_ui_daemon.json <<CFG
{
  "server": {
    "host": "${UI_HOST}",
    "port": ${UI_PORT}
  },
  "refresh": {
    "intervalMs": 60000
  },
  "fileSources": {
    "decisionsWorkerPath": "${REMOTE_VERIFIER_RUNTIME_DIR}/decisions.jsonl",
    "jobsPath": "${REMOTE_VERIFIER_RUNTIME_DIR}/jobs.jsonl",
    "resultsPath": "${REMOTE_VERIFIER_RUNTIME_DIR}/results.jsonl",
    "deadLettersPath": "${REMOTE_VERIFIER_RUNTIME_DIR}/dead_letters.jsonl",
    "claimsPath": "${REMOTE_VERIFIER_RUNTIME_DIR}/claims.jsonl",
    "claimTtlSeconds": 300,
    "additionalSources": ${ADDITIONAL_SOURCES_JSON}
  },
  "triage": {
    "statePath": "${REMOTE_UI_RUNTIME_DIR}/triage_state.json",
    "eventsPath": "${REMOTE_UI_RUNTIME_DIR}/triage_events.jsonl"
  },
  "sources": {
    "fileSourceEnabled": true,
    "additionalPaths": ${ADDITIONAL_SOURCES_JSON}
  },
  "labels": {
    "title": "Vulnerability Visualizer UI"
  },
  "storage": {
    "issueDatabasePath": "${REMOTE_UI_RUNTIME_DIR}/issues.sqlite3"
  },
  "analysisControl": {
    "enabled": true,
    "runtimeConfigPath": "/etc/php_taint_trace/runtime.json"
  }
}
CFG

write_root_file /etc/systemd/system/vulnerability-visualizer-ui-daemon.service <<UNIT
[Unit]
Description=Vulnerability Visualizer UI Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${REMOTE_UI_DIR}
ExecStart=/usr/bin/node ${REMOTE_UI_DIR}/dist/cli.cjs --config /etc/php_taint_trace/visualizer_ui_daemon.json
Restart=on-failure
RestartSec=3
StandardOutput=append:/var/log/php_taint_trace/vulnerability_visualizer_ui_daemon.log
StandardError=append:/var/log/php_taint_trace/vulnerability_visualizer_ui_daemon.log

[Install]
WantedBy=multi-user.target
UNIT

run_sudo install -d -m 0755 /usr/local/bin
write_root_file /usr/local/bin/php-taint-trace-run-all-verifier-workers.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

ROOT="${PHP_TAINT_TRACE_REMOTE_ROOT:-/opt/php_taint_trace_vuln_lab/rewrite}"
WORKER="${ROOT}/scripts/run_verifier_worker.php"
BATCH_SIZE="${PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE:-200}"
MAX_CYCLES="${PHP_TAINT_TRACE_VERIFIER_MAX_CYCLES:-4}"
APP_TIMEOUT_SEC="${PHP_TAINT_TRACE_VERIFIER_APP_TIMEOUT_SEC:-180}"
RUNTIME_CONFIG_PATH="${PHP_TAINT_TRACE_RUNTIME_CONFIG:-/etc/php_taint_trace/runtime.json}"

if [[ ! -f "${WORKER}" ]]; then
  echo "[verifier-supervisor] missing worker script: ${WORKER}" >&2
  exit 1
fi

LOCK_FILE="/var/lock/php-taint-trace-verifier-worker.lock"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "[verifier-supervisor] another run is active; skipping"
  exit 0
fi

mapfile -t TARGETS < <(
  for runtime_dir in /opt/php_audit_apps/_runtime/*/verifier; do
    [[ -d "${runtime_dir}" ]] || continue
    slug="$(basename "$(dirname "${runtime_dir}")")"
    [[ -n "${slug}" ]] || continue
    site_conf="/etc/nginx/sites-available/${slug}-ptt.conf"
    [[ -f "${site_conf}" ]] || continue
    port="$(
      awk '
        match($0, /listen[[:space:]]+([0-9]+)/, m) {
          print m[1];
          exit 0;
        }
      ' "${site_conf}"
    )"
    [[ -n "${port}" ]] || continue
    printf '%s\t%s\n' "${slug}" "${port}"
  done | sort
)

if (( ${#TARGETS[@]} == 0 )); then
  echo "[verifier-supervisor] no app targets discovered from inventory"
  exit 0
fi

is_verifier_daemon_enabled() {
  python3 - "${RUNTIME_CONFIG_PATH}" <<'PY'
import json
import os
import sys

def parse_bool(value, default=True):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
    return default

path = sys.argv[1]
enabled = True

if os.path.isfile(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception:
        raw = {}

    runtime = raw.get("runtime") if isinstance(raw, dict) and isinstance(raw.get("runtime"), dict) else raw
    if isinstance(runtime, dict):
        if "verifier_daemon_enabled" in runtime:
            enabled = parse_bool(runtime.get("verifier_daemon_enabled"), True)
        elif "enabled" in runtime:
            # Legacy fallback for older UI toggles that wrote runtime.enabled.
            enabled = parse_bool(runtime.get("enabled"), True)

print("1" if enabled else "0")
PY
}

if [[ "$(is_verifier_daemon_enabled)" != "1" ]]; then
  echo "[verifier-supervisor] verifier daemon disabled via ${RUNTIME_CONFIG_PATH}; skipping run"
  exit 0
fi

failures=0
processed_apps=0

for line in "${TARGETS[@]}"; do
  slug="${line%%$'\t'*}"
  port="${line##*$'\t'}"
  runtime_dir="/opt/php_audit_apps/_runtime/${slug}/verifier"
  jobs_path="${runtime_dir}/jobs.jsonl"

  if [[ ! -f "${jobs_path}" ]]; then
    continue
  fi

  processed_apps=$((processed_apps + 1))
  echo "[verifier-supervisor] processing slug=${slug} port=${port} runtime=${runtime_dir}"

  if ! timeout --signal=TERM "${APP_TIMEOUT_SEC}s" env \
    PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${runtime_dir}" \
    PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=local \
    PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL="http://127.0.0.1:${port}" \
    PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE="${BATCH_SIZE}" \
    php "${WORKER}" --drain --max-cycles="${MAX_CYCLES}"; then
    failures=$((failures + 1))
    echo "[verifier-supervisor] worker failed for slug=${slug}" >&2
  fi
  echo "[verifier-supervisor] finished slug=${slug}"
done

echo "[verifier-supervisor] complete apps_seen=${#TARGETS[@]} apps_processed=${processed_apps} failures=${failures}"
exit 0
SCRIPT
run_sudo chmod 0755 /usr/local/bin/php-taint-trace-run-all-verifier-workers.sh

write_root_file /etc/systemd/system/vulnerability-verifier-worker.service <<WORKERSVC
[Unit]
Description=PHP Taint Trace Verifier Worker Supervisor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=www-data
Group=www-data
Environment=PHP_TAINT_TRACE_REMOTE_ROOT=${REMOTE_ROOT}
ExecStart=/usr/local/bin/php-taint-trace-run-all-verifier-workers.sh
StandardOutput=append:/var/log/php_taint_trace/verifier_worker_supervisor.log
StandardError=append:/var/log/php_taint_trace/verifier_worker_supervisor.log
WORKERSVC

write_root_file /etc/systemd/system/vulnerability-verifier-worker.timer <<WORKERTIMER
[Unit]
Description=Run PHP Taint Trace Verifier Worker Supervisor periodically

[Timer]
OnBootSec=20s
OnUnitInactiveSec=15s
AccuracySec=1s
Persistent=true
Unit=vulnerability-verifier-worker.service

[Install]
WantedBy=timers.target
WORKERTIMER

run_sudo systemctl daemon-reload
run_sudo systemctl enable --now vulnerability-visualizer-ui-daemon.service
run_sudo systemctl restart vulnerability-visualizer-ui-daemon.service
run_sudo systemctl enable --now vulnerability-verifier-worker.timer

for _ in $(seq 1 40); do
  if curl -fsS "http://${UI_HOST}:${UI_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

curl -fsS "http://${UI_HOST}:${UI_PORT}/health" >/dev/null
run_sudo systemctl --no-pager --full status vulnerability-visualizer-ui-daemon.service | sed -n '1,20p'
run_sudo systemctl --no-pager --full status vulnerability-verifier-worker.timer | sed -n '1,20p'
REMOTE

echo "[deploy-daemons] Complete"
echo "[deploy-daemons] UI health (remote bind): http://${UI_HOST}:${UI_PORT}/health"
if [[ "${UI_HOST}" == "0.0.0.0" ]]; then
  echo "[deploy-daemons] UI health (from local network): http://${HOST}:${UI_PORT}/health"
fi
echo "[deploy-daemons] Worker service: vulnerability-verifier-worker.service (timer-driven)"
