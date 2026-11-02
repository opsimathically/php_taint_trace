#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
EXTENSION_PROFILE="${PHP_TAINT_TRACE_REMOTE_EXTENSION_PROFILE:-base}"
UI_PORT="${PHP_TAINT_TRACE_REMOTE_UI_DAEMON_PORT:-19120}"
REQUIRED_CATEGORIES="${PHP_TAINT_TRACE_REMOTE_DAEMON_REQUIRED_CATEGORIES:-rce,ssrf,sqli,file,xss,idor,xxe}"

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_daemon_full_stack_e2e.sh [--config PATH] [--host-label LABEL] [--remote-root PATH]
                                                    [--extension-profile base|extended_sql|extended_rce|extended_all]
                                                    [--ui-port PORT]
                                                    [--required-categories CSV]

Runs full-stack remote worker-artifact + UI validation:
  1) deploy UI daemon
  2) restart/reset remote vulnerable lab with verifier queue enabled
  3) trigger real vulnerable requests (rce/ssrf/sqli/file/xss/idor/xxe)
  4) run php verifier worker drain on remote runtime queue
  5) assert worker decisions and UI issue projection are populated
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
    --extension-profile)
      EXTENSION_PROFILE="$2"
      shift 2
      ;;
    --ui-port)
      UI_PORT="$2"
      shift 2
      ;;
    --required-categories)
      REQUIRED_CATEGORIES="$2"
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

EXTENSION_PROFILE="$(printf '%s' "${EXTENSION_PROFILE}" | tr '[:upper:]' '[:lower:]' | xargs)"
case "${EXTENSION_PROFILE}" in
  base|extended_sql|extended_rce|extended_all)
    ;;
  *)
    echo "Invalid --extension-profile: ${EXTENSION_PROFILE}. Expected base|extended_sql|extended_rce|extended_all." >&2
    exit 1
    ;;
esac

if ! [[ "${UI_PORT}" =~ ^[0-9]+$ ]]; then
  echo "UI port must be numeric." >&2
  exit 1
fi

REQUIRED_CATEGORIES="$(printf '%s' "${REQUIRED_CATEGORIES}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ -z "${REQUIRED_CATEGORIES}" ]]; then
  echo "Invalid --required-categories: empty set." >&2
  exit 1
fi

for cmd in python3 ssh sshpass rsync; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
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
required = ("ipv4", "ssh_username", "ssh_password")
missing = [k for k in required if k not in entry or not str(entry[k]).strip()]
if missing:
    raise SystemExit(f"Missing required config keys for {label}: {', '.join(missing)}")
print(entry["ipv4"])
print(entry["ssh_username"])
print(entry["ssh_password"])
PY
)

HOST="${_cfg[0]}"
SSH_USER="${_cfg[1]}"
SSH_PASSWORD="${_cfg[2]}"

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

REMOTE_PROJECT_ROOT="${REMOTE_ROOT}/rewrite"
REMOTE_RUNTIME_ROOT="${REMOTE_PROJECT_ROOT}/.remote_vuln_lab_runtime"
REMOTE_VERIFIER_RUNTIME_DIR="${REMOTE_RUNTIME_ROOT}/verifier"
REMOTE_UI_RUNTIME_DIR="${REMOTE_RUNTIME_ROOT}/ui"

echo "[remote-daemon-full-stack] Deploying UI daemon"
bash "${ROOT_DIR}/scripts/deploy_remote_daemons.sh" \
  --config "${CONFIG_PATH}" \
  --host-label "${HOST_LABEL}" \
  --remote-root "${REMOTE_PROJECT_ROOT}" \
  --ui-host 0.0.0.0 \
  --ui-port "${UI_PORT}"

echo "[remote-daemon-full-stack] Syncing remote lab manager script"
sshpass -p "${SSH_PASSWORD}" rsync -a \
  -e "ssh ${SSH_OPTS[*]}" \
  "${ROOT_DIR}/scripts/remote_vuln_lab_manage.sh" \
  "${SSH_USER}@${HOST}:${REMOTE_PROJECT_ROOT}/scripts/"

REMOTE_CMD="$(printf \
  "REMOTE_PROJECT_ROOT=%q REMOTE_VERIFIER_RUNTIME_DIR=%q REMOTE_UI_RUNTIME_DIR=%q EXTENSION_PROFILE=%q UI_PORT=%q REQUIRED_CATEGORIES=%q bash -s" \
  "${REMOTE_PROJECT_ROOT}" \
  "${REMOTE_VERIFIER_RUNTIME_DIR}" \
  "${REMOTE_UI_RUNTIME_DIR}" \
  "${EXTENSION_PROFILE}" \
  "${UI_PORT}" \
  "${REQUIRED_CATEGORIES}" \
)"

echo "[remote-daemon-full-stack] Restarting remote lab and clearing runtime artifacts"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

if [[ ! -d "${REMOTE_PROJECT_ROOT}" ]]; then
  echo "Remote project root does not exist: ${REMOTE_PROJECT_ROOT}" >&2
  exit 1
fi

export PHP_TAINT_TRACE_ENABLE_VERIFIER=1
export PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${REMOTE_VERIFIER_RUNTIME_DIR}"
export PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=remote_lab
export PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1
export PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=safe
export PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE="${EXTENSION_PROFILE}"

cd "${REMOTE_PROJECT_ROOT}"
bash scripts/remote_vuln_lab_manage.sh profile "${EXTENSION_PROFILE}"
bash scripts/remote_vuln_lab_manage.sh restart
bash scripts/remote_vuln_lab_manage.sh reset

rm -rf "${REMOTE_VERIFIER_RUNTIME_DIR}"
mkdir -p "${REMOTE_VERIFIER_RUNTIME_DIR}"
rm -f "${REMOTE_UI_RUNTIME_DIR}/triage_state.json" "${REMOTE_UI_RUNTIME_DIR}/triage_events.jsonl"
REMOTE

echo "[remote-daemon-full-stack] Triggering real vulnerable requests"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

http_get() {
  php -r '
$url = $argv[1];
$ctx = stream_context_create(array(
    "http" => array(
        "ignore_errors" => true,
        "timeout" => 4,
    ),
));
$body = @file_get_contents($url, false, $ctx);
if ($body === false) {
    fwrite(STDERR, "request failed: " . $url . PHP_EOL);
    exit(1);
}
' "$1"
}

http_get 'http://127.0.0.1:19082/?cmd=echo%20fullstack-rce'
http_get 'http://127.0.0.1:19084/?url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dfullstack-ssrf'
http_get 'http://127.0.0.1:19085/?q=SELECT%20username%20FROM%20users%20WHERE%20id%20%3D%201'
http_get 'http://127.0.0.1:19083/?path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19081/?name=%3Cscript%3Efullstack-xss%3C%2Fscript%3E'
http_get 'http://127.0.0.1:19086/?resource_id=42&actor_id=1043&mode=vuln'
http_get 'http://127.0.0.1:19087/?xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dfullstack-xxe%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'

jobs_path="${REMOTE_VERIFIER_RUNTIME_DIR}/jobs.jsonl"
job_lines=0
for _ in $(seq 1 40); do
  if [[ -f "${jobs_path}" ]]; then
    job_lines="$(wc -l < "${jobs_path}" | tr -d '[:space:]')"
    if [[ "${job_lines}" =~ ^[0-9]+$ ]] && [[ "${job_lines}" -gt 0 ]]; then
      break
    fi
  fi
  sleep 0.25
done

if ! [[ "${job_lines}" =~ ^[0-9]+$ ]] || [[ "${job_lines}" -le 0 ]]; then
  echo "No verifier jobs were generated after triggering vulnerable requests (jobs_path=${jobs_path})." >&2
  exit 1
fi

echo "[remote-daemon-full-stack] queued_jobs=${job_lines}"
REMOTE

echo "[remote-daemon-full-stack] Running worker drain + validating worker/UI projection"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

cd "${REMOTE_PROJECT_ROOT}"
export PHP_TAINT_TRACE_ENABLE_VERIFIER=1
export PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${REMOTE_VERIFIER_RUNTIME_DIR}"
export PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=remote_lab
export PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1
export PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=safe
php scripts/run_verifier_worker.php --drain --max-cycles=240

DECISIONS_PATH="${REMOTE_VERIFIER_RUNTIME_DIR}/decisions.jsonl"
if [[ ! -s "${DECISIONS_PATH}" ]]; then
  echo "worker produced no decisions at ${DECISIONS_PATH}" >&2
  exit 1
fi

python3 - "${DECISIONS_PATH}" "${REQUIRED_CATEGORIES}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
required = {part for part in str(sys.argv[2]).split(',') if part}
seen = set()
for line in path.read_text(encoding='utf-8').splitlines():
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    metadata = row.get('metadata') or {}
    category = str(metadata.get('sink_category') or '').strip().lower()
    if category:
        seen.add(category)
missing = sorted(required - seen)
if missing:
    raise SystemExit(f"worker decisions missing required categories: {missing}")
print("[remote-daemon-full-stack] worker_categories_seen=" + ",".join(sorted(seen)))
PY

fetch_json_with_retry() {
  local url="$1"
  local attempts="${2:-20}"
  local delay="${3:-0.5}"
  local response=""
  for _ in $(seq 1 "${attempts}"); do
    if response="$(curl -fsS "${url}" 2>/dev/null)"; then
      printf '%s' "${response}"
      return 0
    fi
    sleep "${delay}"
  done
  echo "failed to fetch JSON from ${url} after ${attempts} attempts" >&2
  return 1
}

ISSUES_JSON="$(fetch_json_with_retry "http://127.0.0.1:${UI_PORT}/api/v1/issues" 30 0.5)"
python3 - "${DECISIONS_PATH}" "${ISSUES_JSON}" <<'PY'
import json
import sys
from pathlib import Path

decisions_path = Path(sys.argv[1])
issues_payload = json.loads(sys.argv[2])
issues = issues_payload.get('issues') or []
if not issues:
    raise SystemExit('ui returned zero issues')

candidate_ids = set()
for line in decisions_path.read_text(encoding='utf-8').splitlines():
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    cid = str(row.get('candidate_id') or '').strip()
    if cid:
        candidate_ids.add(cid)

issue_ids = {str(row.get('candidateId') or '').strip() for row in issues}
issue_ids.discard('')
intersection = sorted(candidate_ids & issue_ids)
if not intersection:
    raise SystemExit('ui issues do not include any worker decision candidate IDs')
print(f"[remote-daemon-full-stack] ui_issue_matches={len(intersection)}")
PY
REMOTE

echo "[remote-daemon-full-stack] PASS"
