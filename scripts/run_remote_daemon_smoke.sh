#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab/rewrite"
UI_PORT="${PHP_TAINT_TRACE_REMOTE_UI_DAEMON_PORT:-19120}"

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_daemon_smoke.sh [--config PATH] [--host-label LABEL] [--remote-root PATH]
                                          [--ui-port PORT]

Runs remote smoke validation for deployed UI daemon using real verifier output:
  1. UI health endpoint
  2. trigger real vulnerable request in remote vuln lab
  3. run verifier worker drain to produce real decision
  4. verify issue appears in UI
  5. apply triage and verify persistence
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

REMOTE_SMOKE_CMD="$(printf \
  "REMOTE_ROOT=%q UI_PORT=%q bash -s" \
  "${REMOTE_ROOT}" \
  "${UI_PORT}" \
)"

echo "[smoke-daemons] Running smoke flow on ${HOST}"
ssh_exec "${REMOTE_SMOKE_CMD}" <<'REMOTE'
set -euo pipefail

VERIFIER_RUNTIME_DIR="${REMOTE_ROOT}/.remote_vuln_lab_runtime/verifier"
UI_RUNTIME_DIR="${REMOTE_ROOT}/.remote_vuln_lab_runtime/ui"
DECISIONS_PATH="${VERIFIER_RUNTIME_DIR}/decisions.jsonl"
JOBS_PATH="${VERIFIER_RUNTIME_DIR}/jobs.jsonl"
TRIAGE_STATE_PATH="${UI_RUNTIME_DIR}/triage_state.json"
mkdir -p "${VERIFIER_RUNTIME_DIR}" "${UI_RUNTIME_DIR}"

curl -fsS "http://127.0.0.1:${UI_PORT}/health" >/dev/null

TOKEN="daemon_smoke_$(date +%s)_$RANDOM"
MARKER="ptt_daemon_smoke_${TOKEN}"
REQUEST_URL="http://127.0.0.1:19082/?cmd=echo%20${MARKER}"
curl -fsS "${REQUEST_URL}" >/dev/null

CANDIDATE_ID="$(python3 - "${JOBS_PATH}" "${TOKEN}" <<'PY'
import json
import sys
import time
from pathlib import Path

jobs_path = Path(sys.argv[1])
token = sys.argv[2]
deadline = time.time() + 90.0
candidate_id = ""

while time.time() < deadline and not candidate_id:
    if jobs_path.exists():
        lines = jobs_path.read_text(encoding='utf-8').splitlines()
    else:
        lines = []
    for raw in reversed(lines):
        raw = raw.strip()
        if not raw or token not in raw:
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        cid = row.get("candidate_id")
        if isinstance(cid, str) and cid:
            candidate_id = cid
            break
    if candidate_id:
        break
    time.sleep(0.5)

if not candidate_id:
    raise SystemExit("No verifier job found for daemon smoke request.")

print(candidate_id)
PY
)"

if [[ -z "${CANDIDATE_ID}" ]]; then
  echo "failed to resolve candidate id from verifier jobs" >&2
  exit 1
fi

(
  cd "${REMOTE_ROOT}"
  export PHP_TAINT_TRACE_ENABLE_VERIFIER=1
  export PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${VERIFIER_RUNTIME_DIR}"
  export PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=remote_lab
  php scripts/run_verifier_worker.php --drain --max-cycles=80
) >/tmp/remote_daemon_smoke_worker.log 2>&1

if [[ ! -s "${DECISIONS_PATH}" ]]; then
  echo "worker produced no decisions at ${DECISIONS_PATH}" >&2
  cat /tmp/remote_daemon_smoke_worker.log >&2 || true
  exit 1
fi

curl -fsS -X POST "http://127.0.0.1:${UI_PORT}/api/v1/issues/refresh" >/dev/null

for _ in $(seq 1 40); do
  ISSUES_JSON_PATH="$(mktemp)"
  curl -fsS \
    "http://127.0.0.1:${UI_PORT}/api/v1/issues?q=${CANDIDATE_ID}&page=1&pageSize=25&sortKey=updatedAt&sortDirection=desc" \
    > "${ISSUES_JSON_PATH}"
  if python3 - "${CANDIDATE_ID}" "${ISSUES_JSON_PATH}" <<'PY'
import json
import sys
cid = sys.argv[1]
issues_path = sys.argv[2]
with open(issues_path, 'r', encoding='utf-8') as handle:
    payload = json.load(handle)
issues = payload.get("issues") or []
for issue in issues:
    if issue.get("candidateId") == cid:
        raise SystemExit(0)
raise SystemExit(1)
PY
  then
    rm -f "${ISSUES_JSON_PATH}"
    break
  fi
  rm -f "${ISSUES_JSON_PATH}"
  sleep 0.5
done

curl -fsS -X POST \
  -H 'content-type: application/json' \
  -d '{"status":"affirmed","notes":"remote-smoke","actor":"smoke"}' \
  "http://127.0.0.1:${UI_PORT}/api/v1/issues/${CANDIDATE_ID}/triage" >/dev/null

python3 - <<'PY' "${TRIAGE_STATE_PATH}" "${CANDIDATE_ID}"
import json
import sys
from pathlib import Path

state_path = Path(sys.argv[1])
cid = sys.argv[2]
if not state_path.exists():
    raise SystemExit(f"triage state file not found: {state_path}")
state = json.loads(state_path.read_text())
entry = state.get(cid)
if not entry:
    raise SystemExit(f"triage entry missing for {cid}")
if entry.get("status") != "affirmed":
    raise SystemExit(f"triage status mismatch for {cid}: {entry}")
PY

echo "remote-daemon-smoke: PASS candidate=${CANDIDATE_ID}"
REMOTE

echo "[smoke-daemons] PASS"
