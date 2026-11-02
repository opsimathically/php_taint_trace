#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
REMOTE_VERIFIER_RUNTIME_DIR=""
REASON_CODES=()
JOB_IDS=()
MAX_REQUEUE=0
REQUEUE_TAG="remote_dead_letter_recovery_$(date -u +%Y%m%dT%H%M%SZ)"
INCLUDE_REQUEUED_JOBS=0
DRY_RUN=0
SUMMARY_ONLY=0
WORKER_MAX_RUNS=25
WORKER_BATCH_SIZE=50
WORKER_SLEEP_MS=200

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_dead_letter_recovery_cycle.sh [options]

Options:
  --config PATH              Host credential config JSON (default: testing_container_config.json)
  --host-label LABEL         Host label in config (default: lab.example.invalid)
  --remote-root PATH         Remote lab root (default: /opt/php_taint_trace_vuln_lab)
  --runtime-dir PATH         Remote verifier runtime dir (default: <remote-root>/rewrite/.remote_vuln_lab_runtime/verifier)
  --reason-code CODE         Filter dead letters by reason code (repeatable)
  --job-id ID                Filter dead letters by source job id (repeatable)
  --max N                    Maximum rows to requeue (0 means unlimited)
  --requeue-tag TAG          Stable requeue tag
  --include-requeued-jobs    Include dead letters that were themselves requeue jobs
  --dry-run                  Preview requeue actions without writes
  --summary-only             Print filtered summary and exit
  --worker-max-runs N        Maximum remote worker runs during drain phase
  --worker-batch-size N      Batch size per remote worker invocation
  --worker-sleep-ms N        Sleep between worker runs while pending remains
  -h, --help                 Show this help
USAGE
}

normalize_bool() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "${value}" in
    1|true|yes|on)
      echo 1
      ;;
    0|false|no|off|"")
      echo 0
      ;;
    *)
      return 1
      ;;
  esac
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
    --runtime-dir)
      REMOTE_VERIFIER_RUNTIME_DIR="$2"
      shift 2
      ;;
    --reason-code)
      REASON_CODES+=("$2")
      shift 2
      ;;
    --job-id)
      JOB_IDS+=("$2")
      shift 2
      ;;
    --max)
      MAX_REQUEUE="$2"
      shift 2
      ;;
    --requeue-tag)
      REQUEUE_TAG="$2"
      shift 2
      ;;
    --include-requeued-jobs)
      INCLUDE_REQUEUED_JOBS=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --summary-only)
      SUMMARY_ONLY=1
      shift
      ;;
    --worker-max-runs)
      WORKER_MAX_RUNS="$2"
      shift 2
      ;;
    --worker-batch-size)
      WORKER_BATCH_SIZE="$2"
      shift 2
      ;;
    --worker-sleep-ms)
      WORKER_SLEEP_MS="$2"
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

for value in "${MAX_REQUEUE}" "${WORKER_MAX_RUNS}" "${WORKER_BATCH_SIZE}" "${WORKER_SLEEP_MS}"; do
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    echo "Invalid numeric option value: ${value}. Expected non-negative integer." >&2
    exit 1
  fi
done

if [[ "${WORKER_BATCH_SIZE}" -eq 0 ]]; then
  echo "--worker-batch-size must be >= 1" >&2
  exit 1
fi
if [[ "${REQUEUE_TAG}" =~ ^[[:space:]]*$ ]]; then
  echo "--requeue-tag must be non-empty." >&2
  exit 1
fi

for cmd in python3 ssh setsid; do
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
REMOTE_PROJECT_ROOT="${REMOTE_ROOT}/rewrite"
if [[ -z "${REMOTE_VERIFIER_RUNTIME_DIR}" ]]; then
  REMOTE_VERIFIER_RUNTIME_DIR="${REMOTE_PROJECT_ROOT}/.remote_vuln_lab_runtime/verifier"
fi

ASKPASS_SCRIPT="$(mktemp /tmp/php_taint_trace_askpass.XXXXXX)"
cleanup() {
  rm -f "${ASKPASS_SCRIPT}"
}
trap cleanup EXIT

cat > "${ASKPASS_SCRIPT}" <<'ASKPASS'
#!/usr/bin/env sh
printf '%s\n' "$SSH_PASSWORD"
ASKPASS
chmod 700 "${ASKPASS_SCRIPT}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=15
)

ssh_exec() {
  DISPLAY=:0 \
  SSH_ASKPASS="${ASKPASS_SCRIPT}" \
  SSH_ASKPASS_REQUIRE=force \
  SSH_PASSWORD="${SSH_PASSWORD}" \
  setsid -w ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "$@"
}

REASON_CODES_CSV="$(IFS=,; echo "${REASON_CODES[*]}")"
JOB_IDS_CSV="$(IFS=,; echo "${JOB_IDS[*]}")"

REMOTE_CMD="$(printf \
  "REMOTE_PROJECT_ROOT=%q REMOTE_VERIFIER_RUNTIME_DIR=%q REASON_CODES_CSV=%q JOB_IDS_CSV=%q MAX_REQUEUE=%q REQUEUE_TAG=%q INCLUDE_REQUEUED_JOBS=%q DRY_RUN=%q SUMMARY_ONLY=%q WORKER_MAX_RUNS=%q WORKER_BATCH_SIZE=%q WORKER_SLEEP_MS=%q bash -s" \
  "${REMOTE_PROJECT_ROOT}" \
  "${REMOTE_VERIFIER_RUNTIME_DIR}" \
  "${REASON_CODES_CSV}" \
  "${JOB_IDS_CSV}" \
  "${MAX_REQUEUE}" \
  "${REQUEUE_TAG}" \
  "${INCLUDE_REQUEUED_JOBS}" \
  "${DRY_RUN}" \
  "${SUMMARY_ONLY}" \
  "${WORKER_MAX_RUNS}" \
  "${WORKER_BATCH_SIZE}" \
  "${WORKER_SLEEP_MS}" \
)"

echo "[remote-dead-letter-recovery] host=${HOST} label=${HOST_LABEL} runtime_dir=${REMOTE_VERIFIER_RUNTIME_DIR}"

ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

if [[ ! -d "${REMOTE_PROJECT_ROOT}" ]]; then
  echo "Remote project root does not exist: ${REMOTE_PROJECT_ROOT}" >&2
  exit 1
fi

cd "${REMOTE_PROJECT_ROOT}"

args=(--runtime-dir "${REMOTE_VERIFIER_RUNTIME_DIR}" --requeue-tag "${REQUEUE_TAG}" --max "${MAX_REQUEUE}" --worker-max-runs "${WORKER_MAX_RUNS}" --worker-batch-size "${WORKER_BATCH_SIZE}" --worker-sleep-ms "${WORKER_SLEEP_MS}")

if [[ "${INCLUDE_REQUEUED_JOBS}" == "1" ]]; then
  args+=(--include-requeued-jobs)
fi
if [[ "${DRY_RUN}" == "1" ]]; then
  args+=(--dry-run)
fi
if [[ "${SUMMARY_ONLY}" == "1" ]]; then
  args+=(--summary-only)
fi

if [[ -n "${REASON_CODES_CSV}" ]]; then
  IFS=',' read -r -a reason_codes <<< "${REASON_CODES_CSV}"
  for code in "${reason_codes[@]}"; do
    code_trimmed="$(echo "${code}" | xargs)"
    if [[ -n "${code_trimmed}" ]]; then
      args+=(--reason-code "${code_trimmed}")
    fi
  done
fi
if [[ -n "${JOB_IDS_CSV}" ]]; then
  IFS=',' read -r -a job_ids <<< "${JOB_IDS_CSV}"
  for job_id in "${job_ids[@]}"; do
    job_id_trimmed="$(echo "${job_id}" | xargs)"
    if [[ -n "${job_id_trimmed}" ]]; then
      args+=(--job-id "${job_id_trimmed}")
    fi
  done
fi

bash scripts/run_dead_letter_recovery_cycle.sh "${args[@]}"
REMOTE

echo "[remote-dead-letter-recovery] completed."

