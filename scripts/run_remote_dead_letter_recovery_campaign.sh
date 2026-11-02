#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
RUNTIME_DIR=""
REASON_CODES=()
JOB_IDS=()
MAX_REQUEUE=0
MAX_ROUNDS=5
MAX_STALL_ROUNDS=1
INCLUDE_REQUEUED_JOBS=0
WORKER_MAX_RUNS=25
WORKER_BATCH_SIZE=50
WORKER_SLEEP_MS=200
REQUEUE_TAG_PREFIX="remote_dead_letter_campaign_$(date -u +%Y%m%dT%H%M%SZ)"
VERIFY_AFTER_CAMPAIGN=0
RECOVERY_CYCLE_SCRIPT="${PHP_TAINT_TRACE_REMOTE_DEAD_LETTER_RECOVERY_CYCLE_SCRIPT:-scripts/run_remote_dead_letter_recovery_cycle.sh}"
REMOTE_VERIFIER_SCRIPT="${PHP_TAINT_TRACE_REMOTE_VERIFIER_TESTS_SCRIPT:-scripts/run_remote_verifier_tests.sh}"

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_dead_letter_recovery_campaign.sh [options]

Options:
  --config PATH              Host credential config JSON (default: testing_container_config.json)
  --host-label LABEL         Host label in config (default: lab.example.invalid)
  --remote-root PATH         Remote lab root (default: /opt/php_taint_trace_vuln_lab)
  --runtime-dir PATH         Remote verifier runtime dir override
  --reason-code CODE         Filter dead letters by reason code (repeatable)
  --job-id ID                Filter dead letters by source job id (repeatable)
  --max N                    Maximum rows to requeue per round (0 means unlimited)
  --max-rounds N             Maximum recovery rounds (default: 5)
  --max-stall-rounds N       Allowed non-improving rounds before failure (default: 1)
  --include-requeued-jobs    Include dead letters that were themselves requeue jobs
  --worker-max-runs N        Worker drain runs per recovery round
  --worker-batch-size N      Worker batch size per run
  --worker-sleep-ms N        Sleep between worker runs while pending remains
  --requeue-tag-prefix TAG   Prefix for per-round requeue tags
  --verify-after-campaign    Run remote verifier validation after campaign completion
  -h, --help                 Show this help
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
    --runtime-dir)
      RUNTIME_DIR="$2"
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
    --max-rounds)
      MAX_ROUNDS="$2"
      shift 2
      ;;
    --max-stall-rounds)
      MAX_STALL_ROUNDS="$2"
      shift 2
      ;;
    --include-requeued-jobs)
      INCLUDE_REQUEUED_JOBS=1
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
    --requeue-tag-prefix)
      REQUEUE_TAG_PREFIX="$2"
      shift 2
      ;;
    --verify-after-campaign)
      VERIFY_AFTER_CAMPAIGN=1
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

for value in "${MAX_REQUEUE}" "${MAX_ROUNDS}" "${MAX_STALL_ROUNDS}" "${WORKER_MAX_RUNS}" "${WORKER_BATCH_SIZE}" "${WORKER_SLEEP_MS}"; do
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    echo "Invalid numeric option value: ${value}. Expected non-negative integer." >&2
    exit 1
  fi
done
if [[ "${MAX_ROUNDS}" -eq 0 ]]; then
  echo "--max-rounds must be >= 1" >&2
  exit 1
fi
if [[ "${WORKER_BATCH_SIZE}" -eq 0 ]]; then
  echo "--worker-batch-size must be >= 1" >&2
  exit 1
fi
if [[ "${REQUEUE_TAG_PREFIX}" =~ ^[[:space:]]*$ ]]; then
  echo "--requeue-tag-prefix must be non-empty." >&2
  exit 1
fi
if [[ "${RECOVERY_CYCLE_SCRIPT}" =~ ^[[:space:]]*$ ]]; then
  echo "PHP_TAINT_TRACE_REMOTE_DEAD_LETTER_RECOVERY_CYCLE_SCRIPT must be non-empty." >&2
  exit 1
fi
if [[ "${REMOTE_VERIFIER_SCRIPT}" =~ ^[[:space:]]*$ ]]; then
  echo "PHP_TAINT_TRACE_REMOTE_VERIFIER_TESTS_SCRIPT must be non-empty." >&2
  exit 1
fi
if [[ ! -f "${RECOVERY_CYCLE_SCRIPT}" ]]; then
  echo "Recovery cycle script not found: ${RECOVERY_CYCLE_SCRIPT}" >&2
  exit 1
fi
if [[ "${VERIFY_AFTER_CAMPAIGN}" -eq 1 && ! -f "${REMOTE_VERIFIER_SCRIPT}" ]]; then
  echo "Remote verifier script not found: ${REMOTE_VERIFIER_SCRIPT}" >&2
  exit 1
fi

extract_json_payload() {
  php -r '
$raw = (string) stream_get_contents(STDIN);
$start = strpos($raw, "{");
if ($start === false) {
    fwrite(STDERR, "failed to locate JSON payload in command output" . PHP_EOL);
    exit(1);
}
for ($end = strlen($raw) - 1; $end > $start; $end--) {
    if ($raw[$end] !== "}") {
        continue;
    }
    $candidate = substr($raw, $start, $end - $start + 1);
    $decoded = json_decode($candidate, true);
    if (is_array($decoded)) {
        echo $candidate;
        exit(0);
    }
}
fwrite(STDERR, "failed to decode JSON payload from command output" . PHP_EOL);
exit(1);
'
}

json_get_int() {
  local key="$1"
  php -r '
$payload = json_decode((string) stream_get_contents(STDIN), true);
if (!is_array($payload)) {
    fwrite(STDERR, "invalid json payload for key lookup" . PHP_EOL);
    exit(1);
}
echo (int) ($payload[$argv[1]] ?? 0);
' "${key}"
}

build_common_args() {
  local arr_name="$1"
  local -n out_ref="${arr_name}"
  out_ref=(--config "${CONFIG_PATH}" --host-label "${HOST_LABEL}" --remote-root "${REMOTE_ROOT}" --max "${MAX_REQUEUE}" --worker-max-runs "${WORKER_MAX_RUNS}" --worker-batch-size "${WORKER_BATCH_SIZE}" --worker-sleep-ms "${WORKER_SLEEP_MS}")
  if [[ -n "${RUNTIME_DIR}" ]]; then
    out_ref+=(--runtime-dir "${RUNTIME_DIR}")
  fi
  if [[ "${INCLUDE_REQUEUED_JOBS}" -eq 1 ]]; then
    out_ref+=(--include-requeued-jobs)
  fi
  for code in "${REASON_CODES[@]}"; do
    out_ref+=(--reason-code "${code}")
  done
  for job_id in "${JOB_IDS[@]}"; do
    out_ref+=(--job-id "${job_id}")
  done
}

run_summary() {
  local -n out_json_ref="$1"
  local args=()
  build_common_args args
  args+=(--summary-only)
  local output
  output="$(bash "${RECOVERY_CYCLE_SCRIPT}" "${args[@]}")"
  out_json_ref="$(printf '%s' "${output}" | extract_json_payload)"
}

echo "[remote-dead-letter-campaign] starting (max_rounds=${MAX_ROUNDS} max_stall_rounds=${MAX_STALL_ROUNDS})"

previous_selected=-1
stall_rounds=0
for (( round=1; round<=MAX_ROUNDS; round++ )); do
  summary_json=""
  run_summary summary_json
  selected_rows="$(printf '%s' "${summary_json}" | json_get_int selected_rows)"
  dead_letter_total="$(printf '%s' "${summary_json}" | json_get_int dead_letter_total)"
  echo "[remote-dead-letter-campaign] round=${round} selected_rows=${selected_rows} dead_letter_total=${dead_letter_total}"

  if [[ "${selected_rows}" -eq 0 ]]; then
    echo "[remote-dead-letter-campaign] converged: no matching dead letters remain."
    break
  fi

  if [[ "${previous_selected}" -ge 0 && "${selected_rows}" -ge "${previous_selected}" ]]; then
    stall_rounds=$((stall_rounds + 1))
  else
    stall_rounds=0
  fi
  previous_selected="${selected_rows}"
  if [[ "${stall_rounds}" -gt "${MAX_STALL_ROUNDS}" ]]; then
    echo "[remote-dead-letter-campaign] stalled: selected_rows did not improve for ${stall_rounds} consecutive rounds." >&2
    exit 1
  fi

  recovery_args=()
  build_common_args recovery_args
  recovery_args+=(--requeue-tag "${REQUEUE_TAG_PREFIX}_r${round}")
  echo "[remote-dead-letter-campaign] executing recovery round ${round}"
  bash "${RECOVERY_CYCLE_SCRIPT}" "${recovery_args[@]}"
done

final_summary_json=""
run_summary final_summary_json
final_selected_rows="$(printf '%s' "${final_summary_json}" | json_get_int selected_rows)"
final_dead_letter_total="$(printf '%s' "${final_summary_json}" | json_get_int dead_letter_total)"
echo "[remote-dead-letter-campaign] final selected_rows=${final_selected_rows} dead_letter_total=${final_dead_letter_total}"

if [[ "${final_selected_rows}" -ne 0 ]]; then
  echo "[remote-dead-letter-campaign] campaign ended with unresolved matching dead letters." >&2
  exit 1
fi

if [[ "${VERIFY_AFTER_CAMPAIGN}" -eq 1 ]]; then
  echo "[remote-dead-letter-campaign] running remote verifier validation after recovery campaign"
  bash "${REMOTE_VERIFIER_SCRIPT}" --config "${CONFIG_PATH}" --host-label "${HOST_LABEL}" --remote-root "${REMOTE_ROOT}"
fi

echo "[remote-dead-letter-campaign] completed successfully."
