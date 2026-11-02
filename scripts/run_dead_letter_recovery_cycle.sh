#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.php_taint_trace_runtime/verifier"
REASON_CODES=()
JOB_IDS=()
MAX_REQUEUE=0
REQUEUE_TAG="dead_letter_recovery_$(date -u +%Y%m%dT%H%M%SZ)"
INCLUDE_REQUEUED_JOBS=0
DRY_RUN=0
SUMMARY_ONLY=0
WORKER_MAX_RUNS=25
WORKER_BATCH_SIZE="${PHP_TAINT_TRACE_DEAD_LETTER_RECOVERY_BATCH_SIZE:-50}"
WORKER_SLEEP_MS=200

usage() {
  cat <<'USAGE'
Usage: scripts/run_dead_letter_recovery_cycle.sh [options]

Options:
  --runtime-dir PATH          Verifier runtime directory (default: .php_taint_trace_runtime/verifier)
  --reason-code CODE          Filter dead letters by reason code (repeatable)
  --job-id ID                 Filter dead letters by source job id (repeatable)
  --max N                     Maximum dead-letter rows to requeue (0 means unlimited)
  --requeue-tag TAG           Stable tag used for idempotent requeue ids
  --include-requeued-jobs     Include dead letters that were themselves requeue jobs
  --dry-run                   Preview selected requeues without writing jobs
  --summary-only              Print dead-letter summary and exit
  --worker-max-runs N         Max verifier worker invocations after requeue
  --worker-batch-size N       Batch size per worker invocation
  --worker-sleep-ms N         Sleep between worker runs when pending remains
  -h, --help                  Show this help

Examples:
  bash scripts/run_dead_letter_recovery_cycle.sh --summary-only
  bash scripts/run_dead_letter_recovery_cycle.sh --reason-code VERIFIER_EXCEPTION_RETRY_EXHAUSTED --dry-run
  bash scripts/run_dead_letter_recovery_cycle.sh --reason-code VERIFIER_EXCEPTION_RETRY_EXHAUSTED --max 20 --worker-max-runs 40
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

if ! command -v php >/dev/null 2>&1; then
  echo "Missing required command: php" >&2
  exit 1
fi

cd "${ROOT_DIR}"

SUMMARY_ARGS=(php scripts/requeue_verifier_dead_letters.php --runtime-dir "${RUNTIME_DIR}" --summary-only)
if [[ "${INCLUDE_REQUEUED_JOBS}" -eq 1 ]]; then
  SUMMARY_ARGS+=(--include-requeued-jobs)
fi
for code in "${REASON_CODES[@]}"; do
  SUMMARY_ARGS+=(--reason-code "${code}")
done
for job_id in "${JOB_IDS[@]}"; do
  SUMMARY_ARGS+=(--job-id "${job_id}")
done
if [[ "${MAX_REQUEUE}" -gt 0 ]]; then
  SUMMARY_ARGS+=(--max "${MAX_REQUEUE}")
fi

echo "[dead-letter-recovery] pre-check summary"
PRE_SUMMARY_JSON="$("${SUMMARY_ARGS[@]}")"
echo "${PRE_SUMMARY_JSON}"

if [[ "${SUMMARY_ONLY}" -eq 1 ]]; then
  exit 0
fi

REQUEUE_ARGS=(php scripts/requeue_verifier_dead_letters.php --runtime-dir "${RUNTIME_DIR}" --requeue-tag "${REQUEUE_TAG}")
if [[ "${INCLUDE_REQUEUED_JOBS}" -eq 1 ]]; then
  REQUEUE_ARGS+=(--include-requeued-jobs)
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
  REQUEUE_ARGS+=(--dry-run)
fi
for code in "${REASON_CODES[@]}"; do
  REQUEUE_ARGS+=(--reason-code "${code}")
done
for job_id in "${JOB_IDS[@]}"; do
  REQUEUE_ARGS+=(--job-id "${job_id}")
done
if [[ "${MAX_REQUEUE}" -gt 0 ]]; then
  REQUEUE_ARGS+=(--max "${MAX_REQUEUE}")
fi

echo "[dead-letter-recovery] requeue action (tag=${REQUEUE_TAG} dry_run=${DRY_RUN})"
REQUEUE_JSON="$("${REQUEUE_ARGS[@]}")"
echo "${REQUEUE_JSON}"

ENQUEUED_ROWS="$(php -r '$payload = json_decode((string) stream_get_contents(STDIN), true); if (!is_array($payload)) { fwrite(STDERR, "invalid requeue json output" . PHP_EOL); exit(1); } echo (int) ($payload["enqueued_rows"] ?? 0);' <<<"${REQUEUE_JSON}")"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "[dead-letter-recovery] dry-run complete; no jobs enqueued."
  exit 0
fi

if [[ "${ENQUEUED_ROWS}" -eq 0 ]]; then
  echo "[dead-letter-recovery] no jobs enqueued; nothing to drain."
  exit 0
fi

sleep_for_ms() {
  local millis="$1"
  php -r 'usleep((int) ($argv[1] ?? 0) * 1000);' "${millis}"
}

read_queue_health_json() {
  php -r '
require $argv[1];
use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;
$queue = new JsonlVerificationQueue($argv[2]);
echo json_encode($queue->queueHealth(), JSON_UNESCAPED_SLASHES);
' "${ROOT_DIR}/vendor/autoload.php" "${RUNTIME_DIR}"
}

last_pending=0
for (( run=1; run<=WORKER_MAX_RUNS; run++ )); do
  echo "[dead-letter-recovery] worker run ${run}/${WORKER_MAX_RUNS}"
  PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${RUNTIME_DIR}" \
  PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE="${WORKER_BATCH_SIZE}" \
  php scripts/run_verifier_worker.php

  HEALTH_JSON="$(read_queue_health_json)"
  echo "[dead-letter-recovery] queue_health=${HEALTH_JSON}"
  last_pending="$(php -r '$payload = json_decode((string) stream_get_contents(STDIN), true); if (!is_array($payload)) { exit(1); } echo (int) ($payload["pending_count"] ?? 0);' <<<"${HEALTH_JSON}")"
  if [[ "${last_pending}" -le 0 ]]; then
    break
  fi

  if [[ "${run}" -lt "${WORKER_MAX_RUNS}" && "${WORKER_SLEEP_MS}" -gt 0 ]]; then
    sleep_for_ms "${WORKER_SLEEP_MS}"
  fi
done

if [[ "${last_pending}" -gt 0 ]]; then
  echo "[dead-letter-recovery] recovery cycle incomplete: pending jobs remain (${last_pending}) after ${WORKER_MAX_RUNS} runs." >&2
  exit 1
fi

echo "[dead-letter-recovery] post-check summary"
POST_SUMMARY_JSON="$(php scripts/requeue_verifier_dead_letters.php --runtime-dir "${RUNTIME_DIR}" --summary-only)"
echo "${POST_SUMMARY_JSON}"
echo "[dead-letter-recovery] completed."

