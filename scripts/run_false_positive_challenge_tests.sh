#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.php_taint_trace_runtime/verifier_false_positive_challenges"
CORPUS_DIR="${ROOT_DIR}/tests/fixtures/verification_corpus_false_positive_challenges"
METRICS_OUTPUT="${RUNTIME_DIR}/metrics.json"
BASE_PORT=18180
CALLBACK_PORT=18181

usage() {
  cat <<'USAGE'
Usage: scripts/run_false_positive_challenge_tests.sh [--runtime-dir PATH] [--corpus-dir PATH] [--metrics-output PATH] [--base-port PORT] [--callback-port PORT]

Runs a challenge corpus specifically designed to validate false-positive resistance:
- safe-but-suspicious scenarios should remain not_confirmed/invalid,
- tricky-but-exploitable scenarios should be confirmed.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-dir)
      RUNTIME_DIR="$2"
      shift 2
      ;;
    --corpus-dir)
      CORPUS_DIR="$2"
      shift 2
      ;;
    --metrics-output)
      METRICS_OUTPUT="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --callback-port)
      CALLBACK_PORT="$2"
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

if [[ ! -d "${CORPUS_DIR}" ]]; then
  echo "Challenge corpus directory not found: ${CORPUS_DIR}" >&2
  exit 1
fi

mkdir -p "${RUNTIME_DIR}"

echo "[fp-challenge] running local verifier corpus with challenge scenarios"
bash "${ROOT_DIR}/scripts/run_local_verifier_corpus.sh" \
  --runtime-dir "${RUNTIME_DIR}" \
  --corpus-dir "${CORPUS_DIR}" \
  --base-port "${BASE_PORT}" \
  --callback-port "${CALLBACK_PORT}"

echo "[fp-challenge] building metrics"
bash "${ROOT_DIR}/scripts/report_verification_metrics.sh" \
  --runtime-dir "${RUNTIME_DIR}" \
  --corpus-dir "${CORPUS_DIR}" \
  --output "${METRICS_OUTPUT}" \
  --fail-on-unexpected-confirmed \
  --expected-formula-version phase_c_v1_step27 \
  --fail-on-formula-version-drift

php "${ROOT_DIR}/scripts/validate_false_positive_suite_metrics.php" \
  --mode challenge \
  --metrics "${METRICS_OUTPUT}"

echo "[fp-challenge] metrics: ${METRICS_OUTPUT}"
echo "[fp-challenge] complete"
